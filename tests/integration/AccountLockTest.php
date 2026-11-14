<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Login\AccountLock;

final class AccountLockTest extends TestCase
{
    private \WP_User $owner;
    /** The site e-mail before the test: tests change it and the HTTP checks that follow need it back. */
    private string $siteEmail = '';

    protected function setUp(): void
    {
        parent::setUp();
        $this->siteEmail = (string) get_option('admin_email');
        $this->owner = $this->user('administrator', 'owner-' . bin2hex(random_bytes(3)) . '@example.org');
        // The owner switches it on from the panel.
        wp_set_current_user($this->owner->ID);
        AccountLock::enable($this->owner);
        AccountLock::boot();
    }

    protected function tearDown(): void
    {
        AccountLock::disable();
        update_option('admin_email', $this->siteEmail);
        update_option('default_role', 'subscriber');
        parent::tearDown();
    }

    /**
     * What Draco decides once WordPress found this user's credentials (cookie, application password,
     * XML-RPC): WordPress's own callbacks on the filter read the cookie, so only Draco's is called.
     */
    private function decided(int $userId): int
    {
        $this->assertSame(99, has_filter('determine_current_user', [AccountLock::class, 'currentUser']));
        $result = AccountLock::currentUser($userId);

        return is_int($result) ? $result : 0;
    }

    public function test_the_owner_is_approved_and_keeps_working(): void
    {
        $this->assertTrue(AccountLock::approved($this->owner));
        $this->assertSame($this->owner->ID, $this->decided($this->owner->ID));
        $this->assertSame($this->owner->user_email, AccountLock::ownerEmail());
    }

    public function test_an_administrator_created_behind_the_owners_back_cannot_get_in(): void
    {
        wp_set_current_user(0); // an exploit, a bad plugin or WP-CLI: nobody approved at the panel
        $intruder = $this->user('administrator');
        $this->assertFalse(AccountLock::approved($intruder));
        $this->assertSame(0, $this->decided($intruder->ID), 'cookies, application passwords and XML-RPC all go through here');

        $login = wp_authenticate($intruder->user_login, 'Long-Pass-123!');
        $this->assertWPError($login);
        $this->assertSame('draco_lock', $login->get_error_code());
        $this->assertCount(1, $this->mailsTo($this->owner->user_email), 'the owner is asked');
        wp_authenticate($intruder->user_login, 'Long-Pass-123!');
        $this->assertCount(1, $this->mailsTo($this->owner->user_email), 'once an hour, not on every try');
    }

    public function test_a_wrong_password_never_bothers_the_owner(): void
    {
        wp_set_current_user(0);
        $intruder = $this->user('administrator');
        wp_authenticate($intruder->user_login, 'wrong');
        $this->assertCount(0, $this->mailsTo($this->owner->user_email));
    }

    public function test_ordinary_accounts_are_never_touched(): void
    {
        wp_set_current_user(0);
        foreach (['subscriber', 'author', 'contributor'] as $role) {
            $user = $this->user($role);
            $this->assertFalse(AccountLock::privileged($user), $role);
            $this->assertSame($user->ID, $this->decided($user->ID), $role);
        }
    }

    public function test_editors_count_as_privileged(): void
    {
        $this->assertTrue(AccountLock::privileged($this->user('editor')));
    }

    public function test_an_account_the_owner_creates_or_promotes_is_approved(): void
    {
        $this->decided($this->owner->ID); // the request starts as the owner
        $editor = $this->user('editor');
        $this->assertTrue(AccountLock::approved($editor));
        $author = $this->user('author');
        $author->set_role('administrator');
        $this->assertTrue(AccountLock::approved(new \WP_User($author->ID)));
    }

    public function test_the_owner_approves_from_the_e_mail(): void
    {
        wp_set_current_user(0);
        $intruder = $this->user('administrator');
        wp_authenticate($intruder->user_login, 'Long-Pass-123!');
        $mail = $this->mailsTo($this->owner->user_email)[0];
        $this->assertSame(1, preg_match('/[?&]t=([a-f0-9]{48})/', $mail['message'], $m));
        $row = get_transient('draco_lock_link_' . hash('sha256', $m[1]));
        $this->assertSame(['kind' => 'approve', 'user' => $intruder->ID], $row);
        $this->assertFalse(get_transient('draco_lock_link_' . $m[1]), 'only the hash of the link is kept');
    }

    public function test_a_change_of_the_site_e_mail_by_anyone_else_pauses_every_privileged_account(): void
    {
        wp_set_current_user(0);
        update_option('admin_email', 'attacker@example.net');
        $this->assertSame('setting_changed', AccountLock::frozen());
        $this->assertSame(0, $this->decided($this->owner->ID), 'even the owner, until confirmed');
        $mails = $this->mailsTo($this->owner->user_email);
        $this->assertCount(1, $mails, 'the confirmation goes to the address kept at switch-on, not the new one');
        $this->assertCount(0, $this->mailsTo('attacker@example.net'));

        AccountLock::unfreeze();
        $this->assertSame($this->owner->ID, $this->decided($this->owner->ID));
    }

    public function test_the_owner_changing_a_watched_setting_is_fine(): void
    {
        $this->decided($this->owner->ID);
        update_option('users_can_register', '1');
        $this->assertSame('', AccountLock::frozen());
        update_option('users_can_register', '0');
    }

    public function test_a_change_straight_in_the_database_is_noticed(): void
    {
        global $wpdb;
        $wpdb->update($wpdb->options, ['option_value' => 'administrator'], ['option_name' => 'default_role']);
        wp_cache_delete('alloptions', 'options');
        wp_cache_delete('default_role', 'options');
        $this->assertSame('changed_outside', AccountLock::frozen());
        $wpdb->update($wpdb->options, ['option_value' => 'subscriber'], ['option_name' => 'default_role']);
        wp_cache_delete('alloptions', 'options');
        AccountLock::unfreeze();
    }

    public function test_an_approval_written_into_the_database_is_worthless(): void
    {
        wp_set_current_user(0);
        $intruder = $this->user('administrator');
        $list = (array) get_option(AccountLock::OPTION_APPROVED, []);
        $list[$intruder->ID] = hash_hmac('sha256', 'approve|' . $intruder->ID, (string) get_option('draco_secret'));
        update_option(AccountLock::OPTION_APPROVED, $list);
        $this->assertFalse(AccountLock::approved($intruder));
    }

    public function test_changing_an_approved_admins_e_mail_elsewhere_withdraws_the_approval(): void
    {
        $admin = $this->user('administrator'); // created by the owner: approved
        $this->decided($this->owner->ID);
        $this->assertTrue(AccountLock::approved($admin));
        AccountLock::reset();
        wp_set_current_user(0);
        wp_update_user(['ID' => $admin->ID, 'user_email' => 'stolen@example.net']);
        $this->assertFalse(AccountLock::approved(new \WP_User($admin->ID)), 'otherwise a reset-password e-mail would hand it over');
    }

    public function test_the_emergency_exit_is_only_in_wp_config(): void
    {
        $this->assertTrue(AccountLock::active());
        $this->assertFalse(defined('DRACO_LOCK_OFF'));
    }

    private function assertWPError($value): void
    {
        $this->assertInstanceOf(\WP_Error::class, $value);
    }
}
