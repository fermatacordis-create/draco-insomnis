<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Login\Challenge;
use DracoInsomnis\Login\Mfa;
use DracoInsomnis\Login\Recovery;
use DracoInsomnis\Login\TrustedDevice;

final class LoginTest extends TestCase
{
    public function test_a_code_is_six_digits_and_only_its_hash_is_kept(): void
    {
        $code = Challenge::newCode();
        $this->assertMatchesRegularExpression('/^\d{6}$/', $code);
        $row = Challenge::create(7, $code);
        $stored = get_transient('draco_mfa_' . $row['id']);
        $this->assertIsArray($stored);
        $this->assertArrayNotHasKey('code', $stored);
        $this->assertNotSame($code, $stored['hash']);
        $this->assertSame(Challenge::hash($code), $stored['hash']);
    }

    public function test_a_code_works_once(): void
    {
        $row = Challenge::create(7, '123456');
        $this->assertSame('wrong', Challenge::check($row['id'], '654321'));
        $this->assertSame('wrong', Challenge::check($row['id'], 'abcdef'));
        $this->assertSame('ok', Challenge::check($row['id'], '123456'));
        $this->assertSame('expired', Challenge::check($row['id'], '123456'));
    }

    public function test_five_wrong_tries_burn_the_code(): void
    {
        $row = Challenge::create(7, '123456');
        for ($i = 0; $i < Challenge::MAX_ATTEMPTS; $i++) {
            $this->assertSame('wrong', Challenge::check($row['id'], '000000'));
        }
        $this->assertSame('locked', Challenge::check($row['id'], '123456'), 'the right code after five misses is too late');
        $this->assertNull(Challenge::get($row['id']));
    }

    public function test_tries_are_counted_atomically_in_the_counters_table(): void
    {
        global $wpdb;
        $row = Challenge::create(7, '123456');
        Challenge::check($row['id'], '000000');
        Challenge::check($row['id'], '000001');
        $this->assertSame('2', $wpdb->get_var($wpdb->prepare('SELECT n FROM %i WHERE k = %s', \DracoInsomnis\Shield\Store::counters(), 'draco_mfa_try_' . $row['id'])));
        $this->assertSame(1, \DracoInsomnis\Shield\Store::bump('draco_test_' . $row['id'], 60));
        $this->assertSame(2, \DracoInsomnis\Shield\Store::bump('draco_test_' . $row['id'], 60));
        $wpdb->query($wpdb->prepare('UPDATE %i SET expires_at = %d WHERE k = %s', \DracoInsomnis\Shield\Store::counters(), time() - 1, 'draco_test_' . $row['id']));
        $this->assertSame(1, \DracoInsomnis\Shield\Store::bump('draco_test_' . $row['id'], 60), 'an expired counter starts again');
    }

    public function test_a_new_code_cancels_the_previous_one_and_old_codes_expire(): void
    {
        $first = Challenge::create(7, '111111');
        $second = Challenge::create(7, '222222');
        $this->assertNull(Challenge::get($first['id']));
        $this->assertNotNull(Challenge::get($second['id']));

        $row = get_transient('draco_mfa_' . $second['id']);
        $row['expires_at'] = time() - 1;
        set_transient('draco_mfa_' . $second['id'], $row, 60);
        $this->assertSame('expired', Challenge::check($second['id'], '222222'));
        $this->assertNull(Challenge::get('not-a-valid-id'));
    }

    public function test_redirect_after_login_stays_on_this_site(): void
    {
        Challenge::setRedirect(7, 'https://evil.example/steal');
        $this->assertSame('', Challenge::takeRedirect(7));
        Challenge::setRedirect(7, admin_url('edit.php'));
        $this->assertSame(admin_url('edit.php'), Challenge::takeRedirect(7));
        $this->assertSame('', Challenge::takeRedirect(7), 'used once');
    }

    public function test_trusted_device_belongs_to_one_user_and_can_be_revoked(): void
    {
        $alice = $this->user('administrator');
        $bob = $this->user('administrator');
        TrustedDevice::issue($alice->ID);
        $this->assertTrue(TrustedDevice::isValid($alice->ID));
        $this->assertFalse(TrustedDevice::isValid($bob->ID));
        TrustedDevice::revokeAll($alice->ID);
        $this->assertFalse(TrustedDevice::isValid($alice->ID));
    }

    public function test_trusted_device_expires_and_the_list_is_capped(): void
    {
        $alice = $this->user('administrator');
        for ($i = 0; $i < 7; $i++) {
            TrustedDevice::issue($alice->ID);
        }
        $list = get_user_meta($alice->ID, TrustedDevice::META, true);
        $this->assertCount(5, $list);
        $this->assertStringNotContainsString((string) $_COOKIE[TrustedDevice::COOKIE], serialize($list), 'only hashes are stored');
        foreach ($list as $k => $row) {
            $list[$k]['expires_at'] = time() - 1;
        }
        update_user_meta($alice->ID, TrustedDevice::META, $list);
        $this->assertFalse(TrustedDevice::isValid($alice->ID));
    }

    public function test_who_needs_a_code(): void
    {
        $admin = $this->user('administrator');
        $editor = $this->user('editor');
        $subscriber = $this->user('subscriber');
        $this->assertTrue(Mfa::requiredFor($admin));
        $this->assertFalse(Mfa::requiredFor($editor));
        update_option(Mfa::OPTION_WHO, 'editors');
        $this->assertTrue(Mfa::requiredFor($editor));
        $this->assertFalse(Mfa::requiredFor($subscriber));
        update_option(Mfa::OPTION_WHO, 'all');
        $this->assertTrue(Mfa::requiredFor($subscriber));
        add_filter('draco_insomnis_mfa_required', '__return_false');
        $this->assertFalse(Mfa::requiredFor($admin));
    }

    public function test_a_wrong_password_never_earns_a_code(): void
    {
        $admin = $this->user('administrator');
        $this->assertSame($admin, Mfa::afterPassword($admin, 'wrong-password'));
        $this->assertSame([], $this->mails);
        $this->assertFalse(get_transient('draco_mfa_uid_' . $admin->ID));
    }

    public function test_login_boxes_that_cannot_show_the_code_step_are_sent_to_the_login_page(): void
    {
        $admin = $this->user('administrator');
        add_filter('wp_doing_ajax', '__return_true');
        $result = Mfa::afterPassword($admin, 'Long-Pass-123!');
        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('draco_mfa_page', $result->get_error_code());
        $this->assertSame([], $this->mails);
    }

    public function test_a_trusted_device_skips_the_code(): void
    {
        $admin = $this->user('administrator');
        TrustedDevice::issue($admin->ID);
        $this->assertSame($admin, Mfa::afterPassword($admin, 'Long-Pass-123!'));
        update_option(Mfa::OPTION_TRUST, 'no');
        add_filter('wp_doing_ajax', '__return_true');
        $this->assertInstanceOf(\WP_Error::class, Mfa::afterPassword($admin, 'Long-Pass-123!'), 'with trust off the device does not count');
    }

    public function test_repeated_failures_lock_the_address(): void
    {
        $admin = $this->user('administrator');
        for ($i = 0; $i < 8; $i++) {
            Mfa::recordFailure();
        }
        $result = Mfa::afterPassword($admin, 'Long-Pass-123!');
        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertSame('draco_locked', $result->get_error_code());
        $_SERVER['REMOTE_ADDR'] = '203.0.113.99';
        $this->assertSame($admin, Mfa::afterPassword($admin, 'wrong'), 'another address is not affected');
    }

    public function test_password_reset_and_email_change_revoke_trusted_devices(): void
    {
        $admin = $this->user('administrator');
        TrustedDevice::issue($admin->ID);
        Mfa::onPasswordReset($admin);
        $this->assertFalse(TrustedDevice::isValid($admin->ID));

        TrustedDevice::issue($admin->ID);
        $old = clone $admin;
        wp_update_user(['ID' => $admin->ID, 'user_email' => 'changed-' . $admin->user_email]);
        Mfa::onProfileUpdate($admin->ID, $old);
        $this->assertFalse(TrustedDevice::isValid($admin->ID));
    }

    public function test_forgetting_the_mailbox_switches_codes_off(): void
    {
        update_option(Mfa::OPTION_ENABLED, 'yes');
        do_action('draco_insomnis_mail_forgotten');
        $this->assertSame('no', get_option(Mfa::OPTION_ENABLED));
    }

    public function test_it_refuses_to_run_next_to_the_opnv_login_code_or_without_smtp(): void
    {
        $this->assertNotSame('', Mfa::blocker(), 'no SMTP');
        update_option('opnv_login_mfa_enabled', 'yes');
        $this->assertStringContainsString('OPNV-WP', Mfa::blocker());
    }

    public function test_the_address_on_screen_is_masked(): void
    {
        $this->assertSame('ma***@example.org', Mfa::mask('maria@example.org'));
        $this->assertSame('a*@x.org', Mfa::mask('a@x.org'));
        $this->assertSame('', Mfa::mask('nope'));
    }

    public function test_recovery_address_is_used_only_when_asked_and_at_most_three_times_an_hour(): void
    {
        $admin = $this->user('administrator');
        $this->assertFalse(Recovery::useRecovery($admin->ID), 'none saved');
        delete_transient('draco_mfa_switch_' . $admin->ID);
        update_user_meta($admin->ID, Recovery::META, 'backup@example.net');
        $this->assertSame($admin->user_email, Recovery::destination($admin));
        $this->assertTrue(Recovery::useRecovery($admin->ID));
        $this->assertSame('backup@example.net', Recovery::destination($admin));
        $this->assertTrue(Recovery::useRecovery($admin->ID));
        $this->assertTrue(Recovery::useRecovery($admin->ID));
        $this->assertFalse(Recovery::useRecovery($admin->ID));
        Recovery::onCodeAccepted($admin->ID);
        $this->assertSame($admin->user_email, Recovery::destination($admin));
    }

    public function test_the_login_code_mail(): void
    {
        $admin = $this->user('administrator');
        $this->assertTrue(Mfa::send($admin, '424242', $admin->user_email));
        $mails = $this->mailsTo($admin->user_email);
        $this->assertCount(1, $mails);
        $this->assertStringContainsString('424242', $mails[0]['message']);
        $this->assertFalse(Mfa::send($admin, '424242', 'not-an-address'));
    }
}
