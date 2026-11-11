<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Gate\MailHold;
use DracoInsomnis\Gate\Mailer;
use DracoInsomnis\Gate\RegistrationHold;
use DracoInsomnis\Gate\Store;
use DracoInsomnis\Gate\Verify;
use DracoInsomnis\Shield\Store as Blocks;

final class GateTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        RegistrationHold::register();
        MailHold::register();
    }

    private function signUp(string $role = 'subscriber'): int
    {
        $login = 'new_' . bin2hex(random_bytes(4));
        $id = wp_insert_user(['user_login' => $login, 'user_email' => "$login@example.org", 'user_pass' => 'Long-Pass-123!', 'role' => $role]);
        $this->assertIsInt($id);
        $this->track($id);

        return $id;
    }

    /** What Verify::handle() does for a POST to the link, without its page and exit. */
    private function confirm(string $token): bool
    {
        self::resetStatics(); // the click on the link is another request
        $row = Store::findPending($token);
        if ($row === null || !Store::claim((int) $row['id'])) {
            return false;
        }
        Verify::complete($row);

        return true;
    }

    public function test_a_new_account_stays_closed_until_its_address_is_confirmed(): void
    {
        $id = $this->signUp();
        $user = get_userdata($id);
        $this->assertTrue(RegistrationHold::isPending($id));

        $mails = $this->mailsTo($user->user_email);
        $this->assertCount(1, $mails, 'only the confirmation, not WordPress\'s welcome');
        $token = $this->tokenIn($mails[0]);

        $login = wp_authenticate($user->user_login, 'Long-Pass-123!');
        $this->assertInstanceOf(\WP_Error::class, $login);
        $this->assertSame('draco_pending', $login->get_error_code());
        $this->assertFalse(apply_filters('allow_password_reset', true, $id));
        $this->assertSame(0, RegistrationHold::ignorePending($id), 'themes that log the new user in themselves');

        $this->assertTrue($this->confirm($token));
        $this->assertFalse(RegistrationHold::isPending($id));
        $this->assertInstanceOf(\WP_User::class, wp_authenticate($user->user_login, 'Long-Pass-123!'));
        $this->assertNotEmpty($this->mailsTo(get_option('admin_email')), 'the usual new-user notice goes out after confirming');
        $this->assertFalse($this->confirm($token), 'a link works once');
    }

    public function test_other_mail_in_the_sign_up_request_is_silenced(): void
    {
        $id = $this->signUp();
        $email = get_userdata($id)->user_email;
        // RealHomes sends its own welcome with the password in it.
        $this->assertTrue(wp_mail($email, 'Welcome! Your password is Long-Pass-123!', 'Long-Pass-123!'));
        $this->assertTrue(wp_mail('admin@example.org', 'New user', '...'));
        $this->assertCount(1, $this->mails);
        $this->assertStringNotContainsString('Long-Pass-123!', $this->mails[0]['message']);
    }

    public function test_editors_must_confirm_too_but_administrators_and_admin_made_accounts_do_not(): void
    {
        $this->assertTrue(RegistrationHold::isPending($this->signUp('editor')));
        self::resetStatics();
        $this->assertFalse(RegistrationHold::isPending($this->signUp('administrator')));
        wp_set_current_user($this->user('administrator')->ID);
        $this->assertFalse(RegistrationHold::isPending($this->signUp()));
    }

    public function test_blocked_or_too_frequent_senders_cannot_register(): void
    {
        Blocks::block('email', 'spam@example.org', 7, 'manual');
        $errors = RegistrationHold::rejectBlocked(new \WP_Error(), 'spam', 'spam@example.org');
        $this->assertContains('draco_rejected', $errors->get_error_codes());

        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue(Mailer::allow('ana@example.org', '192.0.2.' . $i));
        }
        $this->assertFalse(Mailer::allow('ana@example.org', '192.0.2.200'), 'three confirmation mails a day per address');
        for ($i = 0; $i < 5; $i++) {
            Mailer::allow("p$i@example.org", '192.0.2.50');
        }
        $this->assertFalse(Mailer::allow('other@example.org', '192.0.2.50'), 'five an hour per address');
    }

    public function test_links_expire_after_48_hours_and_malformed_tokens_are_ignored(): void
    {
        global $wpdb;
        $created = Store::create('form', 'cf7', 'ana@example.org', self::VISITOR_IP);
        $this->assertNotNull(Store::findPending($created['token']));
        $this->assertNull(Store::findPending(strtoupper($created['token'])));
        $this->assertNull(Store::findPending("' OR 1=1 -- "));
        $row = Store::find($created['id']);
        $this->assertNotSame($created['token'], $row['token_hash'], 'only the hash of the token is stored');
        $wpdb->update(Store::table(), ['created_at' => gmdate('Y-m-d H:i:s', time() - 49 * HOUR_IN_SECONDS)], ['id' => $created['id']]);
        $this->assertNull(Store::findPending($created['token']));
        Store::cleanup();
        $this->assertSame('expired', Store::find($created['id'])['status']);
    }

    public function test_abandoned_accounts_are_deleted_but_accounts_with_content_wait_for_a_person(): void
    {
        $empty = $this->signUp();
        $withPost = $this->signUp();
        wp_insert_post(['post_title' => 'Mine', 'post_author' => $withPost, 'post_status' => 'draft']);
        foreach ([$empty, $withPost] as $id) {
            update_user_meta($id, RegistrationHold::META, time() - 49 * HOUR_IN_SECONDS);
        }
        RegistrationHold::purge();
        $this->assertFalse(get_userdata($empty));
        $this->assertInstanceOf(\WP_User::class, get_userdata($withPost));
        $this->assertNotSame('', get_user_meta($withPost, RegistrationHold::META_REVIEW, true));
        $this->assertTrue(RegistrationHold::isPending($withPost), 'still cannot log in');
    }

    public function test_a_contact_form_message_waits_for_the_sender_and_then_reaches_the_owner(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = ['_wpcf7' => '5', 'your-name' => 'Ana', 'your-email' => 'ana@example.org', 'your-message' => 'Hola'];
        $this->assertTrue(wp_mail('owner@example.org', 'New message', 'Hola from Ana', ['Reply-To: Ana <ana@example.org>']));
        $this->assertSame([], $this->mailsTo('owner@example.org'), 'nothing reaches the owner yet');
        $confirmation = $this->mailsTo('ana@example.org');
        $this->assertCount(1, $confirmation);
        $token = $this->tokenIn($confirmation[0]);
        $row = Store::findPending($token);
        $this->assertSame('cf7', $row['context']);
        $this->assertStringContainsString('Hola from Ana', $row['payload']);

        $_POST = [];
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $this->assertTrue($this->confirm($token));
        $delivered = $this->mailsTo('owner@example.org');
        $this->assertCount(1, $delivered);
        $this->assertSame('New message', $delivered[0]['subject']);
        $this->assertStringContainsString('Hola from Ana', $delivered[0]['message']);
        $this->assertStringContainsString('block=' . $row['id'], $delivered[0]['message'], 'the owner can block the sender in one click');
        $this->assertNull(Store::find((int) $row['id'])['payload'], 'the message is not kept once delivered');
    }

    public function test_a_blocked_sender_is_told_the_same_and_nothing_is_sent(): void
    {
        Blocks::block('email', 'spam@example.org', 7, 'manual');
        $_POST = ['_wpcf7' => '5', 'your-email' => 'spam@example.org'];
        $this->assertTrue(wp_mail('owner@example.org', 'New message', 'Buy now'));
        $this->assertSame([], $this->mails);
        $this->assertSame([], Store::recent());
    }

    public function test_mail_that_is_not_a_public_form_is_untouched(): void
    {
        // A confirmed member, created in an earlier request.
        $member = $this->user('subscriber');
        delete_user_meta($member->ID, RegistrationHold::META);
        self::resetStatics();
        $this->mails = [];

        $this->assertTrue(wp_mail('owner@example.org', 'Order #1', 'Thanks'));
        $this->assertCount(1, $this->mailsTo('owner@example.org'));

        $_POST = ['_wpcf7' => '5', 'your-email' => 'ana@example.org'];
        wp_set_current_user($member->ID);
        $this->assertTrue(wp_mail('owner@example.org', 'From a member', 'Hi'));
        $this->assertCount(2, $this->mailsTo('owner@example.org'), 'logged-in people are not asked to confirm');
    }

    public function test_the_page_answer_of_a_held_form_is_replaced(): void
    {
        $_POST = ['_wpcf7' => '5', 'your-email' => 'ana@example.org'];
        wp_mail('owner@example.org', 'New message', 'Hola');
        $response = MailHold::cf7Response(['status' => 'mail_sent', 'message' => 'Thank you'], null);
        $this->assertSame(MailHold::notice(), $response['message']);
        $json = MailHold::rewriteOutput((string) wp_json_encode(['success' => true, 'data' => ['message' => 'Sent']]));
        $this->assertSame(MailHold::notice(), json_decode($json, true)['data']['message']);
    }
}
