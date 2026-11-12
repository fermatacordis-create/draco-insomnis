<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Core\FormStamp;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

final class ShieldTest extends TestCase
{
    private function signUp(string $login, string $email): \WP_Error
    {
        return Guard::wpRegistration(new \WP_Error(), $login, $email);
    }

    private function asBot(): void
    {
        $_POST[Guard::trapField()] = 'http://spam.example';
    }

    private function asPerson(): void
    {
        $_POST[Guard::stampField()] = FormStamp::make(Plugin::secret(), time() - 40);
    }

    public function test_the_address_comes_from_the_connection_unless_a_proxy_is_trusted(): void
    {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.1, 10.0.0.1';
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '198.51.100.2';
        $this->assertSame(self::VISITOR_IP, Guard::clientIp(), 'forged headers are ignored by default');
        update_option(Guard::OPTION_PROXY, 'xff');
        $this->assertSame(self::VISITOR_IP, Guard::clientIp(), 'a header sent straight to the site is ignored');
        update_option(Guard::OPTION_PROXY, 'cf');
        $this->assertSame(self::VISITOR_IP, Guard::clientIp(), 'a Cloudflare header that does not come from Cloudflare is ignored');

        // Through nginx on the same machine: read from the right, the visitor's own text on the left is ignored.
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '192.0.2.50, 198.51.100.1';
        update_option(Guard::OPTION_PROXY, 'xff');
        $this->assertSame('198.51.100.1', Guard::clientIp());

        // Through Cloudflare.
        $_SERVER['REMOTE_ADDR'] = '172.68.1.20';
        update_option(Guard::OPTION_PROXY, 'cf');
        $this->assertSame('198.51.100.2', Guard::clientIp());
        $_SERVER['HTTP_CF_CONNECTING_IP'] = 'not-an-ip';
        $this->assertSame('172.68.1.20', Guard::clientIp());

        // A public load balancer, once listed.
        $_SERVER['REMOTE_ADDR'] = '198.51.100.9';
        update_option(Guard::OPTION_PROXY, 'xff');
        $this->assertSame('198.51.100.9', Guard::clientIp());
        update_option(Guard::OPTION_TRUSTED, '198.51.100.9');
        $this->assertSame('198.51.100.1', Guard::clientIp());
    }

    public function test_a_bot_sign_up_is_refused_and_kept_as_evidence(): void
    {
        $this->asBot();
        $_POST['user_pass'] = 'never-stored';
        $errors = $this->signUp('usru88w16kx', 'bot@spam.example');
        $this->assertContains('draco_rejected', $errors->get_error_codes());
        $rows = Store::recent();
        $this->assertCount(1, $rows);
        $this->assertSame('bot', $rows[0]['verdict']);
        $this->assertSame(self::VISITOR_IP, $rows[0]['ip']);
        $this->assertStringContainsString('bot@spam.example', $rows[0]['fields']);
        $this->assertStringNotContainsString('never-stored', serialize($rows), 'passwords are never kept');
    }

    public function test_a_person_signs_up_normally_and_leaves_no_trace(): void
    {
        $this->asPerson();
        $errors = $this->signUp('maria1985', 'maria@example.org');
        $this->assertFalse($errors->has_errors());
        $this->assertSame([], Store::recent());
    }

    public function test_logged_in_users_are_not_judged(): void
    {
        wp_set_current_user($this->user('administrator')->ID);
        $this->asBot();
        $this->assertFalse($this->signUp('x', 'x@example.org')->has_errors());
    }

    public function test_three_bot_attempts_in_a_day_block_the_address(): void
    {
        $this->asBot();
        for ($i = 0; $i < 3; $i++) {
            $this->signUp('bot' . $i, "bot$i@spam.example");
        }
        $this->assertTrue(Store::isBlocked('', self::VISITOR_IP));
        $blocks = Store::activeBlocks();
        $this->assertCount(1, $blocks);
        $this->assertSame('ip', $blocks[0]['kind']);
    }

    public function test_an_address_an_administrator_used_is_never_blocked(): void
    {
        update_option(Plugin::OPTION_ADMIN_IPS, [self::VISITOR_IP]);
        $this->asBot();
        for ($i = 0; $i < 4; $i++) {
            $this->signUp('bot' . $i, "bot$i@spam.example");
        }
        $this->assertFalse(Store::isBlocked('', self::VISITOR_IP));
    }

    public function test_what_the_block_list_refuses(): void
    {
        $admin = $this->user('administrator', 'boss@example.org');
        $this->assertFalse(Store::block('ip', 'not-an-ip', 7, 'x'));
        $this->assertFalse(Store::block('ip', '198.51.100.7', 5, 'x'), 'only 7, 15, 30 or 90 days');
        $this->assertFalse(Store::block('email', $admin->user_email, 7, 'x'), 'never an administrator');
        $this->assertFalse(Store::block('ip', self::VISITOR_IP, 7, 'x'), 'not your own address from the screen');
        $this->assertTrue(Store::block('ip', self::VISITOR_IP, 7, 'x', true), 'the automatic block runs in the bot\'s request');
        $this->assertFalse(Store::block('phone', '123', 7, 'x'));
    }

    public function test_block_unblock_and_expiry(): void
    {
        $this->assertTrue(Store::block('email', 'Spam@Example.org', 7, 'manual'));
        $this->assertTrue(Store::isBlocked('SPAM@example.org', '192.0.2.1'));
        $id = (int) Store::activeBlocks()[0]['id'];
        Store::unblock($id);
        $this->assertFalse(Store::isBlocked('spam@example.org', '192.0.2.1'));

        global $wpdb;
        Store::block('ip', '198.51.100.7', 7, 'old');
        $wpdb->query($wpdb->prepare('UPDATE %i SET until_at = %s', Store::blocks(), gmdate('Y-m-d H:i:s', time() - 60)));
        $this->assertFalse(Store::isBlocked('', '198.51.100.7'));
        Store::cleanup();
        $this->assertSame(0, (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i', Store::blocks())));
    }

    public function test_a_flood_cannot_fill_the_database(): void
    {
        $result = ['score' => 90, 'verdict' => 'bot', 'reasons' => ['honeypot']];
        for ($i = 0; $i < 40; $i++) {
            Store::log('198.51.100.9', '198.51.100.9', 'wp_register', $result, 'curl', []);
        }
        $this->assertCount(30, Store::byIp('198.51.100.9'));
    }

    public function test_old_evidence_is_deleted_after_90_days(): void
    {
        global $wpdb;
        Store::log('198.51.100.9', '198.51.100.9', 'wp_register', ['score' => 90, 'verdict' => 'bot', 'reasons' => []], 'curl', []);
        $wpdb->query($wpdb->prepare('UPDATE %i SET created_at = %s', Store::events(), gmdate('Y-m-d H:i:s', time() - 91 * DAY_IN_SECONDS)));
        Store::cleanup();
        $this->assertSame([], Store::recent());
    }

    public function test_the_hidden_fields_differ_per_site_and_are_printed_in_forms(): void
    {
        $this->assertMatchesRegularExpression('/^dr_[a-f0-9]{8}$/', Guard::stampField());
        ob_start();
        Guard::fields();
        $html = (string) ob_get_clean();
        $this->assertStringContainsString('name="' . Guard::stampField() . '"', $html);
        $this->assertStringContainsString('name="' . Guard::trapField() . '"', $html);
        $this->assertStringContainsString('tabindex="-1"', $html);
    }
}
