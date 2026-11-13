<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Gate\Store as Submissions;
use DracoInsomnis\Shield\Store;

/**
 * Each test starts from a clean Draco: no options, no rows, no transients, no hooks added by the
 * test before, nobody logged in, and every outgoing e-mail captured instead of sent.
 */
abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected const VISITOR_IP = '203.0.113.10';
    protected const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';

    /** @var list<array{to: mixed, subject: string, message: string, headers: mixed}> */
    protected array $mails = [];
    /** @var array<string, \WP_Hook> */
    private array $hooks = [];
    /** @var list<int> */
    private array $users = [];

    protected function setUp(): void
    {
        parent::setUp();
        global $wpdb;
        foreach ($GLOBALS['wp_filter'] as $name => $hook) {
            $this->hooks[$name] = clone $hook;
        }
        $_GET = $_POST = $_REQUEST = $_COOKIE = [];
        $_SERVER['REMOTE_ADDR'] = self::VISITOR_IP;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';
        $_SERVER['HTTP_USER_AGENT'] = self::BROWSER;
        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_REFERER']);
        wp_set_current_user(0);
        self::resetStatics();

        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'draco\\_%' AND option_name NOT IN ('draco_schema', 'draco_gate_schema', 'draco_secret')");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_%draco\\_%' OR option_name LIKE '\\_transient\\_timeout\\_%draco\\_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE 'opnv\\_%'");
        wp_cache_flush();
        Store::ensureTables();
        Submissions::ensureTable();
        $wpdb->query('TRUNCATE TABLE ' . Store::events());
        $wpdb->query('TRUNCATE TABLE ' . Store::blocks());
        $wpdb->query('TRUNCATE TABLE ' . Store::counters());
        $wpdb->query('TRUNCATE TABLE ' . Store::reviews());
        $wpdb->query('TRUNCATE TABLE ' . Submissions::table());

        $this->mails = [];
        add_filter('pre_wp_mail', function ($return, array $atts) {
            if ($return !== null) {
                return $return;
            }
            $this->mails[] = [
                'to' => $atts['to'] ?? '',
                'subject' => (string) ($atts['subject'] ?? ''),
                'message' => (string) ($atts['message'] ?? ''),
                'headers' => $atts['headers'] ?? [],
            ];

            return true;
        }, 1000, 2);
        // The slow answer for bots would make every bot test wait seconds.
        set_transient('draco_slow_' . gmdate('YmdHi'), 1000, 120);
        set_transient('draco_slow_' . gmdate('YmdHi', time() + 60), 1000, 180);
    }

    protected function tearDown(): void
    {
        wp_set_current_user(0);
        foreach ($this->users as $id) {
            if (get_userdata($id)) {
                wp_delete_user($id);
            }
        }
        $GLOBALS['wp_filter'] = $this->hooks;
        self::resetStatics();
        parent::tearDown();
    }

    protected function user(string $role, string $email = '', string $password = 'Long-Pass-123!'): \WP_User
    {
        $login = $role . '_' . bin2hex(random_bytes(4));
        $id = wp_insert_user([
            'user_login' => $login,
            'user_email' => $email !== '' ? $email : $login . '@example.org',
            'user_pass' => $password,
            'role' => $role,
        ]);
        $this->assertIsInt($id, 'could not create the test user');
        $this->users[] = $id;

        return new \WP_User($id);
    }

    protected function track(int $userId): void
    {
        $this->users[] = $userId;
    }

    /** @return list<array{to: mixed, subject: string, message: string, headers: mixed}> */
    protected function mailsTo(string $email): array
    {
        return array_values(array_filter($this->mails, static function (array $m) use ($email): bool {
            $to = is_array($m['to']) ? implode(',', $m['to']) : (string) $m['to'];

            return stripos($to, $email) !== false;
        }));
    }

    /** The confirmation token inside a mail sent by the form gate. */
    protected function tokenIn(array $mail): string
    {
        $this->assertSame(1, preg_match('/[?&;]t=([a-f0-9]{64})/', html_entity_decode($mail['message']), $m), 'no confirmation link in the mail');

        return $m[1];
    }

    /** Draco keeps per-request state in static properties; a new test is a new request. */
    protected static function resetStatics(): void
    {
        $reset = [
            \DracoInsomnis\Gate\MailHold::class => ['submission' => 0, 'held' => false, 'dropped' => false, 'releasing' => false],
            \DracoInsomnis\Gate\RegistrationHold::class => ['held' => false],
            \DracoInsomnis\Gate\Mailer::class => ['sending' => false],
            \DracoInsomnis\Shield\Store::class => ['values' => []],
            \DracoInsomnis\Mail\Transport::class => ['forced' => false, 'transport' => 'php', 'lastError' => '', 'originalFrom' => ''],
        ];
        foreach ($reset as $class => $props) {
            foreach ($props as $name => $value) {
                $p = new \ReflectionProperty($class, $name);
                $p->setValue(null, $value);
            }
        }
    }
}
