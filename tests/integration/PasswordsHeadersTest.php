<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\Headers;
use DracoInsomnis\Login\Passwords;

final class PasswordsHeadersTest extends TestCase
{
    /** @var list<string> */
    private array $asked = [];

    protected function setUp(): void
    {
        parent::setUp();
        // Have I Been Pwned, answered here: "password123" is breached, anything else is not.
        add_filter('pre_http_request', function ($pre, $args, $url) {
            if (!str_starts_with((string) $url, 'https://api.pwnedpasswords.com/range/')) {
                return $pre;
            }
            $this->asked[] = (string) $url;
            $hash = strtoupper(sha1('password123'));
            $body = substr((string) $url, -5) === substr($hash, 0, 5) ? "0000000000000000000000000000000000A:0\r\n" . substr($hash, 5) . ":2400000" : "0000000000000000000000000000000000A:0";

            return ['headers' => [], 'body' => $body, 'response' => ['code' => 200, 'message' => 'OK'], 'cookies' => [], 'filename' => null];
        }, 10, 3);
    }

    public function test_nothing_is_checked_while_off(): void
    {
        $this->assertSame('', Passwords::problem('short'));
        $this->assertSame([], $this->asked, 'off means no request at all');
    }

    public function test_minimum_length(): void
    {
        update_option(Passwords::OPTION_MIN, 12);
        $this->assertNotSame('', Passwords::problem('elevenchars'));
        $this->assertSame('', Passwords::problem('twelve chars'));
        update_option(Passwords::OPTION_MIN, 3);
        $this->assertSame(0, Passwords::minLength(), 'below 8 counts as no minimum');
    }

    public function test_breached_passwords_are_refused_and_only_a_prefix_is_sent(): void
    {
        update_option(Passwords::OPTION_BREACHED, 'yes');
        $this->assertNotSame('', Passwords::problem('password123'));
        $this->assertSame('', Passwords::problem('correct horse battery staple 2026'));
        foreach ($this->asked as $url) {
            $this->assertMatchesRegularExpression('#/range/[A-F0-9]{5}$#', $url, 'only 5 characters of the hash leave the site');
        }
    }

    public function test_a_service_that_does_not_answer_never_locks_anyone_out(): void
    {
        update_option(Passwords::OPTION_BREACHED, 'yes');
        add_filter('pre_http_request', fn () => new \WP_Error('http_request_failed', 'timeout'), 5);
        $this->assertSame('', Passwords::problem('password123'));
    }

    public function test_a_breached_login_is_remembered_and_shown_not_refused(): void
    {
        update_option(Passwords::OPTION_BREACHED, 'yes');
        $user = $this->user('administrator');
        $_POST['pwd'] = 'password123';
        Passwords::onLogin($user->user_login, $user);
        $this->assertNotEmpty(get_user_meta($user->ID, Passwords::META_WARN, true));
        wp_set_current_user($user->ID);
        ob_start();
        Passwords::notice();
        $this->assertStringContainsString('profile.php#password', (string) ob_get_clean());
        Passwords::clearWarning($user);
        $this->assertEmpty(get_user_meta($user->ID, Passwords::META_WARN, true));
    }

    public function test_the_reset_form_refuses_a_weak_password(): void
    {
        update_option(Passwords::OPTION_MIN, 12);
        $errors = new \WP_Error();
        $_POST['pass1'] = 'short';
        Passwords::onReset($errors, $this->user('subscriber'));
        $this->assertTrue($errors->has_errors());
    }

    public function test_headers_are_off_by_default_and_hsts_only_over_https(): void
    {
        $this->assertSame([], Headers::wanted(true));
        update_option(Headers::OPTION_SAFE, 'yes');
        $this->assertSame('nosniff', Headers::wanted(false)['X-Content-Type-Options']);
        $this->assertArrayNotHasKey('Strict-Transport-Security', Headers::wanted(true));
        update_option(Headers::OPTION_HSTS, 'yes');
        $this->assertArrayNotHasKey('Strict-Transport-Security', Headers::wanted(false), 'never over plain HTTP');
        $this->assertSame('max-age=15552000', Headers::wanted(true)['Strict-Transport-Security']);
    }
}
