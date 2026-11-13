<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;
use DracoInsomnis\WpHost;

defined('ABSPATH') || exit;

/**
 * Application firewall for WordPress. The rules and the automatic block live in Core\Firewall, shared
 * with the other CMSs; this class adds what only WordPress has (XML-RPC, user enumeration, logins).
 *
 * Starts in "log only" mode so the owner can see what it would stop before it stops anything. Never
 * inspects people who can edit the site, and never blocks an address an administrator used recently.
 *
 * Emergency exit: define('DRACO_WAF_OFF', true); in wp-config.php.
 */
final class Waf
{
    public const OPTION_ENABLED = 'draco_waf_enabled';
    public const OPTION_MODE = 'draco_waf_mode';
    public const OPTION_HIDE_USERS = 'draco_waf_hide_users';
    public const OPTION_XMLRPC_OFF = 'draco_waf_xmlrpc_off';
    public const OPTION_LOGIN_LIMIT = 'draco_waf_login_limit';
    private const LOGIN_FAILS = 10;
    private const LOGIN_WINDOW = 600;
    private const LOGIN_BLOCK = 1800;

    public static function boot(): void
    {
        if (!self::active()) {
            return;
        }
        // boot() runs on plugins_loaded at priority 1: the earliest point where the current user is
        // known (pluggable functions are loaded), before other plugins start their work.
        self::inspect();
        // Brute force in one request: hundreds of passwords inside system.multicall.
        add_filter('xmlrpc_methods', [self::class, 'xmlrpcMethods']);
        if (get_option(self::OPTION_XMLRPC_OFF, 'no') === 'yes') {
            add_filter('xmlrpc_enabled', '__return_false');
        }
        if (get_option(self::OPTION_HIDE_USERS, 'yes') === 'yes') {
            add_filter('rest_endpoints', [self::class, 'hideUserEndpoints']);
            add_action('template_redirect', [self::class, 'hideAuthorScan'], 0);
        }
        if (get_option(self::OPTION_LOGIN_LIMIT, 'yes') === 'yes') {
            add_action('wp_login_failed', [self::class, 'loginFailed']);
            add_filter('authenticate', [self::class, 'refuseLockedLogin'], 30);
        }
    }

    public static function active(): bool
    {
        return get_option(self::OPTION_ENABLED, 'no') === 'yes' && !(defined('DRACO_WAF_OFF') && DRACO_WAF_OFF);
    }

    public static function blocking(): bool
    {
        return get_option(self::OPTION_MODE, 'log') === 'block';
    }

    public static function inspect(): void
    {
        if ((defined('WP_CLI') && WP_CLI) || wp_doing_cron() || current_user_can('edit_posts')) {
            return;
        }
        if (Review::handle() || self::answerTest()) {
            return;
        }
        $request = WpHost::request();
        $firewall = new Firewall(WpHost::get(), self::blocking());
        if ($firewall->exempt($request)) {
            return;
        }
        // Addresses on the block list may read the site, but not log in, post forms or use XML-RPC.
        if ($firewall->refusedAsBlocked($request, ['/wp-login.php', '/xmlrpc.php'])) {
            self::deny('blocked');
        }
        // WordPress's XML-RPC library adds system.multicall itself, after the xmlrpc_methods filter,
        // so it is refused here: one call can carry hundreds of password guesses.
        if ($request->method === 'POST' && str_ends_with($request->path, '/xmlrpc.php')
            && preg_match('#<methodName>\s*system\.multicall\s*</methodName>#i', (string) file_get_contents('php://input', false, null, 0, 65536)) === 1) {
            $firewall->record($request, 'multicall');
            self::deny('multicall');
        }
        $rule = $firewall->inspect($request);
        if ($rule !== null && $firewall->blocking()) {
            self::deny($rule);
        }
    }

    /** No details for the attacker: what matched stays in the log. */
    private static function deny(string $why): void
    {
        WpHost::earlyTranslations();
        nocache_headers();
        status_header(403);
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Robots-Tag: noindex, nofollow');
        $page = Firewall::page(
            __('Request blocked', 'draco-insomnis'),
            __('This request was stopped for security reasons. If you think this is a mistake, tell the owner of the site what you were doing:', 'draco-insomnis'),
            $why,
            Review::form($why)
        );
        echo $page; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- every text is escaped inside Firewall::page()
        exit;
    }

    public const TEST_HEADER = 'HTTP_X_DRACO_TEST';
    public const TEST_ATTACK = "1' union select user_pass from wp_users-- ";

    /** Header value that proves the request is the owner's test (signed, valid for a minute). */
    public static function testToken(int $ts): string
    {
        return $ts . '.' . hash_hmac('sha256', 'waf-test|' . $ts, Plugin::secret());
    }

    /**
     * The "Test the firewall" button sends an attack-shaped request to the site itself with a signed
     * header. It is judged by the same rules, but nothing is logged or counted (it would otherwise put
     * the server's own address on the block list), and the answer says what would have happened.
     */
    private static function answerTest(): bool
    {
        $token = isset($_SERVER[self::TEST_HEADER]) ? (string) $_SERVER[self::TEST_HEADER] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- compared with hash_equals only
        if ($token === '') {
            return false;
        }
        $ts = (int) strtok($token, '.');
        if (abs(time() - $ts) > 60 || !hash_equals(self::testToken($ts), $token)) {
            return false;
        }
        $rule = \DracoInsomnis\Core\WafRules::inspect(['path' => '/', 'query' => 'draco_test=' . self::TEST_ATTACK, 'params' => [self::TEST_ATTACK], 'user_agent' => 'Draco test']);
        nocache_headers();
        header('X-Draco-Test-Result: ' . ($rule ?? 'none') . '|' . (self::blocking() ? 'block' : 'log'));
        status_header($rule !== null && self::blocking() ? 403 : 200);
        exit;
    }

    /** @param array<string, mixed> $methods @return array<string, mixed> */
    public static function xmlrpcMethods($methods): array
    {
        $methods = (array) $methods;
        // Pingbacks are used to make sites attack third parties. system.multicall is cut in inspect().
        unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);

        return $methods;
    }

    /** @param array<string, mixed> $endpoints @return array<string, mixed> */
    public static function hideUserEndpoints($endpoints): array
    {
        $endpoints = (array) $endpoints;
        if (!current_user_can('list_users')) {
            unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }

        return $endpoints;
    }

    /** ?author=1 turns a user number into a login name. Anonymous visitors go to the home page instead. */
    public static function hideAuthorScan(): void
    {
        if (isset($_GET['author']) && !is_user_logged_in()) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    public static function loginFailed(): void
    {
        $key = 'draco_waf_login_' . md5(Guard::clientIp());
        $fails = Store::bump($key, self::LOGIN_WINDOW);
        if ($fails >= self::LOGIN_FAILS) {
            set_transient('draco_waf_login_lock_' . md5(Guard::clientIp()), 1, self::LOGIN_BLOCK);
        }
    }

    /** @param \WP_User|\WP_Error|null $user @return \WP_User|\WP_Error|null */
    public static function refuseLockedLogin($user)
    {
        if (get_transient('draco_waf_login_lock_' . md5(Guard::clientIp()))) {
            return new \WP_Error('draco_login_locked', __('Too many failed logins from your address. Try again in 30 minutes.', 'draco-insomnis'));
        }

        return $user;
    }
}
