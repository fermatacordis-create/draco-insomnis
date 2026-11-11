<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

use DracoInsomnis\Input;
use DracoInsomnis\Core\WafRules;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Application firewall. Starts in "log only" mode so the owner can see what it would stop before it
 * stops anything. Never inspects people who can edit the site, and never blocks an address an
 * administrator used recently.
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
    private const HITS_TO_BLOCK = 5;
    private const HIT_WINDOW = 600;
    private const BLOCK_DAYS = 7;
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
        $ip = Guard::clientIp();
        if (in_array($ip, (array) get_option(Plugin::OPTION_ADMIN_IPS, []), true)) {
            return;
        }
        $method = Input::method();
        $uri = Input::rawServer('REQUEST_URI');
        $path = rawurldecode((string) wp_parse_url($uri, PHP_URL_PATH));
        $query = urldecode((string) wp_parse_url($uri, PHP_URL_QUERY));

        // Addresses on the block list may read the site, but not log in, post forms or use XML-RPC.
        $sensitive = $method === 'POST' || str_ends_with($path, '/wp-login.php') || str_ends_with($path, '/xmlrpc.php');
        if ($sensitive && Store::isBlocked('', $ip)) {
            self::deny('blocked');
        }
        // WordPress's XML-RPC library adds system.multicall itself, after the xmlrpc_methods filter,
        // so it is refused here: one call can carry hundreds of password guesses.
        if ($method === 'POST' && str_ends_with($path, '/xmlrpc.php')
            && preg_match('#<methodName>\s*system\.multicall\s*</methodName>#i', (string) file_get_contents('php://input', false, null, 0, 65536)) === 1) {
            self::record($ip, 'multicall', $path, '');
            self::deny('multicall');
        }

        $rule = WafRules::inspect([
            'path' => $path,
            'query' => $query,
            'params' => WafRules::flatten(array_merge(wp_unslash($_GET), $method === 'POST' ? wp_unslash($_POST) : [])), // phpcs:ignore WordPress.Security.NonceVerification -- inspected, never acted on
            'user_agent' => Input::rawServer('HTTP_USER_AGENT'),
        ]);
        if ($rule === null) {
            return;
        }
        self::record($ip, $rule, $path, $query);
        if (self::blocking()) {
            self::deny($rule);
        }
    }

    private static function record(string $ip, string $rule, string $path, string $query): void
    {
        $remote = (string) (filter_var(Input::server('REMOTE_ADDR'), FILTER_VALIDATE_IP) ?: '0.0.0.0');
        $ua = substr(Input::server('HTTP_USER_AGENT'), 0, 255);
        $verdict = self::blocking() ? 'bot' : 'doubtful';
        Store::log($ip, $remote, 'waf:' . $rule, ['score' => 100, 'verdict' => $verdict, 'reasons' => ['waf_' . $rule]], $ua, [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($path . ($query !== '' ? '?' . $query : ''), 0, 200),
        ]);
        if (!self::blocking()) {
            return;
        }
        $key = 'draco_waf_hits_' . md5($ip);
        $hits = (int) get_transient($key) + 1;
        set_transient($key, $hits, self::HIT_WINDOW);
        $trusted = $ip === $remote || (string) get_option(Guard::OPTION_PROXY, '') !== '';
        if ($hits >= self::HITS_TO_BLOCK && $trusted && !Store::isBlocked('', $ip)) {
            /* translators: %d: number of attacks */
            Store::block('ip', $ip, self::BLOCK_DAYS, sprintf(__('Firewall: %d attacks in 10 minutes', 'draco-insomnis'), $hits), true);
        }
    }

    /** No details for the attacker: what matched stays in the log. */
    private static function deny(string $why): void
    {
        nocache_headers();
        status_header(403);
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Robots-Tag: noindex, nofollow');
        $ref = substr(hash('sha256', $why . '|' . microtime(true)), 0, 10);
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>'
            . '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}</style></head><body><main>'
            . '<h1 style="font-size:20px">' . esc_html__('Request blocked', 'draco-insomnis') . '</h1>'
            . '<p>' . esc_html__('This request was stopped for security reasons. If you think this is a mistake, contact the owner of the site.', 'draco-insomnis') . '</p>'
            . '<p style="color:#64748b;font-size:13px">Ref. ' . esc_html($ref) . '</p></main></body></html>';
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
        $fails = (int) get_transient($key) + 1;
        set_transient($key, $fails, self::LOGIN_WINDOW);
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
