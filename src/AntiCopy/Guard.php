<?php

declare(strict_types=1);

namespace DracoInsomnis\AntiCopy;

use DracoInsomnis\Core\Crawler;
use DracoInsomnis\Input;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard as Shield;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Makes copying the whole site harder, without getting in the way of people or search engines.
 *
 * Two independent parts, each off, "log" or "block":
 * - Content API: anonymous reads of /wp/v2/* (posts, pages, media...) are refused, except the
 *   routes on the allow list. Pages themselves stay public; only the bulk JSON door closes.
 * - Pace: more pages per minute than a person reads, from one address or one network, get a 429
 *   for the rest of that minute. Search engines verified by reverse DNS are never limited.
 *
 * Nobody logged in is ever touched, nor the addresses an administrator used.
 */
final class Guard
{
    public const OPTION_REST = 'draco_anticopy_rest';
    public const OPTION_REST_ALLOW = 'draco_anticopy_rest_allow';
    public const OPTION_RATE = 'draco_anticopy_rate';
    public const OPTION_RATE_IP = 'draco_anticopy_rate_ip';
    public const OPTION_RATE_NET = 'draco_anticopy_rate_net';
    public const MODES = ['off', 'log', 'block'];
    public const DEFAULT_RATE_IP = 120;
    public const DEFAULT_RATE_NET = 600;
    private const WINDOW = 60;
    private const VERIFIED_FOR = DAY_IN_SECONDS;

    public static function boot(): void
    {
        if (self::mode(self::OPTION_REST) !== 'off') {
            add_filter('rest_pre_dispatch', [self::class, 'rest'], 5, 3);
        }
        if (self::mode(self::OPTION_RATE) !== 'off') {
            self::pace();
        }
    }

    public static function mode(string $option): string
    {
        $mode = (string) get_option($option, 'off');

        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    /**
     * @param mixed $result
     * @param \WP_REST_Server|null $server
     * @param \WP_REST_Request|null $request
     * @return mixed
     */
    public static function rest($result, $server = null, $request = null)
    {
        if ($result !== null || !$request instanceof \WP_REST_Request || is_user_logged_in()) {
            return $result;
        }
        if (!in_array(strtoupper((string) $request->get_method()), ['GET', 'HEAD'], true)) {
            return $result;
        }
        $route = '/' . ltrim((string) $request->get_route(), '/');
        if (!str_starts_with($route, '/wp/v2/') || self::allowed($route) || self::exempt()) {
            return $result;
        }
        $block = self::mode(self::OPTION_REST) === 'block';
        self::record('rest', $block, $route);
        if (!$block) {
            return $result;
        }

        return new \WP_Error('draco_rest_closed', __('This content is not available through the API.', 'draco-insomnis'), ['status' => 401]);
    }

    /** Route prefixes that stay open: one per line, from the screen, plus the draco_insomnis_rest_allow filter. */
    public static function allowList(): array
    {
        $lines = preg_split('/\R/', (string) get_option(self::OPTION_REST_ALLOW, '')) ?: [];
        $list = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line !== '' && $line[0] === '/') {
                $list[] = rtrim($line, '/');
            }
        }

        return array_values(array_unique((array) apply_filters('draco_insomnis_rest_allow', $list)));
    }

    public static function allowed(string $route): bool
    {
        $route = rtrim($route, '/');
        foreach (self::allowList() as $prefix) {
            if ($route === $prefix || str_starts_with($route, $prefix . '/')) {
                return true;
            }
        }

        return false;
    }

    /** Counts this request; past the limit, records it once and, in block mode, answers 429. */
    public static function pace(): void
    {
        if (wp_doing_cron() || (defined('WP_CLI') && WP_CLI) || (is_admin() && !wp_doing_ajax()) || is_user_logged_in()) {
            return;
        }
        $ip = Shield::clientIp();
        $minute = (int) floor(time() / self::WINDOW);
        $ipHits = self::bump('draco_rl_i_' . md5($ip) . '_' . $minute);
        $netHits = self::bump('draco_rl_n_' . md5(Crawler::network($ip)) . '_' . $minute);
        $ipLimit = self::limit(self::OPTION_RATE_IP, self::DEFAULT_RATE_IP);
        $netLimit = self::limit(self::OPTION_RATE_NET, self::DEFAULT_RATE_NET);
        $over = $ipHits > $ipLimit ? 'ip' : ($netHits > $netLimit ? 'net' : '');
        if ($over === '' || self::exempt()) {
            return;
        }
        $block = self::mode(self::OPTION_RATE) === 'block';
        // One line per address and minute is enough evidence; the rest only counts.
        if ($ipHits === $ipLimit + 1 || $netHits === $netLimit + 1) {
            self::record('rate_' . $over, $block, (string) wp_parse_url(Input::rawServer('REQUEST_URI'), PHP_URL_PATH));
        }
        if ($block) {
            self::tooMany(self::WINDOW - (time() % self::WINDOW));
        }
    }

    /** The addresses an administrator used, and search engines verified by DNS. */
    private static function exempt(): bool
    {
        $ip = Shield::clientIp();
        if (in_array($ip, (array) get_option(Plugin::OPTION_ADMIN_IPS, []), true)) {
            return true;
        }

        return self::verifiedCrawler($ip, Input::server('HTTP_USER_AGENT'));
    }

    /**
     * Reverse DNS, then forward DNS back to the same address. Only runs for an address that claims to
     * be a crawler and has hit a limit, and the answer is kept for a day.
     */
    public static function verifiedCrawler(string $ip, string $userAgent): bool
    {
        $claimed = Crawler::claimed($userAgent);
        if ($claimed === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $forced = apply_filters('draco_insomnis_crawler_verified', null, $ip, $claimed);
        if (is_bool($forced)) {
            return $forced;
        }
        $key = 'draco_crawler_' . md5($ip . '|' . $claimed);
        $cached = get_transient($key);
        if ($cached === 'y' || $cached === 'n') {
            return $cached === 'y';
        }
        $ok = self::resolvesBack($ip, $claimed);
        set_transient($key, $ok ? 'y' : 'n', self::VERIFIED_FOR);

        return $ok;
    }

    private static function resolvesBack(string $ip, string $claimed): bool
    {
        $host = (string) gethostbyaddr($ip);
        if (!Crawler::hostMatches($claimed, $host)) {
            return false;
        }
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return in_array($ip, (array) gethostbynamel($host), true);
        }
        $want = inet_pton($ip);
        foreach ((array) dns_get_record($host, DNS_AAAA) as $record) {
            if (isset($record['ipv6']) && inet_pton((string) $record['ipv6']) === $want) {
                return true;
            }
        }

        return false;
    }

    private static function bump(string $key): int
    {
        $hits = (int) get_transient($key) + 1;
        set_transient($key, $hits, self::WINDOW * 2);

        return $hits;
    }

    private static function limit(string $option, int $default): int
    {
        $value = (int) get_option($option, $default);

        return $value >= 10 ? $value : $default;
    }

    /** Never counts towards the shield's bot verdicts: a fast reader or a shared office is not a bot. */
    private static function record(string $kind, bool $block, string $path): void
    {
        $ip = Shield::clientIp();
        $remote = (string) (filter_var(Input::server('REMOTE_ADDR'), FILTER_VALIDATE_IP) ?: '0.0.0.0');
        Store::log($ip, $remote, 'anticopy:' . $kind, ['score' => 0, 'verdict' => 'doubtful', 'reasons' => ['anticopy_' . $kind . '_' . ($block ? 'block' : 'log')]], substr(Input::server('HTTP_USER_AGENT'), 0, 255), [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($path, 0, 200),
        ]);
    }

    private static function tooMany(int $seconds): void
    {
        nocache_headers();
        status_header(429);
        header('Retry-After: ' . max(1, $seconds));
        header('Content-Type: text/plain; charset=UTF-8');
        header('X-Robots-Tag: noindex');
        echo 'Too many requests. Please wait a minute.';
        exit;
    }
}
