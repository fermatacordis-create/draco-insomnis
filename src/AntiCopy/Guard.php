<?php

declare(strict_types=1);

namespace DracoInsomnis\AntiCopy;

use DracoInsomnis\Core\Pace;
use DracoInsomnis\Input;
use DracoInsomnis\WpHost;

defined('ABSPATH') || exit;

/**
 * Makes copying the whole site harder, without getting in the way of people or search engines.
 *
 * Two independent parts, each off, "log" or "block":
 * - Content API: anonymous reads of /wp/v2/* (posts, pages, media...) are refused, except the
 *   routes on the allow list. Pages themselves stay public; only the bulk JSON door closes.
 * - Pace (Core\Pace, shared with the other CMSs): more pages per minute than a person reads, from one
 *   address or one network, get a 429 for the rest of that minute. Search engines verified by
 *   reverse DNS are never limited.
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
    public const DEFAULT_RATE_IP = Pace::DEFAULT_RATE_IP;
    public const DEFAULT_RATE_NET = Pace::DEFAULT_RATE_NET;

    public static function boot(): void
    {
        if (self::mode(self::OPTION_REST) !== 'off') {
            add_filter('rest_pre_dispatch', [self::class, 'rest'], 5, 3);
        }
        if (self::mode(self::OPTION_RATE) !== 'off') {
            self::pace();
        }
    }

    private static function engine(): Pace
    {
        return new Pace(WpHost::get());
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
        $visitor = WpHost::request();
        if (!str_starts_with($route, '/wp/v2/') || self::allowed($route) || self::engine()->exempt($visitor)) {
            return $result;
        }
        $block = self::mode(self::OPTION_REST) === 'block';
        self::engine()->record($visitor, 'rest', $block, $route);
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
        $engine = self::engine();
        $visitor = WpHost::request();
        $count = $engine->count($visitor, time());
        if ($count['over'] === '' || $engine->exempt($visitor)) {
            return;
        }
        $block = self::mode(self::OPTION_RATE) === 'block';
        // One line per address and minute is enough evidence; the rest only counts.
        if ($count['first']) {
            $engine->record($visitor, 'rate_' . $count['over'], $block, (string) wp_parse_url(Input::rawServer('REQUEST_URI'), PHP_URL_PATH));
        }
        if ($block) {
            self::tooMany($count['retry']);
        }
    }

    /**
     * Reverse DNS, then forward DNS back to the same address. Only runs for an address that claims to
     * be a crawler and has hit a limit, and the answer is kept for a day.
     */
    public static function verifiedCrawler(string $ip, string $userAgent): bool
    {
        return self::engine()->verifiedCrawler($ip, $userAgent);
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
