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
        $rest = self::mode(self::OPTION_REST);
        if ($rest === 'block') {
            add_filter('rest_pre_dispatch', [self::class, 'rest'], 5, 3);
        } elseif ($rest === 'log') {
            // Log only: write it down after WordPress answered, so the log shows what the visitor got.
            add_filter('rest_post_dispatch', [self::class, 'restAnswered'], 99, 3);
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
        if ($result !== null || self::mode(self::OPTION_REST) !== 'block') {
            return $result;
        }
        $route = self::watched($request);
        if ($route === null) {
            return $result;
        }
        self::engine()->record(WpHost::request(), 'rest', true, $route, 401);

        return new \WP_Error('draco_rest_closed', __('This content is not available through the API.', 'draco-insomnis'), ['status' => 401]);
    }

    /**
     * Log mode: the same reads, written down with the answer WordPress gave.
     *
     * @param mixed $response
     * @param \WP_REST_Server|null $server
     * @param \WP_REST_Request|null $request
     * @return mixed
     */
    public static function restAnswered($response, $server = null, $request = null)
    {
        $route = self::watched($request);
        if ($route !== null) {
            $status = $response instanceof \WP_HTTP_Response ? (int) $response->get_status() : 0;
            self::engine()->record(WpHost::request(), 'rest', false, $route, $status);
        }

        return $response;
    }

    /** The route of an anonymous GET/HEAD on /wp/v2/ that is neither allowed nor exempt; null otherwise. */
    private static function watched($request): ?string
    {
        if (!$request instanceof \WP_REST_Request || is_user_logged_in()) {
            return null;
        }
        if (!in_array(strtoupper((string) $request->get_method()), ['GET', 'HEAD'], true)) {
            return null;
        }
        $route = '/' . ltrim((string) $request->get_route(), '/');
        if (!str_starts_with($route, '/wp/v2/') || self::allowed($route) || self::engine()->exempt(WpHost::request())) {
            return null;
        }

        return $route;
    }

    /**
     * What kind of door a route is, for the log: identity (user accounts), search (finding and
     * rendering content on demand) or content (posts, pages, terms, media).
     */
    public static function routeKind(string $route): string
    {
        if (preg_match('#^/wp/v2/users(/|$)#', $route)) {
            return 'identity';
        }
        if (preg_match('#^/wp/v2/(search|block-renderer)(/|$)#', $route)) {
            return 'search';
        }

        return 'content';
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
