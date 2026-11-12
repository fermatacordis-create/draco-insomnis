<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Pace;
use DracoInsomnis\Core\Shield;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/** Firewall, pace limit and the sign-up stamp for one request. */
final class Guard
{
    public static function host(): LaravelHost
    {
        return new LaravelHost();
    }

    /** The answer that stops this request, or null to go on. */
    public static function check(Request $http, bool $pace): ?Response
    {
        if (self::excepted($http)) {
            return null;
        }
        $host = self::host();
        $request = LaravelHost::request($http);

        $waf = LaravelHost::mode('waf_mode');
        if ($waf !== 'off' && !config('draco.waf_off')) {
            $firewall = new Firewall($host, $waf === 'block');
            if (!$firewall->exempt($request)) {
                // Addresses on the block list may read, but not post, log in or call the API with POST.
                if ($firewall->refusedAsBlocked($request, ['/login'])) {
                    return self::deny('blocked');
                }
                $rule = $firewall->inspect($request);
                if ($rule !== null && $firewall->blocking()) {
                    return self::deny($rule);
                }
            }
        }

        // Only pages a person reads count: JSON API clients are not scrapers of pages.
        $mode = LaravelHost::mode('pace_mode');
        if ($pace && $mode !== 'off' && in_array($http->getMethod(), ['GET', 'HEAD'], true) && $http->acceptsHtml()) {
            $engine = new Pace($host);
            $count = $engine->count($request, time());
            if ($count['over'] !== '' && !$engine->exempt($request)) {
                $block = $mode === 'block';
                if ($count['first']) {
                    $engine->record($request, 'rate_' . $count['over'], $block, $request->path);
                }
                if ($block) {
                    return new Response('Too many requests. Please wait a minute.', 429, [
                        'Retry-After' => (string) max(1, $count['retry']),
                        'Content-Type' => 'text/plain; charset=UTF-8',
                        'Cache-Control' => 'no-store',
                        'X-Robots-Tag' => 'noindex',
                    ]);
                }
            }
        }

        return null;
    }

    private static function excepted(Request $http): bool
    {
        $path = trim($http->path(), '/');
        foreach ((array) config('draco.except', []) as $prefix) {
            $prefix = trim((string) $prefix, '/');
            if ($prefix !== '' && ($path === $prefix || str_starts_with($path, $prefix . '/'))) {
                return true;
            }
        }

        return false;
    }

    /** No details for the attacker: what matched stays in the log. */
    private static function deny(string $why): Response
    {
        return new Response(Firewall::page((string) __('draco::messages.blocked_title'), (string) __('draco::messages.blocked_text'), $why), 403, [
            'Content-Type' => 'text/html; charset=UTF-8',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }

    /** The two hidden inputs for the sign-up form, when the shield is on and nobody is logged in. */
    public static function fields(): string
    {
        if (!config('draco.shield') || auth()->check()) {
            return '';
        }

        return (new Shield(self::host()))->fieldsHtml(time());
    }
}
