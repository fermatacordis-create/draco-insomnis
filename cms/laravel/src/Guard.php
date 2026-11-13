<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\TestProbe;
use DracoInsomnis\Core\SecurityHeaders;
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
        $waf = config('draco.waf_off') ? 'off' : LaravelHost::mode('waf_mode');
        // Only pages a person reads count for the pace limit: JSON API clients are not scrapers of pages.
        $pages = $pace && in_array($http->getMethod(), ['GET', 'HEAD'], true) && $http->acceptsHtml();
        $request = LaravelHost::request($http);
        $probe = TestProbe::answer($host, (string) $http->headers->get(TestProbe::HEADER, ''), $waf, time());
        if ($probe !== null) {
            return new Response('', $probe['status'], [TestProbe::RESULT => $probe['result'], 'Cache-Control' => 'no-store']);
        }
        if (Review::isRequest($request, $http->request->all())) {
            (new Review($host))->accept($request, $http->request->all(), time());

            return self::page((string) __('draco::messages.review_sent_title'), (string) __('draco::messages.review_sent_text'), 'review', '', 200);
        }
        $answer = (new Gatekeeper($host))->decide($request, $waf, LaravelHost::mode('pace_mode'), ['/login', '/register', '/password'], $pages);
        if ($answer === null) {
            return null;
        }
        if ($answer['status'] === 429) {
            return new Response('Too many requests. Please wait a minute.', 429, [
                'Retry-After' => (string) $answer['retry'],
                'Content-Type' => 'text/plain; charset=UTF-8',
                'Cache-Control' => 'no-store',
                'X-Robots-Tag' => 'noindex',
            ]);
        }

        return self::deny($answer['why'], $request);
    }

    /** Security headers on the answer, when switched on; never one the app already set. */
    public static function headers(Request $http, Response $response): Response
    {
        foreach (SecurityHeaders::wanted(self::host(), $http->isSecure()) as $name => $value) {
            if (!$response->headers->has($name)) {
                $response->headers->set($name, $value);
            }
        }

        return $response;
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
    private static function deny(string $why, \DracoInsomnis\Core\Request $request): Response
    {
        $form = (new Review(self::host()))->form($request, $why, time(), [
            'email' => (string) __('draco::messages.review_email'),
            'message' => (string) __('draco::messages.review_message'),
            'button' => (string) __('draco::messages.review_button'),
        ]);

        return self::page((string) __('draco::messages.blocked_title'), (string) __('draco::messages.blocked_text'), $why, $form, 403);
    }

    private static function page(string $title, string $text, string $why, string $form, int $status): Response
    {
        return new Response(Firewall::page($title, $text, $why, $form), $status, [
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
