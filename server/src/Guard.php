<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\SecurityHeaders;
use DracoInsomnis\Core\TestProbe;

/**
 * One web request, before the application runs: test probe, review requests, then the same
 * Gatekeeper as every CMS (block list, country, firewall rules, pace limit). Any failure of Draco
 * itself lets the request through: a broken guard must never take a site down.
 */
final class Guard
{
    public static function run(): void
    {
        $host = new ServerHost();
        if (self::excepted($host) || !$host->ready()) {
            return;
        }
        $waf = ServerHost::mode($host->setting('waf_mode'));
        $pace = ServerHost::mode($host->setting('pace_mode'));
        if ($waf === 'off' && $pace === 'off' && $host->setting('headers') === '') {
            return;
        }
        $https = (($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? '') !== 'off') || ($_SERVER['SERVER_PORT'] ?? '') === '443';
        $headers = SecurityHeaders::wanted($host, $https);
        if ($headers !== []) {
            // At send time, so the application's own headers win.
            header_register_callback(static function () use ($headers): void {
                $sent = array_map(static fn ($h) => strtolower(trim(explode(':', $h, 2)[0])), headers_list());
                foreach ($headers as $name => $value) {
                    if (!in_array(strtolower($name), $sent, true)) {
                        header($name . ': ' . $value);
                    }
                }
            });
        }

        $probe = TestProbe::answer($host, (string) ($_SERVER['HTTP_X_DRACO_TEST'] ?? ''), $waf, time());
        if ($probe !== null) {
            self::send($probe['status'], [TestProbe::RESULT . ': ' . $probe['result'], 'Cache-Control: no-store'], '');
        }
        $request = ServerHost::request();
        $lang = Texts::visitor();
        if (Review::isRequest($request, $_POST)) {
            (new Review($host))->accept($request, $_POST, time());
            self::page(Texts::get($lang, 'review_sent_title'), Texts::get($lang, 'review_sent_text'), 'review', '', 200);
        }
        $accept = strtolower((string) ($_SERVER['HTTP_ACCEPT'] ?? ''));
        // Only pages a person reads count for the pace limit, not API calls or AJAX.
        $pages = in_array($request->method, ['GET', 'HEAD'], true) && ($accept === '' || str_contains($accept, 'text/html'))
            && strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) !== 'xmlhttprequest';
        try {
            CrowdSec::maybeSync($host);
        } catch (\Throwable $e) {
            // CrowdSec unreachable or odd: Draco goes on with what it has.
            unset($e);
        }
        $answer = (new Gatekeeper($host))->decide($request, $waf, $pace, Config::list($host->setting('sensitive')), $pages);
        if ($answer === null) {
            return;
        }
        if ($answer['status'] === 429) {
            self::send(429, ['Retry-After: ' . $answer['retry'], 'Content-Type: text/plain; charset=UTF-8', 'Cache-Control: no-store', 'X-Robots-Tag: noindex'], Texts::get($lang, 'too_many'));
        }
        $form = (new Review($host))->form($request, $answer['why'], time(), [
            'email' => Texts::get($lang, 'review_email'),
            'message' => Texts::get($lang, 'review_message'),
            'button' => Texts::get($lang, 'review_button'),
        ]);
        self::page(Texts::get($lang, 'blocked_title'), Texts::get($lang, 'blocked_text'), $answer['why'], $form, 403);
    }

    /** Paths listed in "except" (prefixes) are never inspected: health checks, webhooks… */
    private static function excepted(ServerHost $host): bool
    {
        $path = '/' . ltrim((string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH), '/');
        foreach (Config::list($host->setting('except')) as $prefix) {
            $prefix = '/' . ltrim($prefix, '/');
            if ($prefix !== '/' && str_starts_with($path, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private static function page(string $title, string $text, string $why, string $form, int $status): void
    {
        self::send($status, ['Content-Type: text/html; charset=UTF-8', 'Cache-Control: no-store', 'X-Robots-Tag: noindex, nofollow'], Firewall::page($title, $text, $why, $form));
    }

    /** @param list<string> $headers */
    private static function send(int $status, array $headers, string $body): void
    {
        if (!headers_sent()) {
            http_response_code($status);
            foreach ($headers as $h) {
                header($h);
            }
        }
        echo $body;
        exit;
    }
}
