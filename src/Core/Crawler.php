<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Search engines that say who they are in the User-Agent, and the host names their addresses must
 * resolve to. Plain PHP, no WordPress, no network: the DNS lookups live in AntiCopy\Guard.
 *
 * A User-Agent alone proves nothing (anyone can write "Googlebot"); it only tells which check to
 * run: reverse DNS of the address must end in one of these domains, and that name must resolve back
 * to the same address. That is how Google, Bing, Apple and Yandex say to verify their crawlers.
 */
final class Crawler
{
    // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- domain names to compare reverse DNS with; nothing is loaded from them.
    private const GOOGLE = ['googlebot.com', 'google.com', 'googleusercontent.com'];

    /** User-Agent token (lower case) => domains its reverse DNS may end in. */
    public const KNOWN = [
        'googlebot' => self::GOOGLE,
        'google-inspectiontool' => self::GOOGLE,
        'googleother' => self::GOOGLE,
        'adsbot-google' => self::GOOGLE,
        'mediapartners-google' => self::GOOGLE,
        'bingbot' => ['search.msn.com'],
        'msnbot' => ['search.msn.com'],
        'adidxbot' => ['search.msn.com'],
        'applebot' => ['applebot.apple.com'],
        'yandex' => ['yandex.ru', 'yandex.net', 'yandex.com'],
    ];

    /** The crawler this User-Agent claims to be, or '' if it claims none. */
    public static function claimed(string $userAgent): string
    {
        $ua = strtolower($userAgent);
        foreach (array_keys(self::KNOWN) as $token) {
            if (str_contains($ua, $token)) {
                return $token;
            }
        }

        return '';
    }

    /** Whether a reverse-DNS host name belongs to the claimed crawler. "googlebot.com.evil.example" does not. */
    public static function hostMatches(string $claimed, string $host): bool
    {
        $host = rtrim(strtolower(trim($host)), '.');
        if ($host === '' || !isset(self::KNOWN[$claimed]) || filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return false;
        }
        foreach (self::KNOWN[$claimed] as $domain) {
            if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The network an address belongs to, for limits that a scraper cannot dodge by rotating
     * addresses next to each other: /24 for IPv4, /64 for IPv6 (what one customer usually gets).
     */
    public static function network(string $ip): string
    {
        $packed = filter_var($ip, FILTER_VALIDATE_IP) !== false ? inet_pton($ip) : false;
        if ($packed === false) {
            return '';
        }
        if (strlen($packed) === 4) {
            return inet_ntop(substr($packed, 0, 3) . "\0") . '/24';
        }

        return inet_ntop(substr($packed, 0, 8) . str_repeat("\0", 8)) . '/64';
    }
}
