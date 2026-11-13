<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * Security headers for public pages, both off by default (settings "headers" and "hsts"). The safe set
 * changes nothing a visitor sees; HSTS only over HTTPS, 6 months, without subdomains or preload.
 * Callers never send one that the server or another extension already set.
 */
final class SecurityHeaders
{
    /** @return array<string, string> */
    public static function wanted(Host $host, bool $https): array
    {
        $out = [];
        if (in_array($host->setting('headers'), ['1', 'yes', 'true', 'on'], true)) {
            $out = [
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'SAMEORIGIN',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
            ];
        }
        if ($https && in_array($host->setting('hsts'), ['1', 'yes', 'true', 'on'], true)) {
            $out['Strict-Transport-Security'] = 'max-age=15552000';
        }

        return (array) $host->filter('security_headers', $out);
    }

    /**
     * Sends the wanted headers with PHP's header(), skipping any already set.
     *
     * @param array<string, string> $wanted
     */
    public static function send(array $wanted): void
    {
        if (headers_sent()) {
            return;
        }
        $already = array_map(static fn (string $h): string => strtolower(trim(explode(':', $h, 2)[0])), headers_list());
        foreach ($wanted as $name => $value) {
            if (!in_array(strtolower($name), $already, true)) {
                header($name . ': ' . $value);
            }
        }
    }
}
