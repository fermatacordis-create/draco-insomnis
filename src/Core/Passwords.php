<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

// phpcs:disable WordPress.WP.AlternativeFunctions -- this engine also runs outside WordPress; the WordPress plugin checks passwords through wp_remote_get() instead (Login\Passwords).

/**
 * Password rules for every CMS, both off by default (settings "pwd_min" and "pwd_breached"):
 * - a minimum length, 8 to 64 characters;
 * - refusing passwords that appear in known data breaches, asked to Have I Been Pwned with
 *   k-anonymity: only the first 5 characters of the password's SHA-1 leave the site, never the
 *   password or its full hash, and the answer is padded so its size says nothing either. If the
 *   service does not answer in 3 seconds, the password is accepted: a slow service never locks
 *   anyone out.
 *
 * The texts come from Host::text('pwd_short', minimum) and Host::text('pwd_breached', 0).
 */
final class Passwords
{
    public const API = 'https://api.pwnedpasswords.com/range/';

    public static function minLength(Host $host): int
    {
        $min = (int) $host->setting('pwd_min');

        return $min >= 8 && $min <= 64 ? $min : 0;
    }

    public static function checksBreaches(Host $host): bool
    {
        return in_array(strtolower($host->setting('pwd_breached')), ['1', 'yes', 'true', 'on'], true);
    }

    public static function enabled(Host $host): bool
    {
        return self::minLength($host) > 0 || self::checksBreaches($host);
    }

    /** Why this password is refused, in the site's language; '' when it is fine. */
    public static function problem(Host $host, string $password): string
    {
        if ($password === '') {
            return '';
        }
        $min = self::minLength($host);
        if ($min > 0 && self::length($password) < $min) {
            return $host->text('pwd_short', $min);
        }
        if (self::checksBreaches($host) && self::timesBreached($host, $password) > 0) {
            return $host->text('pwd_breached', 0);
        }

        return '';
    }

    /** How many times the password appears in Have I Been Pwned; 0 when not found or the service did not answer. */
    public static function timesBreached(Host $host, string $password): int
    {
        if ($password === '') {
            return 0;
        }
        $hash = strtoupper(sha1($password));
        // Sites (and tests) may answer the range themselves, e.g. from a local copy of the list.
        $body = $host->filter('pwd_range', null, substr($hash, 0, 5));
        if (!is_string($body)) {
            $body = self::fetch(self::API . substr($hash, 0, 5));
        }

        return $body === null ? 0 : self::countIn(substr($hash, 5), $body);
    }

    /** The count for one SHA-1 suffix in a range answer ("SUFFIX:COUNT" per line; padding lines count 0). */
    public static function countIn(string $suffix, string $body): int
    {
        $suffix = strtoupper($suffix);
        foreach (preg_split('/\R/', $body) ?: [] as $line) {
            $parts = explode(':', trim($line), 2);
            if (count($parts) === 2 && hash_equals($suffix, strtoupper($parts[0]))) {
                return (int) $parts[1];
            }
        }

        return 0;
    }

    private static function length(string $password): int
    {
        return function_exists('mb_strlen') ? mb_strlen($password, 'UTF-8') : strlen((string) preg_replace('/[\x80-\xBF]/', '', $password));
    }

    private static function fetch(string $url): ?string
    {
        $headers = ['Add-Padding: true'];
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 3, CURLOPT_CONNECTTIMEOUT => 3, CURLOPT_USERAGENT => 'Draco-Insomnis', CURLOPT_HTTPHEADER => $headers]);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

            return is_string($body) && $code === 200 ? $body : null;
        }
        $ctx = stream_context_create(['http' => ['timeout' => 3, 'user_agent' => 'Draco-Insomnis', 'header' => implode("\r\n", $headers)]]);
        $body = @file_get_contents($url, false, $ctx);

        return is_string($body) ? $body : null;
    }
}
