<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

// phpcs:disable WordPress.WP.AlternativeFunctions -- this engine also runs outside WordPress; the WordPress plugin downloads through wp_remote_get() instead (Firewall\GeoFilter).

/**
 * Downloads the country list for CMSs without an HTTP API of their own: cURL when it is there,
 * otherwise PHP streams. Checks the SHA-256 published next to the file and keeps the old file unless
 * the new one checks out.
 */
final class GeoUpdate
{
    public const SOURCE = 'https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin';
    public const MAX_AGE_DAYS = 35;

    public static function stale(string $file, int $now): bool
    {
        $built = Geo::built($file);

        return $built === '' || ($now - (int) strtotime($built)) > self::MAX_AGE_DAYS * 86400;
    }

    /** '' when done, otherwise why not: checksum, folder, download or format. */
    public static function update(string $file): string
    {
        $sum = self::fetch(self::SOURCE . '.sha256');
        $want = $sum === null ? '' : strtolower(substr(trim($sum), 0, 64));
        if (preg_match('/^[a-f0-9]{64}$/', $want) !== 1) {
            return 'checksum';
        }
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            return 'folder';
        }
        $body = self::fetch(self::SOURCE);
        if ($body === null || !hash_equals($want, hash('sha256', $body))) {
            return 'download';
        }
        $tmp = $file . '.part';
        if (@file_put_contents($tmp, $body) === false) {
            return 'folder';
        }
        if (Geo::built($tmp) === '') {
            @unlink($tmp);

            return 'format';
        }

        return @rename($tmp, $file) ? '' : 'folder';
    }

    private static function fetch(string $url): ?string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 5, CURLOPT_TIMEOUT => 120, CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_USERAGENT => 'Draco-Insomnis']);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

            return is_string($body) && $code === 200 ? $body : null;
        }
        $ctx = stream_context_create(['http' => ['timeout' => 120, 'follow_location' => 1, 'user_agent' => 'Draco-Insomnis']]);
        $body = @file_get_contents($url, false, $ctx);

        return is_string($body) ? $body : null;
    }
}
