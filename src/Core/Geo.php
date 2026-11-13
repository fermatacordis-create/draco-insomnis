<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

// phpcs:disable WordPress.WP.AlternativeFunctions -- random-access reads (fseek) of a read-only binary file: WP_Filesystem has no seek, and this engine runs outside WordPress too.

/**
 * The country of an address, from the file bin/build-geo.php writes (DB-IP Lite, CC BY 4.0). Plain PHP:
 * a binary search over fixed-size records, about 20 reads, no extension and nothing sent anywhere.
 * Private, reserved and unknown addresses have no country (null): they are never filtered by country.
 */
final class Geo
{
    private const HEADER = 22;

    /** @var array<string, array{fh: resource, v4: int, v6: int, built: string}> */
    private static array $open = [];

    public static function country(string $file, string $ip): ?string
    {
        $addr = @inet_pton($ip);
        $db = $addr === false ? null : self::open($file);
        if ($db === null) {
            return null;
        }
        $v4 = strlen($addr) === 4;
        $count = $v4 ? $db['v4'] : $db['v6'];
        $size = $v4 ? 6 : 18;
        $base = self::HEADER + ($v4 ? 0 : $db['v4'] * 6);
        $width = $size - 2;
        $lo = 0;
        $hi = $count - 1;
        $found = -1;
        while ($lo <= $hi) {
            $mid = intdiv($lo + $hi, 2);
            fseek($db['fh'], $base + $mid * $size);
            $start = (string) fread($db['fh'], $width);
            if (strcmp($start, $addr) <= 0) {
                $found = $mid;
                $lo = $mid + 1;
            } else {
                $hi = $mid - 1;
            }
        }
        if ($found < 0) {
            return null;
        }
        fseek($db['fh'], $base + $found * $size + $width);
        $cc = (string) fread($db['fh'], 2);

        return preg_match('/^[A-Z]{2}$/', $cc) === 1 ? $cc : null;
    }

    /** The date the file was built (YYYYMMDD), or '' when it is missing or not a Draco file. */
    public static function built(string $file): string
    {
        $db = self::open($file);

        return $db === null ? '' : $db['built'];
    }

    /** @return array{fh: resource, v4: int, v6: int, built: string}|null */
    private static function open(string $file): ?array
    {
        if (isset(self::$open[$file])) {
            return self::$open[$file];
        }
        $fh = is_readable($file) ? @fopen($file, 'rb') : false;
        if ($fh === false) {
            return null;
        }
        $head = (string) fread($fh, self::HEADER);
        if (strlen($head) !== self::HEADER || !str_starts_with($head, 'DRGEO1')) {
            fclose($fh);

            return null;
        }
        $counts = unpack('Nv4/Nv6', substr($head, 14, 8));
        $expected = self::HEADER + $counts['v4'] * 6 + $counts['v6'] * 18;
        if (!is_array($counts) || filesize($file) !== $expected) {
            fclose($fh);

            return null;
        }

        return self::$open[$file] = ['fh' => $fh, 'v4' => (int) $counts['v4'], 'v6' => (int) $counts['v6'], 'built' => substr($head, 6, 8)];
    }

    /** "ES, fr de" → ['ES', 'FR', 'DE']. @return list<string> */
    public static function parseList(string $text): array
    {
        preg_match_all('/\b[A-Za-z]{2}\b/', $text, $m);

        return array_values(array_unique(array_map('strtoupper', $m[0])));
    }
}
