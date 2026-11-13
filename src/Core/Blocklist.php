<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * What every CMS store checks before it adds a block: the lengths it accepts (0 = forever), and that a
 * value is a real address or a range no wider than /16 (IPv4) or /32 (IPv6) that holds no protected
 * address (an administrator's, or the person clicking). Plain PHP: each store keeps its own table.
 */
final class Blocklist
{
    public const DAYS = [7, 15, 30, 90, 0];
    /** Forever, stored as the last second MySQL datetimes and 32-bit-safe timestamps can both hold. */
    public const FOREVER_AT = '9999-12-31 23:59:59';
    public const FOREVER_TS = 253402300799;
    private const MIN_PREFIX = ['4' => 16, '6' => 32];

    public static function untilAt(int $days, int $now): string
    {
        return $days === 0 ? self::FOREVER_AT : gmdate('Y-m-d H:i:s', $now + $days * 86400);
    }

    public static function untilTs(int $days, int $now): int
    {
        return $days === 0 ? self::FOREVER_TS : $now + $days * 86400;
    }

    /**
     * The kind and value to store for an address or range, or null when it must not be blocked.
     * "ip" with a "/" becomes "net".
     *
     * @param list<string> $protected Addresses never to block (administrators, the current visitor).
     * @return array{kind: string, value: string}|null
     */
    public static function address(string $value, int $days, array $protected): ?array
    {
        $value = strtolower(trim($value));
        if (!in_array($days, self::DAYS, true)) {
            return null;
        }
        if (str_contains($value, '/')) {
            if (!self::validNet($value)) {
                return null;
            }
            foreach ($protected as $ip) {
                if ($ip !== '' && NetList::inNet($value, $ip)) {
                    return null;
                }
            }

            return ['kind' => 'net', 'value' => $value];
        }
        if (filter_var($value, FILTER_VALIDATE_IP) === false || in_array($value, $protected, true)) {
            return null;
        }

        return ['kind' => 'ip', 'value' => $value];
    }

    public static function validNet(string $cidr): bool
    {
        $parts = explode('/', $cidr, 2);
        if (count($parts) !== 2 || !ctype_digit($parts[1]) || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $family = str_contains($parts[0], ':') ? '6' : '4';
        $bits = (int) $parts[1];

        return $bits >= self::MIN_PREFIX[$family] && $bits <= ($family === '4' ? 32 : 128);
    }

    public static function isForever(string|int $until): bool
    {
        return is_int($until) ? $until >= self::FOREVER_TS : $until === self::FOREVER_AT;
    }
}
