<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/** IPv4 and IPv6 ranges in CIDR form. Plain PHP, no WordPress. */
final class NetList
{
    /**
     * Rented servers seen sending fake sign-ups in the wild (Oct–Nov 2026).
     * Being on this list only adds points; on its own it never makes anyone a bot.
     */
    public const SEEN_HOSTING = [
        '2402:1f00::/32',   // OVH Singapore
        '2602:fa5d::/32',   // White Label Services
        '31.40.204.0/24',   // White Label Services
        '198.46.154.0/24',  // ColoCrossing
        '198.12.69.0/24',   // ColoCrossing
        '107.173.160.0/24', // ColoCrossing
    ];

    /** @param list<string> $nets */
    public static function contains(array $nets, string $ip): bool
    {
        foreach ($nets as $net) {
            if (self::inNet(trim($net), $ip)) {
                return true;
            }
        }

        return false;
    }

    public static function inNet(string $cidr, string $ip): bool
    {
        $parts = explode('/', $cidr, 2);
        $base = @inet_pton($parts[0]);
        $addr = @inet_pton($ip);
        if ($base === false || $addr === false || strlen($base) !== strlen($addr)) {
            return false;
        }
        $max = strlen($base) * 8;
        $bits = isset($parts[1]) && ctype_digit($parts[1]) ? (int) $parts[1] : $max;
        if ($bits > $max) {
            return false;
        }
        $whole = intdiv($bits, 8);
        if (substr($base, 0, $whole) !== substr($addr, 0, $whole)) {
            return false;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rest)) & 0xFF;

        return (ord($base[$whole]) & $mask) === (ord($addr[$whole]) & $mask);
    }

    /** CIDRs one per line (or separated by commas or spaces); comments after # and junk lines are dropped. @return list<string> */
    public static function parse(string $text): array
    {
        $out = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            foreach (preg_split('/[\s,]+/', (string) preg_replace('/#.*/', '', $line)) ?: [] as $item) {
                $ip = explode('/', $item, 2)[0];
                if ($item !== '' && filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    $out[] = $item;
                }
            }
        }

        return array_values(array_unique($out));
    }
}
