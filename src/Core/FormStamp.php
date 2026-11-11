<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

/**
 * A signed "this page was loaded at T" value that the form sends back.
 *
 * It never expires, because cached pages hand out old stamps: an old stamp only means "slow", which is
 * fine. What matters is that a script posting straight to the endpoint has none, or a forged one.
 */
final class FormStamp
{
    public static function make(string $key, int $now): string
    {
        return $now . '.' . substr(hash_hmac('sha256', 'draco|' . $now, $key), 0, 20);
    }

    /** @return array{state: 'missing'|'invalid'|'ok', elapsed: int|null} */
    public static function check(string $key, string $stamp, int $now): array
    {
        $stamp = trim($stamp);
        if ($stamp === '') {
            return ['state' => 'missing', 'elapsed' => null];
        }
        if (preg_match('/^(\d{9,11})\.([a-f0-9]{20})$/', $stamp, $m) !== 1) {
            return ['state' => 'invalid', 'elapsed' => null];
        }
        $time = (int) $m[1];
        if (!hash_equals(self::make($key, $time), $stamp) || $time > $now + 60) {
            return ['state' => 'invalid', 'elapsed' => null];
        }

        return ['state' => 'ok', 'elapsed' => max(0, $now - $time)];
    }
}
