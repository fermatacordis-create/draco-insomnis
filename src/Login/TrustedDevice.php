<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

defined('ABSPATH') || exit;

/** "Trust this device for 7 days": a random cookie whose hash is kept on the user, five devices at most. */
final class TrustedDevice
{
    public const COOKIE = 'draco_trusted';
    public const META = '_draco_trusted_devices';
    public const DAYS = 7;
    private const MAX = 5;

    public static function isValid(int $userId): bool
    {
        $token = isset($_COOKIE[self::COOKIE]) ? sanitize_key(wp_unslash((string) $_COOKIE[self::COOKIE])) : '';
        if (strlen($token) !== 64) {
            return false;
        }
        $hash = self::hash($token);
        foreach (self::devices($userId) as $row) {
            if (hash_equals((string) $row['hash'], $hash) && (int) $row['expires_at'] >= time()) {
                return true;
            }
        }

        return false;
    }

    public static function issue(int $userId): void
    {
        $token = bin2hex(random_bytes(32));
        $expires = time() + self::DAYS * DAY_IN_SECONDS;
        $list = array_values(array_filter(self::devices($userId), static fn (array $r): bool => (int) $r['expires_at'] >= time()));
        $list[] = ['hash' => self::hash($token), 'expires_at' => $expires];
        update_user_meta($userId, self::META, array_slice($list, -self::MAX));
        self::cookie($token, $expires);
    }

    /** After a password reset or an e-mail change, every device has to prove itself again. */
    public static function revokeAll(int $userId): void
    {
        delete_user_meta($userId, self::META);
        if (isset($_COOKIE[self::COOKIE])) {
            self::cookie('', time() - YEAR_IN_SECONDS);
        }
    }

    /** @return list<array{hash: string, expires_at: int}> */
    private static function devices(int $userId): array
    {
        $raw = get_user_meta($userId, self::META, true);
        $out = [];
        foreach (is_array($raw) ? $raw : [] as $row) {
            if (is_array($row) && !empty($row['hash'])) {
                $out[] = ['hash' => (string) $row['hash'], 'expires_at' => (int) ($row['expires_at'] ?? 0)];
            }
        }

        return $out;
    }

    private static function hash(string $token): string
    {
        return hash_hmac('sha256', $token, wp_salt('secure_auth'));
    }

    private static function cookie(string $value, int $expires): void
    {
        if (!headers_sent()) {
            setcookie(self::COOKIE, $value, ['expires' => $expires, 'path' => COOKIEPATH ?: '/', 'domain' => COOKIE_DOMAIN ?: '', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']);
        }
        if ($value === '') {
            unset($_COOKIE[self::COOKIE]);
        } else {
            $_COOKIE[self::COOKIE] = $value;
        }
    }
}
