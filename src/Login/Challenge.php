<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/** One pending login code per user. The code itself is never stored, only its keyed hash. */
final class Challenge
{
    public const TTL = 600;
    public const MAX_ATTEMPTS = 5;
    private const KEY = 'draco_mfa_';
    private const USER = 'draco_mfa_uid_';
    private const REDIRECT = 'draco_mfa_to_';
    private const TRIES = 'draco_mfa_try_';

    public static function newCode(): string
    {
        return str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    }

    public static function hash(string $code): string
    {
        return hash_hmac('sha256', $code, wp_salt('auth'));
    }

    /** @return array{id: string, user_id: int, hash: string, expires_at: int, attempts: int} */
    public static function create(int $userId, string $code): array
    {
        self::forgetUser($userId);
        $row = ['id' => bin2hex(random_bytes(16)), 'user_id' => $userId, 'hash' => self::hash($code), 'expires_at' => time() + self::TTL, 'attempts' => 0];
        set_transient(self::KEY . $row['id'], $row, self::TTL);
        set_transient(self::USER . $userId, $row['id'], self::TTL);

        return $row;
    }

    /** @return array{id: string, user_id: int, hash: string, expires_at: int, attempts: int}|null */
    public static function get(string $id): ?array
    {
        if (preg_match('/^[a-f0-9]{32}$/', $id) !== 1) {
            return null;
        }
        $row = get_transient(self::KEY . $id);
        if (!is_array($row) || empty($row['user_id']) || (int) ($row['expires_at'] ?? 0) < time()) {
            return null;
        }

        return ['id' => $id, 'user_id' => (int) $row['user_id'], 'hash' => (string) $row['hash'], 'expires_at' => (int) $row['expires_at'], 'attempts' => (int) $row['attempts']];
    }

    /** Counts a try and says whether this code is right. Past MAX_ATTEMPTS the code is gone. */
    public static function check(string $id, string $code): string
    {
        $row = self::get($id);
        if ($row === null) {
            return 'expired';
        }
        // Counted in one atomic step: codes sent at the same moment cannot all see the same count.
        if (Store::bump(self::TRIES . $id, self::TTL) > self::MAX_ATTEMPTS) {
            self::delete($id);

            return 'locked';
        }
        if (preg_match('/^\d{6}$/', $code) !== 1 || !hash_equals($row['hash'], self::hash($code))) {
            return 'wrong';
        }
        self::delete($id);

        return 'ok';
    }

    public static function delete(string $id): void
    {
        $row = get_transient(self::KEY . $id);
        if (is_array($row) && isset($row['user_id'])) {
            delete_transient(self::USER . (int) $row['user_id']);
        }
        delete_transient(self::KEY . $id);
    }

    public static function forgetUser(int $userId): void
    {
        $id = get_transient(self::USER . $userId);
        if (is_string($id) && $id !== '') {
            delete_transient(self::KEY . $id);
        }
        delete_transient(self::USER . $userId);
    }

    /** Where the person was going. Only addresses inside this site. */
    public static function setRedirect(int $userId, string $url): void
    {
        $url = wp_validate_redirect(trim($url), '');
        if ($userId > 0 && $url !== '') {
            set_transient(self::REDIRECT . $userId, $url, self::TTL);
        }
    }

    public static function takeRedirect(int $userId): string
    {
        $url = get_transient(self::REDIRECT . $userId);
        delete_transient(self::REDIRECT . $userId);

        return is_string($url) ? (string) wp_validate_redirect($url, '') : '';
    }
}
