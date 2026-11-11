<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/**
 * AES-256-GCM with a key derived from the site's own salts in wp-config.php. A copy of the database
 * alone is not enough to read the password; if the salts change, the password must be typed again.
 */
final class Crypto
{
    private const METHOD = 'aes-256-gcm';
    private const PREFIX = 'g1:';
    private const IV = 12;
    private const TAG = 16;

    public static function encrypt(string $plain, string $aad): string
    {
        if ($plain === '' || !function_exists('openssl_encrypt')) {
            return '';
        }
        $iv = random_bytes(self::IV);
        $tag = '';
        $cipher = openssl_encrypt($plain, self::METHOD, self::key(), OPENSSL_RAW_DATA, $iv, $tag, $aad, self::TAG);

        return $cipher === false || $tag === '' ? '' : self::PREFIX . base64_encode($iv . $tag . $cipher);
    }

    public static function decrypt(string $stored, string $aad): string
    {
        if (!str_starts_with($stored, self::PREFIX) || !function_exists('openssl_decrypt')) {
            return '';
        }
        $raw = base64_decode(substr($stored, strlen(self::PREFIX)), true);
        if ($raw === false || strlen($raw) <= self::IV + self::TAG) {
            return '';
        }
        $plain = openssl_decrypt(substr($raw, self::IV + self::TAG), self::METHOD, self::key(), OPENSSL_RAW_DATA, substr($raw, 0, self::IV), substr($raw, self::IV, self::TAG), $aad);

        return $plain === false ? '' : $plain;
    }

    private static function key(): string
    {
        $a = defined('LOGGED_IN_SALT') ? (string) LOGGED_IN_SALT : '';
        $b = defined('SECURE_AUTH_SALT') ? (string) SECURE_AUTH_SALT : '';

        return hash_hmac('sha256', 'draco-insomnis|' . $a, $b . wp_salt('secure_auth'), true);
    }
}
