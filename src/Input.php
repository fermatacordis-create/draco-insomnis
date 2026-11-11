<?php

declare(strict_types=1);

namespace DracoInsomnis;

defined('ABSPATH') || exit;

/**
 * Request values, unslashed and sanitised in one place. Reading them is never an action by itself:
 * every form that changes something checks its own nonce or token before acting.
 */
final class Input
{
    public static function server(string $key): string
    {
        return isset($_SERVER[$key]) && is_string($_SERVER[$key]) ? sanitize_text_field(wp_unslash($_SERVER[$key])) : '';
    }

    /**
     * Exactly as the client sent it, for the firewall: cleaning it first would erase the very attack
     * it looks for. Never printed or stored as it is.
     */
    public static function rawServer(string $key): string
    {
        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- inspected for attack patterns only.
        return isset($_SERVER[$key]) && is_string($_SERVER[$key]) ? (string) wp_unslash($_SERVER[$key]) : '';
    }

    public static function method(): string
    {
        $method = strtoupper(self::server('REQUEST_METHOD'));

        return $method !== '' ? $method : 'GET';
    }

    public static function post(string $key): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Missing -- see the class comment.
        return isset($_POST[$key]) && is_string($_POST[$key]) ? sanitize_text_field(wp_unslash($_POST[$key])) : '';
    }

    public static function get(string $key): string
    {
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- see the class comment.
        return isset($_GET[$key]) && is_string($_GET[$key]) ? sanitize_text_field(wp_unslash($_GET[$key])) : '';
    }

    public static function postInt(string $key, int $default = 0): int
    {
        $value = self::post($key);

        return $value !== '' && ctype_digit($value) ? (int) $value : $default;
    }

    public static function getInt(string $key): int
    {
        $value = self::get($key);

        return ctype_digit($value) ? (int) $value : 0;
    }

    /** Only the digits of a code the person typed. */
    public static function postDigits(string $key, int $max = 6): string
    {
        return substr((string) preg_replace('/\D/', '', self::post($key)), 0, $max);
    }
}
