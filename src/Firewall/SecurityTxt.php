<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

defined('ABSPATH') || exit;

/**
 * /.well-known/security.txt (RFC 9116), off by default: tells a person who finds a weakness in the
 * site how to tell its owner, instead of guessing or giving up. The contact is the one the owner
 * writes on the Firewall screen; nothing is filled in for them.
 *
 * "Expires" is always about 6 months ahead and moves forward by itself while the option is on, so the
 * file never goes stale; switching the option off removes it. The standard wants the file at the root
 * of the domain, so it is only served when WordPress is installed there. A real file with that name
 * on the server wins: WordPress never sees the request.
 */
final class SecurityTxt
{
    public const OPTION = 'draco_securitytxt';
    public const OPTION_CONTACT = 'draco_securitytxt_contact';
    public const OPTION_POLICY = 'draco_securitytxt_policy';
    public const PATH = '/.well-known/security.txt';
    private const DAYS = 180;

    public static function register(): void
    {
        add_action('init', [self::class, 'serve'], 0);
    }

    public static function active(): bool
    {
        return get_option(self::OPTION, 'no') === 'yes' && self::contact() !== '' && self::atRoot();
    }

    /** True when WordPress answers the root of the domain (the only place the standard allows). */
    public static function atRoot(): bool
    {
        return rtrim((string) wp_parse_url(home_url('/'), PHP_URL_PATH), '/') === '';
    }

    /** "mailto:…" or an https:// address, from what the owner wrote; '' when it is neither. */
    public static function contact(?string $raw = null): string
    {
        $raw = trim($raw ?? (string) get_option(self::OPTION_CONTACT, ''));
        if ($raw === '') {
            return '';
        }
        $mail = preg_replace('/^mailto:/i', '', $raw);
        if (is_email((string) $mail)) {
            return 'mailto:' . $mail;
        }

        return self::https($raw);
    }

    public static function policy(?string $raw = null): string
    {
        return self::https(trim($raw ?? (string) get_option(self::OPTION_POLICY, '')));
    }

    private static function https(string $url): string
    {
        return $url !== '' && wp_parse_url($url, PHP_URL_SCHEME) === 'https' && filter_var($url, FILTER_VALIDATE_URL) ? esc_url_raw($url) : '';
    }

    /** The file, as served. $now is for tests. */
    public static function body(?int $now = null): string
    {
        $now ??= time();
        $expires = gmdate('Y-m-d\T00:00:00\Z', $now + self::DAYS * DAY_IN_SECONDS);
        $lang = strtolower(substr((string) get_locale(), 0, 2));
        $lines = [
            'Contact: ' . self::contact(),
            'Expires: ' . $expires,
            'Preferred-Languages: ' . ($lang !== '' && $lang !== 'en' ? $lang . ', en' : 'en'),
            'Canonical: ' . home_url(self::PATH, 'https'),
        ];
        $policy = self::policy();
        if ($policy !== '') {
            $lines[] = 'Policy: ' . $policy;
        }

        return implode("\n", $lines) . "\n";
    }

    public static function serve(): void
    {
        $path = (string) wp_parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- only compared with a fixed path
        if ($path !== self::PATH || !self::active()) {
            return;
        }
        status_header(200);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: public, max-age=86400');
        header('X-Robots-Tag: noindex');
        echo self::body(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain text built from validated values
        exit;
    }
}
