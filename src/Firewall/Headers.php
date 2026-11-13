<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

defined('ABSPATH') || exit;

/**
 * Security headers for the public pages, off by default. The safe set changes nothing a visitor
 * sees; HSTS is separate and only sent over HTTPS, because once a browser has it the site must stay
 * on HTTPS for as long as it says (here 6 months, without subdomains or preload).
 */
final class Headers
{
    public const OPTION_SAFE = 'draco_headers';
    public const OPTION_HSTS = 'draco_hsts';

    public static function register(): void
    {
        add_action('send_headers', [self::class, 'send']);
    }

    /** @return array<string, string> The headers this site sends now, by name. */
    public static function wanted(bool $https): array
    {
        $out = [];
        if (get_option(self::OPTION_SAFE, 'no') === 'yes') {
            $out = [
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'SAMEORIGIN',
                'Referrer-Policy' => 'strict-origin-when-cross-origin',
                'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
            ];
        }
        if ($https && get_option(self::OPTION_HSTS, 'no') === 'yes') {
            $out['Strict-Transport-Security'] = 'max-age=15552000';
        }

        return (array) apply_filters('draco_insomnis_security_headers', $out);
    }

    public static function send(): void
    {
        if (headers_sent()) {
            return;
        }
        $already = array_map(static fn (string $h): string => strtolower(trim(explode(':', $h, 2)[0])), headers_list());
        foreach (self::wanted(is_ssl()) as $name => $value) {
            // Another plugin or the theme set it already: theirs wins, so there are never two.
            if (!in_array(strtolower($name), $already, true)) {
                header($name . ': ' . $value);
            }
        }
    }
}
