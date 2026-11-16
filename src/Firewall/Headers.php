<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

defined('ABSPATH') || exit;

/**
 * Security headers for the public pages, off by default. The safe set changes nothing a visitor
 * sees; HSTS is separate and only sent over HTTPS, because once a browser has it the site must stay
 * on HTTPS for as long as it says (here 6 months, without subdomains or preload).
 *
 * Microphone: blocked by default (microphone=()). When OPNV-WP Accessibility voice commands need it,
 * OPTION_MIC switches that entry to microphone=(self): this site may ask for the mic; embeds still cannot.
 */
final class Headers
{
    public const OPTION_SAFE = 'draco_headers';
    public const OPTION_HSTS = 'draco_hsts';
    public const OPTION_MIC = 'draco_headers_mic';

    public static function register(): void
    {
        add_action('send_headers', [self::class, 'send']);
    }

    /** True when OPNV-WP is active (bundled Draco, or the Optimizador Pro plugin). */
    public static function opnvWpPresent(): bool
    {
        if (defined('DRACO_INSOMNIS_BUNDLED') && DRACO_INSOMNIS_BUNDLED) {
            return true;
        }
        foreach ((array) get_option('active_plugins', []) as $plugin) {
            if (is_string($plugin) && str_contains($plugin, 'optimizador-pro-notoriusvision')) {
                return true;
            }
        }
        if (is_multisite()) {
            foreach (array_keys((array) get_site_option('active_sitewide_plugins', [])) as $plugin) {
                if (is_string($plugin) && str_contains($plugin, 'optimizador-pro-notoriusvision')) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Permissions-Policy value for the safe set. */
    public static function permissionsPolicy(): string
    {
        $mic = get_option(self::OPTION_MIC, 'no') === 'yes' ? 'microphone=(self)' : 'microphone=()';

        return 'camera=(), ' . $mic . ', geolocation=(), interest-cohort=()';
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
                'Permissions-Policy' => self::permissionsPolicy(),
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
