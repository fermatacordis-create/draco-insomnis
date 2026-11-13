<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

use DracoInsomnis\Core\Geo;
use DracoInsomnis\Core\Pace;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Shield\Store;
use DracoInsomnis\WpHost;

defined('ABSPATH') || exit;

/**
 * Country filter. Off by default. Most visitors of a small business come from many countries and an
 * attacker changes country with a VPN, so the advice on screen is to filter only the sensitive parts
 * (log in, sign up, forms) and to "log only" first. Administrators, people let through after a review
 * and search engines verified by DNS are never filtered; addresses without a country neither.
 *
 * The country list is DB-IP Lite (CC BY 4.0), turned into a compact file once a month by Draco's own
 * GitHub workflow. The site downloads it only while the filter is on, checks its SHA-256, and looks
 * addresses up locally: no address is ever sent anywhere.
 */
final class GeoFilter
{
    public const OPTION_MODE = 'draco_geo_mode';        // off | block | allow
    public const OPTION_COUNTRIES = 'draco_geo_countries';
    public const OPTION_SCOPE = 'draco_geo_scope';      // sensitive | site
    public const OPTION_ACTION = 'draco_geo_action';    // log | block
    public const SOURCE = 'https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin';
    private const MAX_AGE_DAYS = 35;

    public static function register(): void
    {
        add_action(\DracoInsomnis\Plugin::HOOK_CLEANUP, [self::class, 'maybeUpdate']);
    }

    public static function mode(): string
    {
        $mode = (string) get_option(self::OPTION_MODE, 'off');

        return in_array($mode, ['block', 'allow'], true) ? $mode : 'off';
    }

    public static function file(): string
    {
        $dir = wp_upload_dir(null, false);

        return (string) apply_filters('draco_insomnis_geo_file', trailingslashit((string) $dir['basedir']) . 'draco-insomnis/draco-geo.bin');
    }

    /** @return list<string> */
    public static function countries(): array
    {
        return Geo::parseList((string) get_option(self::OPTION_COUNTRIES, ''));
    }

    /**
     * The country this request is refused for, or '' when it passes.
     */
    public static function refusedCountry(Request $r): string
    {
        $mode = self::mode();
        $list = self::countries();
        if ($mode === 'off' || $list === []) {
            return '';
        }
        if (get_option(self::OPTION_SCOPE, 'sensitive') !== 'site' && !self::sensitive($r)) {
            return '';
        }
        $ip = $r->via(WpHost::get());
        $country = Geo::country(self::file(), $ip);
        if ($country === null) {
            return '';
        }
        $listed = in_array($country, $list, true);
        if (($mode === 'block' && !$listed) || ($mode === 'allow' && $listed)) {
            return '';
        }
        // Checked last: it may ask the DNS, and only matters for a request that would be refused.
        if ((new Pace(WpHost::get()))->exempt($r)) {
            return '';
        }

        return $country;
    }

    /** Logging in, signing up, XML-RPC and anything posted (forms, comments, checkout). */
    private static function sensitive(Request $r): bool
    {
        return $r->method === 'POST'
            || str_ends_with($r->path, '/wp-login.php')
            || str_ends_with($r->path, '/xmlrpc.php')
            || str_contains($r->path, '/wp-admin/');
    }

    /** Written down without counting towards the automatic block: a person may simply try again. */
    public static function log(Request $r, string $country, bool $blocking): void
    {
        Store::log($r->via(WpHost::get()), $r->remote(), 'waf:geo', ['score' => 0, 'verdict' => $blocking ? 'bot' : 'doubtful', 'reasons' => ['waf_geo']], substr($r->userAgent, 0, 255), [
            'username' => '',
            'email' => '',
            'role' => '',
            'referer' => substr($country . ' ' . $r->path, 0, 200),
        ]);
    }

    public static function maybeUpdate(): void
    {
        if (self::mode() === 'off') {
            return;
        }
        $built = Geo::built(self::file());
        $age = $built === '' ? PHP_INT_MAX : (int) floor((time() - (int) strtotime($built)) / 86400);
        if ($age > self::MAX_AGE_DAYS) {
            self::update();
        }
    }

    /** Downloads the file and its SHA-256; keeps the old file unless the new one checks out. '' when done, otherwise why not. */
    public static function update(): string
    {
        $sum = wp_remote_get(self::SOURCE . '.sha256', ['timeout' => 20]);
        $want = is_wp_error($sum) ? '' : strtolower(substr(trim((string) wp_remote_retrieve_body($sum)), 0, 64));
        if (preg_match('/^[a-f0-9]{64}$/', $want) !== 1) {
            return 'checksum';
        }
        $file = self::file();
        if (!wp_mkdir_p(dirname($file))) {
            return 'folder';
        }
        $tmp = $file . '.part';
        $got = wp_remote_get(self::SOURCE, ['timeout' => 120, 'stream' => true, 'filename' => $tmp]);
        if (is_wp_error($got) || (int) wp_remote_retrieve_response_code($got) !== 200 || !hash_equals($want, (string) hash_file('sha256', $tmp))) {
            wp_delete_file($tmp);

            return 'download';
        }
        if (Geo::built($tmp) === '') {
            wp_delete_file($tmp);

            return 'format';
        }
        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();

        return $wp_filesystem !== null && $wp_filesystem->move($tmp, $file, true) ? '' : 'move';
    }
}
