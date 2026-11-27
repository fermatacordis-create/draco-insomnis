<?php

declare(strict_types=1);

namespace DracoInsomnis\Firewall;

defined('ABSPATH') || exit;

/**
 * Hide versions, off by default: public pages stop saying which WordPress, theme and plugins the
 * site runs, so a robot looking for sites left on an old version does not find this one with one
 * request. It hides; it does not fix anything: a determined scanner can still guess versions by
 * comparing files, and the real protection is to keep everything updated.
 *
 * - The WordPress "generator" tag, in pages and feeds.
 * - The other "generator" tags in <head> (themes and page builders print their own).
 * - "?ver=" of styles and scripts, when it carries a version: it becomes a short code made from that
 *   value with this site's secret key, so it still changes on every update (browsers and caches fetch
 *   the new file) but no longer says which version it is. Only on public pages, never in wp-admin.
 *
 * readme.html and license.txt are sent by the web server without WordPress: no plugin can refuse
 * them. The screen says so; the web server or Draco's rules generator must refuse them.
 */
final class Versions
{
    public const OPTION = 'draco_hide_versions';

    /** @var array<string, string> */
    private static array $codes = [];

    /** Output-buffer level of the <head> buffer; 0 when none is open. */
    private static int $level = 0;

    public static function register(): void
    {
        add_action('init', [self::class, 'boot']);
    }

    public static function active(): bool
    {
        return get_option(self::OPTION, 'no') === 'yes';
    }

    public static function boot(): void
    {
        if (!self::active() || is_admin()) {
            return;
        }
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string', 99);
        add_filter('style_loader_src', [self::class, 'filterSrc'], 30);
        add_filter('script_loader_src', [self::class, 'filterSrc'], 30);
        // Around everything else that prints into <head>, to take out the other generator tags.
        add_action('wp_head', [self::class, 'headStart'], PHP_INT_MIN);
        add_action('wp_head', [self::class, 'headEnd'], PHP_INT_MAX);
    }

    public static function headStart(): void
    {
        ob_start();
        self::$level = ob_get_level();
    }

    public static function headEnd(): void
    {
        // Another plugin left a buffer of its own open in <head>: leave everything as it is.
        if (self::$level === 0 || ob_get_level() !== self::$level) {
            return;
        }
        self::$level = 0;
        $head = (string) ob_get_clean();
        echo self::stripGenerators($head); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- the theme's and plugins' own <head>, with only the generator tags removed
    }

    public static function stripGenerators(string $html): string
    {
        return (string) preg_replace('/[ \t]*<meta\b(?=[^>]*\bname\s*=\s*(["\']?)generator\1)[^>]*>[ \t]*\R?/i', '', $html);
    }

    /**
     * @param mixed $src
     * @return mixed
     */
    public static function filterSrc($src)
    {
        return is_string($src) ? self::rewrite($src) : $src;
    }

    /** "?ver=7.1.5" or "?ver=abc-1.2.3" becomes "?ver=<code>"; a "ver" with no version (a timestamp) stays. */
    public static function rewrite(string $src): string
    {
        return (string) preg_replace_callback(
            '/([?&]ver=)([^&#]*?\d+\.\d+(?:\.\d+){0,2}[^&#]*)(?=&|#|$)/',
            static fn (array $m): string => $m[1] . self::code($m[2]),
            $src,
        );
    }

    public static function code(string $value): string
    {
        if (!isset(self::$codes[$value])) {
            self::$codes[$value] = substr(hash_hmac('sha256', 'draco-asset|' . $value, wp_salt('nonce')), 0, 10);
        }

        return self::$codes[$value];
    }
}
