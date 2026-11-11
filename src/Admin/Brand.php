<?php

declare(strict_types=1);

namespace DracoInsomnis\Admin;

defined('ABSPATH') || exit;

/**
 * Who made it. Shown only inside the admin screens of this plugin and in the plugin list, never to
 * the site's visitors.
 */
final class Brand
{
    public const PARENT = 'draco-insomnis';
    public const URL_NV = 'https://notoriusvision.com';
    public const URL_OPNV = 'https://opnv.systems';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 5);
        add_filter('plugin_row_meta', [self::class, 'rowMeta'], 10, 2);
    }

    public static function menu(): void
    {
        add_menu_page('Draco Insomnis', 'Draco Insomnis', 'manage_options', self::PARENT, '__return_null', 'dashicons-shield', 81);
    }

    /** @param list<string> $links @return list<string> */
    public static function rowMeta(array $links, string $file): array
    {
        if ($file === plugin_basename(DRACO_INSOMNIS_FILE)) {
            $links[] = '<a href="' . esc_url(self::URL_OPNV) . '" target="_blank" rel="noopener">OPNV Systems</a>';
            $links[] = '<a href="' . esc_url(self::URL_NV) . '" target="_blank" rel="noopener">Notorius Vision</a>';
        }

        return $links;
    }

    public static function header(string $title): void
    {
        $logo = plugins_url('assets/draco-insomnis.webp', DRACO_INSOMNIS_FILE);
        echo '<div style="display:flex;align-items:center;gap:16px;margin:12px 0 8px">';
        echo '<img src="' . esc_url($logo) . '" width="72" height="72" alt="Draco Insomnis" style="flex:none">';
        echo '<div><h1 style="margin:0;padding:0">Draco Insomnis · ' . esc_html($title) . '</h1>';
        echo '<p style="margin:2px 0 0"><em>Ab insomni custodita dracone</em> — ';
        /* translators: %1$s, %2$s, %3$s: brand names with links */
        printf(
            esc_html__('by %1$s · %2$s · %3$s', 'draco-insomnis'),
            '<a href="' . esc_url(self::URL_NV) . '" target="_blank" rel="noopener">Notorius Vision</a>',
            '<a href="' . esc_url(self::URL_OPNV) . '" target="_blank" rel="noopener">OPNV Systems</a>',
            '<strong>OPNV SOLΞ</strong>'
        );
        // WordPress moves other plugins' notices to this mark instead of into the header.
        echo '</p></div></div><hr class="wp-header-end">';
    }
}
