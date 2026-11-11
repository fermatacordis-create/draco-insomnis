<?php

declare(strict_types=1);

namespace DracoInsomnis\Admin;

defined('ABSPATH') || exit;

/**
 * Who made it, and the look of the plugin's own screens: header, module tabs, cards, status pills,
 * switches and mode choosers. Shown only inside the admin screens of this plugin and in the plugin
 * list, never to the site's visitors.
 */
final class Brand
{
    public const PARENT = 'draco-insomnis';
    public const URL_NV = 'https://notoriusvision.com';
    public const URL_OPNV = 'https://opnv.systems';
    public const URL_CODE = 'https://github.com/fermatacordis-create/draco-insomnis';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 5);
        add_filter('plugin_row_meta', [self::class, 'rowMeta'], 10, 2);
        add_action('admin_enqueue_scripts', [self::class, 'enqueue']);
    }

    public static function menu(): void
    {
        $title = __('Overview', 'draco-insomnis');
        add_menu_page('Draco Insomnis', 'Draco Insomnis', 'manage_options', self::PARENT, [Overview::class, 'render'], 'dashicons-shield', 81);
        add_submenu_page(self::PARENT, $title, $title, 'manage_options', self::PARENT, [Overview::class, 'render']);
    }

    /** The plugin's screens, in the order of the tabs: slug => [title, dashicon, status]. */
    public static function modules(): array
    {
        $waf = get_option('draco_waf_enabled', 'no') === 'yes' ? (get_option('draco_waf_mode', 'log') === 'block' ? 'on' : 'log') : 'off';
        $copy = 'off';
        foreach (['draco_anticopy_rest', 'draco_anticopy_rate'] as $option) {
            $mode = (string) get_option($option, 'off');
            $copy = $mode === 'block' ? 'on' : ($mode === 'log' && $copy === 'off' ? 'log' : $copy);
        }
        $on = static fn (string $option): string => get_option($option, 'no') === 'yes' ? 'on' : 'off';

        return [
            self::PARENT => [__('Overview', 'draco-insomnis'), 'dashboard', ''],
            'draco-insomnis-shield' => [__('Anti-bot shield', 'draco-insomnis'), 'shield-alt', $on('draco_shield_enabled')],
            'draco-insomnis-forms' => [__('Forms and sign-ups', 'draco-insomnis'), 'feedback', $on('draco_gate_enabled')],
            'draco-insomnis-login' => [__('Two-step login', 'draco-insomnis'), 'lock', $on('draco_mfa_enabled')],
            'draco-insomnis-firewall' => [__('Firewall', 'draco-insomnis'), 'privacy', $waf],
            'draco-insomnis-anticopy' => [__('Anti-copy', 'draco-insomnis'), 'hidden', $copy],
            'draco-insomnis-mail' => [__('Site mail (SMTP)', 'draco-insomnis'), 'email-alt', \DracoInsomnis\Mail\Settings::active() ? 'on' : 'off'],
        ];
    }

    private static function currentPage(): string
    {
        return sanitize_key((string) ($_GET['page'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- which screen is open
    }

    public static function enqueue(): void
    {
        $page = self::currentPage();
        if (isset(self::modules()[$page]) || $page === \DracoInsomnis\Login\Recovery::SLUG) {
            wp_enqueue_style('draco-insomnis-admin', plugins_url('assets/admin.css', DRACO_INSOMNIS_FILE), [], DRACO_INSOMNIS_VERSION);
        }
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

    /** Opens the screen: wrapper, header with the logo, module tabs and an optional lead paragraph. */
    public static function open(string $title, string $lead = ''): void
    {
        echo '<div class="wrap draco">';
        self::header($title);
        if ($lead !== '') {
            echo '<p class="draco-lead">' . esc_html($lead) . '</p>';
        }
    }

    public static function close(): void
    {
        echo '<p class="draco-foot">Draco Insomnis ' . esc_html(DRACO_INSOMNIS_VERSION) . ' · <a href="' . esc_url(self::URL_CODE) . '" target="_blank" rel="noopener">' . esc_html__('Open source (GPL)', 'draco-insomnis') . '</a></p></div>';
    }

    public static function header(string $title): void
    {
        $logo = plugins_url('assets/draco-insomnis.webp', DRACO_INSOMNIS_FILE);
        echo '<div class="draco-hero">';
        echo '<img src="' . esc_url($logo) . '" width="60" height="60" alt="">';
        echo '<div class="draco-hero__text"><p class="draco-hero__brand">Draco Insomnis</p><h1>' . esc_html($title) . '</h1>';
        echo '<p class="draco-hero__motto"><em>Ab insomni custodita dracone</em></p></div>';
        echo '<div class="draco-hero__credits">';
        printf(
            /* translators: %1$s, %2$s, %3$s: brand names with links */
            esc_html__('by %1$s · %2$s · %3$s', 'draco-insomnis'),
            '<a href="' . esc_url(self::URL_NV) . '" target="_blank" rel="noopener">Notorius Vision</a>',
            '<a href="' . esc_url(self::URL_OPNV) . '" target="_blank" rel="noopener">OPNV Systems</a>',
            '<strong>OPNV SOLΞ</strong>'
        );
        echo '</div></div>';
        self::nav();
        // WordPress moves other plugins' notices to this mark instead of into the header.
        echo '<hr class="wp-header-end">';
    }

    private static function nav(): void
    {
        $page = self::currentPage();
        echo '<nav class="draco-nav" aria-label="Draco Insomnis">';
        foreach (self::modules() as $slug => [$label, $icon, $state]) {
            $current = $slug === $page;
            echo '<a href="' . esc_url(admin_url('admin.php?page=' . $slug)) . '"' . ($current ? ' class="is-current" aria-current="page"' : '') . '>'
                . '<span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($label);
            if ($state !== '') {
                echo ' <span class="draco-nav__dot' . ($state === 'off' ? '' : ' is-' . esc_attr($state)) . '" title="' . esc_attr(self::stateLabel($state)) . '"></span>';
            }
            echo '</a>';
        }
        if (\DracoInsomnis\Login\Mfa::active()) {
            echo '<a href="' . esc_url(admin_url('users.php?page=' . \DracoInsomnis\Login\Recovery::SLUG)) . '"' . ($page === \DracoInsomnis\Login\Recovery::SLUG ? ' class="is-current" aria-current="page"' : '') . '>'
                . '<span class="dashicons dashicons-sos" aria-hidden="true"></span>' . esc_html__('Recovery e-mail', 'draco-insomnis') . '</a>';
        }
        echo '</nav>';
    }

    public static function stateLabel(string $state): string
    {
        $labels = ['on' => __('On', 'draco-insomnis'), 'log' => __('Log only', 'draco-insomnis'), 'off' => __('Off', 'draco-insomnis')];

        return $labels[$state] ?? $state;
    }

    /** A status pill. $tone: on, log, warn, bad, info or off. */
    public static function pill(string $label, string $tone = 'off'): string
    {
        return '<span class="draco-pill' . ($tone !== 'off' ? ' is-' . esc_attr($tone) : '') . '">' . esc_html($label) . '</span>';
    }

    /** Opens a card; $pill is HTML from pill(). $tone colours the icon: '', warn, bad or info. */
    public static function card(string $icon, string $title, string $subtitle = '', string $pill = '', string $tone = '', string $class = ''): void
    {
        echo '<section class="draco-card' . ($class !== '' ? ' ' . esc_attr($class) : '') . '"><div class="draco-card__head">';
        echo '<span class="draco-card__icon' . ($tone !== '' ? ' is-' . esc_attr($tone) : '') . '"><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span></span>';
        echo '<div class="draco-card__title"><h2>' . esc_html($title) . '</h2>';
        if ($subtitle !== '') {
            echo '<p>' . esc_html($subtitle) . '</p>';
        }
        echo '</div>' . wp_kses_post($pill) . '</div><div class="draco-card__body">';
    }

    public static function cardEnd(): void
    {
        echo '</div></section>';
    }

    /** A checkbox drawn as a switch, with a bold label and an optional explanation. */
    public static function toggle(string $name, bool $checked, string $label, string $hint = ''): void
    {
        echo '<label class="draco-switch"><input type="checkbox" name="' . esc_attr($name) . '" value="1" ' . checked($checked, true, false) . '>'
            . '<span class="draco-switch__text"><strong>' . esc_html($label) . '</strong>' . ($hint !== '' ? '<span>' . esc_html($hint) . '</span>' : '') . '</span></label>';
    }

    /**
     * Radio buttons drawn as cards.
     *
     * @param array<string, array{0: string, 1?: string, 2?: string}> $options value => [title, explanation, dashicon]
     */
    public static function modes(string $name, string $current, array $options): void
    {
        echo '<div class="draco-modes" role="radiogroup">';
        foreach ($options as $value => $o) {
            echo '<label class="draco-mode"><input type="radio" name="' . esc_attr($name) . '" value="' . esc_attr((string) $value) . '" ' . checked($current, (string) $value, false) . '>'
                . '<span><strong>' . (isset($o[2]) ? '<span class="dashicons dashicons-' . esc_attr($o[2]) . '" aria-hidden="true"></span>' : '') . esc_html($o[0]) . '</strong>'
                . (isset($o[1]) && $o[1] !== '' ? '<small>' . esc_html($o[1]) . '</small>' : '') . '</span></label>';
        }
        echo '</div>';
    }

    /** The row shown in an empty table. */
    public static function emptyRow(int $columns, string $text, string $icon = 'yes-alt'): void
    {
        echo '<tr><td colspan="' . (int) $columns . '" class="draco-empty"><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($text) . '</td></tr>';
    }

    /** A WordPress notice that stays below the header. $type: success, error, warning or info. */
    public static function notice(string $type, string $text, string $link = '', string $linkText = ''): void
    {
        echo '<div class="notice notice-' . esc_attr($type) . '"><p>' . esc_html($text);
        if ($link !== '') {
            echo ' <a href="' . esc_url($link) . '">' . esc_html($linkText) . '</a>';
        }
        echo '</p></div>';
    }
}
