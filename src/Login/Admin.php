<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Admin\Brand;

defined('ABSPATH') || exit;

/** The owner's screen for the two-step login. */
final class Admin
{
    public const SLUG = 'draco-insomnis-login';
    private const ACTION = 'draco_mfa_admin';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu'], 18);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
    }

    public static function menu(): void
    {
        $title = __('Two-step login', 'draco-insomnis');
        add_submenu_page(Brand::PARENT, $title, $title, 'manage_options', self::SLUG, [self::class, 'render']);
    }

    public static function save(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'draco-insomnis'), 403);
        }
        check_admin_referer(self::ACTION);
        $result = 'ok';
        $wanted = !empty($_POST['enabled']);
        if ($wanted && get_option(Mfa::OPTION_ENABLED, 'no') !== 'yes' && Mfa::blocker() !== '') {
            $wanted = false;
            $result = 'blocked';
        }
        update_option(Mfa::OPTION_ENABLED, $wanted ? 'yes' : 'no');
        $who = sanitize_key((string) ($_POST['who'] ?? 'admins'));
        update_option(Mfa::OPTION_WHO, in_array($who, ['admins', 'editors', 'all'], true) ? $who : 'admins');
        update_option(Mfa::OPTION_TRUST, empty($_POST['trust']) ? 'no' : 'yes');
        if (empty($_POST['trust'])) {
            TrustedDevice::revokeAll(get_current_user_id());
        }
        wp_safe_redirect(admin_url('admin.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    public static function render(): void
    {
        $on = get_option(Mfa::OPTION_ENABLED, 'no') === 'yes';
        $who = (string) get_option(Mfa::OPTION_WHO, 'admins');
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        echo '<div class="wrap">';
        Brand::header(__('Two-step login', 'draco-insomnis'));
        echo '<p>' . esc_html__('After the right password, WordPress asks for a 6-digit code sent by e-mail. A stolen password alone is no longer enough to get in.', 'draco-insomnis') . '</p>';
        if ($result === 'blocked') {
            echo '<div class="notice notice-error"><p>' . esc_html(Mfa::blocker()) . '</p></div>';
        } elseif ($result === 'ok') {
            echo '<div class="notice notice-success"><p>' . esc_html__('Changes saved.', 'draco-insomnis') . '</p></div>';
        }
        if (defined('DRACO_MFA_OFF') && DRACO_MFA_OFF) {
            echo '<div class="notice notice-warning"><p>' . esc_html__('DRACO_MFA_OFF is set in wp-config.php: no codes are asked for. Remove that line once you are back in.', 'draco-insomnis') . '</p></div>';
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';
        echo '<p><label><input type="checkbox" name="enabled" value="1" ' . checked($on, true, false) . '> ' . esc_html__('Ask for a code by e-mail after the password', 'draco-insomnis') . '</label></p>';
        echo '<p>' . esc_html__('Who has to enter it:', 'draco-insomnis') . '</p><p>';
        foreach (['admins' => __('Administrators', 'draco-insomnis'), 'editors' => __('Anyone who can write or edit content', 'draco-insomnis'), 'all' => __('Every user', 'draco-insomnis')] as $value => $label) {
            echo '<label style="display:block;margin:4px 0"><input type="radio" name="who" value="' . esc_attr($value) . '" ' . checked($who, $value, false) . '> ' . esc_html($label) . '</label>';
        }
        echo '</p>';
        /* translators: %d: days */
        echo '<p><label><input type="checkbox" name="trust" value="1" ' . checked(get_option(Mfa::OPTION_TRUST, 'yes') === 'yes', true, false) . '> ' . esc_html(sprintf(__('Offer "Trust this device for %d days"', 'draco-insomnis'), TrustedDevice::DAYS)) . '</label></p>';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</form>';

        echo '<h2>' . esc_html__('Good to know', 'draco-insomnis') . '</h2><ul style="list-style:disc;margin-left:1.5em">';
        foreach ([
            __('It can only be switched on with Site mail (SMTP) working, and it switches itself off if that connection is forgotten: a code that never arrives would lock you out.', 'draco-insomnis'),
            __('The code is only sent after the right password. It expires in 10 minutes and allows 5 tries; repeated failures block the address for 15 minutes.', 'draco-insomnis'),
            __('Changing the password or the e-mail of an account makes all its trusted devices ask for a code again.', 'draco-insomnis'),
            __('Login boxes that work without reloading the page (some themes) cannot show the code step: those users are asked to log in from the normal login page.', 'draco-insomnis'),
            __('If you are ever locked out, add define(\'DRACO_MFA_OFF\', true); to wp-config.php, log in, fix the problem and remove the line. Only someone with access to the server can do this, unlike a "skip" button.', 'draco-insomnis'),
        ] as $item) {
            echo '<li>' . esc_html($item) . '</li>';
        }
        echo '</ul></div>';
    }
}
