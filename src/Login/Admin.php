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
        add_action('admin_menu', [self::class, 'menu'], 12);
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
        Brand::open(__('Two-step login', 'draco-insomnis'), __('After the right password, WordPress asks for a 6-digit code sent by e-mail. A stolen password alone is no longer enough to get in.', 'draco-insomnis'));
        if ($result === 'blocked') {
            Brand::notice('error', Mfa::blocker());
        } elseif ($result === 'ok') {
            Brand::notice('success', __('Changes saved.', 'draco-insomnis'));
        }
        if (defined('DRACO_MFA_OFF') && DRACO_MFA_OFF) {
            Brand::notice('warning', __('DRACO_MFA_OFF is set in wp-config.php: no codes are asked for. Remove that line once you are back in.', 'draco-insomnis'));
        }
        echo '<div class="draco-grid">';
        Brand::card('lock', __('Settings', 'draco-insomnis'), '', Brand::pill(Brand::stateLabel($on ? 'on' : 'off'), $on ? 'on' : 'off'));
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field(self::ACTION);
        echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '">';
        Brand::toggle('enabled', $on, __('Ask for a code by e-mail after the password', 'draco-insomnis'));
        echo '<p class="draco-field__label" style="margin-top:10px">' . esc_html__('Who has to enter it:', 'draco-insomnis') . '</p>';
        Brand::modes('who', $who, [
            'admins' => [__('Administrators', 'draco-insomnis'), '', 'admin-network'],
            'editors' => [__('Anyone who can write or edit content', 'draco-insomnis'), '', 'edit'],
            'all' => [__('Every user', 'draco-insomnis'), '', 'groups'],
        ]);
        /* translators: %d: days */
        Brand::toggle('trust', get_option(Mfa::OPTION_TRUST, 'yes') === 'yes', sprintf(__('Offer "Trust this device for %d days"', 'draco-insomnis'), TrustedDevice::DAYS));
        echo '<p style="margin-top:12px">';
        submit_button(__('Save', 'draco-insomnis'), 'primary', 'submit', false);
        echo '</p></form>';
        Brand::cardEnd();

        Brand::card('lightbulb', __('Good to know', 'draco-insomnis'), '', '', 'info');
        echo '<ul class="draco-list">';
        foreach ([
            ['email-alt', __('It can only be switched on with Site mail (SMTP) working, and it switches itself off if that connection is forgotten: a code that never arrives would lock you out.', 'draco-insomnis')],
            ['clock', __('The code is only sent after the right password. It expires in 10 minutes and allows 5 tries; repeated failures block the address for 15 minutes.', 'draco-insomnis')],
            ['update', __('Changing the password or the e-mail of an account makes all its trusted devices ask for a code again.', 'draco-insomnis')],
            ['admin-appearance', __('Login boxes that work without reloading the page (some themes) cannot show the code step: those users are asked to log in from the normal login page.', 'draco-insomnis')],
            ['sos', __('If you are ever locked out, add define(\'DRACO_MFA_OFF\', true); to wp-config.php, log in, fix the problem and remove the line. Only someone with access to the server can do this, unlike a "skip" button.', 'draco-insomnis')],
        ] as [$icon, $item]) {
            echo '<li><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
        Brand::cardEnd();
        echo '</div>';
        Brand::close();
    }
}
