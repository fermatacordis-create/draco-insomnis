<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store as Blocks;

defined('ABSPATH') || exit;

/**
 * A public registration stays inactive until its owner confirms the address.
 *
 * It works on the user itself, not on one registration form, because themes create users in their own
 * way. Accounts made during a WooCommerce checkout are left alone so a sale is never interrupted.
 */
final class RegistrationHold
{
    public const META = '_draco_pending';
    /** Unconfirmed but with content or orders: never deleted automatically, a person reviews it. */
    public const META_REVIEW = '_draco_review';
    private static bool $held = false;

    public static function register(): void
    {
        add_filter('registration_errors', [self::class, 'rejectBlocked'], 10, 3);
        add_filter('woocommerce_registration_errors', [self::class, 'rejectBlocked'], 10, 3);
        add_action('user_register', [self::class, 'onRegister'], 5);
        add_filter('wp_send_new_user_notification_to_admin', [self::class, 'muteWhilePending'], 10, 2);
        add_filter('wp_send_new_user_notification_to_user', [self::class, 'muteWhilePending'], 10, 2);
        add_filter('wp_authenticate_user', [self::class, 'denyLogin'], 20);
        add_filter('allow_password_reset', [self::class, 'denyReset'], 10, 2);
        // Some themes log the new user in themselves, without going through the login form.
        add_filter('determine_current_user', [self::class, 'ignorePending'], 99);
        add_filter('woocommerce_registration_auth_new_customer', [self::class, 'wooAutoLogin'], 10, 2);
        add_action('woocommerce_created_customer', [self::class, 'wooNotice']);
        // Themes send their own welcome mail (RealHomes even includes a password) and admin alert.
        add_filter('pre_wp_mail', [self::class, 'muteOtherMail'], 5);
    }

    /**
     * In the request that held an account, nothing but the confirmation leaves. Once confirmed,
     * WordPress's own notices go out, with a link for the person to set their password.
     *
     * @param null|bool $return
     */
    public static function muteOtherMail($return)
    {
        return self::$held && !Mailer::isSending() && $return === null ? true : $return;
    }

    public static function heldInThisRequest(): bool
    {
        return self::$held;
    }

    public static function isAjaxRegistration(): bool
    {
        return ($_POST['action'] ?? '') === 'inspiry_ajax_register'; // phpcs:ignore WordPress.Security.NonceVerification.Missing
    }

    /**
     * @param \WP_Error $errors
     * @param mixed $a
     * @param mixed $b
     */
    public static function rejectBlocked($errors, $a = '', $b = '')
    {
        $email = is_string($b) && is_email($b) ? $b : (is_string($a) && is_email($a) ? $a : '');
        if ($email !== '' && $errors instanceof \WP_Error && !$errors->has_errors()) {
            $ip = Guard::clientIp();
            if (Blocks::isBlocked($email, $ip) || !Mailer::allow($email, $ip)) {
                $errors->add('draco_rejected', __('The registration could not be completed.', 'draco-insomnis'));
            }
        }

        return $errors;
    }

    public static function onRegister(int $userId): void
    {
        if (!self::applies()) {
            return;
        }
        $user = get_userdata($userId);
        // Only administration accounts are exempt. An anonymous sign-up with a role that can edit
        // (RealHomes "agent", for example) must confirm its address too.
        if (!$user instanceof \WP_User || user_can($user, 'manage_options') || user_can($user, 'promote_users') || $user->user_email === '') {
            return;
        }
        $created = Store::create('user', 'registration', $user->user_email, Guard::clientIp(), $userId);
        if ($created === null) {
            return;
        }
        update_user_meta($userId, self::META, time());
        self::$held = true;
        Mailer::send($user->user_email, $created['token'], 'user');
    }

    private static function applies(): bool
    {
        if (is_user_logged_in() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI)) {
            return false;
        }
        $checkout = did_action('woocommerce_checkout_process') > 0
            || defined('WOOCOMMERCE_CHECKOUT')
            || str_contains((string) ($_SERVER['REQUEST_URI'] ?? ''), '/wc/store/');

        return !$checkout && !apply_filters('draco_insomnis_skip_user', false);
    }

    public static function isPending(int $userId): bool
    {
        return $userId > 0 && get_user_meta($userId, self::META, true) !== '';
    }

    /** @param bool $send @param \WP_User $user */
    public static function muteWhilePending($send, $user): bool
    {
        return $user instanceof \WP_User && self::isPending((int) $user->ID) ? false : (bool) $send;
    }

    /** @param \WP_User|\WP_Error $user */
    public static function denyLogin($user)
    {
        if (!$user instanceof \WP_User) {
            return $user;
        }
        if (self::isPending((int) $user->ID)) {
            return new \WP_Error('draco_pending', self::notice());
        }
        if (!user_can($user, 'manage_options') && Blocks::isBlocked((string) $user->user_email, Guard::clientIp())) {
            return new \WP_Error('draco_blocked', __('Access unavailable.', 'draco-insomnis'));
        }

        return $user;
    }

    /** @param bool $allow */
    public static function denyReset($allow, int $userId): bool
    {
        return self::isPending($userId) ? false : (bool) $allow;
    }

    /** @param int|false $userId */
    public static function ignorePending($userId)
    {
        return is_numeric($userId) && self::isPending((int) $userId) ? 0 : $userId;
    }

    /** @param bool $login */
    public static function wooAutoLogin($login, int $userId): bool
    {
        return self::isPending($userId) ? false : (bool) $login;
    }

    public static function wooNotice(int $userId): void
    {
        if (self::isPending($userId) && function_exists('wc_add_notice')) {
            wc_add_notice(self::notice(), 'notice');
        }
    }

    /** @param array<string, mixed> $row */
    public static function activate(array $row): void
    {
        $userId = (int) $row['user_id'];
        delete_user_meta($userId, self::META);
        delete_user_meta($userId, self::META_REVIEW);
        if (get_userdata($userId)) {
            wp_send_new_user_notifications($userId, 'both');
        }
    }

    /** Accounts nobody confirmed. Anything with content or orders is kept for a person to review. */
    public static function purge(): void
    {
        $users = get_users([
            'meta_query' => [
                'relation' => 'AND',
                ['key' => self::META, 'value' => time() - Store::PENDING_HOURS * 3600, 'compare' => '<', 'type' => 'NUMERIC'],
                ['key' => self::META_REVIEW, 'compare' => 'NOT EXISTS'],
            ],
            'number' => 100,
            'fields' => 'ID',
        ]);
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/user.php';
        foreach ($users as $id) {
            $id = (int) $id;
            // Public profile some themes create on sign-up (RealHomes agent/agency).
            $profile = (int) get_user_meta($id, 'inspiry_role_post_id', true);
            $profile = $profile > 0 && (int) get_post_field('post_author', $profile) === $id ? $profile : 0;
            $content = (int) $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_author = %d AND ID <> %d
                 AND post_type NOT IN ('revision','attachment','nav_menu_item','customize_changeset','oembed_cache')
                 AND post_status NOT IN ('trash','auto-draft')",
                $id,
                $profile
            ));
            $orders = function_exists('wc_get_orders') ? wc_get_orders(['customer_id' => $id, 'limit' => 1, 'return' => 'ids']) : [];
            if (user_can($id, 'manage_options') || user_can($id, 'promote_users') || $content > 0 || $orders !== []) {
                // Has something of its own: still cannot log in, and waits for a person.
                update_user_meta($id, self::META_REVIEW, time());
                continue;
            }
            if ($profile > 0) {
                wp_delete_post($profile, true);
            }
            wp_delete_user($id);
        }
    }

    public static function notice(): string
    {
        return __('Almost done: we have sent you an email. Your account will not be activated until you confirm it from that email. If you cannot see it, check your spam folder.', 'draco-insomnis');
    }
}
