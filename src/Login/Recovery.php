<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Mail\Template;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * A second mailbox for the login code, like the PUK of a phone.
 *
 * The main address gets the code every day. The recovery address is the way back in when the main one
 * stops receiving mail or is stolen. After a password reset the next code goes only to the recovery
 * address, because a reset is what someone holding the stolen main mailbox would do. Changing the
 * recovery address needs a code from the new one and one from the current one, and every change is
 * told to the other mailbox.
 */
final class Recovery
{
    public const META = '_draco_recovery_email';
    public const META_PENDING = '_draco_recovery_pending';
    public const META_FORCE = '_draco_recovery_force';
    public const SLUG = 'draco-recovery-email';
    private const ACTION = 'draco_recovery';
    private const DEST = 'draco_mfa_dest_';
    private const SWITCHES = 'draco_mfa_switch_';
    private const MAX_SWITCHES_HOUR = 3;
    private const PENDING_TTL = 900;
    private const MAX_TRIES = 5;
    private static string $lostPasswordTo = '';

    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'menu']);
        add_action('admin_init', [self::class, 'enforce']);
        add_action('admin_post_' . self::ACTION, [self::class, 'save']);
        add_action('password_reset', [self::class, 'onPasswordReset'], 20);
        add_action('profile_update', [self::class, 'onProfileUpdate'], 20, 2);
        add_filter('lostpassword_user_data', [self::class, 'lostPasswordUser'], 10, 2);
        add_filter('retrieve_password_notification_email', [self::class, 'lostPasswordMail'], 10, 4);
    }

    public static function email(int $userId): string
    {
        return (string) get_user_meta($userId, self::META, true);
    }

    /** Where the next code goes: the recovery address after a reset or when asked for, the main one otherwise. */
    public static function destination(\WP_User $user): string
    {
        $id = (int) $user->ID;
        $recovery = self::email($id);
        if ($recovery !== '' && get_user_meta($id, self::META_FORCE, true) !== '') {
            return $recovery;
        }
        $chosen = (string) get_transient(self::DEST . $id);

        return $chosen !== '' && $chosen === $recovery ? $recovery : (string) $user->user_email;
    }

    /** Sends the next code to the recovery address. A few times an hour at most. */
    public static function useRecovery(int $userId): bool
    {
        $recovery = self::email($userId);
        $key = self::SWITCHES . $userId;
        $hits = Store::bump($key, HOUR_IN_SECONDS);
        if ($recovery === '' || $hits > self::MAX_SWITCHES_HOUR) {
            return false;
        }
        set_transient(self::DEST . $userId, $recovery, Challenge::TTL);

        return true;
    }

    /** The code reached the person, so whatever forced the recovery address is over. */
    public static function onCodeAccepted(int $userId): void
    {
        delete_user_meta($userId, self::META_FORCE);
        delete_transient(self::DEST . $userId);
    }

    public static function menu(): void
    {
        $title = __('Recovery e-mail', 'draco-insomnis');
        // OPNV-WP has a screen with the same name; with both installed, say which one this is.
        $menu = class_exists('NotoriusVision\\OptimizadorPro\\Core\\Security\\LoginRecovery') ? $title . ' (Draco)' : $title;
        add_users_page($title, $menu, 'read', self::SLUG, [self::class, 'render']);
    }

    private static function mustHave(\WP_User $user): bool
    {
        return $user->ID !== 0 && Mfa::active() && Mfa::requiredFor($user) && self::email((int) $user->ID) === '';
    }

    /** Someone who needs the code but has no recovery address goes no further than this screen. */
    public static function enforce(): void
    {
        global $pagenow;
        if (wp_doing_ajax() || !self::mustHave(wp_get_current_user())) {
            return;
        }
        // The mail screen stays open: without working mail this screen could never be completed.
        $page = sanitize_key((string) ($_GET['page'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if ($pagenow === 'admin-post.php' || in_array($page, [self::SLUG, 'draco-insomnis-mail'], true)) {
            return;
        }
        wp_safe_redirect(admin_url('users.php?page=' . self::SLUG));
        exit;
    }

    public static function save(): void
    {
        $user = wp_get_current_user();
        if ($user->ID === 0) {
            wp_die('', 403);
        }
        check_admin_referer(self::ACTION);
        $do = sanitize_key((string) ($_POST['do'] ?? ''));
        if ($do === 'request') {
            $result = self::request($user, sanitize_email(wp_unslash((string) ($_POST['email'] ?? ''))));
        } elseif ($do === 'confirm') {
            $result = self::confirm($user, Input::postDigits('code_new'), Input::postDigits('code_old'));
        } else {
            delete_user_meta((int) $user->ID, self::META_PENDING);
            $result = 'cancelled';
        }
        wp_safe_redirect(admin_url('users.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    private static function request(\WP_User $user, string $email): string
    {
        $id = (int) $user->ID;
        if (!is_email($email)) {
            return 'invalid';
        }
        if (strcasecmp($email, (string) $user->user_email) === 0) {
            return 'same';
        }
        $current = self::email($id);
        $codeNew = Challenge::newCode();
        $codeOld = $current !== '' ? Challenge::newCode() : '';
        if (!Mfa::send($user, $codeNew, $email, 'recovery') || ($codeOld !== '' && !Mfa::send($user, $codeOld, $current, 'recovery'))) {
            return 'unsent';
        }
        update_user_meta($id, self::META_PENDING, [
            'email' => strtolower($email),
            'new' => Challenge::hash($codeNew),
            'old' => $codeOld !== '' ? Challenge::hash($codeOld) : '',
            'at' => time(),
            'tries' => 0,
        ]);

        return 'sent';
    }

    private static function confirm(\WP_User $user, string $codeNew, string $codeOld): string
    {
        $id = (int) $user->ID;
        $pending = get_user_meta($id, self::META_PENDING, true);
        if (!is_array($pending) || time() - (int) ($pending['at'] ?? 0) > self::PENDING_TTL) {
            delete_user_meta($id, self::META_PENDING);

            return 'expired';
        }
        $pending['tries'] = (int) ($pending['tries'] ?? 0) + 1;
        if ($pending['tries'] > self::MAX_TRIES) {
            delete_user_meta($id, self::META_PENDING);

            return 'expired';
        }
        $newOk = preg_match('/^\d{6}$/', $codeNew) === 1 && hash_equals((string) $pending['new'], Challenge::hash($codeNew));
        $oldOk = (string) $pending['old'] === '' || (preg_match('/^\d{6}$/', $codeOld) === 1 && hash_equals((string) $pending['old'], Challenge::hash($codeOld)));
        if (!$newOk || !$oldOk) {
            update_user_meta($id, self::META_PENDING, $pending);

            return 'bad';
        }
        $previous = self::email($id);
        update_user_meta($id, self::META, (string) $pending['email']);
        delete_user_meta($id, self::META_PENDING);
        self::notify((string) $user->user_email, __('Your recovery e-mail has been changed.', 'draco-insomnis'));
        if ($previous !== '') {
            self::notify($previous, __('This address is no longer your recovery e-mail.', 'draco-insomnis'));
        }

        return 'saved';
    }

    /** @param \WP_User $user */
    public static function onPasswordReset($user): void
    {
        $id = $user instanceof \WP_User ? (int) $user->ID : 0;
        $recovery = $id > 0 ? self::email($id) : '';
        if ($recovery === '') {
            return;
        }
        update_user_meta($id, self::META_FORCE, time());
        self::notify($recovery, __('Your password has been reset. The next login code will be sent to this address.', 'draco-insomnis'));
    }

    /** @param \WP_User|array<string, mixed>|null $old */
    public static function onProfileUpdate(int $userId, $old = null): void
    {
        $user = get_userdata($userId);
        $recovery = self::email($userId);
        $before = $old instanceof \WP_User ? (string) $old->user_email : '';
        if (!$user instanceof \WP_User || $recovery === '' || $before === '' || $before === (string) $user->user_email) {
            return;
        }
        self::notify($recovery, __('The main e-mail of your account has been changed.', 'draco-insomnis'));
    }

    private static function notify(string $to, string $what): void
    {
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $tail = __('If this was not you, log in with your recovery e-mail and change your password.', 'draco-insomnis');
        $title = __('Security notice', 'draco-insomnis');
        Template::send($to, sprintf('[%s] %s', $site, $title), $what . "\n\n" . $tail, $title, [$what, $tail], ['tone' => 'orange']);
    }

    /**
     * "Lost your password?" also accepts the recovery address, and then the link goes there: with the
     * main mailbox stolen, this is the only way back into the account.
     *
     * @param \WP_User|false $userData
     * @param \WP_Error|null $errors
     * @return \WP_User|false
     */
    public static function lostPasswordUser($userData, $errors = null)
    {
        $typed = trim(Input::post('user_login'));
        if ($userData instanceof \WP_User || !is_email($typed)) {
            return $userData;
        }
        $found = get_users(['meta_key' => self::META, 'meta_value' => strtolower($typed), 'number' => 2]); // phpcs:ignore WordPress.DB.SlowDBQuery
        if (count($found) !== 1) {
            return $userData;
        }
        if ($errors instanceof \WP_Error) {
            $errors->remove('invalid_email');
            $errors->remove('invalidcombo');
        }
        self::$lostPasswordTo = strtolower($typed);

        return $found[0];
    }

    /** @param array<string, mixed> $mail @return array<string, mixed> */
    public static function lostPasswordMail($mail, $key = '', $login = '', $user = null): array
    {
        $mail = (array) $mail;
        if (self::$lostPasswordTo !== '') {
            $mail['to'] = self::$lostPasswordTo;
        }

        return $mail;
    }

    public static function render(): void
    {
        $user = wp_get_current_user();
        $id = (int) $user->ID;
        $current = self::email($id);
        $pending = get_user_meta($id, self::META_PENDING, true);
        $pending = is_array($pending) && time() - (int) ($pending['at'] ?? 0) <= self::PENDING_TTL ? $pending : null;
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $open = static function (string $do): void {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field(self::ACTION);
            echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
        };
        $messages = [
            'sent' => ['info', __('We have sent a code to the new address. Type it below.', 'draco-insomnis')],
            'saved' => ['success', __('Recovery e-mail saved.', 'draco-insomnis')],
            'invalid' => ['error', __('That e-mail address is not valid.', 'draco-insomnis')],
            'same' => ['error', __('It must be different from the main e-mail of your account, or it would be no use if that one fails.', 'draco-insomnis')],
            'unsent' => ['error', __('The code could not be sent. Check Site mail (SMTP).', 'draco-insomnis')],
            'bad' => ['error', __('Wrong code.', 'draco-insomnis')],
            'expired' => ['error', __('The codes expired or were tried too many times. Start again.', 'draco-insomnis')],
            'cancelled' => ['warning', __('Cancelled.', 'draco-insomnis')],
        ];

        Brand::open(__('Recovery e-mail', 'draco-insomnis'), __('A second mailbox for your login code, like the PUK of a phone. Use one on another provider than your main e-mail (for example Gmail if the main one is on this site\'s domain).', 'draco-insomnis'));
        if (isset($messages[$result])) {
            Brand::notice($messages[$result][0], $messages[$result][1]);
        }
        if (self::mustHave($user)) {
            Brand::notice('warning', __('Your account needs a login code. Add a recovery e-mail before going on: it is your way back in if your main mailbox fails or is stolen.', 'draco-insomnis'));
        }
        echo '<div class="draco-grid">';
        /* translators: %s: masked e-mail */
        $status = $current !== '' ? sprintf(__('Current recovery e-mail: %s', 'draco-insomnis'), Mfa::mask($current)) : __('You have no recovery e-mail yet.', 'draco-insomnis');
        Brand::card('sos', $current !== '' ? __('New recovery e-mail', 'draco-insomnis') : __('Recovery e-mail', 'draco-insomnis'), $status, $current !== '' ? Brand::pill(Brand::stateLabel('on'), 'on') : Brand::pill(__('Missing', 'draco-insomnis'), 'warn'), $current !== '' ? '' : 'warn');
        if ($pending !== null) {
            $open('confirm');
            /* translators: %s: masked e-mail */
            echo '<div class="draco-field"><label for="draco-code-new">' . esc_html(sprintf(__('Code sent to %s', 'draco-insomnis'), Mfa::mask((string) $pending['email']))) . '</label><input id="draco-code-new" type="text" name="code_new" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autocomplete="one-time-code" class="regular-text"></div>';
            if ((string) $pending['old'] !== '') {
                /* translators: %s: masked e-mail */
                echo '<div class="draco-field"><label for="draco-code-old">' . esc_html(sprintf(__('Code sent to your current recovery e-mail %s', 'draco-insomnis'), Mfa::mask($current))) . '</label><input id="draco-code-old" type="text" name="code_old" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required class="regular-text"></div>';
            }
            submit_button(__('Confirm', 'draco-insomnis'), 'primary', 'submit', false);
            echo '</form>';
            $open('cancel');
            submit_button(__('Cancel', 'draco-insomnis'), 'link', 'submit', false);
            echo '</form>';
        } else {
            $open('request');
            echo '<div class="draco-field"><label for="draco-rec-email">' . esc_html($current !== '' ? __('New recovery e-mail', 'draco-insomnis') : __('Recovery e-mail', 'draco-insomnis')) . '</label><input id="draco-rec-email" type="email" name="email" required class="large-text" placeholder="you@gmail.com">';
            if ($current !== '') {
                echo '<p class="description">' . esc_html__('A code will go to the new address and another to the current one: both are needed, so nobody can change it with your session alone.', 'draco-insomnis') . '</p>';
            }
            echo '</div>';
            submit_button(__('Send code', 'draco-insomnis'), 'primary', 'submit', false);
            echo '</form>';
        }
        Brand::cardEnd();

        Brand::card('lightbulb', __('Good to know', 'draco-insomnis'), '', '', 'info');
        echo '<ul class="draco-list">';
        foreach ([
            ['randomize', __('On the code screen you can ask for the code to go to this address instead.', 'draco-insomnis')],
            ['admin-network', __('"Lost your password?" also accepts this address, and the link goes there.', 'draco-insomnis')],
            ['update', __('After a password reset, the next code goes only to this address.', 'draco-insomnis')],
            ['megaphone', __('Any change to it, or to your main e-mail, is told to the other mailbox.', 'draco-insomnis')],
        ] as [$icon, $item]) {
            echo '<li><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
        Brand::cardEnd();
        echo '</div>';
        Brand::close();
    }
}
