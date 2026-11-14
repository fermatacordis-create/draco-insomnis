<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;

defined('ABSPATH') || exit;

/**
 * Privileged accounts lock. An account that can change the site (administrator, editor, shop manager…)
 * only works once the owner approved it, so an administrator created by an exploit, a stolen database
 * or a bad plugin cannot log in. And when something sensitive changes outside the owner's hands (the
 * site e-mail, its address, the default role, open registration), every privileged account is frozen
 * until the owner confirms from the e-mail kept when the lock was switched on.
 *
 * It is checked wherever WordPress decides who the user is (determine_current_user): login cookies,
 * XML-RPC, the REST API with application passwords. Not only on wp-login.php.
 *
 * Approvals are signed with a key derived from the salts in wp-config.php, not with anything kept in
 * the database: someone who can only write to the database cannot approve themselves. Someone who can
 * also edit wp-config.php owns the server anyway.
 *
 * Emergency exit for an owner locked out: define('DRACO_LOCK_OFF', true); in wp-config.php.
 */
final class AccountLock
{
    public const OPTION_ENABLED = 'draco_lock_enabled';
    public const OPTION_OWNER = 'draco_lock_owner';
    public const OPTION_APPROVED = 'draco_lock_approved';
    public const OPTION_WATCH = 'draco_lock_watch';
    public const OPTION_FROZEN = 'draco_lock_frozen';
    public const ACTION = 'draco_lock';
    /** Settings that, changed by anyone but an approved administrator, freeze every privileged account. */
    public const WATCHED = ['admin_email', 'siteurl', 'home', 'default_role', 'users_can_register'];
    /** Any of these makes an account privileged. */
    public const CAPS = [
        'manage_options', 'activate_plugins', 'install_plugins', 'edit_plugins', 'edit_themes', 'edit_theme_options',
        'create_users', 'edit_users', 'promote_users', 'delete_users', 'unfiltered_html', 'edit_others_posts', 'manage_woocommerce',
    ];
    private const LINK_TTL = 86400;
    private const ASK_EVERY = 3600;

    /** While true, determine_current_user is left alone (the lock is asking WordPress about a user itself). */
    private static bool $busy = false;
    /**
     * The approved, privileged account this request started with (0 = none). Read once, before the
     * request changes anything, so the owner editing their own e-mail is still the owner.
     */
    private static int $actor = 0;

    public static function boot(): void
    {
        if (!self::active()) {
            return;
        }
        add_filter('determine_current_user', [self::class, 'currentUser'], 99);
        add_filter('wp_authenticate_user', [self::class, 'atLogin'], 98, 2);
        add_action('login_form_' . self::ACTION, [self::class, 'page']);
        foreach (self::WATCHED as $option) {
            add_action('update_option_' . $option, [self::class, 'onWatchedChange'], 10, 0);
        }
        add_action('user_register', [self::class, 'onUserChange'], 20);
        add_action('set_user_role', [self::class, 'onUserChange'], 20);
        add_action('add_user_role', [self::class, 'onUserChange'], 20);
        add_action('profile_update', [self::class, 'onUserChange'], 20);
    }

    public static function active(): bool
    {
        return get_option(self::OPTION_ENABLED, 'no') === 'yes' && !(defined('DRACO_LOCK_OFF') && DRACO_LOCK_OFF);
    }

    /** Why it cannot be switched on, or '' if it can. */
    public static function blocker(): string
    {
        if (is_multisite()) {
            return __('Not available on multisite networks yet.', 'draco-insomnis');
        }

        return '';
    }

    /** Switches the lock on: the owner's e-mail is kept for confirmations, and the owner is approved. */
    public static function enable(\WP_User $owner): void
    {
        update_option(self::OPTION_OWNER, ['email' => (string) $owner->user_email, 'sig' => self::sign('owner|' . $owner->user_email)], false);
        update_option(self::OPTION_APPROVED, [], true);
        self::approve($owner);
        self::$actor = (int) $owner->ID;
        self::snapshot();
        delete_option(self::OPTION_FROZEN);
        update_option(self::OPTION_ENABLED, 'yes');
    }

    public static function disable(): void
    {
        update_option(self::OPTION_ENABLED, 'no');
        foreach ([self::OPTION_OWNER, self::OPTION_APPROVED, self::OPTION_WATCH, self::OPTION_FROZEN] as $option) {
            delete_option($option);
        }
    }

    /** Where confirmations go: the address kept when the lock was switched on, if nobody changed it since. */
    public static function ownerEmail(): string
    {
        $owner = get_option(self::OPTION_OWNER, []);
        $email = is_array($owner) ? (string) ($owner['email'] ?? '') : '';
        $sig = is_array($owner) ? (string) ($owner['sig'] ?? '') : '';

        return $email !== '' && hash_equals(self::sign('owner|' . $email), $sig) ? $email : '';
    }

    public static function privileged(\WP_User $user): bool
    {
        self::$busy = true;
        try {
            $privileged = false;
            foreach (self::CAPS as $cap) {
                if ($user->has_cap($cap)) {
                    $privileged = true;
                    break;
                }
            }
        } finally {
            self::$busy = false;
        }

        return (bool) apply_filters('draco_insomnis_lock_privileged', $privileged, $user);
    }

    public static function approved(\WP_User $user): bool
    {
        $list = (array) get_option(self::OPTION_APPROVED, []);
        $sig = (string) ($list[$user->ID] ?? '');

        return $sig !== '' && hash_equals(self::approval($user), $sig);
    }

    public static function approve(\WP_User $user): void
    {
        $list = (array) get_option(self::OPTION_APPROVED, []);
        $list[$user->ID] = self::approval($user);
        update_option(self::OPTION_APPROVED, $list, true);
    }

    public static function revoke(int $userId): void
    {
        $list = (array) get_option(self::OPTION_APPROVED, []);
        unset($list[$userId]);
        update_option(self::OPTION_APPROVED, $list, true);
    }

    /**
     * Why the lock is closed for everyone, or '' when it is not. A watched setting that differs from the
     * signed copy (changed straight in the database) freezes too.
     */
    public static function frozen(): string
    {
        $reason = self::frozenReason();
        if ($reason !== '') {
            return $reason;
        }
        if (!hash_equals(self::watchSig(), (string) get_option(self::OPTION_WATCH, ''))) {
            self::freeze('changed_outside');

            return 'changed_outside';
        }

        return '';
    }

    /** The recorded freeze only, without comparing the watched settings. */
    private static function frozenReason(): string
    {
        $frozen = get_option(self::OPTION_FROZEN, []);

        return is_array($frozen) ? (string) ($frozen['reason'] ?? '') : '';
    }

    public static function freeze(string $reason): void
    {
        if (self::frozenReason() !== '') {
            return;
        }
        update_option(self::OPTION_FROZEN, ['reason' => $reason, 'at' => time()], true);
        $to = self::ownerEmail();
        if ($to !== '') {
            self::mailOwner($to, 'unfreeze', 0);
        }
    }

    public static function unfreeze(): void
    {
        self::snapshot();
        delete_option(self::OPTION_FROZEN);
    }

    /** Whether this account must be kept out: privileged and not approved, or privileged while frozen. */
    public static function refused(\WP_User $user): bool
    {
        return self::privileged($user) && (!self::approved($user) || self::frozen() !== '');
    }

    /**
     * determine_current_user: a refused account is nobody, whatever way it came in (cookie, application
     * password, XML-RPC).
     *
     * @param int|false $userId
     * @return int|false
     */
    public static function currentUser($userId)
    {
        if (self::$busy || !is_int($userId) || $userId <= 0) {
            return $userId;
        }
        self::$busy = true;
        try {
            $user = get_userdata($userId);
        } finally {
            self::$busy = false;
        }

        if (!$user instanceof \WP_User) {
            return $userId;
        }
        if (self::refused($user)) {
            return 0;
        }
        if (self::$actor === 0 && self::privileged($user)) {
            self::$actor = $userId;
        }

        return $userId;
    }

    /**
     * At the login form: a clear message, and the owner asked for approval (only after the right
     * password, and at most once an hour per account).
     *
     * @param \WP_User|\WP_Error $user
     * @return \WP_User|\WP_Error
     */
    public static function atLogin($user, $password)
    {
        if (!$user instanceof \WP_User || !self::refused($user)) {
            return $user;
        }
        if (!wp_check_password((string) $password, (string) $user->user_pass, (int) $user->ID)) {
            return $user;
        }
        $to = self::ownerEmail();
        if ($to !== '' && get_transient('draco_lock_asked_' . $user->ID) === false) {
            set_transient('draco_lock_asked_' . $user->ID, 1, self::ASK_EVERY);
            self::mailOwner($to, self::frozen() !== '' ? 'unfreeze' : 'approve', (int) $user->ID);
        }
        $message = self::frozen() !== ''
            ? __('Accounts that can change this site are paused because a sensitive setting changed. The site owner has been sent an e-mail to confirm.', 'draco-insomnis')
            : __('This account can change the site, so it has to be approved by the site owner first. The owner has been sent an e-mail.', 'draco-insomnis');

        return new \WP_Error('draco_lock', $message);
    }

    /** A watched setting changed: fine when an approved administrator did it, a freeze otherwise. */
    public static function onWatchedChange(): void
    {
        if (self::actingOwner()) {
            self::snapshot();

            return;
        }
        self::freeze('setting_changed');
    }

    /**
     * An account was created, promoted or edited: approved automatically when an approved administrator
     * did it in the panel; any other way (an exploit, a plugin, the database) it waits for the owner.
     */
    public static function onUserChange($userId): void
    {
        $user = get_userdata((int) $userId);
        if (!$user instanceof \WP_User) {
            return;
        }
        $was = isset(((array) get_option(self::OPTION_APPROVED, []))[$user->ID]);
        if (self::actingOwner() && self::privileged($user)) {
            self::approve($user);
        } elseif ($was && !self::approved($user)) {
            // Its e-mail or login name changed by someone else: the old approval no longer matches.
            self::revoke((int) $user->ID);
        }
    }

    /** The confirmation page the owner reaches from the e-mail. GET shows a button; only the POST acts. */
    public static function page(): void
    {
        $token = preg_replace('/[^a-f0-9]/', '', Input::get('t')) ?? '';
        $row = $token !== '' ? get_transient('draco_lock_link_' . hash('sha256', $token)) : false;
        $title = __('Privileged accounts', 'draco-insomnis');
        if (!is_array($row)) {
            wp_die(esc_html__('This link has expired or was already used.', 'draco-insomnis'), esc_html($title), ['response' => 410]);
        }
        $user = (int) $row['user'] > 0 ? get_userdata((int) $row['user']) : null;
        if (Input::method() === 'POST') {
            check_admin_referer('draco_lock_' . $token);
            delete_transient('draco_lock_link_' . hash('sha256', $token));
            if ($row['kind'] === 'unfreeze') {
                self::unfreeze();
            }
            if ($user instanceof \WP_User) {
                self::approve($user);
            }
            wp_die(esc_html__('Done. The account can log in now.', 'draco-insomnis'), esc_html($title), ['response' => 200]);
        }
        $what = $row['kind'] === 'unfreeze'
            ? __('A sensitive setting of the site changed (its e-mail, its address, the default role or open registration) and every account that can change the site was paused. Confirm only if you or someone you trust made that change.', 'draco-insomnis')
            /* translators: 1: login name, 2: e-mail */
            : sprintf(__('The account %1$s (%2$s) can change the site and is waiting for your approval. Approve it only if you know who it belongs to.', 'draco-insomnis'), $user instanceof \WP_User ? $user->user_login : '?', $user instanceof \WP_User ? $user->user_email : '?');
        $form = '<p>' . esc_html($what) . '</p><form method="post" action="' . esc_url(add_query_arg(['action' => self::ACTION, 't' => $token], wp_login_url())) . '">'
            . wp_nonce_field('draco_lock_' . $token, '_wpnonce', true, false)
            . '<p><button type="submit" class="button button-primary">' . esc_html__('Confirm', 'draco-insomnis') . '</button></p></form>';
        wp_die(wp_kses($form, ['p' => [], 'form' => ['method' => true, 'action' => true], 'input' => ['type' => true, 'name' => true, 'value' => true, 'id' => true], 'button' => ['type' => true, 'class' => true]]), esc_html($title), ['response' => 200]);
    }

    /** The e-mail to the owner, with a one-time link valid for a day. */
    private static function mailOwner(string $to, string $kind, int $userId): void
    {
        $token = bin2hex(random_bytes(24));
        set_transient('draco_lock_link_' . hash('sha256', $token), ['kind' => $kind, 'user' => $userId], self::LINK_TTL);
        $link = add_query_arg(['action' => self::ACTION, 't' => $token], wp_login_url());
        $user = $userId > 0 ? get_userdata($userId) : null;
        $site = wp_specialchars_decode((string) get_option('blogname'), ENT_QUOTES);
        if ($kind === 'unfreeze') {
            /* translators: %s: site name */
            $subject = sprintf(__('[%s] Accounts that can change the site were paused', 'draco-insomnis'), $site);
            $body = __('A sensitive setting of your site changed (its e-mail, its address, the default role or open registration) without an approved administrator doing it, so every account that can change the site was paused. If you made the change, confirm it here. If not, your site may be compromised: do not confirm, and ask whoever manages your hosting for help.', 'draco-insomnis');
        } else {
            /* translators: %s: site name */
            $subject = sprintf(__('[%s] An account is waiting for your approval', 'draco-insomnis'), $site);
            /* translators: 1: login name, 2: e-mail */
            $body = sprintf(__('The account %1$s (%2$s) can change your site and tried to log in. It was not approved by you. If you know who it belongs to, approve it here. If not, do not approve it: someone may have created it to take over your site.', 'draco-insomnis'), $user instanceof \WP_User ? $user->user_login : '?', $user instanceof \WP_User ? $user->user_email : '?');
        }
        $body .= "\n\n" . $link . "\n\n" . __('The link works once and expires in 24 hours.', 'draco-insomnis');
        wp_mail($to, $subject, $body);
    }

    /** True when the request comes from a logged-in, approved, privileged account (the owner at the panel). */
    private static function actingOwner(): bool
    {
        return self::$actor > 0 && self::$actor === get_current_user_id() && self::frozenReason() === '';
    }

    /** For tests: forget who this request started with. */
    public static function reset(): void
    {
        self::$actor = 0;
        self::$busy = false;
    }

    private static function snapshot(): void
    {
        update_option(self::OPTION_WATCH, self::watchSig(), true);
    }

    private static function watchSig(): string
    {
        $values = [];
        foreach (self::WATCHED as $option) {
            $values[$option] = (string) get_option($option, '');
        }

        return self::sign('watch|' . (string) wp_json_encode($values));
    }

    private static function approval(\WP_User $user): string
    {
        return self::sign('approve|' . $user->ID . '|' . $user->user_login . '|' . $user->user_email);
    }

    /** Signed with the salts of wp-config.php: the database alone cannot forge an approval. */
    private static function sign(string $value): string
    {
        return hash_hmac('sha256', $value, hash_hmac('sha256', 'draco-account-lock', wp_salt('auth')));
    }
}
