<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;
use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Mail\Template;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Up to three recovery mailboxes for the login code, like nested PUKs.
 *
 * The main address gets the code every day. A recovery address is the way back in when the main one
 * stops receiving mail or is stolen. After a password reset the next code goes to the first recovery
 * slot. Changing a slot needs a code from the new address and, when replacing, from the current one.
 */
final class Recovery
{
    /** @deprecated Prefer META_LIST; kept for migration and slot-0 alias. */
    public const META = '_draco_recovery_email';
    public const META_LIST = '_draco_recovery_emails';
    public const META_PENDING = '_draco_recovery_pending';
    public const META_FORCE = '_draco_recovery_force';
    public const SLUG = 'draco-recovery-email';
    public const MAX_SLOTS = 3;
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

    /** @return list<string> */
    public static function emails(int $userId): array
    {
        $raw = get_user_meta($userId, self::META_LIST, true);
        if (is_array($raw)) {
            $out = [];
            foreach ($raw as $email) {
                $email = strtolower(trim((string) $email));
                if (is_email($email) && !in_array($email, $out, true)) {
                    $out[] = $email;
                }
            }

            return array_slice($out, 0, self::MAX_SLOTS);
        }
        $legacy = strtolower(trim((string) get_user_meta($userId, self::META, true)));
        if (is_email($legacy)) {
            self::persist($userId, [$legacy]);

            return [$legacy];
        }

        return [];
    }

    /** First recovery slot (legacy callers). */
    public static function email(int $userId): string
    {
        $emails = self::emails($userId);

        return $emails[0] ?? '';
    }

    /** The light of the tab: 'on' with every slot verified, 'log' (amber) with some, 'off' with none. */
    public static function state(int $userId): string
    {
        $n = count(self::emails($userId));

        return $n === 0 ? 'off' : ($n < self::MAX_SLOTS ? 'log' : 'on');
    }

    /** @param list<string> $emails */
    private static function persist(int $userId, array $emails): void
    {
        $clean = [];
        foreach ($emails as $email) {
            $email = strtolower(trim($email));
            if (is_email($email) && !in_array($email, $clean, true)) {
                $clean[] = $email;
            }
        }
        $clean = array_slice($clean, 0, self::MAX_SLOTS);
        update_user_meta($userId, self::META_LIST, $clean);
        update_user_meta($userId, self::META, $clean[0] ?? '');
        for ($i = 1; $i <= self::MAX_SLOTS; $i++) {
            $key = self::META . '_' . $i;
            if (isset($clean[$i - 1])) {
                update_user_meta($userId, $key, $clean[$i - 1]);
            } else {
                delete_user_meta($userId, $key);
            }
        }
    }

    /** Where the next code goes: recovery after a reset or when asked for, the main one otherwise. */
    public static function destination(\WP_User $user): string
    {
        $id = (int) $user->ID;
        $emails = self::emails($id);
        if ($emails !== [] && get_user_meta($id, self::META_FORCE, true) !== '') {
            return $emails[0];
        }
        $chosen = (string) get_transient(self::DEST . $id);

        return $chosen !== '' && in_array($chosen, $emails, true) ? $chosen : (string) $user->user_email;
    }

    /** Sends the next code to a recovery slot (default 0). A few times an hour at most. */
    public static function useRecovery(int $userId, int $slot = 0): bool
    {
        $emails = self::emails($userId);
        $recovery = $emails[$slot] ?? ($emails[0] ?? '');
        $key = self::SWITCHES . $userId;
        $hits = Store::bump($key, HOUR_IN_SECONDS);
        if ($recovery === '' || $hits > self::MAX_SWITCHES_HOUR) {
            return false;
        }
        set_transient(self::DEST . $userId, $recovery, Challenge::TTL);

        return true;
    }

    public static function onCodeAccepted(int $userId): void
    {
        delete_user_meta($userId, self::META_FORCE);
        delete_transient(self::DEST . $userId);
    }

    public static function menu(): void
    {
        $title = __('Recovery e-mail', 'draco-insomnis');
        $menu = class_exists('NotoriusVision\\OptimizadorPro\\Core\\Security\\LoginRecovery') ? $title . ' (Draco)' : $title;
        add_users_page($title, $menu, 'read', self::SLUG, [self::class, 'render']);
    }

    private static function mustHave(\WP_User $user): bool
    {
        return $user->ID !== 0 && Mfa::active() && Mfa::requiredFor($user) && self::emails((int) $user->ID) === [];
    }

    public static function enforce(): void
    {
        global $pagenow;
        if (wp_doing_ajax() || !self::mustHave(wp_get_current_user())) {
            return;
        }
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
            $slotRaw = Input::post('slot');
            $slot = $slotRaw === '-1' || $slotRaw === '' ? -1 : Input::postInt('slot', -1);
            $result = self::request($user, sanitize_email(wp_unslash((string) ($_POST['email'] ?? ''))), $slot);
        } elseif ($do === 'confirm') {
            $result = self::confirm($user, Input::postDigits('code_new'), Input::postDigits('code_old'));
        } elseif ($do === 'remove') {
            $result = self::requestRemove($user, Input::postInt('slot'));
        } elseif ($do === 'remove_confirm') {
            $result = self::confirmRemove($user, Input::postDigits('code'));
        } else {
            delete_user_meta((int) $user->ID, self::META_PENDING);
            $result = 'cancelled';
        }
        wp_safe_redirect(admin_url('users.php?page=' . self::SLUG . '&result=' . $result));
        exit;
    }

    /** $slot -1 = append; 0..2 = replace that slot. */
    private static function request(\WP_User $user, string $email, int $slot): string
    {
        $id = (int) $user->ID;
        $emails = self::emails($id);
        if (!is_email($email)) {
            return 'invalid';
        }
        $email = strtolower($email);
        if (strcasecmp($email, (string) $user->user_email) === 0) {
            return 'same';
        }
        if (in_array($email, $emails, true)) {
            return 'dup';
        }
        if ($slot < 0) {
            if (count($emails) >= self::MAX_SLOTS) {
                return 'full';
            }
            $replaces = null;
            $current = '';
        } else {
            if (!isset($emails[$slot])) {
                return 'invalid';
            }
            $replaces = $slot;
            $current = $emails[$slot];
        }
        $codeNew = Challenge::newCode();
        $codeOld = $current !== '' ? Challenge::newCode() : '';
        if (!Mfa::send($user, $codeNew, $email, 'recovery') || ($codeOld !== '' && !Mfa::send($user, $codeOld, $current, 'recovery'))) {
            return 'unsent';
        }
        update_user_meta($id, self::META_PENDING, [
            'email' => $email,
            'new' => Challenge::hash($codeNew),
            'old' => $codeOld !== '' ? Challenge::hash($codeOld) : '',
            'replaces' => $replaces,
            'at' => time(),
            'tries' => 0,
            'op' => 'set',
        ]);

        return 'sent';
    }

    private static function confirm(\WP_User $user, string $codeNew, string $codeOld): string
    {
        $id = (int) $user->ID;
        $pending = get_user_meta($id, self::META_PENDING, true);
        if (!is_array($pending) || ($pending['op'] ?? 'set') !== 'set' || time() - (int) ($pending['at'] ?? 0) > self::PENDING_TTL) {
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
        $emails = self::emails($id);
        $previous = null;
        $replaces = $pending['replaces'] ?? null;
        if ($replaces === null || $replaces === '') {
            $emails[] = (string) $pending['email'];
        } else {
            $i = (int) $replaces;
            $previous = $emails[$i] ?? null;
            $emails[$i] = (string) $pending['email'];
        }
        self::persist($id, $emails);
        delete_user_meta($id, self::META_PENDING);
        self::notify((string) $user->user_email, __('Your recovery e-mail has been changed.', 'draco-insomnis'));
        if (is_string($previous) && $previous !== '') {
            self::notify($previous, __('This address is no longer your recovery e-mail.', 'draco-insomnis'));
        }

        return 'saved';
    }

    private static function requestRemove(\WP_User $user, int $slot): string
    {
        $id = (int) $user->ID;
        $emails = self::emails($id);
        if (!isset($emails[$slot])) {
            return 'invalid';
        }
        if (count($emails) === 1 && self::mustHave($user)) {
            return 'last';
        }
        $code = Challenge::newCode();
        if (!Mfa::send($user, $code, $emails[$slot], 'recovery')) {
            return 'unsent';
        }
        update_user_meta($id, self::META_PENDING, [
            'op' => 'remove',
            'slot' => $slot,
            'email' => $emails[$slot],
            'new' => Challenge::hash($code),
            'old' => '',
            'at' => time(),
            'tries' => 0,
        ]);

        return 'sent_remove';
    }

    private static function confirmRemove(\WP_User $user, string $code): string
    {
        $id = (int) $user->ID;
        $pending = get_user_meta($id, self::META_PENDING, true);
        if (!is_array($pending) || ($pending['op'] ?? '') !== 'remove' || time() - (int) ($pending['at'] ?? 0) > self::PENDING_TTL) {
            delete_user_meta($id, self::META_PENDING);

            return 'expired';
        }
        $pending['tries'] = (int) ($pending['tries'] ?? 0) + 1;
        if ($pending['tries'] > self::MAX_TRIES) {
            delete_user_meta($id, self::META_PENDING);

            return 'expired';
        }
        if (preg_match('/^\d{6}$/', $code) !== 1 || !hash_equals((string) $pending['new'], Challenge::hash($code))) {
            update_user_meta($id, self::META_PENDING, $pending);

            return 'bad';
        }
        $emails = self::emails($id);
        $slot = (int) ($pending['slot'] ?? -1);
        $removed = $emails[$slot] ?? '';
        if (isset($emails[$slot])) {
            array_splice($emails, $slot, 1);
        }
        self::persist($id, $emails);
        delete_user_meta($id, self::META_PENDING);
        self::notify((string) $user->user_email, __('A recovery e-mail was removed from your account.', 'draco-insomnis'));
        if ($removed !== '') {
            self::notify($removed, __('This address is no longer your recovery e-mail.', 'draco-insomnis'));
        }

        return 'removed';
    }

    /** @param \WP_User $user */
    public static function onPasswordReset($user): void
    {
        $id = $user instanceof \WP_User ? (int) $user->ID : 0;
        $emails = $id > 0 ? self::emails($id) : [];
        if ($emails === []) {
            return;
        }
        update_user_meta($id, self::META_FORCE, time());
        self::notify($emails[0], __('Your password has been reset. The next login code will be sent to this address.', 'draco-insomnis'));
        foreach (array_slice($emails, 1) as $extra) {
            self::notify($extra, __('Your password has been reset. The next login code will go to your primary recovery e-mail.', 'draco-insomnis'));
        }
    }

    /** @param \WP_User|array<string, mixed>|null $old */
    public static function onProfileUpdate(int $userId, $old = null): void
    {
        $user = get_userdata($userId);
        $emails = self::emails($userId);
        $before = $old instanceof \WP_User ? (string) $old->user_email : '';
        if (!$user instanceof \WP_User || $emails === [] || $before === '' || $before === (string) $user->user_email) {
            return;
        }
        foreach ($emails as $to) {
            self::notify($to, __('The main e-mail of your account has been changed.', 'draco-insomnis'));
        }
    }

    private static function notify(string $to, string $what): void
    {
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $tail = __('If this was not you, log in with your recovery e-mail and change your password.', 'draco-insomnis');
        $title = __('Security notice', 'draco-insomnis');
        Template::send($to, sprintf('[%s] %s', $site, $title), $what . "\n\n" . $tail, $title, [$what, $tail], ['tone' => 'orange']);
    }

    /**
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
        $needle = strtolower($typed);
        $found = [];
        for ($i = 1; $i <= self::MAX_SLOTS; $i++) {
            $hits = get_users(['meta_key' => self::META . '_' . $i, 'meta_value' => $needle, 'number' => 2]); // phpcs:ignore WordPress.DB.SlowDBQuery
            foreach ($hits as $u) {
                $found[(int) $u->ID] = $u;
            }
        }
        // Legacy single meta.
        foreach (get_users(['meta_key' => self::META, 'meta_value' => $needle, 'number' => 2]) as $u) { // phpcs:ignore WordPress.DB.SlowDBQuery
            $found[(int) $u->ID] = $u;
        }
        if (count($found) !== 1) {
            return $userData;
        }
        if ($errors instanceof \WP_Error) {
            $errors->remove('invalid_email');
            $errors->remove('invalidcombo');
        }
        self::$lostPasswordTo = $needle;

        return array_values($found)[0];
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
        $emails = self::emails($id);
        $pending = get_user_meta($id, self::META_PENDING, true);
        $pending = is_array($pending) && time() - (int) ($pending['at'] ?? 0) <= self::PENDING_TTL ? $pending : null;
        $result = sanitize_key((string) ($_GET['result'] ?? '')); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $open = static function (string $do, string $class = ''): void {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"' . ($class !== '' ? ' class="' . esc_attr($class) . '"' : '') . '>';
            wp_nonce_field(self::ACTION);
            echo '<input type="hidden" name="action" value="' . esc_attr(self::ACTION) . '"><input type="hidden" name="do" value="' . esc_attr($do) . '">';
        };
        $messages = [
            'sent' => ['info', __('We have sent a code to the new address. Type it below.', 'draco-insomnis')],
            'sent_remove' => ['info', __('We have sent a code to that recovery address. Type it below to remove it.', 'draco-insomnis')],
            'saved' => ['success', __('Recovery e-mail saved.', 'draco-insomnis')],
            'removed' => ['success', __('Recovery e-mail removed.', 'draco-insomnis')],
            'invalid' => ['error', __('That e-mail address is not valid.', 'draco-insomnis')],
            'same' => ['error', __('It must be different from the main e-mail of your account, or it would be no use if that one fails.', 'draco-insomnis')],
            'dup' => ['error', __('That address is already one of your recovery e-mails.', 'draco-insomnis')],
            'full' => ['error', __('You already have three recovery e-mails. Remove one to add another.', 'draco-insomnis')],
            'last' => ['error', __('You need at least one recovery e-mail while the login code is on.', 'draco-insomnis')],
            'unsent' => ['error', __('The code could not be sent. Check Site mail (SMTP).', 'draco-insomnis')],
            'bad' => ['error', __('Wrong code.', 'draco-insomnis')],
            'expired' => ['error', __('The codes expired or were tried too many times. Start again.', 'draco-insomnis')],
            'cancelled' => ['warning', __('Cancelled.', 'draco-insomnis')],
        ];

        Brand::open(__('Recovery e-mail', 'draco-insomnis'), __('Up to three mailboxes for your login code, like nested PUKs. Prefer providers different from your main e-mail (for example Gmail if the main one is on this site\'s domain).', 'draco-insomnis'));
        if (isset($messages[$result])) {
            Brand::notice($messages[$result][0], $messages[$result][1]);
        }
        if (self::mustHave($user)) {
            Brand::notice('warning', __('Your account needs a login code. Add a recovery e-mail before going on: it is your way back in if your main mailbox fails or is stolen.', 'draco-insomnis'));
        }

        $count = count($emails);
        $tones = ['on' => 'on', 'log' => 'warn', 'off' => 'warn'];
        $state = self::state($id);
        $pill = $count === 0 ? __('Missing', 'draco-insomnis') : ($state === 'on' ? Brand::stateLabel('on') : $count . '/' . self::MAX_SLOTS);
        /* translators: %d: number of recovery slots in use */
        Brand::card('sos', __('Recovery e-mails', 'draco-insomnis'), sprintf(__('Slots in use: %d of 3', 'draco-insomnis'), $count), Brand::pill($pill, $tones[$state]), $count === 0 ? 'warn' : '');
        if ($count < self::MAX_SLOTS || $pending !== null) {
            echo '<p class="draco-callout is-warn"><span class="dashicons dashicons-info" aria-hidden="true"></span><span>' . esc_html__('One at a time: type an address, get its code and confirm it before going on to the next one.', 'draco-insomnis') . '</span></p>';
        }
        // The slot whose code is awaited: the one being replaced or removed, else the first free one.
        $waiting = -1;
        if ($pending !== null) {
            $waiting = ($pending['op'] ?? 'set') === 'remove' ? (int) ($pending['slot'] ?? -1) : (int) ($pending['replaces'] ?? $count);
        }
        echo '<ol class="draco-slots">';
        for ($i = 0; $i < self::MAX_SLOTS; $i++) {
            $addr = $emails[$i] ?? '';
            echo '<li class="draco-slot' . ($addr === '' ? ' is-free' : '') . ($i === $waiting ? ' is-waiting' : '') . '">';
            echo '<span class="draco-slot__num" aria-hidden="true">' . (int) ($i + 1) . '</span>';
            echo '<div class="draco-slot__who">';
            if ($addr !== '') {
                echo '<strong>' . esc_html(Mfa::mask($addr)) . '</strong>';
                if ($i === 0) {
                    echo '<small>' . esc_html__('Primary recovery', 'draco-insomnis') . '</small>';
                }
            } elseif ($i === $waiting && $pending !== null) {
                echo '<strong>' . esc_html(Mfa::mask((string) $pending['email'])) . '</strong>';
            } elseif ($pending === null && $i === $count) {
                $open('request', 'draco-inline');
                echo '<input type="hidden" name="slot" value="-1"><label class="screen-reader-text" for="draco-rec-email">' . esc_html__('Add recovery e-mail', 'draco-insomnis') . '</label>';
                echo '<input id="draco-rec-email" type="email" name="email" required placeholder="you@gmail.com" autocomplete="email">';
                submit_button(__('Send code', 'draco-insomnis'), 'primary', 'submit', false, ['id' => 'draco-rec-send']);
                echo '</form>';
            } else {
                echo '<small>' . esc_html__('Confirm the previous one first.', 'draco-insomnis') . '</small>';
            }
            echo '</div>';
            if ($i === $waiting) {
                $slotPill = Brand::pill(__('Waiting for confirmation', 'draco-insomnis'), 'warn');
            } else {
                $slotPill = $addr !== '' ? Brand::pill(__('Verified', 'draco-insomnis'), 'on') : Brand::pill(__('Free', 'draco-insomnis'));
            }
            echo '<div class="draco-slot__state">' . wp_kses_post($slotPill) . '</div>';
            // While a code is awaited the other slots stay in view, without buttons.
            if ($addr !== '' && $pending === null) {
                echo '<div class="draco-slot__actions"><details><summary class="button button-small">' . esc_html__('Replace', 'draco-insomnis') . '</summary>';
                $open('request', 'draco-inline');
                echo '<input type="hidden" name="slot" value="' . (int) $i . '"><label class="screen-reader-text" for="draco-rep-' . (int) $i . '">' . esc_html__('Replace with…', 'draco-insomnis') . '</label>';
                echo '<input id="draco-rep-' . (int) $i . '" type="email" name="email" required placeholder="' . esc_attr__('Replace with…', 'draco-insomnis') . '">';
                submit_button(__('Send code', 'draco-insomnis'), 'primary', 'submit', false, ['id' => 'draco-rep-send-' . $i]);
                echo '</form></details>';
                $open('remove');
                echo '<input type="hidden" name="slot" value="' . (int) $i . '">';
                submit_button(__('Remove', 'draco-insomnis'), 'small', 'submit', false, ['id' => 'draco-rm-' . $i]);
                echo '</form></div>';
            }
            if ($i === $waiting && $pending !== null) {
                self::pendingForm($pending, $emails, $open);
            }
            echo '</li>';
        }
        echo '</ol>';
        Brand::cardEnd();

        Brand::card('lightbulb', __('Good to know', 'draco-insomnis'), '', '', 'info');
        echo '<ul class="draco-list">';
        foreach ([
            ['randomize', __('On the code screen you can ask for the code to go to a recovery address instead.', 'draco-insomnis')],
            ['admin-network', __('"Lost your password?" also accepts any of these addresses, and the link goes there.', 'draco-insomnis')],
            ['update', __('After a password reset, the next code goes to your primary recovery address.', 'draco-insomnis')],
            ['megaphone', __('Any change is told to your main mailbox and to the address that was replaced or removed.', 'draco-insomnis')],
        ] as [$icon, $item]) {
            echo '<li><span class="dashicons dashicons-' . esc_attr($icon) . '" aria-hidden="true"></span>' . esc_html($item) . '</li>';
        }
        echo '</ul>';
        Brand::cardEnd();
        Brand::close();
    }

    /**
     * The codes of the change under way, inside its own slot.
     *
     * @param array<string, mixed> $pending
     * @param list<string> $emails
     */
    private static function pendingForm(array $pending, array $emails, callable $open): void
    {
        $remove = ($pending['op'] ?? 'set') === 'remove';
        $code = static function (string $id, string $name, string $label): void {
            echo '<div class="draco-field"><label for="' . esc_attr($id) . '">' . esc_html($label) . '</label><input id="' . esc_attr($id) . '" type="text" name="' . esc_attr($name) . '" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required' . ($name === 'code_old' ? '' : ' autocomplete="one-time-code"') . '></div>';
        };
        echo '<div class="draco-slot__code">';
        $open($remove ? 'remove_confirm' : 'confirm', 'draco-inline');
        /* translators: %s: masked e-mail */
        $code($remove ? 'draco-code-rm' : 'draco-code-new', $remove ? 'code' : 'code_new', sprintf(__('Code sent to %s', 'draco-insomnis'), Mfa::mask((string) $pending['email'])));
        if (!$remove && (string) ($pending['old'] ?? '') !== '') {
            /* translators: %s: masked e-mail */
            $code('draco-code-old', 'code_old', sprintf(__('Code sent to your current recovery e-mail %s', 'draco-insomnis'), Mfa::mask($emails[(int) ($pending['replaces'] ?? 0)] ?? '')));
        }
        submit_button($remove ? __('Remove', 'draco-insomnis') : __('Confirm', 'draco-insomnis'), 'primary', 'submit', false, ['id' => 'draco-rec-confirm']);
        echo '</form>';
        $open('cancel');
        submit_button(__('Cancel', 'draco-insomnis'), 'link', 'submit', false, ['id' => 'draco-rec-cancel']);
        echo '</form></div>';
    }
}
