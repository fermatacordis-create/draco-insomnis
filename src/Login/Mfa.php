<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;
use DracoInsomnis\Mail\Template;
use DracoInsomnis\Mail\Transport;
use DracoInsomnis\Shield\Guard;

defined('ABSPATH') || exit;

/**
 * Two-step login: after the right password, a six-digit code sent by e-mail. The WordPress session only
 * starts once the code is right (or the device is trusted).
 *
 * Emergency exit for an owner locked out: define('DRACO_MFA_OFF', true); in wp-config.php. Only someone
 * with access to the server can do that, unlike a "skip" button a thief holding the password could press.
 */
final class Mfa
{
    public const OPTION_ENABLED = 'draco_mfa_enabled';
    public const OPTION_WHO = 'draco_mfa_who';
    public const OPTION_TRUST = 'draco_mfa_trust';
    public const ACTION = 'draco_mfa';
    private const COOKIE = 'draco_mfa_cid';
    private const FAILS = 8;
    private const FAIL_WINDOW = 300;
    private const BLOCK_SECONDS = 900;

    public static function boot(): void
    {
        // A site that forgets its SMTP must not keep asking for codes that may never arrive.
        add_action('draco_insomnis_mail_forgotten', [self::class, 'switchOff']);
        if (!self::active()) {
            return;
        }
        add_filter('wp_authenticate_user', [self::class, 'afterPassword'], 99, 2);
        add_action('login_form_' . self::ACTION, [self::class, 'page']);
        add_action('login_init', [self::class, 'refuseBlockedIp']);
        add_action('wp_login_failed', [self::class, 'recordFailure']);
        add_action('password_reset', [self::class, 'onPasswordReset']);
        add_action('profile_update', [self::class, 'onProfileUpdate'], 10, 2);
        add_action('clear_auth_cookie', [self::class, 'onLogout']);
        Recovery::register();
    }

    public static function active(): bool
    {
        return get_option(self::OPTION_ENABLED, 'no') === 'yes' && !(defined('DRACO_MFA_OFF') && DRACO_MFA_OFF);
    }

    /** Why it cannot be switched on, or '' if it can. */
    public static function blocker(): string
    {
        if (get_option('opnv_login_mfa_enabled', 'no') === 'yes') {
            return __('The e-mail login code of OPNV-WP is already on in this site. Use one of them, not both.', 'draco-insomnis');
        }
        if (!Transport::hasSmtp()) {
            return __('Without SMTP the code may not arrive and you would be locked out. Set up Site mail (SMTP) first.', 'draco-insomnis');
        }

        return '';
    }

    public static function switchOff(): void
    {
        update_option(self::OPTION_ENABLED, 'no');
    }

    public static function requiredFor(\WP_User $user): bool
    {
        $who = (string) get_option(self::OPTION_WHO, 'admins');
        $required = $who === 'all' || user_can($user, 'manage_options') || ($who === 'editors' && user_can($user, 'edit_posts'));

        return (bool) apply_filters('draco_insomnis_mfa_required', $required, $user);
    }

    /**
     * @param \WP_User|\WP_Error $user
     * @param string $password
     * @return \WP_User|\WP_Error
     */
    public static function afterPassword($user, $password)
    {
        if (!$user instanceof \WP_User) {
            return $user;
        }
        if (self::ipBlocked()) {
            return new \WP_Error('draco_locked', __('Too many attempts. Try again later.', 'draco-insomnis'));
        }
        // This filter runs before WordPress checks the password: without this test any password
        // would earn a code, and the code alone would be enough to get in.
        if (!wp_check_password((string) $password, (string) $user->user_pass, (int) $user->ID)) {
            return $user;
        }
        if (!self::requiredFor($user) || !is_email((string) $user->user_email)) {
            return $user;
        }
        if (get_option(self::OPTION_TRUST, 'yes') === 'yes' && TrustedDevice::isValid((int) $user->ID)) {
            return $user;
        }
        // Login boxes that post by AJAX or REST cannot show the code step.
        if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)) {
            /* translators: %s: login page URL */
            return new \WP_Error('draco_mfa_page', sprintf(__('This account needs a code sent by e-mail. Log in from %s to receive it.', 'draco-insomnis'), wp_login_url()));
        }
        $code = Challenge::newCode();
        $challenge = Challenge::create((int) $user->ID, $code);
        $sent = self::send($user, $code, Recovery::destination($user));
        // The main mailbox not answering is exactly what the recovery address is for.
        if (!$sent && Recovery::useRecovery((int) $user->ID)) {
            $sent = self::send($user, $code, Recovery::destination($user));
        }
        if (!$sent) {
            Challenge::forgetUser((int) $user->ID);

            return new \WP_Error('draco_mfa_mail', __('The login code could not be sent by e-mail. If you own this site and are locked out, add define(\'DRACO_MFA_OFF\', true); to wp-config.php.', 'draco-insomnis'));
        }
        self::setCookie($challenge['id'], time() + Challenge::TTL);
        $to = isset($_REQUEST['redirect_to']) && is_string($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- only remembered, validated on use
        Challenge::setRedirect((int) $user->ID, $to);
        wp_safe_redirect(add_query_arg('action', self::ACTION, wp_login_url()));
        exit;
    }

    /** $purpose 'login' for the login step, 'recovery' to confirm a recovery address. */
    public static function send(\WP_User $user, string $code, string $to, string $purpose = 'login'): bool
    {
        if (!is_email($to)) {
            return false;
        }
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $name = wp_specialchars_decode($user->display_name !== '' ? $user->display_name : $user->user_login, ENT_QUOTES);
        /* translators: %s: person's name */
        $hello = sprintf(__('Hello %s,', 'draco-insomnis'), $name);
        if ($purpose === 'recovery') {
            /* translators: %s: site name */
            $subject = sprintf(__('[%s] Confirm your recovery e-mail', 'draco-insomnis'), $site);
            $title = __('Confirm your recovery e-mail', 'draco-insomnis');
            $use = __('Type this code in the recovery e-mail screen to confirm the change:', 'draco-insomnis');
            $after = __('It expires in 15 minutes. If you did not ask for this, someone has access to your account: change your password.', 'draco-insomnis');
        } else {
            /* translators: %s: site name */
            $subject = sprintf(__('[%s] Your login code', 'draco-insomnis'), $site);
            $title = __('Your login code', 'draco-insomnis');
            $use = __('Use this code to finish logging in:', 'draco-insomnis');
            /* translators: %d: minutes */
            $after = sprintf(__('It expires in %d minutes. If you did not try to log in, someone knows your password: change it.', 'draco-insomnis'), (int) (Challenge::TTL / 60));
        }

        return Template::send($to, $subject, "$hello\n\n$use $code\n\n$after", $title, [$hello, $use], ['code' => $code, 'after' => [$after]]);
    }

    /** wp-login.php?action=draco_mfa */
    public static function page(): void
    {
        $errors = new \WP_Error();
        $id = isset($_COOKIE[self::COOKIE]) ? sanitize_key(wp_unslash((string) $_COOKIE[self::COOKIE])) : '';
        $row = Challenge::get($id);
        $info = '';
        if (Input::method() === 'POST') {
            check_admin_referer(self::ACTION);
            if ($row === null) {
                $errors->add('expired', __('The code has expired. Log in again.', 'draco-insomnis'));
            } elseif (!empty($_POST['resend']) || !empty($_POST['recovery'])) {
                $user = get_userdata($row['user_id']);
                if (!empty($_POST['recovery']) && !Recovery::useRecovery($row['user_id'])) {
                    $errors->add('recovery', __('The recovery e-mail cannot be used right now. Try again later.', 'draco-insomnis'));
                }
                $code = Challenge::newCode();
                $fresh = Challenge::create($row['user_id'], $code);
                if ($user instanceof \WP_User && self::send($user, $code, Recovery::destination($user))) {
                    self::setCookie($fresh['id'], time() + Challenge::TTL);
                    $row = $fresh;
                    $info = __('A new code is on its way. Check your spam folder too.', 'draco-insomnis');
                } else {
                    $errors->add('mail', __('The code could not be sent again.', 'draco-insomnis'));
                }
            } else {
                $code = Input::postDigits('code');
                $result = Challenge::check($row['id'], $code);
                if ($result === 'ok') {
                    Recovery::onCodeAccepted($row['user_id']);
                    self::finish($row['user_id'], !empty($_POST['trust']), !empty($_POST['remember']));
                }
                self::recordFailure();
                $errors->add($result, $result === 'locked' ? __('Too many attempts. Log in again.', 'draco-insomnis') : __('Wrong code.', 'draco-insomnis'));
                $row = $result === 'locked' ? null : $row;
            }
        }
        if ($row === null && !$errors->has_errors()) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        $user = $row !== null ? get_userdata($row['user_id']) : null;
        /* translators: %s: masked e-mail address */
        $message = $info !== '' ? $info : ($user instanceof \WP_User ? sprintf(__('We have sent a 6-digit code to %s. Check your spam folder too.', 'draco-insomnis'), self::mask(Recovery::destination($user))) : '');
        login_header(__('Login code', 'draco-insomnis'), $message !== '' ? '<p class="message">' . esc_html($message) . '</p>' : '', $errors);
        $action = esc_url(add_query_arg('action', self::ACTION, site_url('wp-login.php', 'login_post')));
        if ($row !== null) {
            echo '<form name="dracomfa" id="loginform" action="' . $action . '" method="post">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above
            wp_nonce_field(self::ACTION);
            echo '<p><label for="draco_code">' . esc_html__('Code', 'draco-insomnis') . '</label>'
                . '<input type="text" name="code" id="draco_code" class="input" autocomplete="one-time-code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" required autofocus></p>';
            if (get_option(self::OPTION_TRUST, 'yes') === 'yes') {
                /* translators: %d: days */
                echo '<p class="forgetmenot"><label><input type="checkbox" name="trust" value="1"> ' . esc_html(sprintf(__('Trust this device for %d days', 'draco-insomnis'), TrustedDevice::DAYS)) . '</label></p>';
            }
            echo '<p class="forgetmenot"><label><input type="checkbox" name="remember" value="1"> ' . esc_html__('Remember me', 'draco-insomnis') . '</label></p>';
            echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__('Verify and log in', 'draco-insomnis') . '"></p></form>';
            echo '<form action="' . $action . '" method="post" style="margin-top:8px;padding:0 24px;background:none;box-shadow:none;border:0">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            wp_nonce_field(self::ACTION);
            echo '<button type="submit" name="resend" value="1" class="button-link">' . esc_html__('Send the code again', 'draco-insomnis') . '</button>';
            if ($user instanceof \WP_User && Recovery::email((int) $user->ID) !== '' && Recovery::destination($user) !== Recovery::email((int) $user->ID)) {
                echo '<br><button type="submit" name="recovery" value="1" class="button-link" style="margin-top:8px">' . esc_html__('I cannot reach this mailbox: use my recovery e-mail', 'draco-insomnis') . '</button>';
            }
            echo '</form>';
        }
        echo '<p id="backtoblog"><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('← Back to log in', 'draco-insomnis') . '</a></p>';
        login_footer();
        exit;
    }

    private static function finish(int $userId, bool $trust, bool $remember): void
    {
        self::setCookie('', time() - YEAR_IN_SECONDS);
        if ($trust && get_option(self::OPTION_TRUST, 'yes') === 'yes') {
            TrustedDevice::issue($userId);
        }
        wp_set_current_user($userId);
        wp_set_auth_cookie($userId, $remember, is_ssl());
        $user = get_userdata($userId);
        if ($user instanceof \WP_User) {
            do_action('wp_login', $user->user_login, $user); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress's own hook, fired as wp_signon() would.
        }
        $to = Challenge::takeRedirect($userId);
        wp_safe_redirect($to !== '' ? $to : admin_url());
        exit;
    }

    public static function mask(string $email): string
    {
        if (!is_email($email)) {
            return '';
        }
        [$local, $domain] = explode('@', strtolower($email), 2);
        $keep = min(2, max(1, intdiv(strlen($local), 2)));

        return substr($local, 0, $keep) . str_repeat('*', max(1, strlen($local) - $keep)) . '@' . $domain;
    }

    public static function recordFailure(): void
    {
        $key = 'draco_login_fail_' . md5(Guard::clientIp());
        $hits = (int) get_transient($key) + 1;
        set_transient($key, $hits, self::FAIL_WINDOW);
        if ($hits >= self::FAILS) {
            set_transient('draco_login_block_' . md5(Guard::clientIp()), 1, self::BLOCK_SECONDS);
        }
    }

    private static function ipBlocked(): bool
    {
        return (bool) get_transient('draco_login_block_' . md5(Guard::clientIp()));
    }

    public static function refuseBlockedIp(): void
    {
        if (self::ipBlocked()) {
            wp_die(esc_html__('Too many attempts. Try again later.', 'draco-insomnis'), esc_html__('Access restricted', 'draco-insomnis'), ['response' => 403]);
        }
    }

    /** @param \WP_User $user */
    public static function onPasswordReset($user): void
    {
        if ($user instanceof \WP_User) {
            TrustedDevice::revokeAll((int) $user->ID);
            Challenge::forgetUser((int) $user->ID);
        }
    }

    /** @param \WP_User|array<string, mixed>|null $old */
    public static function onProfileUpdate(int $userId, $old = null): void
    {
        $user = get_userdata($userId);
        $before = $old instanceof \WP_User ? (string) $old->user_email : (is_array($old) ? (string) ($old['user_email'] ?? '') : '');
        if ($user instanceof \WP_User && $before !== '' && $before !== (string) $user->user_email) {
            TrustedDevice::revokeAll($userId);
            Challenge::forgetUser($userId);
        }
    }

    public static function onLogout(): void
    {
        $id = get_current_user_id();
        if ($id > 0) {
            Challenge::forgetUser($id);
        }
    }

    private static function setCookie(string $value, int $expires): void
    {
        if (!headers_sent()) {
            setcookie(self::COOKIE, $value, ['expires' => $expires, 'path' => COOKIEPATH ?: '/', 'domain' => COOKIE_DOMAIN ?: '', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']);
        }
    }
}
