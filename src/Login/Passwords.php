<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

defined('ABSPATH') || exit;

/**
 * Password rules, both off by default:
 * - a minimum length;
 * - refusing passwords that appear in known data breaches, asked to Have I Been Pwned with
 *   k-anonymity: only the first 5 characters of the password's SHA-1 leave the site, never the
 *   password or its full hash, and the answer is padded so its size says nothing either. If the
 *   service does not answer in 3 seconds, the password is accepted (a slow service never locks
 *   anyone out).
 *
 * Applied when a password is chosen (profile, reset, WooCommerce sign-up). At login, a breached
 * password is not refused: the person is told on the dashboard to change it.
 */
final class Passwords
{
    public const OPTION_MIN = 'draco_pwd_min';
    public const OPTION_BREACHED = 'draco_pwd_breached';
    public const META_WARN = '_draco_pwd_breached';
    private const API = 'https://api.pwnedpasswords.com/range/';

    public static function register(): void
    {
        add_action('user_profile_update_errors', [self::class, 'onProfile'], 10, 3);
        add_action('validate_password_reset', [self::class, 'onReset'], 10, 2);
        add_filter('woocommerce_registration_errors', [self::class, 'onWooRegistration'], 10, 3);
        add_action('wp_login', [self::class, 'onLogin'], 10, 2);
        add_action('admin_notices', [self::class, 'notice']);
        add_action('after_password_reset', [self::class, 'clearWarning']);
        add_action('profile_update', [self::class, 'clearWarningIfChanged'], 10, 3);
    }

    public static function minLength(): int
    {
        $min = (int) get_option(self::OPTION_MIN, 0);

        return $min >= 8 && $min <= 64 ? $min : 0;
    }

    public static function checksBreaches(): bool
    {
        return get_option(self::OPTION_BREACHED, 'no') === 'yes';
    }

    /** Why this password is refused ('' when it is fine). Texts already translated. */
    public static function problem(string $password): string
    {
        $min = self::minLength();
        if ($min > 0 && mb_strlen($password) < $min) {
            /* translators: %d: minimum number of characters */
            return sprintf(__('The password must have at least %d characters.', 'draco-insomnis'), $min);
        }
        if (self::checksBreaches() && self::timesBreached($password) > 0) {
            return __('This password appears in known data breaches, so attackers try it first. Please choose another one.', 'draco-insomnis');
        }

        return '';
    }

    /** How many times the password appears in Have I Been Pwned; 0 when not found or the service did not answer. */
    public static function timesBreached(string $password): int
    {
        if ($password === '') {
            return 0;
        }
        $hash = strtoupper(sha1($password));
        $response = wp_remote_get(self::API . substr($hash, 0, 5), [
            'timeout' => 3,
            'headers' => ['Add-Padding' => 'true', 'User-Agent' => 'Draco-Insomnis'],
        ]);
        if (is_wp_error($response) || (int) wp_remote_retrieve_response_code($response) !== 200) {
            return 0;
        }
        $suffix = substr($hash, 5);
        foreach (preg_split('/\R/', (string) wp_remote_retrieve_body($response)) ?: [] as $line) {
            [$tail, $count] = array_pad(explode(':', trim($line), 2), 2, '0');
            if (hash_equals($suffix, strtoupper($tail))) {
                return (int) $count;
            }
        }

        return 0;
    }

    /** @param \WP_Error $errors */
    public static function onProfile($errors, $update, $user): void
    {
        $pass = isset($user->user_pass) && is_string($user->user_pass) ? $user->user_pass : '';
        // On update, user_pass is only set when a new password was typed.
        if ($pass !== '' && !($errors->has_errors()) && ($problem = self::problem($pass)) !== '') {
            $errors->add('draco_password', $problem);
        }
    }

    /** @param \WP_Error $errors */
    public static function onReset($errors, $user): void
    {
        $pass = isset($_POST['pass1']) && is_string($_POST['pass1']) ? (string) wp_unslash($_POST['pass1']) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- WordPress checked the reset key; a password is used as typed
        if ($pass !== '' && ($problem = self::problem($pass)) !== '') {
            $errors->add('draco_password', $problem);
        }
    }

    /** @param \WP_Error $errors @return \WP_Error */
    public static function onWooRegistration($errors, $username, $email)
    {
        $pass = isset($_POST['password']) && is_string($_POST['password']) ? (string) wp_unslash($_POST['password']) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- WooCommerce checked its nonce; a password is used as typed
        if ($pass !== '' && ($problem = self::problem($pass)) !== '') {
            $errors->add('draco_password', $problem);
        }

        return $errors;
    }

    /** At login the password is known: remember, without refusing, that it was breached. */
    public static function onLogin($login, $user): void
    {
        if (!self::checksBreaches() || !$user instanceof \WP_User) {
            return;
        }
        $pass = isset($_POST['pwd']) && is_string($_POST['pwd']) ? (string) wp_unslash($_POST['pwd']) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput -- the login form has no nonce; the password is only hashed
        if ($pass === '') {
            return;
        }
        if (self::timesBreached($pass) > 0) {
            update_user_meta($user->ID, self::META_WARN, time());
        } else {
            delete_user_meta($user->ID, self::META_WARN);
        }
    }

    public static function notice(): void
    {
        $id = get_current_user_id();
        if ($id === 0 || !get_user_meta($id, self::META_WARN, true)) {
            return;
        }
        echo '<div class="notice notice-error"><p><strong>' . esc_html__('Your password appears in known data breaches.', 'draco-insomnis') . '</strong> '
            . esc_html__('Attackers try those first. Change it now:', 'draco-insomnis')
            . ' <a href="' . esc_url(admin_url('profile.php#password')) . '">' . esc_html__('Change my password', 'draco-insomnis') . '</a></p></div>';
    }

    public static function clearWarning($user): void
    {
        if ($user instanceof \WP_User) {
            delete_user_meta($user->ID, self::META_WARN);
        }
    }

    public static function clearWarningIfChanged($userId, $old, $data = []): void
    {
        if ($old instanceof \WP_User && is_array($data) && isset($data['user_pass']) && $data['user_pass'] !== $old->user_pass) {
            delete_user_meta((int) $userId, self::META_WARN);
        }
    }
}
