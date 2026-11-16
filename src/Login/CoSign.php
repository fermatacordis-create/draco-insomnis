<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Second-administrator co-signature before MFA: session belongs only to the primary account.
 *
 * Trust Device ≠ Trusted Login: a trusted cookie never skips this step. Password A, Password B
 * and CoSign stay mandatory; only the MFA e-mail code may be omitted.
 *
 * Audit chain (same auth_id): login:cosign_success → login:mfa → login:session
 * (trusted device: login:cosign_success → login:session, no login:mfa). Failures keep auth_id.
 *
 * Emergency exit: define('DRACO_COSIGN_OFF', true); in wp-config.php.
 */
final class CoSign
{
    public const OPTION_ENABLED = 'draco_cosign_enabled';
    public const ACTION = 'draco_cosign';
    public const TTL = 600;
    private const COOKIE = 'draco_cosign_cid';
    private const KEY = 'draco_cosign_';
    private const FAILS = 5;
    private const FAIL_WINDOW = 900;
    private const NEUTRAL = 'draco_cosign_fail';

    public static function boot(): void
    {
        if (!self::active()) {
            return;
        }
        add_filter('wp_authenticate_user', [self::class, 'afterPrimaryPassword'], 99, 2);
        add_action('login_form_' . self::ACTION, [self::class, 'page']);
    }

    public static function active(): bool
    {
        return get_option(self::OPTION_ENABLED, 'no') === 'yes' && !(defined('DRACO_COSIGN_OFF') && DRACO_COSIGN_OFF);
    }

    public static function requiredFor(\WP_User $user): bool
    {
        $required = user_can($user, 'manage_options');

        return (bool) apply_filters('draco_insomnis_cosign_required', $required, $user);
    }

    /**
     * @param \WP_User|\WP_Error $user
     * @param string $password
     * @return \WP_User|\WP_Error
     */
    public static function afterPrimaryPassword($user, $password)
    {
        if (!$user instanceof \WP_User || !self::active() || !self::requiredFor($user)) {
            return $user;
        }
        if (!wp_check_password((string) $password, (string) $user->user_pass, (int) $user->ID)) {
            return $user;
        }
        if (self::satisfiedFor((int) $user->ID)) {
            return $user;
        }
        if (wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)) {
            /* translators: %s: login page URL */
            return new \WP_Error('draco_cosign_page', sprintf(__('This account needs a second administrator to co-sign. Log in from %s.', 'draco-insomnis'), wp_login_url()));
        }
        $token = self::createChallenge($user);
        self::setCookie($token, time() + self::TTL);
        $to = isset($_REQUEST['redirect_to']) && is_string($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification
        Challenge::setRedirect((int) $user->ID, $to);
        wp_safe_redirect(add_query_arg('action', self::ACTION, wp_login_url()));
        exit;
    }

    public static function createChallenge(\WP_User $primary): string
    {
        $token = bin2hex(random_bytes(16));
        $ip = Guard::clientIp();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        set_transient(self::KEY . $token, [
            'primary_user_id' => (int) $primary->ID,
            'auth_id' => self::newAuthId(),
            'created_at' => time(),
            'ip' => $ip,
            'ua_hash' => self::uaHash($ua),
        ], self::TTL);

        return $token;
    }

    /** @return array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string}|null */
    public static function getChallenge(string $token): ?array
    {
        if (preg_match('/^[a-f0-9]{32}$/', $token) !== 1) {
            return null;
        }
        $row = get_transient(self::KEY . $token);
        if (!is_array($row) || empty($row['primary_user_id']) || time() - (int) ($row['created_at'] ?? 0) > self::TTL) {
            if (is_array($row)) {
                self::auditFailure('COSIGN_TIMEOUT', (int) ($row['primary_user_id'] ?? 0), null, (string) ($row['auth_id'] ?? ''));
                self::destroy($token);
            }

            return null;
        }

        return [
            'primary_user_id' => (int) $row['primary_user_id'],
            'auth_id' => (string) ($row['auth_id'] ?? ''),
            'created_at' => (int) $row['created_at'],
            'ip' => (string) $row['ip'],
            'ua_hash' => (string) $row['ua_hash'],
        ];
    }

    public static function destroy(string $token): void
    {
        delete_transient(self::KEY . $token);
        delete_transient(self::KEY . 'ok_' . $token);
    }

    public static function page(): void
    {
        $errors = new \WP_Error();
        $token = isset($_COOKIE[self::COOKIE]) ? sanitize_key(wp_unslash((string) $_COOKIE[self::COOKIE])) : '';
        $row = self::getChallenge($token);
        if (Input::method() === 'POST') {
            check_admin_referer(self::ACTION);
            if ($row === null) {
                $errors->add('expired', __('The co-signature step has expired. Log in again.', 'draco-insomnis'));
            } elseif (self::blocked()) {
                $errors->add('locked', __('Too many attempts. Try again later.', 'draco-insomnis'));
            } else {
                $login = sanitize_text_field(wp_unslash((string) ($_POST['log'] ?? '')));
                $password = (string) wp_unslash($_POST['pwd'] ?? ''); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- checked with wp_check_password
                $result = self::verify($token, $row, $login, $password);
                if ($result === 'ok') {
                    $primary = get_userdata($row['primary_user_id']);
                    $authId = (string) ($row['auth_id'] ?? '');
                    self::setCookie('', time() - YEAR_IN_SECONDS);
                    self::destroy($token);
                    if ($primary instanceof \WP_User) {
                        $mfaOn = Mfa::active() && Mfa::requiredFor($primary);
                        $trustOk = get_option(Mfa::OPTION_TRUST, 'yes') === 'yes' && TrustedDevice::isValid((int) $primary->ID);
                        if ($mfaOn && !$trustOk) {
                            Mfa::beginChallenge($primary, $authId); // exits — login:mfa then code step
                        }
                        // MFA off or trusted device: no login:mfa; session of A only.
                        self::issueSession($primary, $authId, !empty($_POST['rememberme']));
                        exit;
                    }
                }
                self::recordFail();
                $errors->add(self::NEUTRAL, __('The co-signature could not be verified.', 'draco-insomnis'));
            }
        }
        if ($row === null && !$errors->has_errors()) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        $primary = $row !== null ? get_userdata($row['primary_user_id']) : null;
        /* translators: %s: primary account login */
        $message = $primary instanceof \WP_User
            ? sprintf(__('A second administrator must co-sign before %s can finish logging in.', 'draco-insomnis'), $primary->user_login)
            : '';
        login_header(__('Administrator co-signature', 'draco-insomnis'), $message !== '' ? '<p class="message">' . esc_html($message) . '</p>' : '', $errors);
        if ($row !== null) {
            $action = esc_url(add_query_arg('action', self::ACTION, site_url('wp-login.php', 'login_post')));
            echo '<form name="dracocosign" id="loginform" action="' . $action . '" method="post">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            wp_nonce_field(self::ACTION);
            echo '<p><label for="user_login">' . esc_html__('Co-signer username or e-mail', 'draco-insomnis') . '</label>'
                . '<input type="text" name="log" id="user_login" class="input" autocomplete="username" required autofocus></p>';
            echo '<p><label for="user_pass">' . esc_html__('Co-signer password', 'draco-insomnis') . '</label>'
                . '<input type="password" name="pwd" id="user_pass" class="input" autocomplete="current-password" required></p>';
            echo '<p class="forgetmenot"><label><input type="checkbox" name="rememberme" value="1"> ' . esc_html__('Remember me', 'draco-insomnis') . '</label></p>';
            echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__('Co-sign and continue', 'draco-insomnis') . '"></p></form>';
        }
        echo '<p id="backtoblog"><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('← Back to log in', 'draco-insomnis') . '</a></p>';
        login_footer();
        exit;
    }

    /**
     * @param array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string} $row
     */
    private static function verify(string $token, array $row, string $login, string $password): string
    {
        $authId = (string) ($row['auth_id'] ?? '');
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        if ($row['ip'] !== Guard::clientIp() || !hash_equals($row['ua_hash'], self::uaHash($ua))) {
            self::auditFailure('SYSTEM_ERROR', $row['primary_user_id'], null, $authId);
            self::destroy($token);

            return 'bad';
        }
        $primary = get_userdata($row['primary_user_id']);
        if (!$primary instanceof \WP_User) {
            self::auditFailure('PRIMARY_INVALID', $row['primary_user_id'], null, $authId);
            self::destroy($token);

            return 'bad';
        }
        $cosigner = is_email($login) ? get_user_by('email', $login) : get_user_by('login', $login);
        if (!$cosigner instanceof \WP_User) {
            self::auditFailure('COSIGNER_NOT_FOUND', $row['primary_user_id'], null, $authId);

            return 'bad';
        }
        if ((int) $cosigner->ID === (int) $primary->ID) {
            self::auditFailure('COSIGNER_EQUALS_PRIMARY', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        // Interactive password only — never Application Password / API token / service credential.
        if (self::isApplicationPassword($cosigner, $password)) {
            self::auditFailure('COSIGNER_SERVICE_ACCOUNT', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        if (!wp_check_password($password, (string) $cosigner->user_pass, (int) $cosigner->ID)) {
            self::auditFailure('COSIGNER_INVALID_PASSWORD', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        if (!user_can($cosigner, 'manage_options')) {
            self::auditFailure('COSIGNER_NOT_ADMIN', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        if (AccountLock::active() && !AccountLock::approved($cosigner)) {
            self::auditFailure('COSIGNER_NOT_APPROVED', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        /**
         * Return true when the account must never be accepted as a human co-signer.
         *
         * @param bool     $isService Default false.
         * @param \WP_User $cosigner  Candidate co-signer.
         */
        $isService = (bool) apply_filters('draco_insomnis_cosign_service_account', false, $cosigner);
        if ($isService) {
            self::auditFailure('COSIGNER_SERVICE_ACCOUNT', $row['primary_user_id'], $cosigner, $authId);

            return 'bad';
        }
        // Mark satisfied for this request chain so MFA / trust can proceed without looping.
        set_transient(self::KEY . 'ok_' . (int) $primary->ID, [
            'cosigner_id' => (int) $cosigner->ID,
            'auth_id' => $authId,
        ], 120);
        $mfaRequired = Mfa::active() && Mfa::requiredFor($primary);
        self::auditSuccess($primary, $cosigner, $mfaRequired, false, $authId);

        return 'ok';
    }

    public static function satisfiedFor(int $primaryId): bool
    {
        $row = get_transient(self::KEY . 'ok_' . $primaryId);

        return is_array($row) ? (int) ($row['cosigner_id'] ?? 0) > 0 : (int) $row > 0;
    }

    /** auth_id for the in-flight co-sign → MFA → session chain, or ''. */
    public static function authIdFor(int $primaryId): string
    {
        $row = get_transient(self::KEY . 'ok_' . $primaryId);
        if (is_array($row)) {
            return (string) ($row['auth_id'] ?? '');
        }

        return '';
    }

    /** Called when MFA completes so the one-shot flag cannot be reused. */
    public static function clearSatisfied(int $primaryId): void
    {
        delete_transient(self::KEY . 'ok_' . $primaryId);
    }

    /**
     * Ends the co-sign chain: login:session (linked by auth_id), then clear the one-shot flag.
     * Call immediately before wp_set_auth_cookie when Cosign was part of the login.
     */
    public static function markMfaCompleted(int $primaryId, ?bool $mfaCompleted = null): void
    {
        $row = get_transient(self::KEY . 'ok_' . $primaryId);
        $cosignerId = is_array($row) ? (int) ($row['cosigner_id'] ?? 0) : (int) $row;
        $authId = is_array($row) ? (string) ($row['auth_id'] ?? '') : '';
        if ($cosignerId <= 0) {
            return;
        }
        $primary = get_userdata($primaryId);
        if ($primary instanceof \WP_User) {
            $mfaRequired = Mfa::active() && Mfa::requiredFor($primary);
            $done = $mfaCompleted ?? $mfaRequired;
            self::auditEndpoint('login:session', $primary, [
                'auth_id' => $authId,
                'user_id' => (int) $primary->ID,
                'primary_user_id' => (int) $primary->ID,
                'cosigner_user_id' => $cosignerId,
                'mfa_required' => $mfaRequired,
                'mfa_completed' => $done,
                'timestamp' => time(),
            ]);
        }
        self::clearSatisfied($primaryId);
    }

    /** login:session then WordPress cookie for the primary account only. */
    public static function issueSession(\WP_User $primary, string $authId, bool $remember): void
    {
        if (self::satisfiedFor((int) $primary->ID)) {
            self::markMfaCompleted((int) $primary->ID, Mfa::active() && Mfa::requiredFor($primary) && TrustedDevice::isValid((int) $primary->ID));
        } elseif ($authId !== '') {
            self::auditEndpoint('login:session', $primary, [
                'auth_id' => $authId,
                'user_id' => (int) $primary->ID,
                'primary_user_id' => (int) $primary->ID,
                'timestamp' => time(),
            ]);
        }
        wp_set_current_user((int) $primary->ID);
        wp_set_auth_cookie((int) $primary->ID, $remember, is_ssl());
        do_action('wp_login', $primary->user_login, $primary); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
        $to = Challenge::takeRedirect((int) $primary->ID);
        wp_safe_redirect($to !== '' ? $to : admin_url());
    }

    /** @param array<string, mixed> $fields */
    public static function auditEndpoint(string $endpoint, \WP_User $primary, array $fields): void
    {
        $ip = Guard::clientIp();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        Store::ensureTables();
        $fields['username'] = $primary->user_login;
        $fields['email'] = (string) $primary->user_email;
        Store::log($ip, $ip, $endpoint, ['score' => 0, 'verdict' => 'human', 'reasons' => ['ok']], substr($ua, 0, 255), $fields);
    }

    private static function auditSuccess(\WP_User $primary, \WP_User $cosigner, bool $mfaRequired, bool $mfaCompleted, string $authId): void
    {
        $ip = Guard::clientIp();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        Store::ensureTables();
        Store::log($ip, $ip, 'login:cosign_success', ['score' => 0, 'verdict' => 'human', 'reasons' => ['cosign_ok']], substr($ua, 0, 255), [
            'auth_id' => $authId,
            'primary_user_id' => (int) $primary->ID,
            'primary_email' => (string) $primary->user_email,
            'cosigner_user_id' => (int) $cosigner->ID,
            'cosigner_email' => (string) $cosigner->user_email,
            'timestamp' => time(),
            'mfa_required' => $mfaRequired,
            'mfa_completed' => $mfaCompleted,
            'recovery_slot' => 0,
            'username' => $primary->user_login,
            'email' => (string) $primary->user_email,
        ]);
    }

    private static function auditFailure(string $reason, int $primaryId, ?\WP_User $cosigner = null, string $authId = ''): void
    {
        $ip = Guard::clientIp();
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        Store::ensureTables();
        Store::log($ip, $ip, 'login:cosign_failure', ['score' => 0, 'verdict' => 'bot', 'reasons' => [$reason]], substr($ua, 0, 255), [
            'auth_id' => $authId,
            'primary_user_id' => $primaryId,
            'cosigner_user_id' => $cosigner instanceof \WP_User ? (int) $cosigner->ID : 0,
            'cosigner_email' => $cosigner instanceof \WP_User ? (string) $cosigner->user_email : '',
            'timestamp' => time(),
            'reason' => $reason,
            'username' => $cosigner instanceof \WP_User ? $cosigner->user_login : '',
            'email' => $cosigner instanceof \WP_User ? (string) $cosigner->user_email : '',
        ]);
    }

    private static function newAuthId(): string
    {
        if (function_exists('wp_generate_uuid4')) {
            return (string) wp_generate_uuid4();
        }

        return bin2hex(random_bytes(16));
    }

    /** True when the submitted secret is a WordPress application password (API), not the interactive login password. */
    private static function isApplicationPassword(\WP_User $user, string $password): bool
    {
        if ($password === '' || !function_exists('wp_is_application_passwords_available') || !wp_is_application_passwords_available()) {
            return false;
        }
        if (!function_exists('wp_authenticate_application_password')) {
            return false;
        }
        $via = wp_authenticate_application_password(null, $user->user_login, $password);

        return $via instanceof \WP_User;
    }

    private static function recordFail(): void
    {
        $key = 'draco_cosign_fail_' . md5(Guard::clientIp());
        if (Store::bump($key, self::FAIL_WINDOW) >= self::FAILS) {
            set_transient('draco_cosign_block_' . md5(Guard::clientIp()), 1, self::FAIL_WINDOW);
        }
    }

    private static function blocked(): bool
    {
        return (bool) get_transient('draco_cosign_block_' . md5(Guard::clientIp()));
    }

    private static function uaHash(string $ua): string
    {
        return hash_hmac('sha256', $ua, wp_salt('auth'));
    }

    private static function setCookie(string $value, int $expires): void
    {
        if (!headers_sent()) {
            setcookie(self::COOKIE, $value, ['expires' => $expires, 'path' => COOKIEPATH ?: '/', 'domain' => COOKIE_DOMAIN ?: '', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']);
        }
    }
}
