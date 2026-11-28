<?php

declare(strict_types=1);

namespace DracoInsomnis\Login;

use DracoInsomnis\Input;
use DracoInsomnis\Mail\Template;
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
    /** The page a recovery mailbox opens to approve or reject a sign-in. */
    public const APPROVE = 'draco_cosign_approve';
    /** Approval e-mails per account and hour. */
    private const MAIL_PER_HOUR = 3;
    private const COOKIE = 'draco_cosign_cid';
    private const KEY = 'draco_cosign_';
    private const FAILS = 5;
    private const FAIL_WINDOW = 900;
    private const NEUTRAL = 'draco_cosign_fail';
    private const GRANT_COOKIE = 'draco_cosign_grant';
    /** Runs after every other authenticate filter (WordPress core, lockout and security plugins). */
    public const PRIORITY = PHP_INT_MAX - 1;

    /** The co-signature granted in this request (the cookie only arrives with the next one). */
    private static string $grant = '';

    public static function boot(): void
    {
        if (!self::active()) {
            return;
        }
        add_filter('authenticate', [self::class, 'atAuthenticate'], self::PRIORITY, 3);
        add_action('login_form_' . self::ACTION, [self::class, 'page']);
        add_action('login_form_' . self::APPROVE, [self::class, 'approvePage']);
    }

    /**
     * WordPress's own login, after all other checks: only a WP_User that WordPress and every other
     * plugin accepted gets here. Draco adds a step; it never logs anyone in by itself.
     *
     * @param \WP_User|\WP_Error|null $user
     * @param string $username
     * @param string $password
     * @return \WP_User|\WP_Error|null
     */
    public static function atAuthenticate($user, $username, $password)
    {
        return $user instanceof \WP_User ? self::afterPrimaryPassword($user, (string) $password) : $user;
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
        $ua = Input::server('HTTP_USER_AGENT');
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
        $info = '';
        if (Input::method() === 'POST') {
            check_admin_referer(self::ACTION);
            if ($row === null) {
                $errors->add('expired', __('The co-signature step has expired. Log in again.', 'draco-insomnis'));
            } elseif (self::blocked()) {
                $errors->add('locked', __('Too many attempts. Try again later.', 'draco-insomnis'));
            } elseif (Input::post('do') === 'mail') {
                if (self::requestApproval($token, $row, !empty($_POST['rememberme']))) {
                    $row = self::getChallenge($token);
                } else {
                    $errors->add('mail', __('The approval e-mail could not be sent. Wait a few minutes and try again.', 'draco-insomnis'));
                }
            } else {
                $login = sanitize_text_field(wp_unslash((string) ($_POST['log'] ?? '')));
                $password = (string) wp_unslash($_POST['pwd'] ?? ''); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- checked with wp_check_password
                if (self::verify($token, $row, $login, $password) === 'ok') {
                    self::proceed($token, $row, !empty($_POST['rememberme'])); // exits
                }
                self::recordFail();
                $errors->add(self::NEUTRAL, __('The co-signature could not be verified.', 'draco-insomnis'));
            }
        }
        $mail = $row !== null ? self::mailState($token) : null;
        if ($row !== null && $mail !== null && !$errors->has_errors()) {
            if ($mail['state'] === 'approved') {
                if (self::acceptMailApproval($token, $row)) {
                    self::proceed($token, $row, !empty($mail['remember'])); // exits
                }
                $row = null;
                $errors->add(self::NEUTRAL, __('The co-signature could not be verified.', 'draco-insomnis'));
            } elseif ($mail['state'] === 'denied') {
                self::auditFailure('COSIGN_MAIL_DENIED', $row['primary_user_id'], null, $row['auth_id']);
                self::setCookie('', time() - YEAR_IN_SECONDS);
                self::destroy($token);
                $row = null;
                $errors->add('denied', __('The sign-in was rejected from a recovery e-mail. Nobody was logged in.', 'draco-insomnis'));
            } elseif ($mail['state'] === 'pending') {
                $info = __('We sent a link to your recovery e-mails 2 and 3. Open it, check the details and press «Approve»: this page continues on its own.', 'draco-insomnis');
            }
        }
        if ($row === null && !$errors->has_errors()) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        $primary = $row !== null ? get_userdata($row['primary_user_id']) : null;
        $message = $primary instanceof \WP_User
            /* translators: %s: primary account login */
            ? sprintf(__('A second administrator must co-sign before %s can finish logging in.', 'draco-insomnis'), $primary->user_login)
            : '';
        if ($info !== '') {
            // While the approval is pending the page looks again by itself.
            add_action('login_head', static function (): void {
                echo '<meta http-equiv="refresh" content="5">';
            });
            $message = $info;
        }
        login_header(__('Administrator co-signature', 'draco-insomnis'), $message !== '' ? '<p class="message">' . esc_html($message) . '</p>' : '', $errors);
        if ($row !== null && $primary instanceof \WP_User) {
            $action = esc_url(add_query_arg('action', self::ACTION, site_url('wp-login.php', 'login_post')));
            $approvers = self::approvers((int) $primary->ID);
            $admins = self::otherAdmins((int) $primary->ID);
            if ($approvers !== [] && $info === '') {
                echo '<form name="dracocosignmail" id="loginform" action="' . $action . '" method="post">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                wp_nonce_field(self::ACTION);
                echo '<input type="hidden" name="do" value="mail">';
                echo '<p>' . esc_html__('Ask for approval by e-mail: a link goes to your recovery e-mails 2 and 3. Whoever reads them approves or rejects this sign-in; no other account is needed.', 'draco-insomnis') . '</p>';
                echo '<p class="forgetmenot"><label><input type="checkbox" name="rememberme" value="1"> ' . esc_html__('Remember me', 'draco-insomnis') . '</label></p>';
                echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__('Send the approval link', 'draco-insomnis') . '"></p></form>';
            }
            if ($admins > 0) {
                echo '<form name="dracocosign" id="loginform" action="' . $action . '" method="post"' . ($approvers !== [] ? ' style="margin-top:16px"' : '') . '>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
                wp_nonce_field(self::ACTION);
                if ($approvers !== []) {
                    echo '<p>' . esc_html__('Or another administrator co-signs here with their own password:', 'draco-insomnis') . '</p>';
                }
                echo '<p><label for="user_login">' . esc_html__('Co-signer username or e-mail', 'draco-insomnis') . '</label>'
                    . '<input type="text" name="log" id="user_login" class="input" autocomplete="username" required' . ($approvers === [] ? ' autofocus' : '') . '></p>';
                echo '<p><label for="user_pass">' . esc_html__('Co-signer password', 'draco-insomnis') . '</label>'
                    . '<input type="password" name="pwd" id="user_pass" class="input" autocomplete="current-password" required></p>';
                echo '<p class="forgetmenot"><label><input type="checkbox" name="rememberme" value="1"> ' . esc_html__('Remember me', 'draco-insomnis') . '</label></p>';
                echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__('Co-sign and continue', 'draco-insomnis') . '"></p></form>';
            }
            if ($approvers === [] && $admins === 0) {
                echo '<div id="login_error" class="notice notice-error">' . esc_html__('Nobody can co-sign this account: there is no other administrator and no recovery e-mail 2 or 3. Add define(\'DRACO_COSIGN_OFF\', true); to wp-config.php, log in, add the e-mails and remove the line.', 'draco-insomnis') . '</div>';
            }
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
        $ua = Input::server('HTTP_USER_AGENT');
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
        self::grant($primary, (int) $cosigner->ID, $authId, 0);
        $mfaRequired = Mfa::active() && Mfa::requiredFor($primary);
        self::auditSuccess($primary, $cosigner, $mfaRequired, false, $authId);

        return 'ok';
    }

    /**
     * The co-signature of $primaryId, only for the browser that went through it.
     *
     * @return array{cosigner_id: int, auth_id: string}|null
     */
    private static function grantRow(int $primaryId): ?array
    {
        $row = get_transient(self::KEY . 'ok_' . $primaryId);
        // Co-signed by an administrator (cosigner_id) or by a recovery mailbox (slot 2 or 3).
        if (!is_array($row) || ((int) ($row['cosigner_id'] ?? 0) <= 0 && (int) ($row['slot'] ?? 0) <= 0) || !is_string($row['grant'] ?? null)) {
            return null;
        }
        $presented = self::$grant !== '' ? self::$grant : (isset($_COOKIE[self::GRANT_COOKIE]) ? sanitize_key(wp_unslash((string) $_COOKIE[self::GRANT_COOKIE])) : '');
        if (preg_match('/^[a-f0-9]{32}$/', $presented) !== 1 || !hash_equals((string) $row['grant'], self::grantHash($presented))) {
            return null;
        }
        if ((string) ($row['ip'] ?? '') !== Guard::clientIp() || !hash_equals((string) ($row['ua_hash'] ?? ''), self::uaHash(Input::server('HTTP_USER_AGENT')))) {
            return null;
        }

        return ['cosigner_id' => (int) $row['cosigner_id'], 'auth_id' => (string) ($row['auth_id'] ?? '')];
    }

    public static function satisfiedFor(int $primaryId): bool
    {
        return self::grantRow($primaryId) !== null;
    }

    /** auth_id for the in-flight co-sign → MFA → session chain, or ''. */
    public static function authIdFor(int $primaryId): string
    {
        $row = self::grantRow($primaryId);

        return $row !== null ? $row['auth_id'] : '';
    }

    /** Called when MFA completes or fails so the one-shot grant cannot be reused. */
    public static function clearSatisfied(int $primaryId): void
    {
        delete_transient(self::KEY . 'ok_' . $primaryId);
        self::$grant = '';
        self::setGrantCookie('', time() - YEAR_IN_SECONDS);
    }

    /**
     * Ends the co-sign chain: login:session (linked by auth_id), then clear the one-shot flag.
     * Call immediately before wp_set_auth_cookie when Cosign was part of the login.
     */
    public static function markMfaCompleted(int $primaryId, ?bool $mfaCompleted = null): void
    {
        $row = self::grantRow($primaryId);
        if ($row === null) {
            return;
        }
        $cosignerId = $row['cosigner_id'];
        $authId = $row['auth_id'];
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

    /**
     * Co-signed (by an administrator or a recovery mailbox): on to the e-mail code, or the session.
     *
     * @param array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string} $row
     */
    private static function proceed(string $token, array $row, bool $remember): void
    {
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
            self::issueSession($primary, $authId, $remember);
            exit;
        }
        wp_safe_redirect(wp_login_url());
        exit;
    }

    /** @return array<int, string> recovery slot (2 or 3) => address: the mailboxes that may approve. */
    public static function approvers(int $userId): array
    {
        $emails = Recovery::emails($userId);
        $out = [];
        foreach ([1, 2] as $i) {
            if (isset($emails[$i])) {
                $out[$i + 1] = $emails[$i];
            }
        }

        return $out;
    }

    /** Administrators other than $userId (at most 1 is counted: only «any» matters). */
    public static function otherAdmins(int $userId): int
    {
        return count(get_users(['role' => 'administrator', 'exclude' => [$userId], 'fields' => 'ID', 'number' => 1]));
    }

    /** Whether $user can still log in once co-sign is on: another administrator, or recovery e-mail 2 or 3. */
    public static function reachableFor(\WP_User $user): bool
    {
        return self::otherAdmins((int) $user->ID) > 0 || self::approvers((int) $user->ID) !== [];
    }

    /** @return array{state: string, slot: int, remember: bool, ip: string, ua: string, sent_at: int, keys: list<string>}|null */
    private static function mailState(string $token): ?array
    {
        $raw = preg_match('/^[a-f0-9]{32}$/', $token) === 1 ? get_transient(self::KEY . $token) : false;

        return is_array($raw) && is_array($raw['mail'] ?? null) ? $raw['mail'] : null;
    }

    /**
     * Sends recovery e-mails 2 and 3 their own one-time link to approve or reject this sign-in.
     *
     * @param array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string} $row
     */
    public static function requestApproval(string $token, array $row, bool $remember): bool
    {
        $primary = get_userdata($row['primary_user_id']);
        $raw = get_transient(self::KEY . $token);
        if (!$primary instanceof \WP_User || !is_array($raw)) {
            return false;
        }
        $to = self::approvers((int) $primary->ID);
        $left = self::TTL - (time() - (int) $row['created_at']);
        if ($to === [] || $left < 60 || Store::bump(self::KEY . 'mail_' . (int) $primary->ID, HOUR_IN_SECONDS) > self::MAIL_PER_HOUR) {
            return false;
        }
        foreach ((array) ($raw['mail']['keys'] ?? []) as $old) {
            delete_transient(self::KEY . 'ap_' . $old);
        }
        $ip = Guard::clientIp();
        $ua = substr(Input::server('HTTP_USER_AGENT'), 0, 160);
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $title = __('Approve a sign-in', 'draco-insomnis');
        $keys = [];
        $sent = false;
        foreach ($to as $slot => $email) {
            $secret = bin2hex(random_bytes(16));
            $key = hash('sha256', $secret);
            $keys[] = $key;
            set_transient(self::KEY . 'ap_' . $key, ['token' => $token, 'slot' => $slot], $left);
            $url = add_query_arg(['action' => self::APPROVE, 't' => $secret], wp_login_url());
            /* translators: 1: account login, 2: site name */
            $who = sprintf(__('%1$s wants to sign in to %2$s and needs your approval.', 'draco-insomnis'), $primary->user_login, $site);
            /* translators: 1: IP address, 2: browser, 3: date and time (UTC) */
            $from = sprintf(__('From IP %1$s · %2$s · %3$s UTC', 'draco-insomnis'), $ip, $ua !== '' ? $ua : '-', gmdate('Y-m-d H:i'));
            $what = __('Open the link to approve or reject it. If you do not know about this sign-in, reject it: nobody gets in. Then change the password of the account.', 'draco-insomnis');
            $tail = __('The link works once and expires in 10 minutes. You receive it because this address is a recovery e-mail of the account.', 'draco-insomnis');
            $sent = Template::send($email, sprintf('[%s] %s', $site, $title), $who . "\n\n" . $from . "\n\n" . $what . "\n\n" . $url . "\n\n" . $tail, $title, [$who, $from, $what], [
                'tone' => 'orange', 'url' => $url, 'button' => __('Review the sign-in', 'draco-insomnis'), 'after' => [$tail],
            ]) || $sent;
        }
        $raw['mail'] = ['state' => 'pending', 'slot' => 0, 'remember' => $remember, 'ip' => $ip, 'ua' => $ua, 'sent_at' => time(), 'keys' => $keys];
        set_transient(self::KEY . $token, $raw, $left);
        self::auditEndpoint('login:cosign_mail', $primary, ['auth_id' => (string) $row['auth_id'], 'slots' => implode(',', array_keys($to)), 'sent' => $sent, 'timestamp' => time()]);

        return $sent;
    }

    /**
     * The link from the e-mail. Opening it only shows the details (mail scanners open links too);
     * the decision is a button.
     */
    public static function approvePage(): void
    {
        $secret = isset($_REQUEST['t']) ? sanitize_key(wp_unslash((string) $_REQUEST['t'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- the secret in the link is the credential
        $found = self::approval($secret);
        $errors = new \WP_Error();
        $done = '';
        if ($found !== null && Input::method() === 'POST') {
            $done = self::decide($secret, Input::post('choice'));
        }
        if ($found === null || ($done === '' && Input::method() === 'POST')) {
            $errors->add('gone', __('This link has expired or was already used.', 'draco-insomnis'));
        }
        login_header(__('Approve a sign-in', 'draco-insomnis'), '', $errors);
        if ($done === 'approve') {
            echo '<p class="message">' . esc_html__('Approved. The sign-in continues on the device that asked for it.', 'draco-insomnis') . '</p>';
        } elseif ($done === 'deny') {
            echo '<p class="message">' . esc_html__('Rejected. Nobody was logged in. If you did not expect this, change the password of the account.', 'draco-insomnis') . '</p>';
        } elseif (!$errors->has_errors() && $found !== null) {
            $mail = $found['mail'];
            $primary = $found['primary'];
            $action = esc_url(add_query_arg('action', self::APPROVE, site_url('wp-login.php', 'login_post')));
            echo '<form id="loginform" action="' . $action . '" method="post">'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo '<input type="hidden" name="t" value="' . esc_attr($secret) . '">';
            /* translators: %s: account login */
            echo '<p>' . esc_html(sprintf(__('%s is trying to sign in.', 'draco-insomnis'), $primary->user_login)) . '</p>';
            echo '<p style="margin:12px 0;color:#50575e">IP ' . esc_html((string) $mail['ip']) . '<br>' . esc_html((string) $mail['ua']) . '<br>' . esc_html(gmdate('Y-m-d H:i', (int) $mail['sent_at'])) . ' UTC</p>';
            echo '<p class="submit" style="display:flex;gap:8px;justify-content:space-between"><button type="submit" name="choice" value="deny" class="button button-large">' . esc_html__('It was not me', 'draco-insomnis') . '</button>'
                . '<button type="submit" name="choice" value="approve" class="button button-primary button-large">' . esc_html__('Approve', 'draco-insomnis') . '</button></p></form>';
        }
        login_footer();
        exit;
    }

    /**
     * The pending sign-in behind an e-mail link, or null when the link is unknown, used or expired.
     *
     * @return array{key: string, token: string, slot: int, raw: array<string, mixed>, mail: array<string, mixed>, primary: \WP_User}|null
     */
    private static function approval(string $secret): ?array
    {
        if (preg_match('/^[a-f0-9]{32}$/', $secret) !== 1) {
            return null;
        }
        $key = hash('sha256', $secret);
        $link = get_transient(self::KEY . 'ap_' . $key);
        $token = is_array($link) ? (string) ($link['token'] ?? '') : '';
        $raw = preg_match('/^[a-f0-9]{32}$/', $token) === 1 ? get_transient(self::KEY . $token) : false;
        if (!is_array($raw) || !is_array($raw['mail'] ?? null) || ($raw['mail']['state'] ?? '') !== 'pending' || !in_array($key, (array) ($raw['mail']['keys'] ?? []), true)) {
            return null;
        }
        $primary = get_userdata((int) ($raw['primary_user_id'] ?? 0));

        return $primary instanceof \WP_User ? ['key' => $key, 'token' => $token, 'slot' => (int) ($link['slot'] ?? 0), 'raw' => $raw, 'mail' => $raw['mail'], 'primary' => $primary] : null;
    }

    /** Approve or reject from an e-mail link: returns $choice, or '' when the link no longer holds. Every link of that sign-in is spent. */
    public static function decide(string $secret, string $choice): string
    {
        $found = self::approval($secret);
        if ($found === null || ($choice !== 'approve' && $choice !== 'deny')) {
            return '';
        }
        $raw = $found['raw'];
        $raw['mail']['state'] = $choice === 'approve' ? 'approved' : 'denied';
        $raw['mail']['slot'] = $found['slot'];
        foreach ((array) $raw['mail']['keys'] as $k) {
            delete_transient(self::KEY . 'ap_' . $k);
        }
        set_transient(self::KEY . $found['token'], $raw, max(1, self::TTL - (time() - (int) ($raw['created_at'] ?? 0))));

        return $choice;
    }

    /**
     * The approval holds only in the browser that asked for it (same IP and browser as the challenge).
     *
     * @param array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string} $row
     */
    private static function acceptMailApproval(string $token, array $row): bool
    {
        $mail = self::mailState($token);
        $primary = get_userdata($row['primary_user_id']);
        if ($mail === null || $mail['state'] !== 'approved' || !$primary instanceof \WP_User) {
            return false;
        }
        if ($row['ip'] !== Guard::clientIp() || !hash_equals($row['ua_hash'], self::uaHash(Input::server('HTTP_USER_AGENT')))) {
            self::auditFailure('SYSTEM_ERROR', $row['primary_user_id'], null, $row['auth_id']);
            self::destroy($token);

            return false;
        }
        $slot = (int) $mail['slot'];
        self::grant($primary, 0, $row['auth_id'], $slot);
        $ip = Guard::clientIp();
        Store::ensureTables();
        Store::log($ip, $ip, 'login:cosign_success', ['score' => 0, 'verdict' => 'human', 'reasons' => ['cosign_mail']], substr(Input::server('HTTP_USER_AGENT'), 0, 255), [
            'auth_id' => $row['auth_id'],
            'primary_user_id' => (int) $primary->ID,
            'primary_email' => (string) $primary->user_email,
            'cosigner_user_id' => 0,
            'cosigner_email' => (string) (self::approvers((int) $primary->ID)[$slot] ?? ''),
            'timestamp' => time(),
            'mfa_required' => Mfa::active() && Mfa::requiredFor($primary),
            'mfa_completed' => false,
            'recovery_slot' => $slot,
            'username' => $primary->user_login,
            'email' => (string) $primary->user_email,
        ]);

        return true;
    }

    /**
     * Satisfied for this login attempt only: the grant is a secret held by this browser (cookie),
     * bound to its IP and user agent. Another login with the same password, elsewhere, does not
     * see it and must be co-signed on its own. $slot: the recovery e-mail that approved, 0 for an administrator.
     */
    private static function grant(\WP_User $primary, int $cosignerId, string $authId, int $slot): void
    {
        $grant = bin2hex(random_bytes(16));
        set_transient(self::KEY . 'ok_' . (int) $primary->ID, [
            'cosigner_id' => $cosignerId,
            'slot' => $slot,
            'auth_id' => $authId,
            'grant' => self::grantHash($grant),
            'ip' => Guard::clientIp(),
            'ua_hash' => self::uaHash(Input::server('HTTP_USER_AGENT')),
        ], Challenge::TTL);
        self::$grant = $grant;
        self::setGrantCookie($grant, time() + Challenge::TTL);
    }

    /** @param array<string, mixed> $fields */
    public static function auditEndpoint(string $endpoint, \WP_User $primary, array $fields): void
    {
        $ip = Guard::clientIp();
        $ua = Input::server('HTTP_USER_AGENT');
        Store::ensureTables();
        $fields['username'] = $primary->user_login;
        $fields['email'] = (string) $primary->user_email;
        Store::log($ip, $ip, $endpoint, ['score' => 0, 'verdict' => 'human', 'reasons' => ['ok']], substr($ua, 0, 255), $fields);
    }

    private static function auditSuccess(\WP_User $primary, \WP_User $cosigner, bool $mfaRequired, bool $mfaCompleted, string $authId): void
    {
        $ip = Guard::clientIp();
        $ua = Input::server('HTTP_USER_AGENT');
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
        $ua = Input::server('HTTP_USER_AGENT');
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

    private static function grantHash(string $grant): string
    {
        return hash_hmac('sha256', 'grant|' . $grant, wp_salt('auth'));
    }

    private static function setGrantCookie(string $value, int $expires): void
    {
        if (!headers_sent()) {
            setcookie(self::GRANT_COOKIE, $value, ['expires' => $expires, 'path' => COOKIEPATH ?: '/', 'domain' => COOKIE_DOMAIN ?: '', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Strict']);
        }
    }

    private static function setCookie(string $value, int $expires): void
    {
        if (!headers_sent()) {
            setcookie(self::COOKIE, $value, ['expires' => $expires, 'path' => COOKIEPATH ?: '/', 'domain' => COOKIE_DOMAIN ?: '', 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax']);
        }
    }
}
