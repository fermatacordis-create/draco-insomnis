<?php

declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Login\AccountLock;
use DracoInsomnis\Login\Challenge;
use DracoInsomnis\Login\CoSign;
use DracoInsomnis\Login\Mfa;
use DracoInsomnis\Login\Recovery;
use DracoInsomnis\Login\TrustedDevice;
use DracoInsomnis\Shield\Store;

final class CoSignTest extends TestCase
{
    private \WP_User $adminA;
    private \WP_User $adminB;

    protected function setUp(): void
    {
        parent::setUp();
        $this->adminA = $this->user('administrator', 'admin-a-' . bin2hex(random_bytes(2)) . '@example.org');
        $this->adminB = $this->user('administrator', 'admin-b-' . bin2hex(random_bytes(2)) . '@example.org');
        update_option(CoSign::OPTION_ENABLED, 'yes');
        update_option(Mfa::OPTION_ENABLED, 'no');
        wp_set_current_user(0);
        CoSign::boot();
        Mfa::boot();
    }

    /** @return array{primary_user_id: int, auth_id: string, created_at: int, ip: string, ua_hash: string, token: string} */
    private function challenge(): array
    {
        $token = CoSign::createChallenge($this->adminA);
        $row = CoSign::getChallenge($token);
        $this->assertNotNull($row);

        return $row + ['token' => $token];
    }

    private function verify(string $token, array $row, string $login, string $password): string
    {
        $m = new \ReflectionMethod(CoSign::class, 'verify');
        $m->setAccessible(true);

        return (string) $m->invoke(null, $token, $row, $login, $password);
    }

    /** @return array<string, mixed> */
    private function fields(string $endpoint): array
    {
        $events = Store::recentWhere($endpoint);
        $this->assertNotEmpty($events, $endpoint);

        return json_decode((string) ($events[0]['fields'] ?? '{}'), true) ?: [];
    }

    private function assertNoSession(): void
    {
        $this->assertSame(0, get_current_user_id());
        $this->assertFalse(is_user_logged_in());
        $this->assertSame([], Store::recentWhere('login:session'));
    }

    /** Recovery e-mails 1, 2 and 3 of admin A. */
    private function recoveryMailboxes(int $count = 3): void
    {
        update_user_meta($this->adminA->ID, Recovery::META_LIST, array_slice(['r1@example.org', 'r2@example.org', 'r3@example.org'], 0, $count));
    }

    /** The secret of the approval link sent to $email. */
    private function linkSentTo(string $email): string
    {
        $mails = $this->mailsTo($email);
        $this->assertCount(1, $mails, 'one approval mail to ' . $email);
        $this->assertSame(1, preg_match('/[?&;]t=([a-f0-9]{32})/', html_entity_decode($mails[0]['message']), $m), 'no approval link in the mail');

        return $m[1];
    }

    private function acceptMail(string $token, array $row): bool
    {
        $m = new \ReflectionMethod(CoSign::class, 'acceptMailApproval');
        $m->setAccessible(true);

        return (bool) $m->invoke(null, $token, $row);
    }

    public function test_recovery_mailboxes_2_and_3_approve_the_browser_that_asked(): void
    {
        $this->recoveryMailboxes();
        $c = $this->challenge();
        $this->assertTrue(CoSign::requestApproval($c['token'], $c, false));
        $this->assertSame([], $this->mailsTo('r1@example.org'), 'recovery e-mail 1 is for codes, not approvals');
        $two = $this->linkSentTo('r2@example.org');
        $three = $this->linkSentTo('r3@example.org');
        $this->assertNotSame($two, $three, 'each mailbox has its own link');
        $this->assertFalse($this->acceptMail($c['token'], $c), 'nothing approved yet');

        $this->assertSame('', CoSign::decide(str_repeat('b', 32), 'approve'), 'a guessed link does nothing');
        $this->assertSame('approve', CoSign::decide($three, 'approve'));
        $this->assertSame('', CoSign::decide($two, 'deny'), 'the other link is spent');
        $this->assertSame('', CoSign::decide($three, 'approve'), 'a link works once');

        $this->assertTrue($this->acceptMail($c['token'], $c));
        $this->assertTrue(CoSign::satisfiedFor($this->adminA->ID));
        $f = $this->fields('login:cosign_success');
        $this->assertSame(3, $f['recovery_slot'] ?? 0);
        $this->assertSame('r3@example.org', $f['cosigner_email'] ?? '');
        $this->assertSame($c['auth_id'], $f['auth_id'] ?? '');
        $this->assertNoSession();
        CoSign::clearSatisfied($this->adminA->ID);
    }

    public function test_a_rejection_from_the_mailbox_stops_the_sign_in(): void
    {
        $this->recoveryMailboxes();
        $c = $this->challenge();
        $this->assertTrue(CoSign::requestApproval($c['token'], $c, false));
        $this->assertSame('deny', CoSign::decide($this->linkSentTo('r2@example.org'), 'deny'));
        $this->assertFalse($this->acceptMail($c['token'], $c));
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertNoSession();
    }

    public function test_an_approval_does_not_travel_to_another_address(): void
    {
        $this->recoveryMailboxes();
        $c = $this->challenge();
        $this->assertTrue(CoSign::requestApproval($c['token'], $c, false));
        $this->assertSame('approve', CoSign::decide($this->linkSentTo('r2@example.org'), 'approve'));
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $_SERVER['REMOTE_ADDR'] = '203.0.113.99';
        $this->assertFalse($this->acceptMail($c['token'], $c), 'approved, but asked from another address');
        if ($ip === null) {
            unset($_SERVER['REMOTE_ADDR']);
        } else {
            $_SERVER['REMOTE_ADDR'] = $ip;
        }
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertNull(CoSign::getChallenge($c['token']), 'the challenge is gone');
    }

    public function test_mail_approval_needs_recovery_2_or_3_and_cosign_needs_someone(): void
    {
        $this->recoveryMailboxes(1);
        $c = $this->challenge();
        $this->assertSame([], CoSign::approvers($this->adminA->ID));
        $this->assertFalse(CoSign::requestApproval($c['token'], $c, false));
        $this->assertSame([], $this->mails);
        $this->assertTrue(CoSign::reachableFor($this->adminA), 'admin B can still co-sign');
        require_once ABSPATH . 'wp-admin/includes/user.php';
        wp_delete_user($this->adminB->ID);
        $this->assertFalse(CoSign::reachableFor($this->adminA), 'alone and without recovery 2 or 3');
        $this->recoveryMailboxes(2);
        $this->assertSame([2 => 'r2@example.org'], CoSign::approvers($this->adminA->ID));
        $this->assertTrue(CoSign::reachableFor($this->adminA));
    }

    public function test_approval_mails_are_limited_per_hour(): void
    {
        $this->recoveryMailboxes();
        $c = $this->challenge();
        for ($i = 0; $i < 3; $i++) {
            $this->assertTrue(CoSign::requestApproval($c['token'], $c, false), 'request ' . ($i + 1));
        }
        $this->assertFalse(CoSign::requestApproval($c['token'], $c, false), 'the fourth in an hour');
    }

    public function test_challenge_is_bound_to_primary_and_expires_from_lookup(): void
    {
        $token = CoSign::createChallenge($this->adminA);
        $row = CoSign::getChallenge($token);
        $this->assertNotNull($row);
        $this->assertSame($this->adminA->ID, $row['primary_user_id']);
        $this->assertNotSame('', $row['auth_id'] ?? '');
        CoSign::destroy($token);
        $this->assertNull(CoSign::getChallenge($token));
    }

    public function test_cosigner_must_be_different_user(): void
    {
        $c = $this->challenge();
        $this->assertSame('bad', $this->verify($c['token'], $c, $this->adminA->user_login, 'Long-Pass-123!'));
        $this->assertSame('COSIGNER_EQUALS_PRIMARY', $this->fields('login:cosign_failure')['reason'] ?? '');
        $this->assertNoSession();
    }

    public function test_cosigner_must_be_admin(): void
    {
        $editor = $this->user('editor');
        $c = $this->challenge();
        $this->assertSame('bad', $this->verify($c['token'], $c, $editor->user_login, 'Long-Pass-123!'));
        $this->assertSame('COSIGNER_NOT_ADMIN', $this->fields('login:cosign_failure')['reason'] ?? '');
        $this->assertNoSession();
    }

    public function test_cosigner_must_be_approved_when_lock_enabled(): void
    {
        wp_set_current_user($this->adminA->ID);
        AccountLock::enable($this->adminA);
        wp_set_current_user(0);
        $c = $this->challenge();
        $this->assertFalse(AccountLock::approved($this->adminB));
        $this->assertSame('bad', $this->verify($c['token'], $c, $this->adminB->user_login, 'Long-Pass-123!'));
        $this->assertSame('COSIGNER_NOT_APPROVED', $this->fields('login:cosign_failure')['reason'] ?? '');
        $this->assertNoSession();
        AccountLock::disable();
    }

    public function test_auth_id_links_cosign_mfa_session(): void
    {
        $c = $this->challenge();
        $authId = (string) $c['auth_id'];
        $this->assertSame('ok', $this->verify($c['token'], $c, $this->adminB->user_email, 'Long-Pass-123!'));
        $this->assertSame($authId, $this->fields('login:cosign_success')['auth_id'] ?? '');

        CoSign::auditEndpoint('login:mfa', $this->adminA, [
            'auth_id' => $authId,
            'user_id' => (int) $this->adminA->ID,
            'timestamp' => time(),
        ]);
        $this->assertSame($authId, $this->fields('login:mfa')['auth_id'] ?? '');

        CoSign::markMfaCompleted($this->adminA->ID, true);
        $this->assertSame($authId, $this->fields('login:session')['auth_id'] ?? '');
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID), 'one-shot cleared');
    }

    public function test_auth_id_links_cosign_session_when_trusted(): void
    {
        $c = $this->challenge();
        $authId = (string) $c['auth_id'];
        $this->assertSame('ok', $this->verify($c['token'], $c, $this->adminB->user_email, 'Long-Pass-123!'));
        $this->assertSame($authId, $this->fields('login:cosign_success')['auth_id'] ?? '');

        CoSign::markMfaCompleted($this->adminA->ID, true);
        $this->assertSame($authId, $this->fields('login:session')['auth_id'] ?? '');
        $this->assertSame([], Store::recentWhere('login:mfa'));
    }

    public function test_session_event_contains_same_auth_id(): void
    {
        $c = $this->challenge();
        $authId = (string) $c['auth_id'];
        $this->assertSame('ok', $this->verify($c['token'], $c, $this->adminB->user_login, 'Long-Pass-123!'));
        CoSign::markMfaCompleted($this->adminA->ID, false);
        $success = $this->fields('login:cosign_success');
        $session = $this->fields('login:session');
        $this->assertSame($authId, (string) ($success['auth_id'] ?? ''));
        $this->assertSame($authId, (string) ($session['auth_id'] ?? ''));
        $this->assertSame((int) $this->adminA->ID, (int) ($session['user_id'] ?? $session['primary_user_id'] ?? 0));
    }

    public function test_service_account_cannot_cosign(): void
    {
        $c = $this->challenge();
        add_filter('draco_insomnis_cosign_service_account', '__return_true');
        $this->assertSame('bad', $this->verify($c['token'], $c, $this->adminB->user_login, 'Long-Pass-123!'));
        remove_filter('draco_insomnis_cosign_service_account', '__return_true');
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $fields = $this->fields('login:cosign_failure');
        $this->assertSame('COSIGNER_SERVICE_ACCOUNT', $fields['reason'] ?? '');
        $this->assertSame($c['auth_id'], $fields['auth_id'] ?? '');
        $this->assertNoSession();
    }

    public function test_trusted_device_skips_only_mfa(): void
    {
        // Trust Device ≠ Trusted Login: Cosign never consults TrustedDevice.
        // MFA registers its filter only when it is on (setUp switches it off).
        update_option(Mfa::OPTION_ENABLED, 'yes');
        Mfa::boot();
        $this->assertSame(CoSign::PRIORITY, has_filter('authenticate', [CoSign::class, 'atAuthenticate']));
        $this->assertSame(Mfa::PRIORITY, has_filter('authenticate', [Mfa::class, 'atAuthenticate']));
        // The gate that demands CoSign (afterPrimaryPassword) never looks at trusted devices; they are
        // only consulted after CoSign succeeded, to decide whether the MFA code is still needed.
        $m = new \ReflectionMethod(CoSign::class, 'afterPrimaryPassword');
        $lines = file((string) $m->getFileName());
        $gate = implode('', array_slice($lines, $m->getStartLine() - 1, $m->getEndLine() - $m->getStartLine() + 1));
        $this->assertStringNotContainsString('TrustedDevice', $gate);

        update_option(Mfa::OPTION_ENABLED, 'yes');
        update_option(Mfa::OPTION_TRUST, 'yes');
        TrustedDevice::issue($this->adminA->ID);
        $this->assertTrue(TrustedDevice::isValid($this->adminA->ID));
        $this->assertTrue(CoSign::requiredFor($this->adminA));
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID), 'trust alone does not satisfy Cosign');
        $this->assertNoSession();
    }

    public function test_cosign_failure_preserves_auth_id(): void
    {
        $editor = $this->user('editor');
        $c = $this->challenge();
        $authId = (string) $c['auth_id'];
        $this->assertNotSame('', $authId);
        $this->assertSame('bad', $this->verify($c['token'], $c, $editor->user_login, 'Long-Pass-123!'));
        $fields = $this->fields('login:cosign_failure');
        $this->assertSame('COSIGNER_NOT_ADMIN', $fields['reason'] ?? '');
        $this->assertSame($authId, $fields['auth_id'] ?? '');
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertNoSession();
    }

    public function test_cosign_timeout_has_no_session(): void
    {
        $token = CoSign::createChallenge($this->adminA);
        $row = CoSign::getChallenge($token);
        $this->assertNotNull($row);
        $authId = (string) $row['auth_id'];
        set_transient('draco_cosign_' . $token, [
            'primary_user_id' => (int) $this->adminA->ID,
            'auth_id' => $authId,
            'created_at' => time() - CoSign::TTL - 10,
            'ip' => (string) $row['ip'],
            'ua_hash' => (string) $row['ua_hash'],
        ], CoSign::TTL);
        $this->assertNull(CoSign::getChallenge($token));
        $fields = $this->fields('login:cosign_failure');
        $this->assertSame('COSIGN_TIMEOUT', $fields['reason'] ?? '');
        $this->assertSame($authId, $fields['auth_id'] ?? '');
        $this->assertNoSession();
    }

    public function test_mfa_failure_rolls_back_session(): void
    {
        $c = $this->challenge();
        $this->assertSame('ok', $this->verify($c['token'], $c, $this->adminB->user_login, 'Long-Pass-123!'));
        $this->assertTrue(CoSign::satisfiedFor($this->adminA->ID));

        $code = Challenge::newCode();
        $challenge = Challenge::create((int) $this->adminA->ID, $code, (string) $c['auth_id']);
        $this->assertSame('wrong', Challenge::check($challenge['id'], '000000'));
        $this->assertNotNull(Challenge::get($challenge['id']));
        $this->assertNoSession();
        $this->assertTrue(CoSign::satisfiedFor($this->adminA->ID), 'ok_ kept until MFA locked or finished');

        CoSign::clearSatisfied($this->adminA->ID);
        Challenge::forgetUser((int) $this->adminA->ID);
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertNull(Challenge::get($challenge['id']));
        $this->assertNoSession();
    }

    public function test_wrong_password_does_not_satisfy(): void
    {
        $c = $this->challenge();
        $this->assertSame('bad', $this->verify($c['token'], $c, $this->adminB->user_login, 'wrong-password'));
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertSame('COSIGNER_INVALID_PASSWORD', $this->fields('login:cosign_failure')['reason'] ?? '');
        $this->assertSame($c['auth_id'], $this->fields('login:cosign_failure')['auth_id'] ?? '');
        $this->assertNoSession();
    }

    public function test_login_requires_cosign_when_enabled_without_creating_session(): void
    {
        $result = wp_authenticate($this->adminA->user_login, 'not-the-password');
        $this->assertInstanceOf(\WP_Error::class, $result);
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID));
        $this->assertNoSession();
    }

    public function test_filter_priority_order(): void
    {
        // MFA registers its filter only when it is on (setUp switches it off).
        update_option(Mfa::OPTION_ENABLED, 'yes');
        Mfa::boot();
        $this->assertSame(CoSign::PRIORITY, has_filter('authenticate', [CoSign::class, 'atAuthenticate']));
        $this->assertSame(Mfa::PRIORITY, has_filter('authenticate', [Mfa::class, 'atAuthenticate']));
    }

    public function test_both_steps_run_after_every_other_authenticate_filter(): void
    {
        update_option(Mfa::OPTION_ENABLED, 'yes');
        Mfa::boot();
        $this->assertLessThan(Mfa::PRIORITY, CoSign::PRIORITY, 'co-signature before the e-mail code');
        $this->assertGreaterThan(30, CoSign::PRIORITY, 'after WordPress core and lockout plugins');
        $this->assertFalse(has_filter('wp_authenticate_user', [CoSign::class, 'afterPrimaryPassword']));
        $this->assertFalse(has_filter('wp_authenticate_user', [Mfa::class, 'afterPassword']));
        // An error from an earlier filter (a lockout plugin, Draco's own firewall) is passed on untouched.
        $error = new \WP_Error('locked', 'locked');
        $this->assertSame($error, CoSign::atAuthenticate($error, $this->adminA->user_login, 'Long-Pass-123!'));
        $this->assertSame($error, Mfa::atAuthenticate($error, $this->adminA->user_login, 'Long-Pass-123!'));
        $this->assertNull(CoSign::atAuthenticate(null, '', ''));
    }

    public function test_a_cosignature_belongs_to_one_login_attempt_not_to_the_account(): void
    {
        $c = $this->challenge();
        $this->assertSame('ok', $this->verify($c['token'], $c, $this->adminB->user_login, 'Long-Pass-123!'));
        $this->assertTrue(CoSign::satisfiedFor($this->adminA->ID), 'the browser that was co-signed');
        $grant = new \ReflectionProperty(CoSign::class, 'grant');
        $grant->setAccessible(true);
        $own = (string) $grant->getValue();
        $this->assertMatchesRegularExpression('/^[a-f0-9]{32}$/', $own);

        // Another login of the same account, with the right password, from another browser.
        $grant->setValue(null, '');
        unset($_COOKIE['draco_cosign_grant']);
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID), 'no grant, no co-signature');
        $this->assertSame('', CoSign::authIdFor($this->adminA->ID));
        $_COOKIE['draco_cosign_grant'] = str_repeat('a', 32);
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID), 'a guessed grant does not count');
        CoSign::markMfaCompleted($this->adminA->ID, true);
        $this->assertSame([], Store::recentWhere('login:session'), 'no session event for the other browser');

        // The same grant from another address does not count either.
        $_COOKIE['draco_cosign_grant'] = $own;
        $this->assertTrue(CoSign::satisfiedFor($this->adminA->ID), 'the cookie of the co-signed browser');
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $_SERVER['REMOTE_ADDR'] = '203.0.113.99';
        $this->assertFalse(CoSign::satisfiedFor($this->adminA->ID), 'grant copied to another address');
        if ($ip === null) {
            unset($_SERVER['REMOTE_ADDR']);
        } else {
            $_SERVER['REMOTE_ADDR'] = $ip;
        }
        unset($_COOKIE['draco_cosign_grant']);
        CoSign::clearSatisfied($this->adminA->ID);
    }
}
