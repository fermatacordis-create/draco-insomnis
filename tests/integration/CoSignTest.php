<?php

declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Login\AccountLock;
use DracoInsomnis\Login\Challenge;
use DracoInsomnis\Login\CoSign;
use DracoInsomnis\Login\Mfa;
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
        // Trust Device ≠ Trusted Login: Cosign @99 never consults TrustedDevice.
        // MFA registers its filter only when it is on (setUp switches it off).
        update_option(Mfa::OPTION_ENABLED, 'yes');
        Mfa::boot();
        $this->assertSame(99, has_filter('wp_authenticate_user', [CoSign::class, 'afterPrimaryPassword']));
        $this->assertSame(100, has_filter('wp_authenticate_user', [Mfa::class, 'afterPassword']));
        $src = (string) file_get_contents((new \ReflectionClass(CoSign::class))->getFileName());
        $this->assertStringNotContainsString('TrustedDevice::isValid', $src);

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
        $this->assertSame(99, has_filter('wp_authenticate_user', [CoSign::class, 'afterPrimaryPassword']));
        $this->assertSame(100, has_filter('wp_authenticate_user', [Mfa::class, 'afterPassword']));
    }
}
