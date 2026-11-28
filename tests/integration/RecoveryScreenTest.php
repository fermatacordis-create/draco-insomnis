<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Login\Recovery;

/** The recovery screen: always three slots, one change at a time, and the light in the tab. */
final class RecoveryScreenTest extends TestCase
{
    /** @param list<string> $emails @param array<string, mixed>|null $pending */
    private function screen(array $emails, ?array $pending = null): string
    {
        $admin = $this->user('administrator');
        wp_set_current_user($admin->ID);
        $_GET['page'] = Recovery::SLUG;
        update_option('draco_mfa_enabled', 'yes');
        update_user_meta($admin->ID, Recovery::META_LIST, $emails);
        if ($pending !== null) {
            update_user_meta($admin->ID, Recovery::META_PENDING, $pending + ['new' => 'x', 'old' => '', 'at' => time(), 'tries' => 0]);
        }
        ob_start();
        Recovery::render();
        $html = (string) ob_get_clean();
        $this->assertSame(3, substr_count($html, '<li class="draco-slot'), 'always three slots');
        $this->assertSame(substr_count($html, '<form'), substr_count($html, '</form>'));
        preg_match_all('/ id="([^"]+)"/', $html, $m);
        $ids = array_diff($m[1], ['_wpnonce']); // WordPress repeats this one in every form
        $this->assertSame($ids, array_unique($ids), 'no repeated id');

        return $html;
    }

    private function dot(string $html): string
    {
        $this->assertSame(1, preg_match('/dashicons-sos"[^>]*><\/span>Recovery e-mail\s*<span class="([^"]+)"/', $html, $m));

        return $m[1];
    }

    private function call(string $method, mixed ...$args): string
    {
        $m = new \ReflectionMethod(Recovery::class, $method);
        $m->setAccessible(true);

        return (string) $m->invoke(null, ...$args);
    }

    public function test_the_last_address_stays_while_the_login_code_is_required(): void
    {
        $admin = $this->user('administrator');
        update_option('draco_mfa_enabled', 'yes');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net', 'two@example.net']);
        $this->assertSame('sent_remove', $this->call('requestRemove', $admin, 1), 'with two, one can go');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net']);
        delete_user_meta($admin->ID, Recovery::META_PENDING);
        $this->assertSame('last', $this->call('requestRemove', $admin, 0));
        $this->assertSame('', get_user_meta($admin->ID, Recovery::META_PENDING, true));
        update_option('draco_mfa_enabled', 'no');
        $this->assertSame('sent_remove', $this->call('requestRemove', $admin, 0), 'without the login code it can');
    }

    public function test_a_removal_under_way_does_not_take_the_last_address_either(): void
    {
        $admin = $this->user('administrator');
        update_option('draco_mfa_enabled', 'yes');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net']);
        update_user_meta($admin->ID, Recovery::META_PENDING, ['op' => 'remove', 'slot' => 0, 'email' => 'one@example.net', 'new' => \DracoInsomnis\Login\Challenge::hash('123456'), 'old' => '', 'at' => time(), 'tries' => 0]);
        $this->assertSame('last', $this->call('confirmRemove', $admin, '123456'));
        $this->assertSame(['one@example.net'], Recovery::emails($admin->ID));
    }

    public function test_no_address_yet(): void
    {
        $html = $this->screen([]);
        $this->assertSame('draco-nav__dot', $this->dot($html));
        $this->assertSame(1, substr_count($html, 'type="email"'), 'only the first free slot can be filled');
        $this->assertSame(2, substr_count($html, 'Confirm the previous one first.'));
        $this->assertStringContainsString('One at a time', $html);
    }

    public function test_some_addresses(): void
    {
        $html = $this->screen(['one@example.net', 'two@example.net']);
        $this->assertSame('draco-nav__dot is-log', $this->dot($html));
        $this->assertSame(2, substr_count($html, '>Verified<'));
        $this->assertSame(1, substr_count($html, '>Free<'));
        $this->assertSame(1, substr_count($html, 'name="slot" value="-1"'));
    }

    public function test_all_verified(): void
    {
        $html = $this->screen(['one@example.net', 'two@example.net', 'three@example.net']);
        $this->assertSame('draco-nav__dot is-on', $this->dot($html));
        $this->assertSame(3, substr_count($html, '>Verified<'));
        $this->assertStringNotContainsString('name="slot" value="-1"', $html);
        $this->assertStringNotContainsString('One at a time', $html);
        $this->assertStringNotContainsString('one@example.net', $html, 'addresses are masked');
    }

    public function test_adding_keeps_the_others_in_view_without_buttons(): void
    {
        $html = $this->screen(['one@example.net'], ['op' => 'set', 'email' => 'new@example.net', 'replaces' => null]);
        $this->assertStringContainsString('o**@example.net', $html);
        $this->assertStringNotContainsString('name="slot"', $html);
        $this->assertSame(1, substr_count($html, 'is-waiting'));
        $this->assertStringContainsString('draco-code-new', $html);
        $this->assertStringNotContainsString('draco-code-old', $html);
    }

    public function test_replacing_asks_for_both_codes_in_its_own_slot(): void
    {
        $html = $this->screen(['one@example.net', 'two@example.net'], ['op' => 'set', 'email' => 'new@example.net', 'replaces' => 1, 'old' => 'y']);
        $slots = explode('<li class="draco-slot', $html);
        $this->assertStringContainsString('draco-code-new', $slots[2]);
        $this->assertStringContainsString('draco-code-old', $slots[2]);
        $this->assertStringContainsString('t**@example.net', $slots[2]);
        $this->assertStringNotContainsString('draco-code', $slots[1]);
    }

    public function test_a_new_code_replaces_the_old_one_and_the_tries_start_again(): void
    {
        $admin = $this->user('administrator');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net']);
        $hash = \DracoInsomnis\Login\Challenge::hash('111111');
        update_user_meta($admin->ID, Recovery::META_PENDING, ['op' => 'set', 'email' => 'new@example.net', 'replaces' => null, 'new' => $hash, 'old' => '', 'at' => time() - 60, 'tries' => 3]);

        $this->assertSame('resent', $this->call('resend', $admin));
        $pending = get_user_meta($admin->ID, Recovery::META_PENDING, true);
        $this->assertNotSame($hash, $pending['new'], 'a different code');
        $this->assertSame(0, $pending['tries']);
        $this->assertSame('bad', $this->call('confirm', $admin, '111111', ''), 'the old code no longer works');
    }

    public function test_a_new_code_waits_a_moment_and_only_a_few_an_hour(): void
    {
        $admin = $this->user('administrator');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net']);
        $pending = ['op' => 'set', 'email' => 'new@example.net', 'replaces' => null, 'new' => 'x', 'old' => '', 'at' => time(), 'tries' => 0];
        update_user_meta($admin->ID, Recovery::META_PENDING, $pending);
        $this->assertSame('resend_wait', $this->call('resend', $admin), 'not right after the first one');

        $results = [];
        for ($i = 0; $i < 4; $i++) {
            $p = get_user_meta($admin->ID, Recovery::META_PENDING, true);
            $p['sent'] = time() - 60;
            update_user_meta($admin->ID, Recovery::META_PENDING, $p);
            $results[] = $this->call('resend', $admin);
        }
        $this->assertSame(['resent', 'resent', 'resent', 'resend_limit'], $results);
    }

    public function test_a_new_code_for_a_replacement_renews_both_codes(): void
    {
        $admin = $this->user('administrator');
        update_user_meta($admin->ID, Recovery::META_LIST, ['one@example.net', 'two@example.net']);
        $old = \DracoInsomnis\Login\Challenge::hash('222222');
        update_user_meta($admin->ID, Recovery::META_PENDING, ['op' => 'set', 'email' => 'new@example.net', 'replaces' => 1, 'new' => 'x', 'old' => $old, 'at' => time() - 60, 'tries' => 0]);

        $this->assertSame('resent', $this->call('resend', $admin));
        $this->assertNotSame($old, get_user_meta($admin->ID, Recovery::META_PENDING, true)['old']);
    }

    public function test_no_new_code_once_the_change_has_expired(): void
    {
        $admin = $this->user('administrator');
        update_user_meta($admin->ID, Recovery::META_PENDING, ['op' => 'set', 'email' => 'new@example.net', 'replaces' => null, 'new' => 'x', 'old' => '', 'at' => time() - 3600, 'tries' => 0]);

        $this->assertSame('expired', $this->call('resend', $admin));
        $this->assertSame('', get_user_meta($admin->ID, Recovery::META_PENDING, true));
    }

    public function test_the_waiting_slot_offers_a_new_code(): void
    {
        $html = $this->screen(['one@example.net'], ['op' => 'set', 'email' => 'new@example.net', 'replaces' => null]);
        $slots = explode('<li class="draco-slot', $html);
        $this->assertStringContainsString('value="resend"', $slots[2]);
        $this->assertStringContainsString('draco-rec-resend', $slots[2]);
        $this->assertStringContainsString('draco-spam-hint', $slots[2], 'the spam reminder is always in view while a code is awaited');
        $this->assertStringNotContainsString('value="resend"', $slots[1]);
    }

    public function test_removing_asks_for_the_code_in_its_own_slot(): void
    {
        $html = $this->screen(['one@example.net', 'two@example.net'], ['op' => 'remove', 'slot' => 0, 'email' => 'one@example.net']);
        $slots = explode('<li class="draco-slot', $html);
        $this->assertStringContainsString('draco-code-rm', $slots[1]);
        $this->assertStringContainsString('value="remove_confirm"', $slots[1]);
    }
}
