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

    public function test_removing_asks_for_the_code_in_its_own_slot(): void
    {
        $html = $this->screen(['one@example.net', 'two@example.net'], ['op' => 'remove', 'slot' => 0, 'email' => 'one@example.net']);
        $slots = explode('<li class="draco-slot', $html);
        $this->assertStringContainsString('draco-code-rm', $slots[1]);
        $this->assertStringContainsString('value="remove_confirm"', $slots[1]);
    }
}
