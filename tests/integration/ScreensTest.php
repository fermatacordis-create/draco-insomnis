<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Admin\Brand;
use DracoInsomnis\Admin\Overview;

/** Every admin screen draws without PHP notices, with the header, the tabs and its cards. */
final class ScreensTest extends TestCase
{
    /** @return array<string, array{callable-string|array{class-string, string}, string}> */
    public static function screens(): array
    {
        return [
            'overview' => [[Overview::class, 'render'], 'draco-insomnis'],
            'shield' => [[\DracoInsomnis\Shield\Admin::class, 'render'], 'draco-insomnis-shield'],
            'forms' => [[\DracoInsomnis\Gate\Admin::class, 'render'], 'draco-insomnis-forms'],
            'login' => [[\DracoInsomnis\Login\Admin::class, 'render'], 'draco-insomnis-login'],
            'firewall' => [[\DracoInsomnis\Firewall\Admin::class, 'render'], 'draco-insomnis-firewall'],
            'anti-copy' => [[\DracoInsomnis\AntiCopy\Admin::class, 'render'], 'draco-insomnis-anticopy'],
            'mail' => [[\DracoInsomnis\Mail\Admin::class, 'render'], 'draco-insomnis-mail'],
            'recovery' => [[\DracoInsomnis\Login\Recovery::class, 'render'], 'draco-recovery-email'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('screens')]
    public function test_the_screen_draws(array $render, string $page): void
    {
        wp_set_current_user($this->user('administrator')->ID);
        $_GET['page'] = $page;
        update_option('draco_shield_enabled', 'yes');
        update_option('draco_waf_enabled', 'yes');
        // The recovery screen, and its tab, exist only while the login code is on.
        update_option('draco_mfa_enabled', $page === 'draco-recovery-email' ? 'yes' : 'no');
        \DracoInsomnis\Shield\Store::log('198.51.100.9', '198.51.100.9', 'wp_register', ['score' => 90, 'verdict' => 'bot', 'reasons' => ['honeypot']], 'curl', ['username' => 'x', 'email' => 'x@spam.example', 'role' => '', 'referer' => '']);
        $notices = [];
        set_error_handler(static function (int $no, string $msg, string $file, int $line) use (&$notices): bool {
            $notices[] = "$msg ($file:$line)";

            return true;
        });
        ob_start();
        try {
            call_user_func($render);
        } finally {
            $html = (string) ob_get_clean();
            restore_error_handler();
        }
        $this->assertSame([], $notices);
        $this->assertStringContainsString('class="wrap draco"', $html);
        $this->assertStringContainsString('draco-hero', $html);
        $this->assertStringContainsString('draco-nav', $html);
        $this->assertStringContainsString('draco-card', $html);
        $this->assertStringContainsString('aria-current="page"', $html, 'the open screen is marked in the tabs');
        $this->assertSame(substr_count($html, '<section'), substr_count($html, '</section>'), 'every card is closed');
        $this->assertSame(substr_count($html, '<form'), substr_count($html, '</form>'), 'every form is closed');
    }

    public function test_tabs_show_each_module_state(): void
    {
        update_option('draco_waf_enabled', 'yes');
        update_option('draco_waf_mode', 'log');
        update_option('draco_shield_enabled', 'yes');
        $m = Brand::modules();
        $this->assertSame('on', $m['draco-insomnis-shield'][2]);
        $this->assertSame('log', $m['draco-insomnis-firewall'][2]);
        $this->assertSame('off', $m['draco-insomnis-login'][2]);
        update_option('draco_anticopy_rate', 'block');
        $this->assertSame('on', Brand::modules()['draco-insomnis-anticopy'][2]);
    }
}
