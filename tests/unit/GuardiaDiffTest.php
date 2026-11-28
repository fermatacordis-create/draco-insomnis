<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** Guardia: baseline, new items, persistence (present → missing → back) and its severity. */
final class GuardiaDiffTest extends TestCase
{
    private static function k(string $state, string $fp = '', int $back = 0): array
    {
        return ['state' => $state, 'fp' => $fp, 'back' => $back];
    }

    /** @return array<string, string> id => event */
    private static function events(array $out): array
    {
        return array_column($out, 'event', 'id');
    }

    public function test_the_first_scan_is_the_baseline_and_only_dangerous_code_stands_out(): void
    {
        $out = Diff::compare([], ['mu_plugin|hostinger-preview-domain.php' => ['fp' => 'a'], 'upload_php|shell.php' => ['fp' => 'b', 'danger' => true]], true);
        $this->assertSame(['mu_plugin|hostinger-preview-domain.php' => Diff::BASELINE, 'upload_php|shell.php' => Diff::BASELINE], self::events($out));
        $this->assertSame([Diff::INFO, Diff::HIGH], array_column($out, 'severity'));
    }

    public function test_new_after_the_baseline(): void
    {
        $out = Diff::compare(['admin|owner' => self::k(Diff::PRESENT, 'x')], ['admin|owner' => ['fp' => 'x'], 'admin|admin_backup' => ['fp' => 'y'], 'plugin|seo-helper-pro/x.php' => ['fp' => '1.0']], false);
        $this->assertSame(['admin|admin_backup' => Diff::NEW, 'plugin|seo-helper-pro/x.php' => Diff::NEW], self::events($out));
        $this->assertSame(Diff::HIGH, $out[0]['severity'], 'a new administrator');
        $this->assertSame(Diff::INFO, $out[1]['severity'], 'a new plugin is only noted');
    }

    public function test_persistence_needs_present_then_missing_then_present(): void
    {
        $known = ['upload_php|cache.php' => self::k(Diff::PRESENT, 'h')];
        $gone = Diff::compare($known, [], false);
        $this->assertSame([['id' => 'upload_php|cache.php', 'event' => Diff::GONE, 'state' => Diff::MISSING, 'back' => 0, 'severity' => Diff::INFO, 'fp' => 'h']], $gone);

        $back = Diff::compare(['upload_php|cache.php' => self::k(Diff::MISSING, 'h')], ['upload_php|cache.php' => ['fp' => 'h']], false);
        $this->assertSame(Diff::BACK, $back[0]['event']);
        $this->assertSame(Diff::REAPPEARED, $back[0]['state']);
        $this->assertSame(1, $back[0]['back']);
        $this->assertSame(Diff::MEDIUM, $back[0]['severity']);

        // Still there on the next scan: nothing new to say.
        $this->assertSame([], Diff::compare(['upload_php|cache.php' => self::k(Diff::REAPPEARED, 'h', 1)], ['upload_php|cache.php' => ['fp' => 'h']], false));
    }

    public function test_each_return_raises_the_level(): void
    {
        $this->assertSame(Diff::MEDIUM, Diff::backSeverity(1));
        $this->assertSame(Diff::HIGH, Diff::backSeverity(2));
        $this->assertSame(Diff::CRITICAL_LEVEL, Diff::backSeverity(3));
        $this->assertSame(Diff::CRITICAL_LEVEL, Diff::backSeverity(7));
        $out = Diff::compare(['admin|admin_backup' => self::k(Diff::MISSING, 'e', 2)], ['admin|admin_backup' => ['fp' => 'e']], false);
        $this->assertSame([3, Diff::CRITICAL_LEVEL], [$out[0]['back'], $out[0]['severity']]);
    }

    public function test_a_plugin_update_is_not_a_change_but_a_rewritten_config_is(): void
    {
        $this->assertSame([], Diff::compare(['plugin|woocommerce/woocommerce.php' => self::k(Diff::PRESENT, '10.3')], ['plugin|woocommerce/woocommerce.php' => ['fp' => '10.4']], false));
        $out = Diff::compare(['critical|wp-config.php' => self::k(Diff::PRESENT, 'a')], ['critical|wp-config.php' => ['fp' => 'b']], false);
        $this->assertSame([Diff::CHANGED, Diff::MEDIUM], [$out[0]['event'], $out[0]['severity']]);
    }

    public function test_many_items_back_at_once_look_like_a_restored_backup(): void
    {
        $known = [];
        $seen = [];
        for ($i = 0; $i < 6; $i++) {
            $known["plugin|p$i/p.php"] = self::k(Diff::MISSING, '1');
            $seen["plugin|p$i/p.php"] = ['fp' => '1'];
        }
        $this->assertTrue(Diff::looksLikeRestore(Diff::compare($known, $seen, false)));
        $this->assertFalse(Diff::looksLikeRestore(Diff::compare(['plugin|a/a.php' => self::k(Diff::MISSING, '1')], ['plugin|a/a.php' => ['fp' => '1']], false)));
    }

    public function test_dangerous_calls(): void
    {
        $this->assertTrue(Diff::dangerous('<?php eval($_POST["x"]);'));
        $this->assertTrue(Diff::dangerous('<?php $f = base64_decode($payload);'));
        $this->assertTrue(Diff::dangerous('<?php $_GET["f"]($_GET["a"]);'));
        $this->assertFalse(Diff::dangerous("<?php\n// Silence is golden."));
        $this->assertFalse(Diff::dangerous('<?php exit; ?> 2026-11-28 log line base64_decode text'), 'the word in a log is not a call on a variable');
    }

    public function test_ids(): void
    {
        $this->assertSame('upload_php', Diff::kindOf('upload_php|2026/11/a|b.php'));
        $this->assertSame('2026/11/a|b.php', Diff::keyOf('upload_php|2026/11/a|b.php'));
    }
}
