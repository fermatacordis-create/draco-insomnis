<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\Alerts;
use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** Guardia: which findings of a scan are worth an e-mail. */
final class GuardiaAlertsTest extends TestCase
{
    private static function e(string $id, string $event, string $severity, int $back = 0): array
    {
        return ['id' => $id, 'event' => $event, 'state' => Diff::PRESENT, 'back' => $back, 'severity' => $severity, 'fp' => ''];
    }

    public function test_a_quiet_baseline_sends_nothing_but_a_modified_core_file_does(): void
    {
        $this->assertSame([], Alerts::worth([self::e('mu_plugin|hostinger-auto-updates.php', Diff::BASELINE, Diff::INFO), self::e('upload_php|redux/index.php', Diff::BASELINE, Diff::INFO)], false));
        $out = Alerts::worth([self::e('plugin|a/a.php', Diff::BASELINE, Diff::INFO), self::e('core|wp-login.php', Diff::BASELINE, Diff::HIGH)], false);
        $this->assertSame(['core|wp-login.php'], array_column($out, 'id'));
    }

    public function test_after_the_baseline_medium_or_worse_worst_first_and_never_gone(): void
    {
        $out = Alerts::worth([
            self::e('plugin|seo/seo.php', Diff::NEW, Diff::INFO),
            self::e('upload_php|x.php', Diff::NEW, Diff::MEDIUM),
            self::e('upload_php|old.php', Diff::GONE, Diff::INFO),
            self::e('admin|admin_backup', Diff::BACK, Diff::CRITICAL_LEVEL, 3),
            self::e('mu_plugin|cache.php', Diff::NEW, Diff::HIGH),
        ], false);
        $this->assertSame(['admin|admin_backup', 'mu_plugin|cache.php', 'upload_php|x.php'], array_column($out, 'id'));
    }

    public function test_a_restored_backup_is_one_notice_not_one_per_item(): void
    {
        $events = [];
        for ($i = 0; $i < 6; $i++) {
            $events[] = self::e("plugin|p$i/p.php", Diff::BACK, Diff::MEDIUM, 1);
        }
        $events[] = self::e('core|wp-cache.php', Diff::NEW, Diff::HIGH);
        $this->assertSame(['core|wp-cache.php'], array_column(Alerts::worth($events, true), 'id'), 'the returns are the restore; something new is still listed');
    }
}
