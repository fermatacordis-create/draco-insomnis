<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\CoreFiles;
use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** Guardia: core files against the release checksums. */
final class GuardiaCoreFilesTest extends TestCase
{
    private const SUMS = [
        'index.php' => '926dd0f95df723f9ed934eb058882cc8',
        'wp-login.php' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        'wp-includes/version.php' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        'wp-admin/about.php' => 'cccccccccccccccccccccccccccccccc',
        'wp-content/plugins/akismet/akismet.php' => 'dddddddddddddddddddddddddddddddd',
        'readme.html' => 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    ];

    public function test_an_untouched_install_has_nothing_to_say(): void
    {
        $actual = self::SUMS;
        unset($actual['readme.html']); // deleted by a hardening guide: not reported
        $out = CoreFiles::deviations(self::SUMS, $actual, ['index.php', 'wp-login.php', 'wp-config.php', 'wp-includes/version.php', 'wp-admin/about.php']);
        $this->assertSame([], $out);
    }

    public function test_a_modified_core_file_is_high_from_the_start(): void
    {
        $actual = self::SUMS;
        $actual['wp-login.php'] = 'ffffffffffffffffffffffffffffffff';
        $out = CoreFiles::deviations(self::SUMS, $actual, []);
        $this->assertSame(['core|wp-login.php' => ['fp' => 'modified:ffffffffffffffffffffffffffffffff', 'danger' => true]], $out);
        $events = Diff::compare([], $out, true);
        $this->assertSame([Diff::BASELINE, Diff::HIGH], [$events[0]['event'], $events[0]['severity']], 'already modified at the baseline');
    }

    public function test_php_that_no_release_has_where_backdoors_hide(): void
    {
        $out = CoreFiles::deviations(self::SUMS, self::SUMS, ['index.php', 'wp-config.php', 'wp-cache.php', 'wp-includes/css/class-wp-x.php', 'wp-admin/includes/about.php']);
        $this->assertSame(['core|wp-cache.php', 'core|wp-includes/css/class-wp-x.php', 'core|wp-admin/includes/about.php'], array_keys($out));
        $this->assertSame('extra', $out['core|wp-cache.php']['fp']);
    }

    public function test_wp_content_and_other_folders_are_not_core(): void
    {
        $actual = self::SUMS;
        $actual['wp-content/plugins/akismet/akismet.php'] = 'ffffffffffffffffffffffffffffffff';
        $out = CoreFiles::deviations(self::SUMS, $actual, ['wp-content/plugins/x.php', 'cgi-bin/a.php']);
        $this->assertSame([], $out);
        $this->assertTrue(CoreFiles::watched('wp-cache.php'));
        $this->assertFalse(CoreFiles::watched('cgi-bin/a.php'));
    }

    public function test_a_core_file_put_back_and_modified_again_is_persistence(): void
    {
        $known = ['core|wp-login.php' => ['state' => Diff::MISSING, 'fp' => 'modified:f', 'back' => 0]];
        $out = Diff::compare($known, ['core|wp-login.php' => ['fp' => 'modified:f', 'danger' => true]], false);
        $this->assertSame([Diff::BACK, Diff::MEDIUM, 1], [$out[0]['event'], $out[0]['severity'], $out[0]['back']]);
        $new = Diff::compare([], ['core|wp-cache.php' => ['fp' => 'extra', 'danger' => true]], false);
        $this->assertSame(Diff::HIGH, $new[0]['severity'], 'new after the baseline');
    }
}
