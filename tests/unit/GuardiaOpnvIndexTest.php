<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\Advisories\Matcher;
use DracoInsomnis\Guardia\Advisories\OpnvIndex;
use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** The OPNV index of Wordfence Intelligence: ranges, the fix, and reading only what is installed. */
final class GuardiaOpnvIndexTest extends TestCase
{
    private static function rec(array $ranges, array $patched, string $sev = 'high', bool $unauth = true): array
    {
        return ['id' => 'wf-1', 't' => 'Example <= 1.2.3 - XSS', 'r' => $ranges, 'p' => $patched, 'sev' => $sev, 's' => 7.5, 'u' => $unauth, 'cve' => 'CVE-2024-1111', 'l' => 'https://www.wordfence.com/threat-intel/vulnerabilities/x', 'c' => [0, 1]];
    }

    public function test_inclusive_upper_bound_and_the_patched_version(): void
    {
        $a = Matcher::fromOpnvIndex(self::rec([['1.0.0', true, '1.2.3', true]], ['1.2.4']))[0];
        $this->assertTrue(Matcher::affects($a, '1.0.0'));
        $this->assertTrue(Matcher::affects($a, '1.2.3'));
        $this->assertFalse(Matcher::affects($a, '1.2.4'));
        $this->assertFalse(Matcher::affects($a, '0.9'));
        $this->assertSame('1.2.4', Matcher::fixedIn($a), 'named by the source even for «up to and including»');
        $this->assertSame([[Diff::HIGH], ['CVE-2024-1111'], [0, 1]], [[$a['severity']], $a['cve'], $a['notices']]);
    }

    public function test_star_bounds_and_no_fix(): void
    {
        $any = Matcher::fromOpnvIndex(self::rec([['*', true, '*', true]], []))[0];
        $this->assertTrue(Matcher::affects($any, '0.1'));
        $this->assertTrue(Matcher::affects($any, '99.0'));
        $this->assertSame('', Matcher::fixedIn($any));
        $below = Matcher::fromOpnvIndex(self::rec([['*', true, '5.0.4', false]], ['5.0.4', '4.9.9']))[0];
        $this->assertTrue(Matcher::affects($below, '5.0.3'));
        $this->assertFalse(Matcher::affects($below, '5.0.4'));
        $this->assertSame('5.0.4', Matcher::fixedIn($below), 'the lowest patched version above the range');
    }

    public function test_wordpress_core_proposes_the_fix_of_its_own_branch(): void
    {
        $a = Matcher::fromOpnvIndex(self::rec([['4.3.0', true, '7.1.4', true]], ['7.1.5', '4.3.40', '6.8.4', '7.0.6']));
        $installed = [['type' => 'core', 'slug' => 'wordpress', 'version' => '6.8.1', 'name' => 'WordPress', 'active' => true]];
        $out = Matcher::match($installed, ['core|wordpress' => $a]);
        $this->assertSame('6.8.4', $out[0]['fixed'], 'the lowest patched version above the installed one');
        $this->assertSame('7.1.5', Matcher::fixFor($a[0], '7.1.4'));
        $this->assertSame('', Matcher::fixFor($a[0], '7.1.5'), 'nothing above');
    }

    public function test_a_record_with_two_ranges_is_listed_once(): void
    {
        $advisories = ['plugin|example' => Matcher::fromOpnvIndex(self::rec([['1.0', true, '1.5', true], ['1.4', true, '2.0', false]], ['2.0']))];
        $out = Matcher::match([['type' => 'plugin', 'slug' => 'example', 'version' => '1.4.5', 'name' => 'Example', 'active' => true]], $advisories);
        $this->assertCount(1, $out);
    }

    public function test_scan_decodes_only_the_installed_lines(): void
    {
        $lines = [
            "#meta\t" . json_encode(['format' => 1, 'generated' => '2026-11-28T13:00:36Z', 'records' => 3]) . "\n",
            "#notices\t" . json_encode([['party' => 'defiant', 'notice' => 'Copyright 2012-2026 Defiant Inc.', 'license' => 'L', 'license_url' => 'U']]) . "\n",
            "plugin|aaa\t" . json_encode([self::rec([['*', true, '1.0', false]], ['1.0'])]) . "\n",
            "plugin|example\t" . json_encode([self::rec([['*', true, '2.0', false]], ['2.0'])]) . "\n",
            "plugin|zzz\tTHIS IS NOT JSON AND IS NEVER DECODED\n",
        ];
        $got = OpnvIndex::scan($lines, ['plugin|example' => true, 'theme|missing' => true]);
        $this->assertSame(['plugin|example'], array_keys($got['advisories']));
        $this->assertSame('2026-11-28T13:00:36Z', $got['meta']['generated']);
        $this->assertSame('Copyright 2012-2026 Defiant Inc.', $got['notices'][0]['notice']);
    }
}
