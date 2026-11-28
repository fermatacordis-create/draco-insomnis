<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Guardia\Advisories\Matcher;
use DracoInsomnis\Guardia\Diff;
use PHPUnit\Framework\TestCase;

/** Known vulnerabilities: ranges, severity and what fixes them, compared on the site. */
final class GuardiaAdvisoriesTest extends TestCase
{
    /** A record as WPVulnerability returns it. */
    private static function raw(?string $min, ?string $minOp, ?string $max, ?string $maxOp, string $unfixed = '0', ?string $sev = 'h', string $pr = 'n'): array
    {
        return [
            'uuid' => 'u-' . $max . $unfixed,
            'name' => 'Example [example] < ' . $max,
            'operator' => ['min_version' => $min, 'min_operator' => $minOp, 'max_version' => $max, 'max_operator' => $maxOp, 'unfixed' => $unfixed, 'closed' => '0'],
            'source' => [['id' => 'CVE-2024-12345', 'link' => 'https://www.cve.org/CVERecord?id=CVE-2024-12345'], ['id' => 'abc', 'link' => 'https://example.org/x']],
            'impact' => ['cvss' => ['severity' => $sev, 'score' => $sev === 'c' ? '9.8' : '7.5', 'pr' => $pr]],
        ];
    }

    public function test_upper_bound_lt_and_le(): void
    {
        $lt = Matcher::fromWpVulnerability(self::raw(null, null, '5.3.2', 'lt'));
        $this->assertTrue(Matcher::affects($lt, '5.3.1'));
        $this->assertFalse(Matcher::affects($lt, '5.3.2'), 'the fixed version itself is not affected');
        $this->assertSame('5.3.2', Matcher::fixedIn($lt));
        $le = Matcher::fromWpVulnerability(self::raw(null, null, '4.6.8', 'le'));
        $this->assertTrue(Matcher::affects($le, '4.6.8'));
        $this->assertFalse(Matcher::affects($le, '4.6.9'));
        $this->assertSame('', Matcher::fixedIn($le), '«up to and including» does not name the fix');
    }

    public function test_lower_bound_and_unfixed(): void
    {
        $range = Matcher::fromWpVulnerability(self::raw('2.0', 'ge', '2.5', 'lt'));
        $this->assertFalse(Matcher::affects($range, '1.9'));
        $this->assertTrue(Matcher::affects($range, '2.0'));
        $this->assertTrue(Matcher::affects($range, 'v2.4.1'));
        $open = Matcher::fromWpVulnerability(self::raw('3.1', 'gt', null, null, '1'));
        $this->assertFalse(Matcher::affects($open, '3.1'));
        $this->assertTrue(Matcher::affects($open, '9.0'), 'no fix yet: every later version');
        $this->assertSame('', Matcher::fixedIn($open));
        $this->assertFalse(Matcher::affects(Matcher::fromWpVulnerability(self::raw(null, null, '5.0', 'lt')), ''), 'unknown installed version');
    }

    public function test_severity_cve_and_unauthenticated(): void
    {
        $a = Matcher::fromWpVulnerability(self::raw(null, null, '5.3.2', 'lt', '0', 'c', 'n'));
        $this->assertSame([Diff::CRITICAL_LEVEL, ['CVE-2024-12345'], true], [$a['severity'], $a['cve'], $a['unauth']]);
        $this->assertSame(Diff::MEDIUM, Matcher::severity(null, 0.0), 'unknown is medium, not nothing');
        $this->assertSame(Diff::HIGH, Matcher::severity(null, 7.2));
        $this->assertSame(Diff::INFO, Matcher::severity('l', 3.1));
    }

    public function test_match_lists_only_what_applies_worst_first(): void
    {
        $adv = ['plugin|example' => [
            Matcher::fromWpVulnerability(self::raw(null, null, '5.0', 'lt', '0', 'h')),
            Matcher::fromWpVulnerability(self::raw(null, null, '6.0', 'lt', '0', 'c')),
            Matcher::fromWpVulnerability(self::raw(null, null, '4.0', 'lt', '0', 'c')),
        ]];
        $installed = [
            ['type' => 'plugin', 'slug' => 'example', 'version' => '4.5', 'name' => 'Example', 'active' => false],
            ['type' => 'theme', 'slug' => 'example', 'version' => '1.0', 'name' => 'Example theme', 'active' => true],
        ];
        $out = Matcher::match($installed, $adv);
        $this->assertSame([[Diff::CRITICAL_LEVEL, '6.0'], [Diff::HIGH, '5.0']], array_map(static fn (array $f): array => [$f['severity'], $f['fixed']], $out));
        $this->assertFalse($out[0]['active'], 'an inactive plugin is still listed: its files are there');
    }
}
