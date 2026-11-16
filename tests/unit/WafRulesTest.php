<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\WafRules;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/Core/WafRules.php';

/**
 * The cases live in tests/vectors/waf.json, shared with the JavaScript port (js/test): both languages
 * must give the same answer for every request there. Add new cases to the JSON, not here.
 */
final class WafRulesTest extends TestCase
{
    /** @return array<string, mixed> */
    private static function vectors(): array
    {
        return json_decode((string) file_get_contents(dirname(__DIR__) . '/vectors/waf.json'), true, 512, JSON_THROW_ON_ERROR);
    }

    /** @param array{path: string, query: string, params: list<string>, userAgent: string} $r @return array<string, mixed> */
    private static function request(array $r): array
    {
        return ['path' => $r['path'], 'query' => $r['query'], 'params' => $r['params'], 'user_agent' => $r['userAgent']];
    }

    /** @return array<string, array{array<string, mixed>, string}> */
    public static function attacks(): array
    {
        $out = [];
        foreach (self::vectors()['attacks'] as $v) {
            $out[$v['name']] = [self::request($v['request']), $v['rule']];
        }

        return $out;
    }

    /** @param array<string, mixed> $request */
    #[DataProvider('attacks')]
    public function testAttacksAreCaught(array $request, string $rule): void
    {
        self::assertSame($rule, WafRules::inspect($request));
    }

    /** @return array<string, array{array<string, mixed>}> */
    public static function ordinary(): array
    {
        $out = [];
        foreach (self::vectors()['ordinary'] as $v) {
            $out[$v['name']] = [self::request($v['request'])];
        }

        return $out;
    }

    /** @param array<string, mixed> $request */
    #[DataProvider('ordinary')]
    public function testOrdinaryRequestsPass(array $request): void
    {
        self::assertNull(WafRules::inspect($request));
    }

    public function testFlatten(): void
    {
        self::assertSame(['a', '1', 'b', 'c', '2'], WafRules::flatten(['a' => 1, 'b' => ['c' => 2]]));
        // Past the limit, values are not dropped: they are joined into one more string.
        self::assertSame(['1', '2', '3', "4\n5\n6\n7\n8\n9\n10"], WafRules::flatten(range(1, 10), 3));
    }

    public function testPaddingAndNestingCannotHideAnAttack(): void
    {
        $attack = "' OR '1'='1";
        $padded = array_fill(0, 250, 'harmless');
        $padded[] = $attack;
        self::assertSame('sqli', WafRules::inspect(['params' => WafRules::flatten($padded)]), 'value 251 of a padded form');
        $deep = ['a' => ['b' => ['c' => ['d' => ['e' => ['f' => ['g' => $attack]]]]]]];
        self::assertSame('sqli', WafRules::inspect(['params' => WafRules::flatten($deep)]), 'nested 7 levels deep');
        self::assertNull(WafRules::inspect(['params' => WafRules::flatten(array_fill(0, 500, 'harmless text'))]));
        $big = WafRules::flatten(array_fill(0, 5000, str_repeat('x', 200)));
        self::assertLessThanOrEqual(WafRules::REST_MAX, strlen((string) end($big)));
    }
}
