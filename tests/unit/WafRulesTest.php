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
        self::assertCount(3, WafRules::flatten(range(1, 10), 3));
    }
}
