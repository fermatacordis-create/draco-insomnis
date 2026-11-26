<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Server\Audit;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/server/autoload.php';

final class AuditTest extends TestCase
{
    private const MISSING = ['code' => 404, 'body' => '<h1>Not found</h1>'];

    /** @return array<string, array{string, array{code: int, body: string, location?: string}, array{code: int, body: string}, string}> */
    public static function answers(): array
    {
        $soft = ['code' => 200, 'body' => '<html>Home page, token 123</html>'];

        return [
            'refused' => ['/.env', ['code' => 403, 'body' => 'Forbidden'], self::MISSING, Audit::PROTECTED],
            'not there' => ['/backup.sql', ['code' => 404, 'body' => '<h1>Not found</h1>'], self::MISSING, Audit::ABSENT],
            'served' => ['/.env', ['code' => 200, 'body' => 'DB_PASSWORD=x'], self::MISSING, Audit::EXPOSED],
            'installer ran and failed' => ['/core/install.php', ['code' => 500, 'body' => 'error'], self::MISSING, Audit::RAN],
            'tool folder ran and failed' => ['/phpmyadmin/', ['code' => 502, 'body' => ''], self::MISSING, Audit::RAN],
            'error on a non-PHP file' => ['/.git/config', ['code' => 503, 'body' => ''], self::MISSING, Audit::REVIEW],
            'redirect is for a person to look at' => ['/phpmyadmin/', ['code' => 302, 'body' => '', 'location' => 'https://x/phpmyadmin/index.php'], self::MISSING, Audit::REVIEW],
            'soft 404: home page for everything' => ['/.env', ['code' => 200, 'body' => '<html>Home page, token 987</html>'], $soft, Audit::ABSENT],
            'a different page is served' => ['/.env', ['code' => 200, 'body' => 'APP_KEY=base64'], $soft, Audit::EXPOSED],
            '403 to everything proves nothing' => ['/.env', ['code' => 403, 'body' => 'Maintenance'], ['code' => 403, 'body' => 'Maintenance'], Audit::REVIEW],
            'no answer' => ['/.env', ['code' => 0, 'body' => ''], self::MISSING, Audit::ERROR],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('answers')]
    public function test_each_answer_means(string $path, array $answer, array $baseline, string $result): void
    {
        $this->assertSame($result, Audit::classify($path, $answer, $baseline)[0]);
    }

    public function test_never_asks_for_update_php(): void
    {
        $all = array_merge(...array_values(Audit::PATHS));
        $this->assertNotContains('/update.php', $all);
        $this->assertNotContains('/core/update.php', $all);
        $this->assertSame($all, array_values(array_unique($all)));
    }

    public function test_run_compares_with_a_missing_path_and_fails_only_on_exposed_or_ran(): void
    {
        $asked = [];
        $fetch = static function (string $url) use (&$asked): array {
            $asked[] = $url;
            if (str_ends_with($url, '/.env')) {
                return ['code' => 200, 'body' => 'SECRET=1', 'location' => ''];
            }

            return ['code' => str_contains($url, 'draco-audit-') ? 404 : 403, 'body' => '', 'location' => ''];
        };
        $rows = Audit::run('https://example.com/', $fetch, 0);
        $this->assertStringContainsString('https://example.com/draco-audit-', $asked[0]);
        $this->assertCount(count(array_merge(...array_values(Audit::PATHS))) + 1, $asked);
        $this->assertSame([Audit::EXPOSED], array_values(array_unique(array_column(array_filter($rows, static fn ($r) => $r['path'] === '/.env'), 'result'))));
        $this->assertTrue(Audit::failed($rows));
        $this->assertFalse(Audit::failed(array_values(array_filter($rows, static fn ($r) => $r['path'] !== '/.env'))));
    }
}
