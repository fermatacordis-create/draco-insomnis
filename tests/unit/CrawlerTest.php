<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Crawler;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/Core/Crawler.php';

final class CrawlerTest extends TestCase
{
    /** @return array<string, array{string, string}> */
    public static function agents(): array
    {
        return [
            'googlebot' => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'googlebot'],
            'googlebot smartphone' => ['Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X) AppleWebKit/537.36 Chrome/131.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'googlebot'],
            'bingbot' => ['Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', 'bingbot'],
            'applebot' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)', 'applebot'],
            'yandex' => ['Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)', 'yandex'],
            'browser' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36', ''],
            'scraper' => ['python-requests/2.32.3', ''],
            'empty' => ['', ''],
        ];
    }

    #[DataProvider('agents')]
    public function testWhoAUserAgentClaimsToBe(string $ua, string $claimed): void
    {
        self::assertSame($claimed, Crawler::claimed($ua));
    }

    /** @return array<string, array{string, string, bool}> */
    public static function hosts(): array
    {
        return [
            'google' => ['googlebot', 'crawl-66-249-66-1.googlebot.com', true],
            'google with dot' => ['googlebot', 'crawl-66-249-66-1.googlebot.com.', true],
            'google other domain' => ['googlebot', 'rate-limited-proxy-66-249-90-77.google.com', true],
            'bing' => ['bingbot', 'msnbot-157-55-39-1.search.msn.com', true],
            'apple' => ['applebot', '17-58-101-179.applebot.apple.com', true],
            'yandex' => ['yandex', '5-255-253-1.spider.yandex.com', true],
            'lookalike suffix' => ['googlebot', 'crawl.googlebot.com.evil.example', false],
            'lookalike prefix' => ['googlebot', 'evilgooglebot.com', false],
            'wrong engine' => ['bingbot', 'crawl-66-249-66-1.googlebot.com', false],
            'no reverse name' => ['googlebot', '66.249.66.1', false],
            'unknown crawler' => ['someone', 'host.googlebot.com', false],
            'empty' => ['googlebot', '', false],
        ];
    }

    #[DataProvider('hosts')]
    public function testReverseNameMustBelongToTheEngine(string $claimed, string $host, bool $ok): void
    {
        self::assertSame($ok, Crawler::hostMatches($claimed, $host));
    }

    public function testNetworks(): void
    {
        self::assertSame('203.0.113.0/24', Crawler::network('203.0.113.77'));
        self::assertSame('2001:db8:1:2::/64', Crawler::network('2001:db8:1:2:aaaa:bbbb:cccc:dddd'));
        self::assertSame('', Crawler::network('not-an-ip'));
        self::assertSame(Crawler::network('198.51.100.1'), Crawler::network('198.51.100.254'));
        self::assertNotSame(Crawler::network('198.51.100.1'), Crawler::network('198.51.101.1'));
    }
}
