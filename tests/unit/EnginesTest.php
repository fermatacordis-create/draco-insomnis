<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Pace;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\Shield;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/MemoryHost.php';

/** The engines every CMS adapter shares, run without any CMS. */
final class EnginesTest extends TestCase
{
    private const BROWSER = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';
    private const VISITOR = '203.0.113.7';
    private const NOW = 1_800_000_000;

    private MemoryHost $host;

    protected function setUp(): void
    {
        $this->host = new MemoryHost();
    }

    /** @param array<string, string> $post */
    private function request(array $post = [], string $path = '/', string $query = '', string $ua = self::BROWSER, string $method = 'POST'): Request
    {
        return new Request($method, $path, $query, [], $post, $ua, $ua, self::VISITOR, '', '', 'https://example.org/register');
    }

    private function person(Shield $shield): Request
    {
        return $this->request([$shield->stampField() => $shield->stamp(self::NOW - 40)]);
    }

    private function bot(Shield $shield): Request
    {
        return $this->request([$shield->trapField() => 'http://spam.example']);
    }

    private const FIELDS = ['username' => 'usru88w16kx', 'email' => 'bot@spam.example', 'role' => ''];

    public function test_field_names_depend_on_the_site_secret(): void
    {
        $shield = new Shield($this->host);
        $this->assertMatchesRegularExpression('/^dr_[a-f0-9]{8}$/', $shield->stampField());
        $this->assertMatchesRegularExpression('/^[a-z_]+_[a-f0-9]{4}$/', $shield->trapField());
        $html = $shield->fieldsHtml(self::NOW);
        $this->assertStringContainsString('name="' . $shield->stampField() . '"', $html);
        $this->assertStringContainsString('name="' . $shield->trapField() . '"', $html);
    }

    public function test_a_person_passes_and_leaves_no_trace(): void
    {
        $shield = new Shield($this->host);
        $result = $shield->judge($this->person($shield), 'test', ['username' => 'maria1985', 'email' => 'maria@example.org', 'role' => ''], null, self::NOW);
        $this->assertSame('clean', $result['verdict']);
        $this->assertSame([], $this->host->logged);
    }

    public function test_a_bot_is_logged_with_evidence_and_three_block_the_address(): void
    {
        $shield = new Shield($this->host);
        $result = $shield->judge($this->bot($shield), 'test', self::FIELDS, null, self::NOW);
        $this->assertSame('bot', $result['verdict']);
        $this->assertContains('honeypot', $result['reasons']);
        $this->assertSame('bot@spam.example', $this->host->logged[0]['fields']['email']);
        $this->assertSame('https://example.org/register', $this->host->logged[0]['fields']['referer']);
        $this->assertSame([], $this->host->blocks);

        $shield->judge($this->bot($shield), 'test', self::FIELDS, null, self::NOW);
        $shield->judge($this->bot($shield), 'test', self::FIELDS, null, self::NOW);
        $this->assertCount(1, $this->host->blocks);
        $this->assertSame(['kind' => 'ip', 'value' => self::VISITOR, 'days' => 7, 'reason' => 'auto_block:3'], $this->host->blocks[0]);
    }

    public function test_a_proxy_header_sent_straight_to_the_site_is_ignored(): void
    {
        // The visitor connects directly and writes the headers itself.
        $r = new Request('POST', '/', '', [], [], self::BROWSER, self::BROWSER, self::VISITOR, '198.51.100.2', '198.51.100.1, 10.0.0.1');
        $this->assertSame(self::VISITOR, $r->ip(''));
        $this->assertSame(self::VISITOR, $r->ip('cf'));
        $this->assertSame(self::VISITOR, $r->ip('xff'));
        $this->assertTrue($r->proxyHeaderIgnored('cf'));
        $this->assertTrue($r->proxyHeaderIgnored('xff'));
        $this->assertFalse($r->proxyHeaderIgnored(''));
    }

    public function test_cloudflare_header_is_believed_only_from_cloudflare(): void
    {
        $viaCloudflare = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '172.68.1.20', self::VISITOR);
        $this->assertSame(self::VISITOR, $viaCloudflare->ip('cf'));
        $this->assertFalse($viaCloudflare->proxyHeaderIgnored('cf'));
        $viaCloudflare6 = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '2a06:98c0:3600::103', self::VISITOR);
        $this->assertSame(self::VISITOR, $viaCloudflare6->ip('cf'));
        // A proxy of the site's own, in front of Cloudflare's header, once listed.
        $ownProxy = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '198.51.100.9', self::VISITOR);
        $this->assertSame('198.51.100.9', $ownProxy->ip('cf'));
        $this->assertSame(self::VISITOR, $ownProxy->ip('cf', "198.51.100.9 # load balancer"));
        // Junk in the header: the connection address.
        $junk = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '172.68.1.20', 'not-an-ip');
        $this->assertSame('172.68.1.20', $junk->ip('cf'));
    }

    public function test_forwarded_for_is_read_from_the_right_and_skips_trusted_proxies(): void
    {
        // nginx on the same machine; the visitor wrote "1.2.3.4" itself, the proxy added the real address.
        $local = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '127.0.0.1', '', '1.2.3.4, ' . self::VISITOR);
        $this->assertSame(self::VISITOR, $local->ip('xff'));
        // Two of the site's proxies: a public load balancer and a private one.
        $chain = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '198.51.100.9', '', '1.2.3.4, ' . self::VISITOR . ', 10.0.0.5');
        $this->assertSame('198.51.100.9', $chain->ip('xff'), 'a public proxy must be listed');
        $this->assertSame(self::VISITOR, $chain->ip('xff', "198.51.100.0/24\n10.0.0.0/8"));
        $this->assertSame(self::VISITOR, $chain->ip('xff', '198.51.100.0/24, 10.0.0.0/8'));
        // Junk in the chain stops the walk at the last trusted hop.
        $junk = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '127.0.0.1', '', 'evil, x');
        $this->assertSame('127.0.0.1', $junk->ip('xff'));
    }

    public function test_a_forged_header_cannot_pose_as_an_administrator(): void
    {
        $this->host->admins = ['192.0.2.50'];
        $this->host->settings['proxy_header'] = 'xff';
        $firewall = new Firewall($this->host, true);
        $direct = new Request('GET', '/', "s=1' union select user_pass from users-- ", [], [], self::BROWSER, self::BROWSER, self::VISITOR, '', '192.0.2.50');
        $this->assertFalse($firewall->exempt($direct));
        $this->assertSame('sqli', $firewall->inspect($direct));
        $local = new Request('GET', '/', '', [], [], self::BROWSER, self::BROWSER, '127.0.0.1', '', '192.0.2.50');
        $this->assertTrue($firewall->exempt($local));
    }

    public function test_the_verdict_can_be_changed_by_site_code(): void
    {
        $this->host->filters['verdict'] = static fn (array $result): array => ['verdict' => 'clean'] + $result;
        $shield = new Shield($this->host);
        $this->assertSame('clean', $shield->judge($this->bot($shield), 'test', self::FIELDS, null, self::NOW)['verdict']);
    }

    public function test_the_firewall_logs_only_until_it_blocks_and_five_attacks_block(): void
    {
        $attack = $this->request([], '/', "s=1' union select user_pass from users-- ", self::BROWSER, 'GET');
        $log = new Firewall($this->host, false);
        $this->assertSame('sqli', $log->inspect($attack));
        $this->assertSame('doubtful', $this->host->logged[0]['verdict']);
        $this->assertSame([], $this->host->blocks);

        $block = new Firewall($this->host, true);
        for ($i = 0; $i < 5; $i++) {
            $block->inspect($attack);
        }
        $this->assertCount(1, $this->host->blocks);
        $this->assertSame('waf_block:5', $this->host->blocks[0]['reason']);
        $this->assertTrue($block->refusedAsBlocked($this->request(), []), 'a blocked address may not post');
        $this->assertFalse($block->refusedAsBlocked($this->request([], '/', '', self::BROWSER, 'GET'), ['/login']), 'but may read');
        $this->assertTrue($block->refusedAsBlocked($this->request([], '/shop/login', '', self::BROWSER, 'GET'), ['/login']));
    }

    public function test_the_firewall_never_inspects_an_administrator_address(): void
    {
        $this->host->admins = [self::VISITOR];
        $this->assertTrue((new Firewall($this->host, true))->exempt($this->request()));
    }

    public function test_the_403_page_escapes_its_texts(): void
    {
        $page = Firewall::page('<b>Blocked</b>', 'Text & more', 'sqli');
        $this->assertStringContainsString('&lt;b&gt;Blocked&lt;/b&gt;', $page);
        $this->assertStringContainsString('Text &amp; more', $page);
    }

    public function test_pace_counts_per_minute_and_flags_the_first_request_over_the_limit(): void
    {
        $this->host->settings['anticopy_rate_ip'] = '10';
        $pace = new Pace($this->host);
        $r = $this->request([], '/page', '', self::BROWSER, 'GET');
        for ($i = 0; $i < 10; $i++) {
            $this->assertSame('', $pace->count($r, self::NOW)['over']);
        }
        $over = $pace->count($r, self::NOW);
        $this->assertSame('ip', $over['over']);
        $this->assertTrue($over['first']);
        $this->assertFalse($pace->count($r, self::NOW)['first']);
        $this->assertSame('', $pace->count($r, self::NOW + 60)['over'], 'a new minute starts again');
    }

    public function test_a_crawler_name_alone_is_not_trusted_but_site_code_can_vouch(): void
    {
        $pace = new Pace($this->host);
        $this->assertFalse($pace->verifiedCrawler(self::VISITOR, 'curl/8'), 'claims no crawler: no DNS lookup');
        $this->host->filters['crawler_verified'] = static fn ($forced, string $ip, string $claimed): bool => $claimed === 'googlebot';
        $this->assertTrue($pace->verifiedCrawler(self::VISITOR, 'Mozilla/5.0 (compatible; Googlebot/2.1)'));
    }
}
