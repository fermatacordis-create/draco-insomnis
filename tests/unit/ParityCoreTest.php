<?php

declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Blocklist;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\GeoUpdate;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\SecurityHeaders;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/MemoryHost.php';

final class ParityCoreTest extends TestCase
{
    private const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36';
    private MemoryHost $host;
    private string $geo;

    protected function setUp(): void
    {
        $this->host = new MemoryHost();
        // 203.0.113.0/24 is "CN" in this small list; everything else has no country.
        $v4 = [['0.0.0.0', '--'], ['203.0.113.0', 'CN'], ['203.0.114.0', '--']];
        $bin = 'DRGEO1' . gmdate('Ymd') . pack('NN', count($v4), 0);
        foreach ($v4 as [$ip, $cc]) {
            $bin .= inet_pton($ip) . $cc;
        }
        $this->geo = sys_get_temp_dir() . '/draco-parity-' . getmypid() . '-' . mt_rand() . '.bin';
        file_put_contents($this->geo, $bin);
        $this->host->settings['geo_file'] = $this->geo;
    }

    protected function tearDown(): void
    {
        @unlink($this->geo);
    }

    private function req(string $ip, string $method = 'GET', string $path = '/', string $query = ''): Request
    {
        return new Request($method, $path, $query, $query === '' ? [] : [$query], [], self::UA, self::UA, $ip);
    }

    public function test_addresses_ranges_and_forever(): void
    {
        $this->assertSame(['kind' => 'ip', 'value' => '198.51.100.7'], Blocklist::address('198.51.100.7', 30, []));
        $this->assertSame(['kind' => 'net', 'value' => '198.51.100.0/24'], Blocklist::address(' 198.51.100.0/24 ', 0, []));
        $this->assertNull(Blocklist::address('10.0.0.0/8', 30, []), 'too wide');
        $this->assertNull(Blocklist::address('2001:db8::/16', 30, []), 'too wide');
        $this->assertNull(Blocklist::address('198.51.100.0/24', 30, ['198.51.100.9']), 'holds a protected address');
        $this->assertNull(Blocklist::address('198.51.100.9', 30, ['198.51.100.9']));
        $this->assertNull(Blocklist::address('198.51.100.7', 13, []), 'odd length');
        $this->assertNull(Blocklist::address('nonsense', 30, []));
        $this->assertSame(Blocklist::FOREVER_AT, Blocklist::untilAt(0, 1_800_000_000));
        $this->assertTrue(Blocklist::isForever(Blocklist::untilTs(0, 1_800_000_000)));
        $this->assertSame(1_800_000_000 + 7 * 86400, Blocklist::untilTs(7, 1_800_000_000));
    }

    public function test_security_headers_are_off_by_default_and_hsts_needs_https(): void
    {
        $this->assertSame([], SecurityHeaders::wanted($this->host, true));
        $this->host->settings['headers'] = '1';
        $this->assertSame('nosniff', SecurityHeaders::wanted($this->host, false)['X-Content-Type-Options']);
        $this->host->settings['hsts'] = '1';
        $this->assertArrayNotHasKey('Strict-Transport-Security', SecurityHeaders::wanted($this->host, false));
        $this->assertSame('max-age=15552000', SecurityHeaders::wanted($this->host, true)['Strict-Transport-Security']);
    }

    public function test_the_country_filter_logs_or_blocks_and_never_counts_towards_a_block(): void
    {
        $gate = new Gatekeeper($this->host);
        $this->host->settings += ['geo_mode' => 'block', 'geo_countries' => 'CN', 'geo_action' => 'log'];
        $this->assertNull($gate->decide($this->req('203.0.113.10'), 'log', 'off', ['/login']), 'reading the site is not sensitive');
        $this->assertNull($gate->decide($this->req('203.0.113.10', 'POST'), 'log', 'off', ['/login']), 'log only');
        $this->assertSame('waf:geo', $this->host->logged[0]['endpoint']);
        $this->host->settings['geo_action'] = 'block';
        for ($i = 0; $i < 6; $i++) {
            $d = $gate->decide($this->req('203.0.113.10', 'GET', '/login'), 'log', 'off', ['/login']);
        }
        $this->assertSame(['status' => 403, 'why' => 'geo', 'retry' => 0], $d);
        $this->assertSame([], $this->host->blocks, 'a country never puts an address on the block list');
        $this->assertNull($gate->decide($this->req('198.51.100.5', 'POST'), 'log', 'off', ['/login']), 'no country, no filter');
        $this->host->settings['geo_scope'] = 'site';
        $this->assertSame('geo', $gate->decide($this->req('203.0.113.10'), 'log', 'off', [])['why']);
        $this->host->settings['geo_mode'] = 'allow';
        $this->assertNull($gate->decide($this->req('203.0.113.10'), 'log', 'off', []), 'CN is the allowed one');
        $this->host->admins = ['203.0.113.10'];
        $this->host->settings['geo_mode'] = 'block';
        $this->assertNull($gate->decide($this->req('203.0.113.10'), 'log', 'off', []), 'administrators are never filtered');
        $this->host->settings['geo_mode'] = 'off';
        $this->host->admins = [];
        $this->assertNull($gate->decide($this->req('203.0.113.10'), 'log', 'off', []));
    }

    public function test_the_gatekeeper_keeps_the_old_order(): void
    {
        $gate = new Gatekeeper($this->host);
        $attack = "s=1' union select user_pass from users-- ";
        $this->assertNull($gate->decide($this->req('198.51.100.20', 'GET', '/', $attack), 'off', 'off', []));
        $this->assertNull($gate->decide($this->req('198.51.100.20', 'GET', '/', $attack), 'log', 'off', []));
        $this->assertSame('sqli', $gate->decide($this->req('198.51.100.20', 'GET', '/', $attack), 'block', 'off', [])['why']);
        $this->host->blocks[] = ['kind' => 'ip', 'value' => '198.51.100.21', 'days' => 7, 'reason' => 'x'];
        $this->assertNull($gate->decide($this->req('198.51.100.21'), 'block', 'off', []), 'blocked addresses can read');
        $this->assertSame('blocked', $gate->decide($this->req('198.51.100.21', 'POST'), 'block', 'off', [])['why']);
        $this->host->settings['anticopy_rate_ip'] = '10';
        $last = null;
        for ($i = 0; $i < 25 && $last === null; $i++) {
            $last = $gate->decide($this->req('198.51.100.22'), 'off', 'block', []);
        }
        $this->assertSame(429, $last['status']);
        $this->assertGreaterThan(0, $last['retry']);
    }

    public function test_a_fresh_country_list_is_not_stale(): void
    {
        $this->assertFalse(GeoUpdate::stale($this->geo, time()));
        $this->assertTrue(GeoUpdate::stale('/nonexistent', time()));
        $this->assertTrue(GeoUpdate::stale($this->geo, time() + 40 * 86400));
    }
}
