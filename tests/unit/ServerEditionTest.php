<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Server\Config;
use DracoInsomnis\Server\ServerHost;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/server/autoload.php';

final class ServerEditionTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite');
        }
        $this->dir = sys_get_temp_dir() . '/draco-server-' . getmypid() . '-' . bin2hex(random_bytes(3));
        mkdir($this->dir . '/state', 0777, true);
        file_put_contents($this->dir . '/draco.ini', "waf_mode = \"log\"\n[firewall]\nanticopy_rate_ip = \"90\"\n\n[site:shop.example.com]\nwaf_mode = \"block\"\n");
        putenv('DRACO_CONFIG=' . $this->dir . '/draco.ini');
    }

    protected function tearDown(): void
    {
        putenv('DRACO_CONFIG');
        exec('rm -rf ' . escapeshellarg($this->dir));
    }

    public function test_site_sections_override_for_the_host_and_its_subdomains(): void
    {
        $this->assertSame('log', Config::forHost('other.org')['waf_mode']);
        $this->assertSame('90', Config::forHost('other.org')['anticopy_rate_ip'], 'other sections are global');
        $this->assertSame('block', Config::forHost('shop.example.com')['waf_mode']);
        $this->assertSame('block', Config::forHost('www.shop.example.com:8443')['waf_mode']);
        $this->assertSame('log', Config::forHost('example.com')['waf_mode']);
        $this->assertSame('off', Config::forHost('')['pace_mode'], 'defaults fill the rest');
    }

    public function test_set_changes_one_key_and_keeps_the_rest(): void
    {
        $this->assertTrue(Config::set('waf_mode', 'block'));
        $this->assertTrue(Config::set('pace_mode', 'log'));
        $this->assertTrue(Config::set('pace_mode', 'block', 'blog.example.org'));
        $this->assertTrue(Config::set('headers', '1', 'shop.example.com'));
        $this->assertSame('block', Config::forHost('x.org')['waf_mode']);
        $this->assertSame('log', Config::forHost('x.org')['pace_mode']);
        $this->assertSame('block', Config::forHost('blog.example.org')['pace_mode']);
        $this->assertSame('1', Config::forHost('shop.example.com')['headers']);
        $this->assertSame('block', Config::forHost('shop.example.com')['waf_mode']);
        $this->assertFalse(Config::set('bad key', 'x'));
        $this->assertStringContainsString('[firewall]', (string) file_get_contents($this->dir . '/draco.ini'));
    }

    public function test_store_blocks_ranges_never_admins_and_allows_after_review(): void
    {
        $host = new ServerHost(array_merge(Config::forHost(''), ['admin_ips' => '198.51.100.7']), $this->dir . '/state/u1');
        $this->assertTrue($host->ready());
        $store = $host->store();
        $this->assertTrue($store->block('net', '203.0.113.0/24', 0, 'test'));
        $this->assertTrue($store->isBlocked('', '203.0.113.9'));
        $this->assertFalse($store->block('ip', '198.51.100.7', 30, 'admin'));
        $this->assertFalse($store->block('net', '10.0.0.0/8', 30, 'too wide'));
        $this->assertTrue($store->allow('192.0.2.5', 1, 'review'));
        $this->assertContains('192.0.2.5', $host->adminIps());
        $this->assertSame(1, $host->bump('k', 60));
        $this->assertSame(2, $host->bump('k', 60));
    }

    public function test_one_secret_per_state_folder(): void
    {
        $a = new ServerHost(Config::forHost(''), $this->dir . '/state/u1');
        $b = new ServerHost(Config::forHost(''), $this->dir . '/state/u2');
        $a->ready();
        $b->ready();
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $a->secret());
        $this->assertSame($a->secret(), (new ServerHost(Config::forHost(''), $this->dir . '/state/u1'))->secret());
        $this->assertNotSame($a->secret(), $b->secret());
        $this->assertSame(0700, fileperms($this->dir . '/state/u1') & 0777);
    }

    public function test_crowdsec_durations(): void
    {
        $this->assertSame(14381, \DracoInsomnis\Server\CrowdSec::seconds('3h59m40.5s'));
        $this->assertSame(2700, \DracoInsomnis\Server\CrowdSec::seconds('45m'));
        $this->assertSame(1, \DracoInsomnis\Server\CrowdSec::seconds('250ms'));
        $this->assertSame(0, \DracoInsomnis\Server\CrowdSec::seconds('-5m'));
        $this->assertSame(0, \DracoInsomnis\Server\CrowdSec::seconds('soon'));
    }

    public function test_crowdsec_bans_are_imported_within_draco_limits(): void
    {
        $host = new ServerHost(Config::forHost(''), $this->dir . '/state/u1');
        $host->ready();
        $store = $host->store();
        $this->assertTrue($store->importBlock('203.0.113.9', time() + 600, 'CrowdSec: crowdsecurity/http-probing', []));
        $this->assertTrue($store->importBlock('198.51.100.0/24', time() + 600, 'CrowdSec: lists', []));
        $this->assertTrue($store->importBlock('203.0.113.9', time() + 900, 'CrowdSec: again', []), 'a newer decision replaces the old one');
        $this->assertFalse($store->importBlock('10.0.0.0/8', time() + 600, 'CrowdSec: too wide', []));
        $this->assertFalse($store->importBlock('192.0.2.1', time() + 600, 'CrowdSec: admin', ['192.0.2.1']));
        $this->assertFalse($store->importBlock('192.0.2.2', time() - 1, 'CrowdSec: expired', []));
        $this->assertTrue($store->isBlocked('', '203.0.113.9'));
        $this->assertTrue($store->isBlocked('', '198.51.100.77'));
        $this->assertCount(2, $store->activeBlocks());
        $store->block('ip', '192.0.2.50', 30, 'By hand');
        $this->assertSame(1, $store->removeImported('CrowdSec', '203.0.113.9'));
        $this->assertSame(1, $store->removeImported('CrowdSec', null));
        $this->assertSame(['192.0.2.50'], array_column($store->activeBlocks(), 'value'), 'blocks made by hand stay');
    }
}
