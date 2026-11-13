<?php

declare(strict_types=1);

namespace DracoInsomnis\Laravel\Tests\Feature;

use DracoInsomnis\Laravel\Store;
use DracoInsomnis\Laravel\Tests\TestCase;

final class ParityTest extends TestCase
{
    public function test_security_headers_only_when_switched_on(): void
    {
        $this->get('/')->assertOk()->assertHeaderMissing('X-Content-Type-Options');
        config(['draco.headers' => true]);
        $this->get('/')->assertHeader('X-Content-Type-Options', 'nosniff')->assertHeader('X-Frame-Options', 'SAMEORIGIN')->assertHeaderMissing('Strict-Transport-Security');
    }

    public function test_a_range_blocked_forever_can_read_but_not_post(): void
    {
        config(['draco.waf_mode' => 'block']);
        $net = implode('.', array_slice(explode('.', self::VISITOR), 0, 3)) . '.0/24';
        $this->assertTrue((new Store())->block('ip', $net, 0, 'range', true));
        $this->assertSame('net', $this->blocks()[0]->kind);
        $this->assertSame('9999-12-31 23:59:59', $this->blocks()[0]->until_at);
        $this->get('/')->assertOk();
        $this->post('/')->assertForbidden();
        $this->assertFalse((new Store())->block('ip', '10.0.0.0/8', 30, 'too wide', true));
    }

    public function test_the_country_filter_uses_a_local_list(): void
    {
        $file = sys_get_temp_dir() . '/draco-geo-' . getmypid() . '.bin';
        $rows = [['0.0.0.0', '--'], [self::VISITOR, 'CN'], [long2ip(ip2long(self::VISITOR) + 1), '--']];
        $bin = 'DRGEO1' . gmdate('Ymd') . pack('NN', count($rows), 0);
        foreach ($rows as [$ip, $cc]) {
            $bin .= inet_pton($ip) . $cc;
        }
        file_put_contents($file, $bin);
        config(['draco.waf_mode' => 'log', 'draco.geo_file' => $file, 'draco.geo_mode' => 'block', 'draco.geo_countries' => 'CN', 'draco.geo_action' => 'block']);
        $this->get('/')->assertOk();
        $this->post('/')->assertForbidden();
        $this->assertSame('waf:geo', $this->events()[0]->endpoint);
        $this->assertSame([], $this->blocks());
        config(['draco.geo_mode' => 'allow']);
        $this->post('/')->assertOk()->assertSee('posted');
        config(['draco.geo_mode' => 'block']);
        $this->get('/login')->assertForbidden();
        @unlink($file);
    }
}
