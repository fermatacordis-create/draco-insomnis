<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Request;
use PHPUnit\Framework\TestCase;

/** What sits in front of the site, from the administrator's own visit, and the setting that fits it. */
final class ProxySetupTest extends TestCase
{
    private function setup_for(string $remote, string $cf = '', string $xff = ''): array
    {
        return (new Request(remoteAddr: $remote, cfConnectingIp: $cf, forwardedFor: $xff))->proxySetup();
    }

    public function test_a_site_reached_directly_keeps_the_connection_address(): void
    {
        $this->assertSame(['kind' => 'direct', 'recommend' => '', 'remote' => '178.139.10.20'], $this->setup_for('178.139.10.20'));
    }

    public function test_cloudflare_is_recognised_only_when_the_connection_comes_from_cloudflare(): void
    {
        $this->assertSame('cf', $this->setup_for('172.68.10.1', '178.139.10.20')['recommend']);
        $this->assertSame('cloudflare', $this->setup_for('2606:4700:10::1', '2001:db8::5')['kind']);
        // The same header from anywhere else is not Cloudflare: anyone can send it.
        $this->assertSame(['kind' => 'direct', 'recommend' => ''], array_slice($this->setup_for('178.139.10.20', '203.0.113.9'), 0, 2));
    }

    public function test_a_proxy_on_the_server_itself_or_a_private_network_recommends_x_forwarded_for(): void
    {
        $this->assertSame(['kind' => 'local', 'recommend' => 'xff'], array_slice($this->setup_for('127.0.0.1', '', '178.139.10.20'), 0, 2));
        $this->assertSame('xff', $this->setup_for('10.0.3.7', '', '178.139.10.20, 10.0.3.1')['recommend']);
    }

    public function test_a_public_proxy_is_reported_but_the_safe_choice_stays(): void
    {
        $this->assertSame(['kind' => 'remote', 'recommend' => ''], array_slice($this->setup_for('151.101.1.1', '', '178.139.10.20'), 0, 2));
    }

    public function test_the_visitors_own_office_proxy_is_not_taken_for_a_cdn(): void
    {
        // A proxy in the administrator's network writes their private address.
        $this->assertSame('direct', $this->setup_for('178.139.10.20', '', '192.168.1.34')['kind']);
        $this->assertSame('direct', $this->setup_for('178.139.10.20', '', '178.139.10.20')['kind']);
    }
}
