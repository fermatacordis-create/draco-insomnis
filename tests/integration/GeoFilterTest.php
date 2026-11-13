<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\GeoFilter;
use DracoInsomnis\Firewall\Waf;
use DracoInsomnis\Shield\Store;
use DracoInsomnis\WpHost;

final class GeoFilterTest extends TestCase
{
    private string $file = '';

    protected function setUp(): void
    {
        parent::setUp();
        // The test visitor (203.0.113.10) is in "CN" in this small list.
        $v4 = [['0.0.0.0', '--'], ['203.0.113.0', 'CN'], ['203.0.114.0', '--']];
        $bin = 'DRGEO1' . gmdate('Ymd') . pack('NN', count($v4), 0);
        foreach ($v4 as [$ip, $cc]) {
            $bin .= inet_pton($ip) . $cc;
        }
        $this->file = get_temp_dir() . 'draco-geo-' . wp_generate_password(6, false) . '.bin';
        file_put_contents($this->file, $bin);
        add_filter('draco_insomnis_geo_file', fn (): string => $this->file);
        update_option(GeoFilter::OPTION_MODE, 'block');
        update_option(GeoFilter::OPTION_COUNTRIES, 'CN');
    }

    protected function tearDown(): void
    {
        wp_delete_file($this->file);
        parent::tearDown();
    }

    public function test_only_sensitive_requests_are_filtered_by_default(): void
    {
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()), 'reading the site is fine');
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $this->assertSame('CN', GeoFilter::refusedCountry(WpHost::request()));
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/wp-login.php';
        $this->assertSame('CN', GeoFilter::refusedCountry(WpHost::request()));
    }

    public function test_the_whole_site_and_the_allow_list(): void
    {
        update_option(GeoFilter::OPTION_SCOPE, 'site');
        $this->assertSame('CN', GeoFilter::refusedCountry(WpHost::request()));
        update_option(GeoFilter::OPTION_MODE, 'allow');
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()), 'CN is the only country allowed');
        update_option(GeoFilter::OPTION_COUNTRIES, 'ES, FR');
        $this->assertSame('CN', GeoFilter::refusedCountry(WpHost::request()));
    }

    public function test_administrators_reviews_and_unknown_addresses_pass(): void
    {
        update_option(GeoFilter::OPTION_SCOPE, 'site');
        update_option('draco_admin_ips', [self::VISITOR_IP]);
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()));
        update_option('draco_admin_ips', []);
        Store::allow(self::VISITOR_IP, 7, 'review');
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()));
        $_SERVER['REMOTE_ADDR'] = '198.51.100.5';
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()), 'no country for this address');
    }

    public function test_log_only_writes_it_down_without_counting_towards_a_block(): void
    {
        update_option(Waf::OPTION_ENABLED, 'yes');
        update_option(Waf::OPTION_MODE, 'block');
        update_option(GeoFilter::OPTION_ACTION, 'log');
        $_SERVER['REQUEST_METHOD'] = 'POST';
        for ($i = 0; $i < 6; $i++) {
            Waf::inspect();
        }
        $sum = Store::wafSummary(1);
        $this->assertSame(['waf_geo' => 6], $sum['rules']);
        $this->assertFalse(Store::isBlocked('', self::VISITOR_IP), 'a country never puts an address on the block list');
    }

    public function test_off_or_empty_list_does_nothing(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        update_option(GeoFilter::OPTION_COUNTRIES, '');
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()));
        update_option(GeoFilter::OPTION_COUNTRIES, 'CN');
        update_option(GeoFilter::OPTION_MODE, 'off');
        $this->assertSame('', GeoFilter::refusedCountry(WpHost::request()));
    }
}
