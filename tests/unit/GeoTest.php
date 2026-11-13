<?php

declare(strict_types=1);

use DracoInsomnis\Core\Geo;
use PHPUnit\Framework\TestCase;

final class GeoTest extends TestCase
{
    private static string $file;

    public static function setUpBeforeClass(): void
    {
        // The same format bin/build-geo.php writes, with a handful of ranges.
        $v4 = [['0.0.0.0', '--'], ['1.0.0.0', 'AU'], ['1.0.1.0', 'CN'], ['1.0.4.0', '--'], ['203.0.113.0', 'ES'], ['203.0.114.0', '--']];
        $v6 = [['::', '--'], ['2a00::', 'ES'], ['2a01::', '--']];
        $bin = 'DRGEO1' . '20261113' . pack('NN', count($v4), count($v6));
        foreach ([...$v4, ...$v6] as [$ip, $cc]) {
            $bin .= inet_pton($ip) . $cc;
        }
        self::$file = sys_get_temp_dir() . '/draco-geo-test-' . getmypid() . '.bin';
        file_put_contents(self::$file, $bin);
    }

    public static function tearDownAfterClass(): void
    {
        @unlink(self::$file);
    }

    public function test_addresses_get_the_country_of_their_range(): void
    {
        $this->assertSame('AU', Geo::country(self::$file, '1.0.0.200'));
        $this->assertSame('CN', Geo::country(self::$file, '1.0.1.0'));
        $this->assertSame('CN', Geo::country(self::$file, '1.0.3.255'));
        $this->assertNull(Geo::country(self::$file, '1.0.4.0'), 'a gap has no country');
        $this->assertSame('ES', Geo::country(self::$file, '203.0.113.10'));
        $this->assertSame('ES', Geo::country(self::$file, '2a00:1450::1'));
        $this->assertNull(Geo::country(self::$file, '2a01::1'));
        $this->assertNull(Geo::country(self::$file, 'not an ip'));
        $this->assertSame('20261113', Geo::built(self::$file));
    }

    public function test_a_missing_or_foreign_file_gives_no_country(): void
    {
        $this->assertNull(Geo::country('/nonexistent/draco-geo.bin', '1.0.1.1'));
        $other = sys_get_temp_dir() . '/draco-geo-junk-' . getmypid() . '.bin';
        file_put_contents($other, str_repeat('x', 100));
        $this->assertSame('', Geo::built($other));
        $this->assertNull(Geo::country($other, '1.0.1.1'));
        @unlink($other);
    }

    public function test_country_lists_are_read_from_free_text(): void
    {
        $this->assertSame(['ES', 'FR', 'DE'], Geo::parseList("es, FR\nde es"));
    }
}
