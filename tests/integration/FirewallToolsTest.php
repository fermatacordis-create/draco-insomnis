<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\Review;
use DracoInsomnis\Firewall\Waf;
use DracoInsomnis\Shield\Store;
use DracoInsomnis\WpHost;

final class FirewallToolsTest extends TestCase
{
    public function test_a_range_and_a_forever_block(): void
    {
        $this->assertTrue(Store::block('ip', '198.51.100.0/24', 0, 'range'));
        $this->assertTrue(Store::isBlocked('', '198.51.100.77'));
        $this->assertFalse(Store::isBlocked('', '198.51.101.1'));
        $rows = Store::activeBlocks();
        $this->assertSame('net', $rows[0]['kind']);
        $this->assertSame(Store::FOREVER, $rows[0]['until_at']);
    }

    public function test_ranges_too_wide_or_holding_an_administrator_are_refused(): void
    {
        $this->assertFalse(Store::block('ip', '10.0.0.0/8', 30, 'too wide'));
        $this->assertFalse(Store::block('ip', '2001:db8::/16', 30, 'too wide'));
        $this->assertFalse(Store::block('ip', 'nonsense/24', 30, 'junk'));
        $this->assertFalse(Store::block('ip', '203.0.113.0/24', 30, 'holds my own address'), 'the visitor in tests is 203.0.113.10');
        update_option('draco_admin_ips', ['192.0.2.9']);
        $this->assertFalse(Store::block('ip', '192.0.2.0/24', 30, 'holds an administrator'));
        $this->assertFalse(Store::block('ip', '192.0.2.10', 13, 'odd number of days'));
    }

    public function test_a_review_request_is_kept_only_when_signed_and_real(): void
    {
        $ip = '198.51.100.20';
        $good = Review::signedFields($ip, 'sqli', time() - 30) + ['draco_email' => 'ana@example.org', 'draco_message' => 'I was searching for a product'];
        $this->assertFalse(Review::accept(['draco_sig' => 'x'] + $good, $ip), 'forged signature');
        $this->assertFalse(Review::accept($good, '198.51.100.21'), 'signed for another address');
        $this->assertFalse(Review::accept(['draco_website' => 'spam'] + $good, $ip), 'trap filled');
        $this->assertFalse(Review::accept(Review::signedFields($ip, 'sqli', time() - 90000) + $good, $ip), 'older than a day');
        $this->assertTrue(Review::accept($good, $ip));
        $this->assertTrue(Review::accept($good, $ip));
        $this->assertTrue(Review::accept($good, $ip));
        $this->assertFalse(Review::accept($good, $ip), 'three per address and day');
        $this->assertSame(3, Review::pendingCount());
        $this->assertCount(1, $this->mails, 'the owner is told once an hour at most');
    }

    public function test_letting_someone_through_unblocks_and_exempts_them(): void
    {
        $ip = '198.51.100.30';
        Store::block('ip', $ip, 30, 'auto', true);
        $this->assertTrue(Store::isBlocked('', $ip));
        $fields = Review::signedFields($ip, 'blocked', time()) + ['draco_email' => 'luis@example.org', 'draco_message' => 'I could not log in'];
        $this->assertTrue(Review::accept($fields, $ip));
        $id = (int) Review::recent()[0]['id'];
        $this->assertTrue(Review::decide($id, 'approve', 7));
        $this->assertFalse(Store::isBlocked('', $ip));
        $this->assertContains($ip, WpHost::get()->adminIps());
        $this->assertSame('approved', Review::find($id)['status']);
    }

    public function test_marking_an_attacker_blocks_the_address(): void
    {
        $ip = '198.51.100.40';
        Review::accept(Review::signedFields($ip, 'sqli', time()) + ['draco_email' => 'x@example.org', 'draco_message' => 'let me in'], $ip);
        $id = (int) Review::recent()[0]['id'];
        $this->assertTrue(Review::decide($id, 'attacker', 0));
        $this->assertTrue(Store::isBlocked('', $ip));
        $this->assertSame('attacker', Review::find($id)['status']);
    }

    public function test_the_summary_counts_the_last_seven_days(): void
    {
        update_option(Waf::OPTION_ENABLED, 'yes');
        update_option(Waf::OPTION_MODE, 'log');
        $_SERVER['REQUEST_URI'] = '/?s=' . rawurlencode(Waf::TEST_ATTACK);
        $_GET = ['s' => Waf::TEST_ATTACK];
        Waf::inspect();
        $sum = Store::wafSummary(7);
        $this->assertSame(1, $sum['total']);
        $this->assertSame(0, $sum['blocked']);
        $this->assertSame(['waf_sqli' => 1], $sum['rules']);
        $this->assertSame([self::VISITOR_IP => 1], $sum['ips']);
    }

    public function test_the_test_token_is_signed_and_short_lived(): void
    {
        $token = Waf::testToken(time());
        $this->assertMatchesRegularExpression('/^\d+\.[a-f0-9]{64}$/', $token);
        $this->assertNotSame($token, Waf::testToken(time() - 120));
    }
}
