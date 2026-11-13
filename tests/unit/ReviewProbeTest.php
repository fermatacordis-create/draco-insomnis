<?php

declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\Review;
use DracoInsomnis\Core\Summary;
use DracoInsomnis\Core\TestProbe;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/MemoryHost.php';

final class ReviewProbeTest extends TestCase
{
    private const NOW = 1_800_000_000;
    private const UA = 'Mozilla/5.0 Chrome/131.0';

    private function req(string $ip): Request
    {
        return new Request('POST', '/', '', [], [], self::UA, self::UA, $ip);
    }

    public function test_the_block_page_form_is_signed_and_has_a_trap(): void
    {
        $host = new MemoryHost();
        $html = (new Review($host))->form($this->req('198.51.100.20'), 'sqli', self::NOW, ['email' => 'E-mail', 'message' => 'Why', 'button' => 'Ask']);
        $this->assertStringContainsString('name="draco_review" value="1"', $html);
        $this->assertStringContainsString('name="draco_website"', $html);
        $this->assertMatchesRegularExpression('/name="draco_sig" value="[a-f0-9]{64}"/', $html);
    }

    public function test_a_review_is_kept_only_when_signed_and_real_and_within_limits(): void
    {
        $host = new MemoryHost();
        $review = new Review($host);
        $ip = '198.51.100.20';
        $good = $review->signedFields($ip, 'sqli', self::NOW - 30) + ['draco_review' => '1', 'draco_email' => 'Ana@Example.org', 'draco_message' => '<b>I was</b> searching'];
        $this->assertTrue(Review::isRequest($this->req($ip), $good));
        $this->assertFalse($review->accept($this->req($ip), ['draco_sig' => 'x'] + $good, self::NOW), 'forged signature');
        $this->assertFalse($review->accept($this->req('198.51.100.21'), $good, self::NOW), 'signed for another address');
        $this->assertFalse($review->accept($this->req($ip), ['draco_website' => 'x'] + $good, self::NOW), 'trap filled');
        $this->assertFalse($review->accept($this->req($ip), $review->signedFields($ip, 'sqli', self::NOW - 90000) + $good, self::NOW), 'older than a day');
        $this->assertTrue($review->accept($this->req($ip), $good, self::NOW));
        $this->assertTrue($review->accept($this->req($ip), $good, self::NOW));
        $this->assertTrue($review->accept($this->req($ip), $good, self::NOW));
        $this->assertFalse($review->accept($this->req($ip), $good, self::NOW), 'three per address and day');
        $this->assertCount(3, $host->logged);
        $this->assertSame('review', $host->logged[0]['endpoint']);
        $this->assertSame('pending', $host->logged[0]['verdict']);
        $this->assertSame('ana@example.org', $host->logged[0]['fields']['email']);
        $this->assertSame('I was searching', $host->logged[0]['fields']['referer'], 'no markup kept');
        $this->assertCount(1, $host->notices, 'one notice an hour at most');
        $this->assertSame('review_subject:0', $host->notices[0][0]);
    }

    public function test_the_test_probe_answers_only_to_its_own_signed_header(): void
    {
        $host = new MemoryHost();
        $token = TestProbe::token($host, self::NOW);
        $this->assertNull(TestProbe::answer($host, '', 'block', self::NOW));
        $this->assertNull(TestProbe::answer($host, $token, 'block', self::NOW + 120), 'older than a minute');
        $this->assertNull(TestProbe::answer($host, (self::NOW) . '.' . str_repeat('a', 64), 'block', self::NOW), 'forged');
        $this->assertSame(['status' => 403, 'result' => 'sqli|block'], TestProbe::answer($host, $token, 'block', self::NOW));
        $this->assertSame(['status' => 200, 'result' => 'sqli|log'], TestProbe::answer($host, $token, 'log', self::NOW));
        $this->assertSame(['status' => 200, 'result' => 'off'], TestProbe::answer($host, $token, 'off', self::NOW));
        $this->assertSame([], $host->logged, 'a test is never logged');
    }

    public function test_the_summary_counts_rules_blocks_and_addresses(): void
    {
        $rows = [
            ['ip' => '198.51.100.1', 'verdict' => 'bot', 'reasons' => 'waf_sqli'],
            ['ip' => '198.51.100.1', 'verdict' => 'doubtful', 'reasons' => 'waf_sqli'],
            ['ip' => '198.51.100.2', 'verdict' => 'bot', 'reasons' => 'waf_scanner'],
        ];
        $this->assertSame(['total' => 3, 'blocked' => 2, 'rules' => ['waf_sqli' => 2, 'waf_scanner' => 1], 'ips' => ['198.51.100.1' => 2, '198.51.100.2' => 1]], Summary::waf($rows));
    }

    public function test_the_block_page_never_says_which_rule_matched(): void
    {
        $host = new MemoryHost();
        $form = (new Review($host))->form($this->req('203.0.113.9'), 'sqli', self::NOW, ['email' => 'E', 'message' => 'M', 'button' => 'B']);
        $this->assertStringNotContainsString('sqli', $form);
        $sealed = Review::seal($host->secret(), '203.0.113.9', (string) self::NOW, 'sqli');
        $this->assertSame('sqli', Review::open($host->secret(), '203.0.113.9', (string) self::NOW, $sealed));
        $this->assertSame('', Review::open($host->secret(), '203.0.113.9', (string) self::NOW, 'sqli'));
        $this->assertNotSame('sqli', Review::open($host->secret(), '198.51.100.1', (string) self::NOW, $sealed), 'another address cannot read it');
    }
}
