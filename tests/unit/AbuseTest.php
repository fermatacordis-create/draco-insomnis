<?php
declare(strict_types=1);

namespace Tests\Unit;

use DracoInsomnis\Core\Abuse;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2) . '/src/Core/Abuse.php';

final class AbuseTest extends TestCase
{
    /** RIPE-style: the abuse entity is at the top level. */
    private const RIPE = '{"handle":"198.51.100.0 - 198.51.100.255","startAddress":"198.51.100.0","endAddress":"198.51.100.255","name":"EXAMPLE-HOSTING","port43":"whois.ripe.net","cidr0_cidrs":[{"v4prefix":"198.51.100.0","length":24}],"entities":[{"handle":"ORG-1","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Hosting"]]]},{"handle":"AR1-RIPE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["email",{"type":"abuse"},"text","Abuse@Example-Hosting.net"]]]}]}';

    /** ARIN-style: the abuse contact is nested inside the organisation. */
    private const ARIN = '{"handle":"NET-203-0-113-0-1","name":"CLOUD-NET","startAddress":"203.0.113.0","endAddress":"203.0.113.255","links":[{"href":"https://rdap.arin.net/registry/ip/203.0.113.0"}],"entities":[{"handle":"CLOUD","roles":["registrant"],"entities":[{"handle":"NOC1-ARIN","roles":["technical"],"vcardArray":["vcard",[["email",{},"text","noc@cloud.example"]]]},{"handle":"ABUSE1-ARIN","roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@cloud.example"]]]}]}]}';

    public function test_ripe_abuse_contact_and_range(): void
    {
        $c = Abuse::contact('198.51.100.7', static fn (string $url) => str_ends_with($url, '198.51.100.7') ? self::RIPE : null);
        $this->assertSame('abuse@example-hosting.net', $c['email']);
        $this->assertSame('198.51.100.0/24', $c['range']);
        $this->assertSame('whois.ripe.net', $c['registry']);
        $this->assertStringContainsString('EXAMPLE-HOSTING', $c['network']);
        $this->assertSame('', $c['error']);
    }

    public function test_arin_nested_abuse_contact_wins_over_technical(): void
    {
        $c = Abuse::parse(json_decode(self::ARIN, true));
        $this->assertSame('abuse@cloud.example', $c['email']);
        $this->assertSame('rdap.arin.net', $c['registry']);
        $this->assertSame('203.0.113.0 - 203.0.113.255', $c['range']);
    }

    public function test_private_addresses_and_silent_registries(): void
    {
        $this->assertSame('not a public address', Abuse::contact('10.1.2.3', static fn () => self::RIPE)['error']);
        $this->assertSame('the registry did not answer', Abuse::contact('198.51.100.7', static fn () => null)['error']);
        $this->assertSame('no abuse contact in the registry', Abuse::parse(['name' => 'X', 'entities' => []])['error']);
    }

    public function test_the_draft_is_factual_and_never_threatens(): void
    {
        $rows = [
            ['created_at' => '2026-11-14 08:00:01', 'endpoint' => 'waf:sqli', 'verdict' => 'bot', 'reasons' => 'waf_sqli', 'user_agent' => "sqlmap/1.8\r\nX: y"],
            ['created_at' => '2026-11-14 08:00:05', 'endpoint' => 'waf:scanner', 'verdict' => 'bot', 'reasons' => 'waf_scanner', 'user_agent' => 'Nikto'],
        ];
        $d = Abuse::draft('198.51.100.7', $rows, 'https://example.org/', ['network' => 'EXAMPLE-HOSTING', 'range' => '198.51.100.0/24']);
        $this->assertStringContainsString('198.51.100.7', $d['subject']);
        $this->assertStringContainsString('SQL injection attempts', $d['subject']);
        $this->assertStringContainsString('vulnerability scanning', $d['body']);
        $this->assertStringContainsString('2026-11-14 08:00:01 to 2026-11-14 08:00:05, 2 requests', $d['body']);
        $this->assertStringContainsString('may well be compromised', $d['body']);
        $this->assertStringNotContainsString("\r", $d['body'], 'what the attacker sent cannot break the mail lines');
        $this->assertSame(Abuse::MAX_ROWS, substr_count(Abuse::draft('1.2.3.4', array_fill(0, 80, $rows[0]), 's', ['network' => '', 'range' => ''])['body'], 'waf:sqli |'));
    }

    public function test_caps_one_report_per_address_and_a_daily_limit(): void
    {
        $now = strtotime('2026-11-14 12:00:00 UTC');
        $this->assertSame('', Abuse::refusal('198.51.100.7', [], $now));
        $this->assertStringContainsString('already reported', Abuse::refusal('198.51.100.7', [['created_at' => '2026-10-20 10:00:00', 'ip' => '198.51.100.7']], $now));
        $this->assertSame('', Abuse::refusal('198.51.100.7', [['created_at' => '2026-10-01 10:00:00', 'ip' => '198.51.100.7']], $now), '30 days later it may be reported again');
        $five = array_map(static fn ($i) => ['created_at' => '2026-11-14 0' . $i . ':00:00', 'ip' => '192.0.2.' . $i], range(1, 5));
        $this->assertStringContainsString('daily limit', Abuse::refusal('198.51.100.7', $five, $now));
        $this->assertSame('', Abuse::refusal('198.51.100.7', $five, $now, 10));
    }
}
