<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Firewall\SecurityTxt;

final class SecurityTxtTest extends TestCase
{
    public function test_off_by_default_and_never_without_a_valid_contact(): void
    {
        $this->assertFalse(SecurityTxt::active());
        update_option(SecurityTxt::OPTION, 'yes');
        $this->assertFalse(SecurityTxt::active(), 'switched on but no contact: nothing is published');
        update_option(SecurityTxt::OPTION_CONTACT, SecurityTxt::contact('not an address'));
        $this->assertFalse(SecurityTxt::active());
        update_option(SecurityTxt::OPTION_CONTACT, SecurityTxt::contact('seguridad@example.org'));
        $this->assertTrue(SecurityTxt::active());
    }

    public function test_only_an_email_or_an_https_address_is_a_contact(): void
    {
        $this->assertSame('mailto:ana@example.org', SecurityTxt::contact('ana@example.org'));
        $this->assertSame('mailto:ana@example.org', SecurityTxt::contact('mailto:ana@example.org'));
        $this->assertSame('https://example.org/security', SecurityTxt::contact('https://example.org/security'));
        $this->assertSame('', SecurityTxt::contact('http://example.org/security'), 'plain http is refused');
        $this->assertSame('', SecurityTxt::contact('javascript:alert(1)'));
        $this->assertSame('', SecurityTxt::policy('ftp://example.org/x'));
    }

    public function test_the_file_follows_rfc_9116(): void
    {
        update_option(SecurityTxt::OPTION, 'yes');
        update_option(SecurityTxt::OPTION_CONTACT, 'mailto:ana@example.org');
        $now = gmmktime(10, 0, 0, 11, 27, 2026);
        $body = SecurityTxt::body($now);
        $this->assertStringStartsWith("Contact: mailto:ana@example.org\n", $body);
        $this->assertStringContainsString("Expires: 2027-05-26T00:00:00Z\n", $body, 'about 6 months ahead, always under a year');
        $this->assertMatchesRegularExpression('#^Canonical: https://[^\n]+/\.well-known/security\.txt$#m', $body);
        $this->assertStringContainsString('Preferred-Languages: ', $body);
        $this->assertStringNotContainsString('Policy:', $body, 'only when the owner gave one');
        update_option(SecurityTxt::OPTION_POLICY, 'https://example.org/policy');
        $this->assertStringContainsString("Policy: https://example.org/policy\n", SecurityTxt::body($now));
    }
}
