<?php
declare(strict_types=1);

namespace Tests\Integration;

use DracoInsomnis\Mail\Crypto;
use DracoInsomnis\Mail\Settings;
use DracoInsomnis\Mail\Transport;
use PHPMailer\PHPMailer\PHPMailer;

final class MailTest extends TestCase
{
    private const PASSWORD = 'S3cret-Pass!';

    /** @return array<string, mixed> */
    private function smtp(array $change = []): array
    {
        return array_merge([
            'host' => 'smtp.example.org',
            'port' => 465,
            'secure' => 'ssl',
            'user' => 'info@example.org',
            'from' => '',
            'from_name' => 'Example',
            'security_recipients' => "alerts@example.org, not-an-email; ALERTS@example.org",
        ], $change);
    }

    private function activeMailbox(): void
    {
        $this->assertSame('ok', Settings::save($this->smtp(), self::PASSWORD));
        Settings::markTested();
        $this->assertTrue(Settings::setEnabled(true));
    }

    public function test_password_is_encrypted_at_rest_and_reads_back(): void
    {
        $this->assertSame('ok', Settings::save($this->smtp(), self::PASSWORD));
        $raw = get_option(Settings::OPTION);
        $this->assertStringStartsWith('g1:', $raw['pass']);
        $this->assertStringNotContainsString(self::PASSWORD, serialize($raw));
        $this->assertSame(self::PASSWORD, Settings::password());
    }

    public function test_a_tampered_or_reused_ciphertext_does_not_decrypt(): void
    {
        Settings::save($this->smtp(), self::PASSWORD);
        $stored = (string) get_option(Settings::OPTION)['pass'];
        $raw = base64_decode(substr($stored, 3), true);
        $raw[strlen($raw) - 1] = chr(ord($raw[strlen($raw) - 1]) ^ 1);
        $this->assertSame('', Crypto::decrypt('g1:' . base64_encode($raw), 'draco:mail:v1'));
        // Bound to its purpose: the same ciphertext is useless anywhere else.
        $this->assertSame('', Crypto::decrypt($stored, 'some:other:purpose'));
        $this->assertSame('', Crypto::decrypt('plain-text', 'draco:mail:v1'));
    }

    public function test_incomplete_or_malformed_settings_are_refused(): void
    {
        $this->assertSame('invalid', Settings::save($this->smtp(), ''), 'no password ever given');
        $this->assertSame('invalid', Settings::save($this->smtp(['host' => 'smtp example.org']), self::PASSWORD));
        $this->assertSame('invalid', Settings::save($this->smtp(['user' => '']), self::PASSWORD));
        $this->assertSame('invalid', Settings::save($this->smtp(['user' => 'info', 'from' => 'nope']), self::PASSWORD));
        $this->assertFalse(Settings::complete());
    }

    public function test_it_cannot_be_switched_on_before_a_real_test(): void
    {
        Settings::save($this->smtp(), self::PASSWORD);
        $this->assertFalse(Settings::setEnabled(true));
        $this->assertFalse(Settings::active());
        Settings::markTested();
        $this->assertTrue(Settings::setEnabled(true));
        $this->assertTrue(Settings::active());
    }

    public function test_changing_the_server_switches_it_off_but_saving_the_same_does_not(): void
    {
        $this->activeMailbox();
        $this->assertSame('ok', Settings::save($this->smtp(), ''), 'empty password keeps the stored one');
        $this->assertTrue(Settings::active());
        $this->assertSame('ok', Settings::save($this->smtp(['host' => 'smtp2.example.org']), ''));
        $this->assertFalse(Settings::tested());
        $this->assertFalse(Settings::active());
        $this->assertSame(self::PASSWORD, Settings::password());
    }

    public function test_security_recipients_are_cleaned_and_kept_when_the_mailbox_is_forgotten(): void
    {
        $this->activeMailbox();
        $this->assertSame(['alerts@example.org'], Settings::securityRecipients());
        Settings::forget();
        $this->assertSame('', Settings::password());
        $this->assertFalse(Settings::active());
        $this->assertSame(['alerts@example.org'], Settings::securityRecipients());
        $mail = Transport::addRecipients(['to' => 'admin@example.org', 'subject' => 'x']);
        $this->assertSame(['admin@example.org', 'alerts@example.org'], $mail['to']);
    }

    public function test_phpmailer_goes_through_the_mailbox_and_the_original_sender_becomes_reply_to(): void
    {
        $this->activeMailbox();
        $mailer = new PHPMailer(true);
        $mailer->setFrom(Transport::fromFilter('contact@visitor.example'), 'WordPress');
        Transport::apply($mailer);
        $this->assertSame('smtp', $mailer->Mailer);
        $this->assertSame('smtp.example.org', $mailer->Host);
        $this->assertSame(465, $mailer->Port);
        $this->assertSame('ssl', $mailer->SMTPSecure);
        $this->assertTrue($mailer->SMTPAuth);
        $this->assertSame('info@example.org', $mailer->Username);
        $this->assertSame(self::PASSWORD, $mailer->Password);
        $this->assertSame('info@example.org', $mailer->From, 'DMARC: the visible sender is the mailbox that signs in');
        $this->assertSame('Example', $mailer->FromName);
        $this->assertContains('contact@visitor.example', array_column($mailer->getReplyToAddresses(), 0));
    }

    public function test_wordpress_default_sender_is_replaced_only_when_draco_sends(): void
    {
        $this->assertSame('wordpress@localhost', Transport::fromFilter('wordpress@localhost'));
        $this->activeMailbox();
        $this->assertSame('info@example.org', Transport::fromFilter('wordpress@localhost'));
    }

    public function test_another_sender_keeps_phpmailer(): void
    {
        $this->activeMailbox();
        update_option('opnv_mail_settings', ['enabled' => 'yes']);
        $this->assertSame('OPNV-WP', Transport::otherSender());
        $mailer = new PHPMailer(true);
        Transport::apply($mailer);
        $this->assertSame('mail', $mailer->Mailer, 'two senders fighting over PHPMailer breaks mail');
        $this->assertSame('wordpress@localhost', Transport::fromFilter('wordpress@localhost'));

        // A plugin that bundles Draco and hands the mail over says so through this filter.
        add_filter('draco_insomnis_other_sender', static fn ($name) => $name === 'OPNV-WP' ? '' : $name);
        $this->assertSame('', Transport::otherSender());
        $this->assertTrue(Transport::hasSmtp());
    }
}
