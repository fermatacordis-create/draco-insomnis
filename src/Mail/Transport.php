<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/** Points WordPress's own PHPMailer at the mailbox, and records how each message left. */
final class Transport
{
    private const TIMEOUT = 15;
    private static bool $forced = false;
    private static string $transport = 'php';
    private static string $lastError = '';
    private static string $originalFrom = '';

    public static function register(): void
    {
        add_filter('wp_mail_from', [self::class, 'fromFilter'], 999);
        add_action('phpmailer_init', [self::class, 'apply'], 999);
        add_action('wp_mail_succeeded', [self::class, 'onSent']);
        add_action('wp_mail_failed', [self::class, 'onFailed']);
        add_filter('recovery_mode_email', [self::class, 'addRecipients']);
        add_filter('wp_password_change_notification_email', [self::class, 'addRecipients']);
    }

    private static function inCharge(): bool
    {
        return self::otherSender() === '' && (self::$forced || Settings::active()) && Settings::password() !== '';
    }

    /**
     * wp_mail() checks the sender before phpmailer_init runs, so a default like wordpress@localhost or
     * a plugin's invalid address would fail there. The mailbox becomes the sender here; the original
     * address is kept for Reply-To.
     *
     * @param string $from
     */
    public static function fromFilter($from): string
    {
        self::$originalFrom = (string) $from;

        return self::inCharge() ? Settings::fromAddress() : (string) $from;
    }

    /** @param \PHPMailer\PHPMailer\PHPMailer $phpmailer */
    public static function apply($phpmailer): void
    {
        self::$transport = self::otherSender() !== '' ? 'other' : 'php';
        // Two senders fighting over PHPMailer is how mail silently breaks: the other one keeps it.
        if (self::$transport === 'other' || (!self::$forced && !Settings::active())) {
            return;
        }
        $password = Settings::password();
        if ($password === '') {
            // The site's salts changed: the stored password can no longer be read.
            return;
        }
        $s = Settings::get();
        $from = Settings::fromAddress();
        $phpmailer->isSMTP();
        $phpmailer->Host = (string) $s['host'];
        $phpmailer->Port = (int) $s['port'];
        $phpmailer->SMTPAuth = true;
        $phpmailer->Username = (string) $s['user'];
        $phpmailer->Password = $password;
        $phpmailer->SMTPSecure = $s['secure'] === 'tls' ? 'tls' : 'ssl';
        $phpmailer->SMTPAutoTLS = true;
        $phpmailer->Timeout = self::TIMEOUT;

        // With DMARC the visible sender must be the mailbox that signs in; the original goes to Reply-To.
        $original = self::$originalFrom !== '' ? self::$originalFrom : (string) $phpmailer->From;
        self::$originalFrom = '';
        $name = (string) $phpmailer->FromName;
        if ($s['from_name'] !== '' && ($name === '' || $name === 'WordPress')) {
            $name = (string) $s['from_name'];
        }
        try {
            if (is_email($original) && self::domain($original) !== self::domain($from) && $phpmailer->getReplyToAddresses() === []) {
                $phpmailer->addReplyTo($original);
            }
            $phpmailer->setFrom($from, $name, false);
            $phpmailer->Sender = $from;
        } catch (\Throwable $e) {
            self::$lastError = substr($e->getMessage(), 0, 240);
        }
        self::$transport = 'smtp';
    }

    /** Name of another active sender (an SMTP plugin, or OPNV-WP's own mail module), or ''. */
    public static function otherSender(): string
    {
        $other = '';
        $opnv = get_option('opnv_mail_settings', []);
        if (is_array($opnv) && ($opnv['enabled'] ?? '') === 'yes') {
            $other = 'OPNV-WP';
        } else {
            $found = preg_grep('/smtp/i', (array) get_option('active_plugins', []));
            $other = $found === false || $found === [] ? '' : dirname((string) reset($found));
        }

        /**
         * A plugin that hands its mail over to Draco (OPNV-WP 1.0.266+) returns '' here for itself, while
         * keeping its own settings so a downgrade still sends mail.
         */
        return (string) apply_filters('draco_insomnis_other_sender', $other);
    }

    /** Some SMTP really carries the mail: this one or another plugin. */
    public static function hasSmtp(): bool
    {
        return Settings::active() || self::otherSender() !== '';
    }

    /** @return array{ok: bool, error: string} */
    public static function test(string $to): array
    {
        if (Settings::password() === '') {
            return ['ok' => false, 'error' => __('The saved password can no longer be read. Type it again.', 'draco-insomnis')];
        }
        if (self::otherSender() !== '') {
            /* translators: %s: plugin name */
            return ['ok' => false, 'error' => sprintf(__('%s is sending the mail of this site. Turn it off first.', 'draco-insomnis'), self::otherSender())];
        }
        self::$forced = true;
        self::$lastError = '';
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        try {
            /* translators: %s: site name */
            $subject = sprintf(__('Mail test · %s', 'draco-insomnis'), $site);
            $body = __('If you can read this, the mail of your site leaves correctly through this connection.', 'draco-insomnis')
                . "\n\n— Draco Insomnis · OPNV Systems\nhttps://opnv.systems";
            $ok = wp_mail($to, $subject, $body);
        } finally {
            self::$forced = false;
        }
        $ok = $ok && self::$transport === 'smtp' && self::$lastError === '';
        if ($ok) {
            Settings::markTested();
        }

        return ['ok' => $ok, 'error' => self::$lastError];
    }

    /** @param array<string, mixed> $mail */
    public static function onSent($mail): void
    {
        $mail = is_array($mail) ? $mail : [];
        Log::add(self::$transport, $mail['to'] ?? [], (string) ($mail['subject'] ?? ''), true, '');
    }

    /** @param \WP_Error $error */
    public static function onFailed($error): void
    {
        if (!is_wp_error($error)) {
            return;
        }
        self::$lastError = substr((string) $error->get_error_message(), 0, 240);
        $data = $error->get_error_data();
        $data = is_array($data) ? $data : [];
        Log::add(self::$transport, $data['to'] ?? [], (string) ($data['subject'] ?? ''), false, self::$lastError);
    }

    /**
     * WordPress's recovery link and password-change alerts also go to the alert addresses.
     *
     * @param array<string, mixed> $email
     * @return array<string, mixed>
     */
    public static function addRecipients($email)
    {
        $extra = Settings::securityRecipients();
        if ($extra === [] || !is_array($email)) {
            return $email;
        }
        $to = is_array($email['to'] ?? null) ? $email['to'] : array_filter([(string) ($email['to'] ?? '')]);
        $email['to'] = array_values(array_unique(array_merge($to, $extra)));

        return $email;
    }

    private static function domain(string $email): string
    {
        return strtolower(substr((string) strrchr($email, '@'), 1));
    }
}
