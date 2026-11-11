<?php

declare(strict_types=1);

namespace DracoInsomnis\Mail;

defined('ABSPATH') || exit;

/** One connection per site. The password is only ever stored encrypted. */
final class Settings
{
    public const OPTION = 'draco_mail';
    private const AAD = 'draco:mail:v1';
    private const DEFAULTS = [
        'enabled' => 'no',
        'tested' => '',
        'host' => '',
        'port' => 465,
        'secure' => 'ssl',
        'user' => '',
        'pass' => '',
        'from' => '',
        'from_name' => '',
        'security_recipients' => [],
    ];

    /** @return array<string, mixed> */
    public static function get(): array
    {
        $saved = get_option(self::OPTION, []);

        return array_merge(self::DEFAULTS, is_array($saved) ? $saved : []);
    }

    public static function password(): string
    {
        $stored = (string) self::get()['pass'];

        return $stored === '' ? '' : Crypto::decrypt($stored, self::AAD);
    }

    public static function fromAddress(): string
    {
        $s = self::get();

        return (string) ($s['from'] !== '' ? $s['from'] : $s['user']);
    }

    public static function complete(): bool
    {
        $s = self::get();

        return $s['host'] !== '' && $s['user'] !== '' && $s['pass'] !== '' && is_email(self::fromAddress());
    }

    public static function tested(): bool
    {
        $s = self::get();

        return $s['tested'] !== '' && hash_equals((string) $s['tested'], self::fingerprint($s));
    }

    public static function active(): bool
    {
        return self::get()['enabled'] === 'yes' && self::tested();
    }

    /**
     * Changing the connection switches it off: only a connection that has passed a test may carry
     * login codes, or a wrong password would lock the owner out.
     *
     * @param array<string, mixed> $in
     * @return string 'ok', 'invalid' or 'cipher'
     */
    public static function save(array $in, string $password): string
    {
        $s = self::get();
        $before = self::fingerprint($s);
        $secure = ($in['secure'] ?? '') === 'tls' ? 'tls' : 'ssl';
        $port = (int) ($in['port'] ?? 0);
        $s['host'] = strtolower(sanitize_text_field((string) ($in['host'] ?? '')));
        $s['port'] = $port > 0 && $port <= 65535 ? $port : ($secure === 'ssl' ? 465 : 587);
        $s['secure'] = $secure;
        $s['user'] = sanitize_text_field((string) ($in['user'] ?? ''));
        $s['from'] = sanitize_email((string) ($in['from'] ?? ''));
        $s['from_name'] = sanitize_text_field((string) ($in['from_name'] ?? ''));
        $s['security_recipients'] = self::recipients((string) ($in['security_recipients'] ?? ''));
        if ($s['host'] === '' || preg_match('/^[a-z0-9.-]+$/', $s['host']) !== 1 || $s['user'] === '') {
            return 'invalid';
        }
        if (!is_email($s['from'] !== '' ? $s['from'] : $s['user'])) {
            return 'invalid';
        }
        if ($password !== '') {
            $cipher = Crypto::encrypt($password, self::AAD);
            if ($cipher === '') {
                return 'cipher';
            }
            $s['pass'] = $cipher;
        }
        if ($s['pass'] === '') {
            return 'invalid';
        }
        if (self::fingerprint($s) !== $before) {
            $s['enabled'] = 'no';
            $s['tested'] = '';
        }
        update_option(self::OPTION, $s, false);

        return 'ok';
    }

    public static function markTested(): void
    {
        $s = self::get();
        $s['tested'] = self::fingerprint($s);
        update_option(self::OPTION, $s, false);
    }

    public static function setEnabled(bool $on): bool
    {
        if ($on && !self::tested()) {
            return false;
        }
        $s = self::get();
        $s['enabled'] = $on ? 'yes' : 'no';
        update_option(self::OPTION, $s, false);

        return true;
    }

    /** @return list<string> */
    public static function securityRecipients(): array
    {
        return array_values((array) self::get()['security_recipients']);
    }

    /** Forgets the connection. The alert addresses stay: other modules use them too. */
    public static function forget(): void
    {
        $s = self::DEFAULTS;
        $s['security_recipients'] = self::securityRecipients();
        update_option(self::OPTION, $s, false);
    }

    /** @return list<string> */
    public static function recipients(string $text): array
    {
        $out = [];
        foreach (preg_split('/[\s,;]+/', $text) ?: [] as $email) {
            $email = strtolower(sanitize_email($email));
            if ($email !== '' && is_email($email)) {
                $out[$email] = $email;
            }
        }

        return array_values($out);
    }

    /** @param array<string, mixed> $s */
    private static function fingerprint(array $s): string
    {
        return hash('sha256', implode("\n", [$s['host'], $s['port'], $s['secure'], $s['user'], $s['from'], $s['pass']]));
    }
}
