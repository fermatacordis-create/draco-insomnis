<?php

declare(strict_types=1);

namespace DracoInsomnis\Core;

// phpcs:disable WordPress.WP.AlternativeFunctions -- this engine also runs outside WordPress; WordPress passes its own fetcher (wp_remote_get).

/**
 * Abuse reports to the network that owns an attacking address. Never automatic: Draco finds the
 * abuse contact in the public registry (RDAP, through rdap.org, which forwards to the right RIR),
 * writes a factual draft with the evidence, and a person reads, edits and sends it. Limits: a daily
 * cap per site and one report per address every 30 days.
 *
 * Nothing is ever sent to the attacker, and a report only asks the network to look at its host:
 * most attacking machines are compromised, their owners are victims too.
 */
final class Abuse
{
    public const ENDPOINT = 'abuse_report';
    public const RDAP = 'https://rdap.org/ip/';
    public const DAILY_CAP = 5;
    public const SAME_IP_DAYS = 30;
    public const MAX_ROWS = 50;

    /**
     * The abuse contact of an address.
     *
     * @param callable(string): ?string $fetch Gets a URL (following redirects), returns the body or null.
     * @return array{email: string, network: string, range: string, registry: string, error: string}
     */
    public static function contact(string $ip, callable $fetch): array
    {
        $out = ['email' => '', 'network' => '', 'range' => '', 'registry' => '', 'error' => ''];
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            $out['error'] = 'not a public address';

            return $out;
        }
        $body = $fetch(self::RDAP . $ip);
        $data = is_string($body) ? json_decode($body, true) : null;
        if (!is_array($data)) {
            $out['error'] = 'the registry did not answer';

            return $out;
        }

        return self::parse($data) + $out;
    }

    /** @param array<string, mixed> $data RDAP "ip network" object @return array{email: string, network: string, range: string, registry: string, error: string} */
    public static function parse(array $data): array
    {
        $emails = [];
        self::walk((array) ($data['entities'] ?? []), $emails);
        // Abuse role first; then whatever contact the network lists, so there is always someone to tell.
        $email = $emails['abuse'][0] ?? ($emails['technical'][0] ?? ($emails['administrative'][0] ?? ($emails['registrant'][0] ?? '')));
        $range = '';
        if (isset($data['cidr0_cidrs'][0]) && is_array($data['cidr0_cidrs'][0])) {
            $c = $data['cidr0_cidrs'][0];
            $range = (string) ($c['v4prefix'] ?? $c['v6prefix'] ?? '') . '/' . (string) ($c['length'] ?? '');
        } elseif (isset($data['startAddress'], $data['endAddress'])) {
            $range = $data['startAddress'] . ' - ' . $data['endAddress'];
        }
        $registry = (string) ($data['port43'] ?? '');
        foreach ((array) ($data['links'] ?? []) as $l) {
            if ($registry === '' && is_array($l) && isset($l['href']) && preg_match('#https?://([^/]+)#', (string) $l['href'], $m)) {
                $registry = $m[1];
            }
        }

        return [
            'email' => strtolower($email),
            'network' => trim((string) ($data['name'] ?? '') . ' ' . (isset($data['handle']) ? '(' . $data['handle'] . ')' : '')),
            'range' => $range,
            'registry' => $registry,
            'error' => $email === '' ? 'no abuse contact in the registry' : '',
        ];
    }

    /** @param array<int, mixed> $entities @param array<string, list<string>> $emails */
    private static function walk(array $entities, array &$emails): void
    {
        foreach ($entities as $e) {
            if (!is_array($e)) {
                continue;
            }
            foreach (self::vcardEmails($e['vcardArray'] ?? null) as $mail) {
                foreach ((array) ($e['roles'] ?? []) as $role) {
                    $emails[(string) $role][] = $mail;
                }
            }
            self::walk((array) ($e['entities'] ?? []), $emails);
        }
    }

    /** @param mixed $vcard @return list<string> */
    private static function vcardEmails($vcard): array
    {
        $out = [];
        if (is_array($vcard) && isset($vcard[1]) && is_array($vcard[1])) {
            foreach ($vcard[1] as $prop) {
                if (is_array($prop) && ($prop[0] ?? '') === 'email' && is_string($prop[3] ?? null) && filter_var($prop[3], FILTER_VALIDATE_EMAIL)) {
                    $out[] = $prop[3];
                }
            }
        }

        return $out;
    }

    /**
     * A factual report in English (what abuse desks read), with the evidence lines. The person who
     * sends it may edit everything.
     *
     * @param list<array<string, mixed>> $rows Evidence rows: created_at (UTC), endpoint, verdict, reasons, user_agent.
     * @return array{subject: string, body: string}
     */
    public static function draft(string $ip, array $rows, string $site, array $contact): array
    {
        $rows = array_slice($rows, 0, self::MAX_ROWS);
        $kinds = [];
        foreach ($rows as $r) {
            $kinds[self::kind((string) ($r['endpoint'] ?? ''), (string) ($r['reasons'] ?? ''))] = true;
        }
        $first = (string) ($rows[0]['created_at'] ?? '');
        $last = (string) ($rows[count($rows) - 1]['created_at'] ?? '');
        $subject = 'Abuse report: ' . $ip . ' — ' . implode(', ', array_keys($kinds));
        $lines = [
            'Hello,',
            '',
            'The address ' . $ip . ($contact['network'] !== '' ? ' (' . $contact['network'] . ($contact['range'] !== '' ? ', ' . $contact['range'] : '') . ')' : '') . ' sent the requests below to ' . $site . '.',
            'Our firewall (Draco Insomnis, open source) stopped them. We did not respond to the host in any way.',
            '',
            'Type: ' . implode(', ', array_keys($kinds)) . '.',
            'Period (UTC): ' . $first . ' to ' . $last . ', ' . count($rows) . ' requests listed.',
            '',
            'The machine may well be compromised and its owner unaware. Please look at it and, if needed, let them know.',
            '',
            'Evidence (times in UTC):',
            'time_utc | what | verdict | signs | user_agent',
        ];
        foreach ($rows as $r) {
            $lines[] = implode(' | ', [
                (string) ($r['created_at'] ?? ''), (string) ($r['endpoint'] ?? ''), (string) ($r['verdict'] ?? ''),
                (string) ($r['reasons'] ?? ''), substr(preg_replace('/[\r\n]+/', ' ', (string) ($r['user_agent'] ?? '')) ?? '', 0, 160),
            ]);
        }
        $lines[] = '';
        $lines[] = 'Thank you.';
        $lines[] = '';
        $lines[] = '-- ';
        $lines[] = $site;

        return ['subject' => $subject, 'body' => implode("\n", $lines)];
    }

    /** What a line of evidence was, in the words abuse desks use. */
    public static function kind(string $endpoint, string $reasons): string
    {
        $rule = str_starts_with($endpoint, 'waf:') ? substr($endpoint, 4) : '';
        $map = [
            'sqli' => 'SQL injection attempts', 'traversal' => 'path traversal attempts', 'lfi' => 'file inclusion attempts', 'rce' => 'remote code execution attempts',
            'xss' => 'cross-site scripting attempts', 'scanner' => 'vulnerability scanning', 'probe' => 'vulnerability scanning', 'multicall' => 'XML-RPC brute force',
        ];
        if ($rule !== '') {
            return $map[$rule] ?? 'web attack attempts';
        }
        if (str_starts_with($endpoint, 'anticopy:')) {
            return 'automated scraping';
        }
        if (str_contains($endpoint, 'login') || str_contains($reasons, 'login')) {
            return 'login brute force';
        }

        return 'fake account sign-ups (spam bot)';
    }

    /**
     * Whether one more report may be sent now. $sent are the earlier reports: created_at (UTC) and ip.
     *
     * @param list<array{created_at: string, ip: string}> $sent
     * @return string '' when it may, else the reason
     */
    public static function refusal(string $ip, array $sent, int $now, int $cap = self::DAILY_CAP): string
    {
        $today = 0;
        foreach ($sent as $s) {
            $t = strtotime((string) $s['created_at'] . ' UTC');
            if ($t === false) {
                continue;
            }
            if ($s['ip'] === $ip && $t > $now - self::SAME_IP_DAYS * 86400) {
                return 'already reported in the last ' . self::SAME_IP_DAYS . ' days';
            }
            if ($t > $now - 86400) {
                $today++;
            }
        }

        return $today >= max(1, $cap) ? 'daily limit of ' . max(1, $cap) . ' reports reached' : '';
    }
}
