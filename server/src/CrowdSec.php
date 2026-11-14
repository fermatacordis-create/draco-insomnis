<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

/**
 * CrowdSec, both ways.
 *
 * In: Draco is a bouncer of the CrowdSec Local API (crowdsec_lapi_url + crowdsec_api_key, from
 * "cscli bouncers add draco"). The decisions stream is copied into Draco's block list at most once a
 * minute, so no request ever waits for CrowdSec. Bans on an address or a range (no wider than /16 or
 * /32) become Draco blocks: like every Draco block, the address may read but not post or log in.
 * Administrators' addresses are never imported.
 *
 * Out: with crowdsec_log = 1, each attempt Draco records is also written as one JSON line to
 * events.log in the PHP user's folder; the parser and scenario in server/crowdsec turn them into
 * CrowdSec alerts (and bans for its other bouncers, e.g. the firewall).
 */
final class CrowdSec
{
    public const REASON = 'CrowdSec';
    private const EVERY = 60;

    public static function configured(ServerHost $host): bool
    {
        return $host->setting('crowdsec_lapi_url') !== '' && $host->setting('crowdsec_api_key') !== '';
    }

    /** From the guard: a sync when the last one is older than a minute, with a short timeout. */
    public static function maybeSync(ServerHost $host): void
    {
        if (!self::configured($host) || $host->recall('crowdsec_sync') !== null) {
            return;
        }
        $host->remember('crowdsec_sync', (string) time(), self::EVERY);
        self::sync($host, 2);
    }

    /** @return array{added: int, removed: int, error: string} */
    public static function sync(ServerHost $host, int $timeout = 10): array
    {
        $out = ['added' => 0, 'removed' => 0, 'error' => ''];
        if (!self::configured($host)) {
            $out['error'] = 'not configured';

            return $out;
        }
        $store = $host->store();
        // The first call of a folder asks for everything in force; later ones only for changes.
        $startup = $store->recall('crowdsec_started') === null;
        $url = rtrim($host->setting('crowdsec_lapi_url'), '/') . '/v1/decisions/stream?startup=' . ($startup ? 'true' : 'false')
            . '&scopes=ip,range';
        [$code, $body] = self::get($url, $host->setting('crowdsec_api_key'), $timeout);
        if ($code !== 200) {
            $out['error'] = $code === 0 ? 'no answer' : 'HTTP ' . $code;
            $store->remember('crowdsec_last', time() . '|' . $out['error'], 86400 * 30);

            return $out;
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            $out['error'] = 'not JSON';

            return $out;
        }
        if ($startup) {
            $out['removed'] += $store->removeImported(self::REASON, null);
        }
        foreach ((array) ($data['deleted'] ?? []) as $d) {
            if (is_array($d) && isset($d['value'])) {
                $out['removed'] += $store->removeImported(self::REASON, strtolower((string) $d['value']));
            }
        }
        $admins = $host->adminIps();
        foreach ((array) ($data['new'] ?? []) as $d) {
            if (!is_array($d) || strtolower((string) ($d['type'] ?? '')) !== 'ban') {
                continue;
            }
            $seconds = self::seconds((string) ($d['duration'] ?? ''));
            if ($seconds <= 0) {
                continue;
            }
            $reason = self::REASON . ': ' . substr((string) ($d['scenario'] ?? ($d['origin'] ?? '')), 0, 150);
            if ($store->importBlock((string) ($d['value'] ?? ''), time() + $seconds, $reason, $admins)) {
                $out['added']++;
            }
        }
        $store->remember('crowdsec_started', '1', 86400 * 365);
        $store->remember('crowdsec_last', time() . '|ok +' . $out['added'] . ' -' . $out['removed'], 86400 * 30);

        return $out;
    }

    /** Go durations as CrowdSec sends them: "3h59m40.5s", "45m", "1.5s"… */
    public static function seconds(string $duration): int
    {
        if (!preg_match_all('/(\d+(?:\.\d+)?)(h|ms|m|s)/', $duration, $m, PREG_SET_ORDER) || str_starts_with(trim($duration), '-')) {
            return 0;
        }
        $total = 0.0;
        foreach ($m as [, $n, $unit]) {
            $total += (float) $n * ['h' => 3600, 'm' => 60, 's' => 1, 'ms' => 0.001][$unit];
        }

        return (int) ceil($total);
    }

    /** One JSON line per recorded attempt, for the CrowdSec agent (acquisition type draco-insomnis). @param array<string, mixed> $row */
    public static function logLine(string $dir, array $row): void
    {
        $file = $dir . '/events.log';
        $line = json_encode([
            'time' => gmdate('Y-m-d\TH:i:s\Z'),
            'ip' => $row['ip'],
            'host' => $row['host'],
            'endpoint' => $row['endpoint'],
            'verdict' => $row['verdict'],
            'reasons' => $row['reasons'],
            'user_agent' => $row['user_agent'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
    }

    /** @return array{0: int, 1: string} */
    private static function get(string $url, string $key, int $timeout): array
    {
        $headers = ['X-Api-Key: ' . $key, 'User-Agent: Draco-Insomnis'];
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => $timeout, CURLOPT_HTTPHEADER => $headers]);
            $body = curl_exec($ch);

            return [is_string($body) ? (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE) : 0, is_string($body) ? $body : ''];
        }
        $ctx = stream_context_create(['http' => ['timeout' => $timeout, 'header' => implode("\r\n", $headers), 'ignore_errors' => true]]);
        $body = @file_get_contents($url, false, $ctx);
        $lines = function_exists('http_get_last_response_headers') ? (array) http_get_last_response_headers() : (array) ($http_response_header ?? []);
        $code = preg_match('#^HTTP/\S+ (\d{3})#', (string) ($lines[0] ?? ''), $m) === 1 ? (int) $m[1] : 0;

        return [$code, is_string($body) ? $body : ''];
    }
}
