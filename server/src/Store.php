<?php

declare(strict_types=1);

namespace DracoInsomnis\Server;

use DracoInsomnis\Core\Blocklist;
use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\NetList;
use DracoInsomnis\Core\Review;

/**
 * Evidence, block list and counters in one SQLite file per PHP user (each PHP-FPM pool writes only
 * its own). Never stores passwords or anything beyond the fields the engines pass.
 */
final class Store implements EventStore
{
    public const KEEP_DAYS = 90;
    private const MAX_ROWS_PER_IP_HOUR = 30;

    private ?\PDO $pdo = null;

    /** @param list<string> $adminIps @param bool $eventLog Also write each attempt to events.log (CrowdSec). */
    public function __construct(private string $file, private array $adminIps = [], private bool $eventLog = false)
    {
    }

    public function file(): string
    {
        return $this->file;
    }

    public function pdo(): \PDO
    {
        if ($this->pdo === null) {
            $new = !is_file($this->file);
            $pdo = new \PDO('sqlite:' . $this->file, null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC]);
            // The rollback journal leaves no -wal/-shm files behind, so root's CLI never leaves files the
            // pool cannot open.
            $pdo->exec('PRAGMA busy_timeout = 3000');
            $pdo->exec('PRAGMA journal_mode = DELETE');
            if ($new) {
                self::own($this->file);
            }
            $pdo->exec('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created_at INTEGER NOT NULL, ip TEXT NOT NULL, remote_addr TEXT NOT NULL, host TEXT NOT NULL DEFAULT \'\', endpoint TEXT NOT NULL, score INTEGER NOT NULL, verdict TEXT NOT NULL, reasons TEXT NOT NULL DEFAULT \'\', user_agent TEXT NOT NULL DEFAULT \'\', fields TEXT)');
            $pdo->exec('CREATE INDEX IF NOT EXISTS events_ip ON events (ip, created_at)');
            $pdo->exec('CREATE INDEX IF NOT EXISTS events_endpoint ON events (endpoint, created_at)');
            $pdo->exec('CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL, reason TEXT NOT NULL DEFAULT \'\', created_at INTEGER NOT NULL, until_at INTEGER NOT NULL)');
            $pdo->exec('CREATE INDEX IF NOT EXISTS blocks_kind ON blocks (kind, value, until_at)');
            $pdo->exec('CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT NOT NULL, until_at INTEGER NOT NULL)');
            $this->pdo = $pdo;
        }

        return $this->pdo;
    }

    /**
     * A file made by root (the draco command) belongs to the PHP user of its folder, or that user's
     * site could no longer open it.
     */
    public static function own(string $file): void
    {
        @chmod($file, 0600);
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $dir = dirname($file);
            @chown($file, (int) fileowner($dir));
            @chgrp($file, (int) filegroup($dir));
        }
    }

    /** @param array<int|string, mixed> $args @return list<array<string, mixed>> */
    public function rows(string $sql, array $args = []): array
    {
        $st = $this->pdo()->prepare($sql);
        $st->execute($args);

        return $st->fetchAll();
    }

    /** @param array<int|string, mixed> $args */
    private function run(string $sql, array $args = []): int
    {
        $st = $this->pdo()->prepare($sql);
        $st->execute($args);

        return $st->rowCount();
    }

    // Counters (when APCu is not there).

    public function bump(string $key, int $ttl): int
    {
        $now = time();
        $this->run('INSERT INTO cache (k, v, until_at) VALUES (?, \'1\', ?) ON CONFLICT(k) DO UPDATE SET v = CASE WHEN until_at > ? THEN CAST(v AS INTEGER) + 1 ELSE 1 END, until_at = CASE WHEN until_at > ? THEN until_at ELSE excluded.until_at END', [$key, $now + $ttl, $now, $now]);

        return (int) ($this->rows('SELECT v FROM cache WHERE k = ?', [$key])[0]['v'] ?? 1);
    }

    public function recall(string $key): ?string
    {
        $row = $this->rows('SELECT v FROM cache WHERE k = ? AND until_at > ?', [$key, time()])[0] ?? null;

        return $row === null ? null : (string) $row['v'];
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        $this->run('INSERT OR REPLACE INTO cache (k, v, until_at) VALUES (?, ?, ?)', [$key, $value, time() + $ttl]);
    }

    // EventStore.

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        if ($this->bump('rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        $row = [
            'ip' => $ip, 'host' => substr(strtolower((string) ($_SERVER['HTTP_HOST'] ?? '')), 0, 190), 'endpoint' => substr($endpoint, 0, 40),
            'verdict' => (string) $result['verdict'], 'reasons' => substr(implode(',', $result['reasons']), 0, 190), 'user_agent' => substr($userAgent, 0, 255),
        ];
        $this->run('INSERT INTO events (created_at, ip, remote_addr, host, endpoint, score, verdict, reasons, user_agent, fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
            time(), $ip, $remoteAddr, $row['host'], $row['endpoint'], min(65535, max(0, (int) $result['score'])), $row['verdict'], $row['reasons'],
            $row['user_agent'], (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
        if ($this->eventLog && $endpoint !== Review::ENDPOINT) {
            CrowdSec::logLine(dirname($this->file), $row);
        }
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return (int) ($this->rows('SELECT COUNT(*) AS n FROM events WHERE ip = ? AND verdict = \'bot\' AND created_at > ?', [$ip, time() - $seconds])[0]['n'] ?? 0);
    }

    public function isBlocked(string $email, string $ip): bool
    {
        $found = $this->rows('SELECT 1 FROM blocks WHERE until_at > ? AND ((kind = \'email\' AND value = ?) OR (kind = \'ip\' AND value = ?)) LIMIT 1', [time(), strtolower($email), strtolower($ip)]);

        return $found !== [] || ($ip !== '' && NetList::contains($this->activeValues('net'), $ip));
    }

    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        $value = strtolower(trim($value));
        if (!in_array($days, Blocklist::DAYS, true)) {
            return false;
        }
        if ($kind === 'ip' || $kind === 'net') {
            $address = Blocklist::address($value, $days, $this->adminIps);
            if ($address === null) {
                return false;
            }
            ['kind' => $kind, 'value' => $value] = $address;
        } elseif ($kind !== 'email' || filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
            return false;
        }
        $this->run('INSERT INTO blocks (kind, value, reason, created_at, until_at) VALUES (?, ?, ?, ?, ?)', [$kind, $value, substr($reason, 0, 190), time(), Blocklist::untilTs($days, time())]);

        return true;
    }

    /**
     * A block decided elsewhere (CrowdSec), until a given time. Same limits as any block: never an
     * administrator's address, no range wider than /16 (IPv4) or /32 (IPv6).
     *
     * @param list<string> $admins
     */
    public function importBlock(string $value, int $until, string $reason, array $admins): bool
    {
        $address = Blocklist::address($value, 30, $admins);
        if ($address === null || $until <= time()) {
            return false;
        }
        $this->run('DELETE FROM blocks WHERE kind = ? AND value = ? AND reason LIKE ?', [$address['kind'], $address['value'], CrowdSec::REASON . '%']);
        $this->run('INSERT INTO blocks (kind, value, reason, created_at, until_at) VALUES (?, ?, ?, ?, ?)', [$address['kind'], $address['value'], substr($reason, 0, 190), time(), $until]);

        return true;
    }

    /** Removes imported blocks: all from that source, or one value. */
    public function removeImported(string $prefix, ?string $value): int
    {
        return $value === null
            ? $this->run('DELETE FROM blocks WHERE reason LIKE ?', [$prefix . '%'])
            : $this->run('DELETE FROM blocks WHERE reason LIKE ? AND value = ?', [$prefix . '%', $value]);
    }

    // Owner side (CLI).

    /** @return list<string> */
    public function activeValues(string $kind): array
    {
        return array_map(static fn ($r) => (string) $r['value'], $this->rows('SELECT value FROM blocks WHERE kind = ? AND until_at > ? LIMIT 500', [$kind, time()]));
    }

    public function allow(string $ip, int $days, string $reason): bool
    {
        $ip = strtolower(trim($ip));
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !in_array($days, [1, 7, 30, 0], true)) {
            return false;
        }
        $this->run('DELETE FROM blocks WHERE kind IN (\'ip\', \'allow\') AND value = ?', [$ip]);
        $this->run('INSERT INTO blocks (kind, value, reason, created_at, until_at) VALUES (\'allow\', ?, ?, ?, ?)', [$ip, substr($reason, 0, 190), time(), Blocklist::untilTs($days, time())]);

        return true;
    }

    /** @return list<array<string, mixed>> */
    public function reviews(int $limit = 50): array
    {
        return $this->rows('SELECT * FROM events WHERE endpoint = ? ORDER BY verdict = \'pending\' DESC, id DESC LIMIT ' . max(1, $limit), [Review::ENDPOINT]);
    }

    /** @return array<string, mixed>|null */
    public function review(int $id): ?array
    {
        return $this->rows('SELECT * FROM events WHERE id = ? AND endpoint = ?', [$id, Review::ENDPOINT])[0] ?? null;
    }

    public function setVerdict(int $id, string $verdict): void
    {
        $this->run('UPDATE events SET verdict = ? WHERE id = ?', [substr($verdict, 0, 10), $id]);
    }

    /** @return list<array<string, mixed>> */
    public function wafRows(int $seconds): array
    {
        return $this->rows('SELECT ip, verdict, reasons FROM events WHERE endpoint LIKE \'waf:%\' AND created_at > ? LIMIT 5000', [time() - $seconds]);
    }

    public function unblock(int $id): bool
    {
        return $this->run('DELETE FROM blocks WHERE id = ?', [$id]) > 0;
    }

    /** @return list<array<string, mixed>> */
    public function recent(int $limit = 50): array
    {
        return $this->rows('SELECT * FROM events ORDER BY id DESC LIMIT ' . max(1, $limit));
    }

    /** @return list<array<string, mixed>> */
    public function activeBlocks(): array
    {
        return $this->rows('SELECT * FROM blocks WHERE until_at > ? ORDER BY until_at DESC LIMIT 200', [time()]);
    }

    /** @return list<array<string, mixed>> */
    public function byIp(string $ip): array
    {
        return $this->rows('SELECT * FROM events WHERE ip = ? OR remote_addr = ? ORDER BY id LIMIT 2000', [$ip, $ip]);
    }

    public function cleanup(): int
    {
        $now = time();
        // The CrowdSec agent reads events.log as it grows; past 5 MB it starts again.
        $log = dirname($this->file) . '/events.log';
        if (is_file($log) && filesize($log) > 5 * 1024 * 1024) {
            @file_put_contents($log, '');
        }

        return $this->run('DELETE FROM events WHERE created_at < ?', [$now - self::KEEP_DAYS * 86400])
            + $this->run('DELETE FROM blocks WHERE until_at < ?', [$now])
            + $this->run('DELETE FROM cache WHERE until_at < ?', [$now]);
    }
}
