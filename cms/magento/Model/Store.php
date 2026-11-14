<?php

declare(strict_types=1);

namespace DracoInsomnis\Magento\Model;

use DracoInsomnis\Core\Blocklist;
use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\NetList;
use DracoInsomnis\Core\Review;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;

/**
 * Suspicious attempts (the evidence for an abuse report), the block list and short-lived counters,
 * in the module's own tables. Never stores passwords or anything beyond the fields the engines pass.
 */
class Store implements EventStore
{
    public const KEEP_DAYS = 90;
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;
    private const ADMIN_IPS = 'draco_admin_ips';

    /** @var array<string, list<string>> */
    private array $active = [];

    public function __construct(private ResourceConnection $resource, private ScopeConfigInterface $config)
    {
    }

    private function db(): AdapterInterface
    {
        return $this->resource->getConnection();
    }

    private function table(string $name): string
    {
        return $this->resource->getTableName('draco_' . $name);
    }

    private static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    /* Counters and short-lived values. */

    public function bump(string $key, int $ttl): int
    {
        $k = substr($key, 0, 190);
        $now = time();
        $until = $now + $ttl;
        $this->db()->query(
            'INSERT INTO ' . $this->table('cache') . ' (k, v, expires) VALUES (?, \'1\', ?)
            ON DUPLICATE KEY UPDATE v = IF(expires < ?, 1, CAST(v AS UNSIGNED) + 1), expires = ?',
            [$k, $until, $now, $until]
        );

        return (int) $this->db()->fetchOne('SELECT v FROM ' . $this->table('cache') . ' WHERE k = ?', [$k]);
    }

    public function recall(string $key): ?string
    {
        $value = $this->db()->fetchOne('SELECT v FROM ' . $this->table('cache') . ' WHERE k = ? AND expires >= ?', [substr($key, 0, 190), time()]);

        return $value === false || $value === null ? null : (string) $value;
    }

    public function remember(string $key, string $value, int $ttl): void
    {
        $this->db()->insertOnDuplicate($this->table('cache'), [
            'k' => substr($key, 0, 190),
            'v' => substr($value, 0, 255),
            'expires' => time() + $ttl,
        ], ['v', 'expires']);
    }

    /* Evidence and block list. */

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        if ($this->bump('draco_rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        $this->db()->insert($this->table('events'), [
            'created_at' => self::now(),
            'ip' => substr($ip, 0, 45),
            'remote_addr' => substr($remoteAddr, 0, 45),
            'endpoint' => substr($endpoint, 0, 40),
            'score' => min(65535, max(0, (int) $result['score'])),
            'verdict' => substr((string) $result['verdict'], 0, 10),
            'reasons' => substr(implode(',', $result['reasons']), 0, 190),
            'user_agent' => substr($userAgent, 0, 255),
            'fields' => (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return (int) $this->db()->fetchOne(
            'SELECT COUNT(*) FROM ' . $this->table('events') . ' WHERE ip = ? AND verdict = \'bot\' AND created_at > ?',
            [$ip, gmdate('Y-m-d H:i:s', time() - $seconds)]
        );
    }

    public function isBlocked(string $email, string $ip): bool
    {
        $hit = $this->db()->fetchOne(
            'SELECT id FROM ' . $this->table('blocks') . ' WHERE until_at > ? AND ((kind = \'email\' AND value = ?) OR (kind = \'ip\' AND value = ?)) LIMIT 1',
            [self::now(), strtolower($email), strtolower($ip)]
        );
        if ($hit) {
            return true;
        }

        return $ip !== '' && NetList::contains($this->activeValues('net'), $ip);
    }

    /**
     * Values of one kind in force: 'net' (blocked ranges) or 'allow' (addresses let through after a
     * review). Read once per request.
     *
     * @return list<string>
     */
    public function activeValues(string $kind): array
    {
        if (!isset($this->active[$kind])) {
            $this->active[$kind] = array_values(array_map('strval', $this->db()->fetchCol(
                'SELECT value FROM ' . $this->table('blocks') . ' WHERE kind = ? AND until_at > ? LIMIT 500',
                [$kind, self::now()]
            )));
        }

        return $this->active[$kind];
    }

    /** Lets an address through the firewall and the block list for a while (1, 7, 30 days or 0 = forever). */
    public function allow(string $ip, int $days, string $reason): bool
    {
        $ip = strtolower(trim($ip));
        if (filter_var($ip, FILTER_VALIDATE_IP) === false || !in_array($days, [1, 7, 30, 0], true)) {
            return false;
        }
        $this->db()->delete($this->table('blocks'), ['kind IN (?)' => ['ip', 'allow'], 'value = ?' => $ip]);
        $this->db()->insert($this->table('blocks'), [
            'kind' => 'allow',
            'value' => $ip,
            'reason' => substr($reason, 0, 190),
            'created_at' => self::now(),
            'until_at' => Blocklist::untilAt($days, time()),
        ]);
        unset($this->active['allow']);

        return true;
    }

    /**
     * Never blocks an administrator's e-mail or an address an administrator used recently.
     *
     * @param list<string> $protected Addresses that must not be blocked.
     */
    public function blockProtected(string $kind, string $value, int $days, string $reason, array $protected): bool
    {
        $value = strtolower(trim($value));
        if (!in_array($days, Blocklist::DAYS, true)) {
            return false;
        }
        if ($kind === 'ip' || $kind === 'net') {
            $address = Blocklist::address($value, $days, $protected);
            if ($address === null) {
                return false;
            }
            ['kind' => $kind, 'value' => $value] = $address;
        } elseif ($kind === 'email') {
            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false || $this->isAdminEmail($value)) {
                return false;
            }
        } else {
            return false;
        }
        $this->db()->insert($this->table('blocks'), [
            'kind' => $kind,
            'value' => $value,
            'reason' => substr($reason, 0, 190),
            'created_at' => self::now(),
            'until_at' => Blocklist::untilAt($days, time()),
        ]);
        unset($this->active[$kind]);

        return true;
    }

    /** Through the engines: the protected addresses are the administrators' ones. */
    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        return $this->blockProtected($kind, $value, $days, $reason, $this->adminIps());
    }

    /**
     * Never blocked, never limited: the addresses in the settings, the last ten administrators logged
     * in from, and the addresses a person let through after a review.
     *
     * @return list<string>
     */
    public function adminIps(): array
    {
        $configured = array_map('trim', explode(',', (string) $this->config->getValue(Settings::PATH . 'network/admin_ips')));
        $remembered = json_decode((string) $this->recall(self::ADMIN_IPS), true);

        return array_values(array_unique(array_filter(array_merge(
            $configured,
            is_array($remembered) ? $remembered : [],
            $this->activeValues('allow')
        ), static fn ($ip): bool => is_string($ip) && $ip !== '')));
    }

    public function rememberAdminIp(string $ip): void
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return;
        }
        $list = json_decode((string) $this->recall(self::ADMIN_IPS), true);
        $list = is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
        if (($list[0] ?? null) === $ip) {
            return;
        }
        $this->remember(self::ADMIN_IPS, (string) json_encode(array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10)), 400 * 86400);
    }

    private function isAdminEmail(string $email): bool
    {
        return (bool) $this->db()->fetchOne('SELECT user_id FROM ' . $this->resource->getTableName('admin_user') . ' WHERE LOWER(email) = ? LIMIT 1', [$email]);
    }

    public function unblock(int $id): bool
    {
        $done = $this->db()->delete($this->table('blocks'), ['id = ?' => $id]) > 0;
        $this->active = [];

        return $done;
    }

    /** Review requests, pending first. @return list<array<string, mixed>> */
    public function reviews(int $limit = 50): array
    {
        $rows = $this->db()->fetchAll(
            'SELECT * FROM ' . $this->table('events') . ' WHERE endpoint = ? ORDER BY id DESC LIMIT ' . max(1, $limit),
            [Review::ENDPOINT]
        );
        usort($rows, static fn (array $a, array $b): int => ($a['verdict'] === 'pending' ? 0 : 1) <=> ($b['verdict'] === 'pending' ? 0 : 1));

        return $rows;
    }

    /** @return array<string, mixed>|null */
    public function review(int $id): ?array
    {
        $row = $this->db()->fetchRow('SELECT * FROM ' . $this->table('events') . ' WHERE id = ? AND endpoint = ?', [$id, Review::ENDPOINT]);

        return is_array($row) ? $row : null;
    }

    public function setVerdict(int $id, string $verdict): void
    {
        $this->db()->update($this->table('events'), ['verdict' => substr($verdict, 0, 10)], ['id = ?' => $id]);
    }

    /** Firewall events of the last $seconds, for the summary. @return list<array<string, mixed>> */
    public function wafRows(int $seconds): array
    {
        return $this->db()->fetchAll(
            'SELECT ip, verdict, reasons FROM ' . $this->table('events') . ' WHERE endpoint LIKE \'waf:%\' AND created_at > ? LIMIT 5000',
            [gmdate('Y-m-d H:i:s', time() - $seconds)]
        );
    }

    /** @return list<array<string, mixed>> */
    public function recent(int $limit = 50): array
    {
        return $this->db()->fetchAll('SELECT * FROM ' . $this->table('events') . ' ORDER BY id DESC LIMIT ' . max(1, $limit));
    }

    /** @return list<array<string, mixed>> */
    public function activeBlocks(): array
    {
        return $this->db()->fetchAll('SELECT * FROM ' . $this->table('blocks') . ' WHERE until_at > ? ORDER BY until_at DESC LIMIT 200', [self::now()]);
    }

    /** Everything from one address, oldest first, for an abuse report. @return list<array<string, mixed>> */
    public function byIp(string $ip): array
    {
        return $this->db()->fetchAll('SELECT * FROM ' . $this->table('events') . ' WHERE ip = ? OR remote_addr = ? ORDER BY id ASC LIMIT 2000', [$ip, $ip]);
    }

    /** Evidence older than 90 days, finished blocks and expired counters. Returns the rows removed. */
    public function cleanup(): int
    {
        $removed = $this->db()->delete($this->table('events'), ['created_at < ?' => gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400)]);
        $removed += $this->db()->delete($this->table('blocks'), ['until_at < ?' => self::now()]);
        $removed += $this->db()->delete($this->table('cache'), ['expires < ?' => time()]);
        $this->active = [];

        return $removed;
    }
}
