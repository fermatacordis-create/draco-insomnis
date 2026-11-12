<?php
/**
 * @author    Notorius Vision
 * @license   GPL-2.0-or-later
 */

declare(strict_types=1);

namespace DracoInsomnis\Presta;

use DracoInsomnis\Core\EventStore;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Suspicious attempts (the evidence for an abuse report), blocked senders, and short-lived counters,
 * in the module's own tables. Never stores passwords or anything beyond the fields the engines pass.
 */
final class Store implements EventStore
{
    public const KEEP_DAYS = 90;
    public const BLOCK_DAYS = [7, 15, 30, 90];
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;

    private static function table(string $name): string
    {
        return '`' . _DB_PREFIX_ . 'draco_' . $name . '`';
    }

    private static function db(): \Db
    {
        return \Db::getInstance();
    }

    private static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    public static function install(): bool
    {
        $engine = _MYSQL_ENGINE_;

        return self::db()->execute('CREATE TABLE IF NOT EXISTS ' . self::table('events') . " (
                id_event bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                created_at datetime NOT NULL,
                ip varchar(45) NOT NULL,
                remote_addr varchar(45) NOT NULL,
                endpoint varchar(40) NOT NULL,
                score smallint(5) unsigned NOT NULL,
                verdict varchar(10) NOT NULL,
                reasons varchar(190) NOT NULL DEFAULT '',
                user_agent varchar(255) NOT NULL DEFAULT '',
                fields text NULL,
                PRIMARY KEY (id_event),
                KEY ip_created (ip, created_at),
                KEY verdict_created (verdict, created_at)
            ) ENGINE=$engine DEFAULT CHARSET=utf8mb4")
            && self::db()->execute('CREATE TABLE IF NOT EXISTS ' . self::table('blocks') . " (
                id_block bigint(20) unsigned NOT NULL AUTO_INCREMENT,
                kind varchar(8) NOT NULL,
                value varchar(190) NOT NULL,
                reason varchar(190) NOT NULL DEFAULT '',
                created_at datetime NOT NULL,
                until_at datetime NOT NULL,
                PRIMARY KEY (id_block),
                KEY lookup (kind, value, until_at)
            ) ENGINE=$engine DEFAULT CHARSET=utf8mb4")
            && self::db()->execute('CREATE TABLE IF NOT EXISTS ' . self::table('cache') . " (
                k varchar(190) NOT NULL,
                v varchar(255) NOT NULL DEFAULT '',
                expires int(10) unsigned NOT NULL,
                PRIMARY KEY (k),
                KEY expires (expires)
            ) ENGINE=$engine DEFAULT CHARSET=utf8mb4");
    }

    public static function uninstall(): void
    {
        foreach (['events', 'blocks', 'cache'] as $name) {
            self::db()->execute('DROP TABLE IF EXISTS ' . self::table($name));
        }
    }

    /* Counters and short-lived values (PrestaShop has no transients). */

    public static function bump(string $key, int $ttl): int
    {
        $k = pSQL(substr($key, 0, 190));
        $now = time();
        $until = $now + $ttl;
        self::db()->execute('INSERT INTO ' . self::table('cache') . " (k, v, expires) VALUES ('$k', '1', $until)
            ON DUPLICATE KEY UPDATE v = IF(expires < $now, 1, CAST(v AS UNSIGNED) + 1), expires = $until");

        return (int) self::db()->getValue('SELECT v FROM ' . self::table('cache') . " WHERE k = '$k'", false);
    }

    public static function recall(string $key): ?string
    {
        $value = self::db()->getValue('SELECT v FROM ' . self::table('cache') . " WHERE k = '" . pSQL(substr($key, 0, 190)) . "' AND expires >= " . time(), false);

        return $value === false || $value === null ? null : (string) $value;
    }

    public static function remember(string $key, string $value, int $ttl): void
    {
        $k = pSQL(substr($key, 0, 190));
        $v = pSQL(substr($value, 0, 255));
        $until = time() + $ttl;
        self::db()->execute('INSERT INTO ' . self::table('cache') . " (k, v, expires) VALUES ('$k', '$v', $until)
            ON DUPLICATE KEY UPDATE v = '$v', expires = $until");
    }

    /* Evidence and block list. */

    public function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        if (self::bump('draco_rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        self::db()->insert('draco_events', [
            'created_at' => self::now(),
            'ip' => pSQL($ip),
            'remote_addr' => pSQL($remoteAddr),
            'endpoint' => pSQL(substr($endpoint, 0, 40)),
            'score' => min(65535, max(0, (int) $result['score'])),
            'verdict' => pSQL((string) $result['verdict']),
            'reasons' => pSQL(substr(implode(',', $result['reasons']), 0, 190)),
            'user_agent' => pSQL(substr($userAgent, 0, 255)),
            'fields' => pSQL((string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)),
        ]);
    }

    public function botAttemptsSince(string $ip, int $seconds): int
    {
        return (int) self::db()->getValue('SELECT COUNT(*) FROM ' . self::table('events') . " WHERE ip = '" . pSQL($ip) . "' AND verdict = 'bot' AND created_at > '" . gmdate('Y-m-d H:i:s', time() - $seconds) . "'", false);
    }

    public function isBlocked(string $email, string $ip): bool
    {
        return (bool) self::db()->getValue('SELECT id_block FROM ' . self::table('blocks') . " WHERE until_at > '" . self::now() . "'
            AND ((kind = 'email' AND value = '" . pSQL(strtolower($email)) . "') OR (kind = 'ip' AND value = '" . pSQL(strtolower($ip)) . "'))", false);
    }

    /** Never blocks an employee's e-mail or an address an employee used recently. */
    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        $value = strtolower(trim($value));
        if (!in_array($days, self::BLOCK_DAYS, true)) {
            return false;
        }
        if ($kind === 'ip') {
            if (filter_var($value, FILTER_VALIDATE_IP) === false || in_array($value, Settings::adminIps(), true)) {
                return false;
            }
            if (!$automatic && $value === strtolower(PsHost::request()->via(PsHost::get()))) {
                return false;
            }
        } elseif ($kind === 'email') {
            if (!\Validate::isEmail($value) || \Employee::employeeExists($value)) {
                return false;
            }
        } else {
            return false;
        }

        return self::db()->insert('draco_blocks', [
            'kind' => pSQL($kind),
            'value' => pSQL($value),
            'reason' => pSQL(substr($reason, 0, 190)),
            'created_at' => self::now(),
            'until_at' => gmdate('Y-m-d H:i:s', time() + $days * 86400),
        ]);
    }

    public static function unblock(int $id): void
    {
        self::db()->delete('draco_blocks', 'id_block = ' . (int) $id);
    }

    /** @return list<array<string, mixed>> */
    public static function recent(int $limit = 50): array
    {
        return (array) self::db()->executeS('SELECT * FROM ' . self::table('events') . ' ORDER BY id_event DESC LIMIT ' . (int) $limit, true, false);
    }

    /** @return list<array<string, mixed>> */
    public static function activeBlocks(): array
    {
        return (array) self::db()->executeS('SELECT * FROM ' . self::table('blocks') . " WHERE until_at > '" . self::now() . "' ORDER BY until_at DESC LIMIT 200", true, false);
    }

    /** Everything from one address, oldest first, for an abuse report. @return list<array<string, mixed>> */
    public static function byIp(string $ip): array
    {
        $ip = pSQL($ip);

        return (array) self::db()->executeS('SELECT * FROM ' . self::table('events') . " WHERE ip = '$ip' OR remote_addr = '$ip' ORDER BY id_event ASC LIMIT 2000", true, false);
    }

    /** PrestaShop has no cron of its own: about one request in two hundred tidies up. */
    public static function maybeCleanup(): void
    {
        if (random_int(1, 200) !== 1) {
            return;
        }
        self::db()->execute('DELETE FROM ' . self::table('events') . " WHERE created_at < '" . gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400) . "'");
        self::db()->execute('DELETE FROM ' . self::table('blocks') . " WHERE until_at < '" . self::now() . "'");
        self::db()->execute('DELETE FROM ' . self::table('cache') . ' WHERE expires < ' . time());
    }
}
