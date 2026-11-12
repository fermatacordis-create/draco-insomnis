<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

defined('ABSPATH') || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- the plugin's own tables have no WordPress API; every value goes through prepare().

/**
 * Suspicious attempts (the evidence for an abuse report) and blocked senders.
 * Never stores passwords or anything beyond the fields the engines in src/Core pass.
 */
final class Store
{
    public const KEEP_DAYS = 90;
    public const BLOCK_DAYS = [7, 15, 30, 90];
    private const SCHEMA = '2';
    private const SCHEMA_OPTION = 'draco_schema';
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;

    public static function events(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_events';
    }

    public static function blocks(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_blocks';
    }

    public static function counters(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_counters';
    }

    /**
     * Adds one to a counter that lives $ttl seconds from its first count and returns the new value, in a
     * single statement: two requests at the same moment never read the same value (a transient would
     * be read, added to and saved in three steps, and both would count the same try).
     */
    public static function bump(string $key, int $ttl): int
    {
        global $wpdb;
        self::ensureTables();
        $now = time();
        $key = substr($key, 0, 190);
        $suppress = $wpdb->suppress_errors(true);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- an atomic counter cannot be cached
        $done = $wpdb->query($wpdb->prepare(
            'INSERT INTO %i (k, n, expires_at) VALUES (%s, LAST_INSERT_ID(1), %d)
             ON DUPLICATE KEY UPDATE n = LAST_INSERT_ID(IF(expires_at < %d, 1, n + 1)), expires_at = IF(expires_at < %d, %d, expires_at)',
            self::counters(),
            $key,
            $now + $ttl,
            $now,
            $now,
            $now + $ttl,
        ));
        $count = $done === false ? 0 : (int) $wpdb->get_var('SELECT LAST_INSERT_ID()'); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $wpdb->suppress_errors($suppress);
        if ($count > 0) {
            return $count;
        }
        // Without the table (a database that refuses it): the old way, good enough on a quiet site.
        $count = (int) get_transient($key) + 1;
        set_transient($key, $count, $ttl);

        return $count;
    }

    public static function ensureTables(): void
    {
        if (get_option(self::SCHEMA_OPTION) === self::SCHEMA) {
            return;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        dbDelta('CREATE TABLE ' . self::events() . " (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            created_at datetime NOT NULL,
            ip varchar(45) NOT NULL,
            remote_addr varchar(45) NOT NULL,
            endpoint varchar(40) NOT NULL,
            score smallint(5) unsigned NOT NULL,
            verdict varchar(10) NOT NULL,
            reasons varchar(190) NOT NULL DEFAULT '',
            user_agent varchar(255) NOT NULL DEFAULT '',
            fields text NULL,
            PRIMARY KEY  (id),
            KEY ip_created (ip, created_at),
            KEY verdict_created (verdict, created_at)
        ) $charset;");
        dbDelta('CREATE TABLE ' . self::blocks() . " (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            kind varchar(8) NOT NULL,
            value varchar(190) NOT NULL,
            reason varchar(190) NOT NULL DEFAULT '',
            created_at datetime NOT NULL,
            until_at datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY lookup (kind, value, until_at)
        ) $charset;");
        dbDelta('CREATE TABLE ' . self::counters() . " (
            k varchar(190) NOT NULL,
            n int(10) unsigned NOT NULL DEFAULT 0,
            expires_at int(10) unsigned NOT NULL,
            PRIMARY KEY  (k),
            KEY expires_at (expires_at)
        ) $charset;");
        update_option(self::SCHEMA_OPTION, self::SCHEMA);
    }

    /** @param array{score: int, verdict: string, reasons: list<string>} $result @param array<string, string> $fields */
    public static function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        $key = 'draco_rows_' . md5($ip);
        $rows = self::bump($key, HOUR_IN_SECONDS);
        if ($rows > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        global $wpdb;
        $wpdb->insert(self::events(), [
            'created_at' => current_time('mysql', true),
            'ip' => $ip,
            'remote_addr' => $remoteAddr,
            'endpoint' => substr($endpoint, 0, 40),
            'score' => min(65535, max(0, $result['score'])),
            'verdict' => $result['verdict'],
            'reasons' => substr(implode(',', $result['reasons']), 0, 190),
            'user_agent' => substr($userAgent, 0, 255),
            'fields' => (string) wp_json_encode($fields),
        ]);
    }

    public static function botAttemptsSince(string $ip, int $seconds): int
    {
        global $wpdb;

        return (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM %i WHERE ip = %s AND verdict = 'bot' AND created_at > %s",
            self::events(),
            $ip,
            gmdate('Y-m-d H:i:s', time() - $seconds),
        ));
    }

    /** @return list<array<string, mixed>> */
    public static function recent(int $limit = 50): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY id DESC LIMIT %d", self::events(), $limit), ARRAY_A);
    }

    /** @return list<array<string, mixed>> */
    public static function recentWhere(string $endpointPrefix, int $limit = 50): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM %i WHERE endpoint LIKE %s ORDER BY id DESC LIMIT %d",
            self::events(),
            $wpdb->esc_like($endpointPrefix) . '%',
            $limit,
        ), ARRAY_A);
    }

    /** Everything from one address, oldest first, for an abuse report. @return list<array<string, mixed>> */
    public static function byIp(string $ip): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM %i WHERE ip = %s OR remote_addr = %s ORDER BY id ASC LIMIT 2000",
            self::events(),
            $ip,
            $ip,
        ), ARRAY_A);
    }

    public static function isBlocked(string $email, string $ip): bool
    {
        global $wpdb;
        $found = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM %i WHERE until_at > %s AND ((kind = 'email' AND value = %s) OR (kind = 'ip' AND value = %s)) LIMIT 1",
            self::blocks(),
            current_time('mysql', true),
            strtolower($email),
            strtolower($ip),
        ));

        return $found !== null;
    }

    /**
     * Never blocks an administrator's e-mail or an address an administrator used recently. From the
     * screen it also refuses the address of whoever is clicking; the automatic block runs inside the
     * bot's own request, where "the current address" is the bot's, so it skips that one check.
     */
    public static function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool
    {
        $value = strtolower(trim($value));
        if (!in_array($days, self::BLOCK_DAYS, true)) {
            return false;
        }
        if ($kind === 'ip') {
            if (filter_var($value, FILTER_VALIDATE_IP) === false || in_array($value, (array) get_option('draco_admin_ips', []), true)) {
                return false;
            }
            if (!$automatic && $value === strtolower(Guard::clientIp())) {
                return false;
            }
        } elseif ($kind === 'email') {
            $user = is_email($value) ? get_user_by('email', $value) : false;
            if (!is_email($value) || ($user instanceof \WP_User && user_can($user, 'manage_options'))) {
                return false;
            }
        } else {
            return false;
        }
        global $wpdb;

        return (bool) $wpdb->insert(self::blocks(), [
            'kind' => $kind,
            'value' => $value,
            'reason' => substr($reason, 0, 190),
            'created_at' => current_time('mysql', true),
            'until_at' => gmdate('Y-m-d H:i:s', time() + $days * 86400),
        ]);
    }

    public static function unblock(int $id): void
    {
        global $wpdb;
        $wpdb->delete(self::blocks(), ['id' => $id]);
    }

    /** @return list<array<string, mixed>> */
    public static function activeBlocks(): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM %i WHERE until_at > %s ORDER BY until_at DESC LIMIT 200",
            self::blocks(),
            current_time('mysql', true),
        ), ARRAY_A);
    }

    public static function cleanup(): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE created_at < %s", self::events(), gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400)));
        $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE until_at < %s", self::blocks(), current_time('mysql', true)));
        $wpdb->query($wpdb->prepare("DELETE FROM %i WHERE expires_at < %d", self::counters(), time()));
    }
}
