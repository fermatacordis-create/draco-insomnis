<?php

declare(strict_types=1);

namespace DracoInsomnis\Shield;

defined('ABSPATH') || exit;

/**
 * Suspicious attempts (the evidence for an abuse report) and blocked senders.
 * Never stores passwords or anything beyond the fields listed in Guard::evidence().
 */
final class Store
{
    public const KEEP_DAYS = 90;
    public const BLOCK_DAYS = [7, 15, 30, 90];
    private const SCHEMA = '1';
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
        update_option(self::SCHEMA_OPTION, self::SCHEMA);
    }

    /** @param array{score: int, verdict: string, reasons: list<string>} $result @param array<string, string> $fields */
    public static function log(string $ip, string $remoteAddr, string $endpoint, array $result, string $userAgent, array $fields): void
    {
        $key = 'draco_rows_' . md5($ip);
        $rows = (int) get_transient($key) + 1;
        set_transient($key, $rows, HOUR_IN_SECONDS);
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
            'SELECT COUNT(*) FROM ' . self::events() . " WHERE ip = %s AND verdict = 'bot' AND created_at > %s",
            $ip,
            gmdate('Y-m-d H:i:s', time() - $seconds),
        ));
    }

    /** @return list<array<string, mixed>> */
    public static function recent(int $limit = 50): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare('SELECT * FROM ' . self::events() . ' ORDER BY id DESC LIMIT %d', $limit), ARRAY_A);
    }

    /** Everything from one address, oldest first, for an abuse report. @return list<array<string, mixed>> */
    public static function byIp(string $ip): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            'SELECT * FROM ' . self::events() . ' WHERE ip = %s OR remote_addr = %s ORDER BY id ASC LIMIT 2000',
            $ip,
            $ip,
        ), ARRAY_A);
    }

    public static function isBlocked(string $email, string $ip): bool
    {
        global $wpdb;
        $found = $wpdb->get_var($wpdb->prepare(
            'SELECT id FROM ' . self::blocks() . " WHERE until_at > %s AND ((kind = 'email' AND value = %s) OR (kind = 'ip' AND value = %s)) LIMIT 1",
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
            'SELECT * FROM ' . self::blocks() . ' WHERE until_at > %s ORDER BY until_at DESC LIMIT 200',
            current_time('mysql', true),
        ), ARRAY_A);
    }

    public static function cleanup(): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare('DELETE FROM ' . self::events() . ' WHERE created_at < %s', gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400)));
        $wpdb->query($wpdb->prepare('DELETE FROM ' . self::blocks() . ' WHERE until_at < %s', current_time('mysql', true)));
    }
}
