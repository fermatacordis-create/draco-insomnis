<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

defined('ABSPATH') || exit;

/**
 * Held submissions. A held message lives here until its sender confirms or PENDING_HOURS pass. Once it
 * is delivered or expires the body is erased; the row keeps only who sent it, for KEEP_DAYS, so the
 * sender can still be blocked. Blocks themselves live in the shield's table: one list for the site.
 */
final class Store
{
    public const PENDING_HOURS = 48;
    public const KEEP_DAYS = 90;
    private const SCHEMA = '1';
    private const SCHEMA_OPTION = 'draco_gate_schema';

    public static function table(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_submissions';
    }

    public static function ensureTable(): void
    {
        if (get_option(self::SCHEMA_OPTION) === self::SCHEMA) {
            return;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta('CREATE TABLE ' . self::table() . " (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            token_hash char(64) NOT NULL,
            kind varchar(12) NOT NULL,
            context varchar(24) NOT NULL,
            email varchar(190) NOT NULL,
            ip varchar(45) NOT NULL,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            payload longtext NULL,
            status varchar(12) NOT NULL DEFAULT 'pending',
            created_at datetime NOT NULL,
            verified_at datetime NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY token_hash (token_hash),
            KEY status_created (status, created_at),
            KEY email (email)
        ) " . $wpdb->get_charset_collate() . ';');
        update_option(self::SCHEMA_OPTION, self::SCHEMA);
    }

    /** @return array{id: int, token: string}|null */
    public static function create(string $kind, string $context, string $email, string $ip, int $userId = 0): ?array
    {
        global $wpdb;
        $token = bin2hex(random_bytes(32));
        $ok = $wpdb->insert(self::table(), [
            'token_hash' => hash('sha256', $token),
            'kind' => $kind,
            'context' => substr($context, 0, 24),
            'email' => strtolower($email),
            'ip' => $ip,
            'user_id' => $userId,
            'payload' => '[]',
            'created_at' => current_time('mysql', true),
        ]);

        return $ok ? ['id' => (int) $wpdb->insert_id, 'token' => $token] : null;
    }

    /** @param array<string, mixed> $mail */
    public static function appendMail(int $id, array $mail): void
    {
        $row = self::find($id);
        if ($row === null) {
            return;
        }
        $mails = json_decode((string) $row['payload'], true);
        $mails = is_array($mails) ? $mails : [];
        $mails[] = $mail;
        self::setPayload($id, $mails);
    }

    /** @param array<mixed> $payload */
    public static function setPayload(int $id, array $payload): void
    {
        global $wpdb;
        $wpdb->update(self::table(), ['payload' => (string) wp_json_encode($payload)], ['id' => $id]);
    }

    /** @return array<string, mixed>|null */
    public static function find(int $id): ?array
    {
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . self::table() . ' WHERE id = %d', $id), ARRAY_A);

        return is_array($row) ? $row : null;
    }

    /** @return array<string, mixed>|null The submission, only while it can still be confirmed. */
    public static function findPending(string $token): ?array
    {
        global $wpdb;
        if (preg_match('/^[a-f0-9]{64}$/', $token) !== 1) {
            return null;
        }
        $row = $wpdb->get_row($wpdb->prepare(
            'SELECT * FROM ' . self::table() . " WHERE token_hash = %s AND status = 'pending' AND created_at > %s",
            hash('sha256', $token),
            gmdate('Y-m-d H:i:s', time() - self::PENDING_HOURS * 3600),
        ), ARRAY_A);

        return is_array($row) ? $row : null;
    }

    /** Only one request wins, so a double click cannot deliver a message twice. */
    public static function claim(int $id): bool
    {
        global $wpdb;

        return (bool) $wpdb->update(self::table(), ['status' => 'verified', 'verified_at' => current_time('mysql', true)], ['id' => $id, 'status' => 'pending']);
    }

    public static function erasePayload(int $id): void
    {
        global $wpdb;
        $wpdb->update(self::table(), ['payload' => null], ['id' => $id]);
    }

    /** @return list<array<string, mixed>> */
    public static function recent(int $limit = 50): array
    {
        global $wpdb;

        return (array) $wpdb->get_results($wpdb->prepare(
            'SELECT id, kind, context, email, ip, status, created_at, verified_at FROM ' . self::table() . ' ORDER BY id DESC LIMIT %d',
            $limit,
        ), ARRAY_A);
    }

    /** Unconfirmed messages are erased; old rows disappear. */
    public static function cleanup(): void
    {
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            'UPDATE ' . self::table() . " SET status = 'expired', payload = NULL WHERE status = 'pending' AND created_at < %s",
            gmdate('Y-m-d H:i:s', time() - self::PENDING_HOURS * 3600),
        ));
        $wpdb->query($wpdb->prepare('DELETE FROM ' . self::table() . ' WHERE created_at < %s', gmdate('Y-m-d H:i:s', time() - self::KEEP_DAYS * 86400)));
    }
}
