<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis;

use DracoInsomnis\Core\EventStore;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../engine/autoload.php');

/**
 * Evidence, block list and short-lived counters, in the plugin's own tables.
 * Never stores passwords or anything beyond the fields the engines pass.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */
final class store implements EventStore {

    /** Days the evidence is kept. */
    public const KEEP_DAYS = 90;
    /** Allowed block lengths, in days. */
    public const BLOCK_DAYS = [7, 15, 30, 90];
    /** One flood must not fill the database: past this, attempts from that IP in the hour are only counted. */
    private const MAX_ROWS_PER_IP_HOUR = 30;

    /**
     * Adds one to a counter that lives $ttl seconds.
     *
     * @param string $key
     * @param int $ttl
     * @return int The new value.
     */
    public static function bump(string $key, int $ttl): int {
        global $DB;
        $k = substr($key, 0, 190);
        $now = time();
        if (!$DB->record_exists('local_dracoinsomnis_cache', ['k' => $k])) {
            try {
                $DB->insert_record('local_dracoinsomnis_cache', (object) ['k' => $k, 'n' => 1, 'v' => '', 'expires' => $now + $ttl]);
                return 1;
            } catch (\dml_exception $e) {
                // Another request inserted it in between: count on that row.
                unset($e);
            }
        }
        $DB->execute('UPDATE {local_dracoinsomnis_cache} SET n = CASE WHEN expires < ? THEN 1 ELSE n + 1 END, expires = ? WHERE k = ?',
            [$now, $now + $ttl, $k]);
        return (int) $DB->get_field('local_dracoinsomnis_cache', 'n', ['k' => $k]);
    }

    /**
     * A short-lived value, or null when missing or expired.
     *
     * @param string $key
     * @return string|null
     */
    public static function recall(string $key): ?string {
        global $DB;
        $value = $DB->get_field_select('local_dracoinsomnis_cache', 'v', 'k = ? AND expires >= ?', [substr($key, 0, 190), time()]);
        return $value === false ? null : (string) $value;
    }

    /**
     * Keeps a value for $ttl seconds.
     *
     * @param string $key
     * @param string $value
     * @param int $ttl
     */
    public static function remember(string $key, string $value, int $ttl): void {
        global $DB;
        $k = substr($key, 0, 190);
        $row = $DB->get_record('local_dracoinsomnis_cache', ['k' => $k]);
        $data = ['k' => $k, 'n' => 0, 'v' => substr($value, 0, 255), 'expires' => time() + $ttl];
        if ($row) {
            $DB->update_record('local_dracoinsomnis_cache', (object) (['id' => $row->id] + $data));
        } else {
            $DB->insert_record('local_dracoinsomnis_cache', (object) $data);
        }
    }

    public function log(string $ip, string $remoteaddr, string $endpoint, array $result, string $useragent, array $fields): void {
        global $DB;
        if (self::bump('draco_rows_' . md5($ip), 3600) > self::MAX_ROWS_PER_IP_HOUR) {
            return;
        }
        $DB->insert_record('local_dracoinsomnis_events', (object) [
            'timecreated' => time(),
            'ip' => $ip,
            'remoteaddr' => $remoteaddr,
            'endpoint' => substr($endpoint, 0, 40),
            'score' => min(65535, max(0, (int) $result['score'])),
            'verdict' => (string) $result['verdict'],
            'reasons' => substr(implode(',', $result['reasons']), 0, 190),
            'useragent' => substr($useragent, 0, 255),
            'fields' => (string) json_encode($fields, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        ]);
    }

    public function botAttemptsSince(string $ip, int $seconds): int {
        global $DB;
        return $DB->count_records_select('local_dracoinsomnis_events', "ip = ? AND verdict = 'bot' AND timecreated > ?", [$ip, time() - $seconds]);
    }

    public function isBlocked(string $email, string $ip): bool {
        global $DB;
        return $DB->record_exists_select('local_dracoinsomnis_blocks',
            "timeuntil > ? AND ((kind = 'email' AND value = ?) OR (kind = 'ip' AND value = ?))",
            [time(), strtolower($email), strtolower($ip)]);
    }

    public function block(string $kind, string $value, int $days, string $reason, bool $automatic = false): bool {
        global $DB;
        $value = strtolower(trim($value));
        if (!in_array($days, self::BLOCK_DAYS, true)) {
            return false;
        }
        if ($kind === 'ip') {
            if (filter_var($value, FILTER_VALIDATE_IP) === false || in_array($value, moodle_host::get()->adminIps(), true)) {
                return false;
            }
        } else if ($kind === 'email') {
            if (filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                return false;
            }
            foreach (get_admins() as $admin) {
                if (strtolower($admin->email) === $value) {
                    return false;
                }
            }
        } else {
            return false;
        }
        $DB->insert_record('local_dracoinsomnis_blocks', (object) [
            'kind' => $kind,
            'value' => $value,
            'reason' => substr($reason, 0, 190),
            'timecreated' => time(),
            'timeuntil' => time() + $days * 86400,
        ]);
        return true;
    }

    /**
     * Removes one block.
     *
     * @param int $id
     */
    public static function unblock(int $id): void {
        global $DB;
        $DB->delete_records('local_dracoinsomnis_blocks', ['id' => $id]);
    }

    /**
     * The latest attempts.
     *
     * @param int $limit
     * @return array
     */
    public static function recent(int $limit = 50): array {
        global $DB;
        return array_values($DB->get_records('local_dracoinsomnis_events', null, 'id DESC', '*', 0, $limit));
    }

    /**
     * Blocks still in force.
     *
     * @return array
     */
    public static function active_blocks(): array {
        global $DB;
        return array_values($DB->get_records_select('local_dracoinsomnis_blocks', 'timeuntil > ?', [time()], 'timeuntil DESC', '*', 0, 200));
    }

    /**
     * Everything from one address, oldest first, for an abuse report.
     *
     * @param string $ip
     * @return array
     */
    public static function by_ip(string $ip): array {
        global $DB;
        return array_values($DB->get_records_select('local_dracoinsomnis_events', 'ip = ? OR remoteaddr = ?', [$ip, $ip], 'id ASC', '*', 0, 2000));
    }

    /**
     * Removes old evidence, finished blocks and expired counters (scheduled task).
     */
    public static function cleanup(): void {
        global $DB;
        $DB->delete_records_select('local_dracoinsomnis_events', 'timecreated < ?', [time() - self::KEEP_DAYS * 86400]);
        $DB->delete_records_select('local_dracoinsomnis_blocks', 'timeuntil < ?', [time()]);
        $DB->delete_records_select('local_dracoinsomnis_cache', 'expires < ?', [time()]);
    }
}
