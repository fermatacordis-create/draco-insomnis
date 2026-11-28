<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

defined('ABSPATH') || exit;

/**
 * Guardia's two tables (docs/adr/0001), created with dbDelta: no foreign keys, ENUM or JSON columns.
 *
 * items:        one row per watched item («kind|key»), its last fingerprint and state, how often it came back.
 * observations: what each scan found for an item (new, changed, gone, back), the history behind a finding.
 */
final class Store
{
    private const SCHEMA = 2;
    private const SCHEMA_OPTION = 'draco_guardia_schema';
    public const OPTION_LAST = 'draco_guardia_last_scan';
    public const OPTION_REVIEWED = 'draco_guardia_reviewed';

    public static function items(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_guardia_items';
    }

    public static function observations(): string
    {
        global $wpdb;

        return $wpdb->prefix . 'draco_guardia_observations';
    }

    public static function ensure(): void
    {
        if ((int) get_option(self::SCHEMA_OPTION, 0) >= self::SCHEMA) {
            return;
        }
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $c = $wpdb->get_charset_collate();
        dbDelta('CREATE TABLE ' . self::items() . " (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  kind varchar(20) NOT NULL,
  item_key varchar(400) NOT NULL,
  item_hash char(40) NOT NULL,
  label varchar(255) NOT NULL DEFAULT '',
  fingerprint varchar(64) NOT NULL DEFAULT '',
  state varchar(12) NOT NULL,
  back_count int(10) unsigned NOT NULL DEFAULT 0,
  origin varchar(10) NOT NULL,
  first_seen datetime NOT NULL,
  last_seen datetime NOT NULL,
  missing_since datetime DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY item_hash (item_hash),
  KEY state (state)
) $c;");
        dbDelta('CREATE TABLE ' . self::observations() . " (
  id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  item_id bigint(20) unsigned NOT NULL,
  event varchar(12) NOT NULL,
  severity varchar(10) NOT NULL,
  back_count int(10) unsigned NOT NULL DEFAULT 0,
  observed_at datetime NOT NULL,
  details varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY  (id),
  KEY item_id (item_id),
  KEY observed_at (observed_at)
) $c;");
        update_option(self::SCHEMA_OPTION, self::SCHEMA, false);
    }

    /** @return array<string, array{state: string, fp: string, back: int}> «kind|key» => stored */
    public static function known(): array
    {
        global $wpdb;
        $out = [];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Guardia's own table
        foreach ((array) $wpdb->get_results($wpdb->prepare('SELECT kind, item_key, fingerprint, state, back_count FROM %i', self::items()), ARRAY_A) as $r) {
            $out[$r['kind'] . '|' . $r['item_key']] = ['state' => (string) $r['state'], 'fp' => (string) $r['fingerprint'], 'back' => (int) $r['back_count']];
        }

        return $out;
    }

    /**
     * Writes one scan: the items' new state and an observation for every event.
     *
     * @param list<array{id: string, event: string, state: string, back: int, severity: string, fp: string}> $events
     * @param array<string, array{fp: string}> $seen   everything found by the scan
     * @param array<string, string>            $labels
     */
    public static function apply(array $events, array $seen, array $labels, bool $restore): void
    {
        global $wpdb;
        $now = current_time('mysql', true);
        // phpcs:disable WordPress.DB.DirectDatabaseQuery -- Guardia's own tables
        foreach ($events as $e) {
            $kind = Diff::kindOf($e['id']);
            $key = Diff::keyOf($e['id']);
            $hash = sha1($e['id']);
            $label = substr((string) ($labels[$e['id']] ?? $key), 0, 255);
            $itemId = (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM %i WHERE item_hash = %s', self::items(), $hash));
            if ($itemId === 0) {
                $wpdb->insert(self::items(), [
                    'kind' => $kind, 'item_key' => substr($key, 0, 400), 'item_hash' => $hash, 'label' => $label, 'fingerprint' => $e['fp'],
                    'state' => $e['state'], 'back_count' => $e['back'], 'origin' => $e['event'] === Diff::BASELINE ? 'baseline' : 'new',
                    'first_seen' => $now, 'last_seen' => $now,
                ]);
                $itemId = (int) $wpdb->insert_id;
            } else {
                $row = ['state' => $e['state'], 'back_count' => $e['back'], 'fingerprint' => $e['fp'], 'label' => $label];
                if ($e['event'] === Diff::GONE) {
                    $row['missing_since'] = $now;
                } else {
                    $row['last_seen'] = $now;
                    $row['missing_since'] = null;
                }
                $wpdb->update(self::items(), $row, ['id' => $itemId]);
            }
            // A restored backup: the returns are recorded but marked, and alerted once as a restore.
            $severity = $restore && $e['event'] === Diff::BACK ? Diff::INFO : $e['severity'];
            $wpdb->insert(self::observations(), ['item_id' => $itemId, 'event' => $restore && $e['event'] === Diff::BACK ? Diff::RESTORE : $e['event'], 'severity' => $severity, 'back_count' => $e['back'], 'observed_at' => $now, 'details' => substr($label, 0, 255)]);
        }
        // After the events every item not missing is one this scan saw: «last seen» moves for all of them.
        $wpdb->query($wpdb->prepare('UPDATE %i SET last_seen = %s WHERE state <> %s', self::items(), $now, Diff::MISSING));
        // phpcs:enable
    }

    /** @return list<array<string, mixed>> the latest observations that matter (not «gone», not baseline info) */
    public static function findings(int $limit = 100): array
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Guardia's own tables
        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT o.id, o.event, o.severity, o.observed_at, o.details, o.back_count, i.kind, i.item_key, i.state FROM %i o JOIN %i i ON i.id = o.item_id
             WHERE o.event NOT IN ('baseline', 'gone') ORDER BY o.id DESC LIMIT %d",
            self::observations(),
            self::items(),
            $limit
        ), ARRAY_A);
    }

    /** @return list<array<string, mixed>> what the first scan accepted, for the one-time review */
    public static function baseline(): array
    {
        global $wpdb;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Guardia's own tables
        return (array) $wpdb->get_results($wpdb->prepare(
            "SELECT i.kind, i.item_key, i.label, i.state, o.severity FROM %i i LEFT JOIN %i o ON o.item_id = i.id AND o.event = 'baseline'
             WHERE i.origin = 'baseline' ORDER BY FIELD(i.kind, 'admin', 'mu_plugin', 'dropin', 'upload_php', 'cron', 'critical', 'plugin'), i.item_key",
            self::items(),
            self::observations()
        ), ARRAY_A);
    }

    /** @return array<string, int> items per kind */
    public static function counts(): array
    {
        global $wpdb;
        $out = [];
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Guardia's own table
        foreach ((array) $wpdb->get_results($wpdb->prepare("SELECT kind, COUNT(*) n FROM %i WHERE state <> 'missing' GROUP BY kind", self::items()), ARRAY_A) as $r) {
            $out[(string) $r['kind']] = (int) $r['n'];
        }

        return $out;
    }

    /** Back to nothing: the next scan becomes the baseline again. */
    public static function reset(): void
    {
        global $wpdb;
        // phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Guardia's own tables
        $wpdb->query($wpdb->prepare('TRUNCATE TABLE %i', self::items()));
        $wpdb->query($wpdb->prepare('TRUNCATE TABLE %i', self::observations()));
        // phpcs:enable
        delete_option(self::OPTION_LAST);
        delete_option(self::OPTION_REVIEWED);
    }
}
