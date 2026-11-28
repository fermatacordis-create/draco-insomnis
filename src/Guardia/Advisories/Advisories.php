<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia\Advisories;

use DracoInsomnis\Guardia\Alerts;
use DracoInsomnis\Guardia\Diff;

defined('ABSPATH') || exit;

/**
 * Known vulnerabilities of the installed plugins, themes and WordPress (off by default; the admin decides).
 *
 * Source: WPVulnerability (wpvulnerability.net, data CC0 1.0, no key). It is asked one slug at a time, so
 * it learns the slugs of the installed plugins and themes and the WordPress version, never the installed
 * versions: the ranges come back and are compared here (Matcher). Answers are kept 24 hours; a daily
 * check asks only for what expired, a few seconds at a time.
 */
final class Advisories
{
    public const OPTION_ENABLED = 'draco_advisories_enabled';
    public const HOOK = 'draco_advisories_check';
    private const OPTION_CACHE = 'draco_advisories_cache';
    private const OPTION_RESULT = 'draco_advisories_result';
    private const OPTION_NOTIFIED = 'draco_advisories_notified';
    private const API = 'https://www.wpvulnerability.net/';
    private const TTL = DAY_IN_SECONDS;
    private const BUDGET = 20.0;
    /** A plugin closed on WordPress.org (abandoned or pulled, often for security) is worth a note. */
    public const CLOSED = 'closed';

    public static function register(): void
    {
        add_action(self::HOOK, [self::class, 'run']);
        add_action('init', [self::class, 'schedule']);
    }

    public static function enabled(): bool
    {
        return get_option(self::OPTION_ENABLED, 'no') === 'yes';
    }

    public static function schedule(): void
    {
        $next = wp_next_scheduled(self::HOOK);
        if (self::enabled() && $next === false) {
            wp_schedule_event(time() + 10 * MINUTE_IN_SECONDS, 'twicedaily', self::HOOK);
        } elseif (!self::enabled() && $next !== false) {
            wp_clear_scheduled_hook(self::HOOK);
        }
    }

    /** Switched off: schedule, answers and results go. */
    public static function forget(): void
    {
        wp_clear_scheduled_hook(self::HOOK);
        foreach ([self::OPTION_CACHE, self::OPTION_RESULT, self::OPTION_NOTIFIED] as $o) {
            delete_option($o);
        }
    }

    /**
     * Asks for what expired (until the budget runs out), matches everything known and stores the result.
     *
     * @return array{at: int, checked: int, pending: int, errors: int, items: list<array<string, mixed>>}
     */
    public static function run(float $budget = self::BUDGET): array
    {
        $installed = self::installed();
        $cache = get_option(self::OPTION_CACHE, []);
        $cache = is_array($cache) ? $cache : [];
        $deadline = microtime(true) + $budget;
        $errors = 0;
        $wanted = [];
        foreach ($installed as $item) {
            $key = $item['type'] . '|' . $item['slug'];
            $wanted[$key] = true;
            if (isset($cache[$key]) && (int) ($cache[$key]['at'] ?? 0) > time() - self::TTL) {
                continue;
            }
            if (microtime(true) > $deadline) {
                continue; // the next check goes on
            }
            $got = self::fetch($item['type'], $item['slug']);
            if ($got === null) {
                $errors++;
                continue;
            }
            $cache[$key] = $got + ['at' => time()];
        }
        $cache = array_intersect_key($cache, $wanted); // uninstalled: forgotten
        update_option(self::OPTION_CACHE, $cache, false);

        $advisories = [];
        foreach ($cache as $key => $entry) {
            $advisories[$key] = (array) ($entry['vulns'] ?? []);
        }
        $items = Matcher::match($installed, $advisories);
        foreach ($installed as $item) {
            $entry = $cache[$item['type'] . '|' . $item['slug']] ?? null;
            if (is_array($entry) && !empty($entry['closed'])) {
                $items[] = ['type' => $item['type'], 'slug' => $item['slug'], 'name' => $item['name'], 'version' => $item['version'], 'active' => $item['active'],
                    'uuid' => self::CLOSED . '|' . $item['slug'], 'title' => (string) ($entry['closed_reason'] ?? ''), 'severity' => Diff::MEDIUM, 'score' => 0.0,
                    'unauth' => false, 'cve' => [], 'fixed' => '', 'link' => 'https://wordpress.org/' . ($item['type'] === 'theme' ? 'themes/' : 'plugins/') . rawurlencode($item['slug']) . '/'];
            }
        }
        $pending = count(array_diff_key($wanted, $cache));
        $result = ['at' => time(), 'checked' => count($cache), 'pending' => $pending, 'errors' => $errors, 'items' => $items];
        update_option(self::OPTION_RESULT, $result, false);
        self::notify($items);

        return $result;
    }

    /** @return array{at: int, checked: int, pending: int, errors: int, items: list<array<string, mixed>>}|null */
    public static function result(): ?array
    {
        $r = get_option(self::OPTION_RESULT, null);

        return is_array($r) && isset($r['at']) ? $r : null;
    }

    /**
     * Every installed plugin (active or not: its files are there) and theme, and WordPress itself.
     *
     * @return list<array{type: string, slug: string, version: string, name: string, active: bool}>
     */
    public static function installed(): array
    {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $out = [['type' => 'core', 'slug' => 'wordpress', 'version' => (string) get_bloginfo('version'), 'name' => 'WordPress', 'active' => true]];
        $active = (array) get_option('active_plugins', []);
        foreach (get_plugins() as $file => $data) {
            $slug = str_contains($file, '/') ? dirname($file) : basename($file, '.php');
            $out[] = ['type' => 'plugin', 'slug' => sanitize_key($slug), 'version' => (string) ($data['Version'] ?? ''), 'name' => (string) ($data['Name'] ?? $slug), 'active' => in_array($file, $active, true)];
        }
        $current = get_stylesheet();
        $parent = get_template();
        foreach (wp_get_themes() as $slug => $theme) {
            $out[] = ['type' => 'theme', 'slug' => sanitize_key((string) $slug), 'version' => (string) $theme->get('Version'), 'name' => (string) $theme->get('Name'), 'active' => in_array($slug, [$current, $parent], true)];
        }

        return $out;
    }

    /**
     * One slug from WPVulnerability: its advisories, normalised, and whether WordPress.org closed it.
     *
     * @return array{vulns: list<array<string, mixed>>, closed: bool, closed_reason: string}|null null on failure
     */
    private static function fetch(string $type, string $slug): ?array
    {
        $path = $type === 'core' ? 'core/' . rawurlencode((string) get_bloginfo('version')) . '/' : $type . '/' . rawurlencode($slug) . '/';
        $res = wp_safe_remote_get(self::API . $path, ['timeout' => 10, 'user-agent' => 'Draco-Insomnis/' . (defined('DRACO_INSOMNIS_VERSION') ? DRACO_INSOMNIS_VERSION : '0')]);
        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            return null;
        }
        $body = json_decode((string) wp_remote_retrieve_body($res), true);
        if (!is_array($body) || (int) ($body['error'] ?? 1) !== 0 || !is_array($body['data'] ?? null)) {
            return null;
        }
        $vulns = [];
        foreach (is_array($body['data']['vulnerability'] ?? null) ? $body['data']['vulnerability'] : [] as $r) {
            if (is_array($r)) {
                $a = Matcher::fromWpVulnerability($r);
                // WordPress core answers are for this exact version: every record applies.
                if ($type === 'core') {
                    $a['min'] = null;
                    $a['max'] = null;
                    $a['unfixed'] = true;
                }
                $vulns[] = $a;
            }
        }

        return ['vulns' => $vulns, 'closed' => (string) ($body['data']['closed'] ?? '0') === '1', 'closed_reason' => substr((string) ($body['data']['closed_reason'] ?? ''), 0, 120)];
    }

    /**
     * One e-mail when new high or critical findings appear; the same finding is not mailed twice.
     *
     * @param list<array<string, mixed>> $items
     */
    private static function notify(array $items): void
    {
        $known = get_option(self::OPTION_NOTIFIED, []);
        $known = is_array($known) ? $known : [];
        $new = [];
        $current = [];
        foreach ($items as $f) {
            $id = $f['type'] . '|' . $f['slug'] . '|' . $f['uuid'];
            $current[$id] = true;
            if (!isset($known[$id]) && in_array($f['severity'], [Diff::HIGH, Diff::CRITICAL_LEVEL], true)) {
                $new[] = $f;
            }
        }
        update_option(self::OPTION_NOTIFIED, $current, false); // fixed ones drop out; if they come back, they are new again
        if ($new === [] || !Alerts::enabled()) {
            return;
        }
        $site = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $title = __('Known vulnerabilities in installed software', 'draco-insomnis');
        /* translators: 1: number of findings, 2: site name */
        $intro = sprintf(__('%2$s has %1$d new high or critical vulnerabilities in installed plugins, themes or WordPress:', 'draco-insomnis'), count($new), $site);
        $lines = [];
        foreach (array_slice($new, 0, Alerts::LINES) as $f) {
            $lines[] = self::line($f);
        }
        $tail = __('Update what has a fix. If there is none yet, consider switching the plugin off until there is. Draco only reports: it changes nothing.', 'draco-insomnis');
        $url = admin_url('admin.php?page=draco-insomnis-integrity#draco-advisories');
        foreach (Alerts::recipients() as $email) {
            \DracoInsomnis\Mail\Template::send($email, sprintf('[%s] %s', $site, $title), $intro . "\n\n" . implode("\n", $lines) . "\n\n" . $tail . "\n\n" . $url, $title, array_merge([$intro], $lines), [
                'tone' => 'orange', 'url' => $url, 'button' => __('Open Integrity', 'draco-insomnis'), 'after' => [$tail],
            ]);
        }
    }

    /** @param array<string, mixed> $f one line for the e-mail */
    public static function line(array $f): string
    {
        $fix = (string) $f['fixed'] !== ''
            /* translators: %s: version */
            ? sprintf(__('fixed in %s', 'draco-insomnis'), (string) $f['fixed'])
            : __('no fix listed', 'draco-insomnis');

        return \DracoInsomnis\Guardia\Admin::severityLabel((string) $f['severity']) . ' · ' . (string) $f['name'] . ' ' . (string) $f['version'] . ' · ' . (string) $f['title']
            . ((array) $f['cve'] !== [] ? ' · ' . implode(', ', (array) $f['cve']) : '') . ' · ' . $fix;
    }
}
