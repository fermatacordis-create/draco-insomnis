<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia\Advisories;

/**
 * The OPNV index of Wordfence Intelligence (node-02 mirror): one download of the whole index, matched here.
 * Nothing about the site is sent, not even the names of its plugins.
 *
 * The file is gzip, one line per software: «plugin|slug<TAB>json», plus «#meta» and «#notices» header lines.
 * It is read line by line and only the installed slugs are decoded, so a small PHP memory limit is enough.
 * A new download is used only if it matches the SHA-256 published next to it.
 */
final class OpnvIndex
{
    public const URL = 'https://api.opnv.systems/intel/wordfence/index.lines.gz';
    private const OPTION_STATE = 'draco_advisories_index';
    private const REFRESH = 12 * 3600;
    public const STALE = 7 * 86400;
    /** The longest line is about 250 KB (WordPress core): read lines of up to 4 MB. */
    private const LINE = 4194304;

    private static string $error = '';

    /**
     * Pure: the records of $keys found in $lines, the header data and the notices.
     *
     * @param iterable<string> $lines
     * @param array<string, true> $keys «type|slug» wanted
     * @return array{advisories: array<string, list<array<string, mixed>>>, notices: list<array<string, string>>, meta: array<string, mixed>}
     */
    public static function scan(iterable $lines, array $keys): array
    {
        $advisories = [];
        $notices = [];
        $meta = [];
        foreach ($lines as $line) {
            $tab = strpos($line, "\t");
            if ($tab === false) {
                continue;
            }
            $key = substr($line, 0, $tab);
            if ($key === '#meta' || $key === '#notices') {
                $v = json_decode(rtrim(substr($line, $tab + 1)), true);
                if (is_array($v)) {
                    $key === '#meta' ? $meta = $v : $notices = $v;
                }
                continue;
            }
            if (!isset($keys[$key])) {
                continue;
            }
            $records = json_decode(rtrim(substr($line, $tab + 1)), true);
            foreach (is_array($records) ? $records : [] as $r) {
                if (is_array($r)) {
                    foreach (Matcher::fromOpnvIndex($r) as $a) {
                        $advisories[$key][] = $a;
                    }
                }
            }
        }

        return ['advisories' => $advisories, 'notices' => array_values(array_filter($notices, 'is_array')), 'meta' => $meta];
    }

    public static function file(): string
    {
        $up = wp_upload_dir(null, false);

        return wp_normalize_path(trailingslashit((string) $up['basedir']) . 'draco-insomnis/wordfence-index.lines.gz');
    }

    /** @return array{at: int, sha256: string, generated: string, records: int, error: string} */
    public static function state(): array
    {
        $s = get_option(self::OPTION_STATE, []);
        $s = is_array($s) ? $s : [];

        return ['at' => (int) ($s['at'] ?? 0), 'sha256' => (string) ($s['sha256'] ?? ''), 'generated' => (string) ($s['generated'] ?? ''), 'records' => (int) ($s['records'] ?? 0), 'error' => (string) ($s['error'] ?? '')];
    }

    /** True when the copy here is older than a week (node-02 or the network may be failing). */
    public static function stale(): bool
    {
        $at = self::state()['at'];

        return $at > 0 && time() - $at > self::STALE;
    }

    /** Downloads a new index when the copy is older than 12 hours. False when there is no usable copy at all. */
    public static function refresh(): bool
    {
        $file = self::file();
        $state = self::state();
        if (is_readable($file) && time() - $state['at'] < self::REFRESH) {
            return true;
        }
        self::$error = '';
        $ok = self::download($file);
        $state['error'] = $ok ? '' : self::$error;
        if ($ok) {
            $state['at'] = time();
            $state['sha256'] = (string) hash_file('sha256', $file);
        }
        update_option(self::OPTION_STATE, $state, false);

        return is_readable($file);
    }

    public static function forget(): void
    {
        wp_delete_file(self::file());
        delete_option(self::OPTION_STATE);
    }

    /**
     * The advisories of the installed «type|slug» keys, from the local copy.
     *
     * @param array<string, true> $keys
     * @return array{advisories: array<string, list<array<string, mixed>>>, notices: list<array<string, string>>, meta: array<string, mixed>}|null
     */
    public static function read(array $keys): ?array
    {
        $h = is_readable(self::file()) ? gzopen(self::file(), 'rb') : false;
        if ($h === false) {
            return null;
        }
        $lines = (static function ($h): \Generator {
            while (!gzeof($h)) {
                $line = gzgets($h, self::LINE);
                if ($line === false) {
                    break;
                }
                yield $line;
            }
        })($h);
        try {
            $got = self::scan($lines, $keys);
        } finally {
            gzclose($h);
        }
        $state = get_option(self::OPTION_STATE, []);
        if (is_array($state) && ($state['generated'] ?? '') !== ($got['meta']['generated'] ?? '')) {
            $state['generated'] = (string) ($got['meta']['generated'] ?? '');
            $state['records'] = (int) ($got['meta']['records'] ?? 0);
            update_option(self::OPTION_STATE, $state, false);
        }

        return $got;
    }

    private static function download(string $file): bool
    {
        $ua = 'Draco-Insomnis/' . (defined('DRACO_INSOMNIS_VERSION') ? DRACO_INSOMNIS_VERSION : '0');
        $sum = wp_safe_remote_get(self::URL . '.sha256', ['timeout' => 15, 'user-agent' => $ua]);
        $want = is_wp_error($sum) ? '' : strtolower(substr(trim((string) wp_remote_retrieve_body($sum)), 0, 64));
        if (preg_match('/^[a-f0-9]{64}$/', $want) !== 1) {
            self::$error = is_wp_error($sum) ? $sum->get_error_message() : 'HTTP ' . (int) wp_remote_retrieve_response_code($sum);

            return false;
        }
        if (!wp_mkdir_p(dirname($file))) {
            self::$error = 'uploads not writable';

            return false;
        }
        $tmp = $file . '.part';
        $res = wp_safe_remote_get(self::URL, ['timeout' => 60, 'stream' => true, 'filename' => $tmp, 'user-agent' => $ua]);
        if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
            self::$error = is_wp_error($res) ? $res->get_error_message() : 'HTTP ' . (int) wp_remote_retrieve_response_code($res);
            wp_delete_file($tmp);

            return false;
        }
        if (!hash_equals($want, (string) hash_file('sha256', $tmp))) {
            self::$error = 'checksum mismatch';
            wp_delete_file($tmp);

            return false;
        }

        global $wp_filesystem;
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        if ($wp_filesystem === null || !$wp_filesystem->move($tmp, $file, true)) {
            self::$error = 'move';
            wp_delete_file($tmp);

            return false;
        }

        return true;
    }
}
