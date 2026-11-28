<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

defined('ABSPATH') || exit;

/**
 * What Guardia watches on this WordPress, as «kind|key» => fingerprint (docs/adr/0001).
 *
 * Read only: nothing here changes a file, an option or a user. A scan is a job: start() lists the cheap
 * kinds at once and the files to read; advance() reads files until a deadline, so a scheduled scan can
 * go on in the next request where the last one stopped.
 *
 * @phpstan-type Job array{started: int, items: array<string, array{fp: string, danger?: bool}>, labels: array<string, string>,
 *     partial: array<string, string>, truncated: bool, core: array{i: int, modified: array<string, string>}|null,
 *     uploads: array{base: string, files: list<string>, i: int}}
 */
final class Inventory
{
    /** PHP files looked at inside uploads, at most (a hacked site can have thousands: the screen says so). */
    public const MAX_UPLOAD_FILES = 5000;
    /** Bytes of each uploads PHP file read to look for dangerous calls. */
    private const SNIFF = 262144;
    private const PHP_EXT = '/\.(php\d?|phtml|phar|pht)$/i';

    /** @return Job */
    public static function start(): array
    {
        $labels = [];
        $items = self::admins($labels) + self::plugins($labels) + self::muPlugins($labels) + self::dropins($labels) + self::critical($labels) + self::cron($labels);
        $job = ['started' => time(), 'items' => $items, 'labels' => $labels, 'partial' => [], 'truncated' => false, 'core' => null, 'uploads' => ['base' => '', 'files' => [], 'i' => 0]];
        if (CoreFiles::sums() === null) {
            $job['partial'][Diff::CORE] = CoreFiles::error();
        } else {
            $job['core'] = ['i' => 0, 'modified' => []];
        }
        self::listUploads($job);

        return $job;
    }

    /**
     * Reads files until $deadline (microtime). True when the job has nothing left to read.
     *
     * @param Job $job
     */
    public static function advance(array &$job, float $deadline): bool
    {
        if ($job['core'] !== null && !self::advanceCore($job, $deadline)) {
            return false;
        }
        $up = &$job['uploads'];
        $count = count($up['files']);
        while ($up['i'] < $count) {
            if (microtime(true) > $deadline) {
                return false;
            }
            $rel = $up['files'][$up['i']++];
            $path = $up['base'] . '/' . $rel;
            if (!is_file($path)) {
                continue; // gone since the list was made: not seen
            }
            $id = Diff::UPLOAD_PHP . '|' . $rel;
            $job['items'][$id] = self::file($path, true);
            $job['labels'][$id] = $rel . ' · ' . size_format((int) filesize($path));
        }

        return true;
    }

    /**
     * Core files, a slice at a time; once all are hashed, the deviations join the items.
     *
     * @param Job $job
     */
    private static function advanceCore(array &$job, float $deadline): bool
    {
        $sums = CoreFiles::sums();
        if ($sums === null) {
            $job['partial'][Diff::CORE] = CoreFiles::error();
            $job['core'] = null;

            return true;
        }
        $root = wp_normalize_path(ABSPATH);
        $paths = array_keys($sums);
        $count = count($paths);
        $core = &$job['core'];
        while ($core['i'] < $count) {
            if (microtime(true) > $deadline) {
                return false;
            }
            $path = (string) $paths[$core['i']++];
            if (str_starts_with($path, 'wp-content/') || !is_file($root . $path)) {
                continue;
            }
            $md5 = (string) md5_file($root . $path);
            if ($md5 !== $sums[$path]) {
                $core['modified'][$path] = $md5;
            }
        }
        // Only the differing files are kept between requests: deviations() skips the rest anyway.
        foreach (CoreFiles::deviations($sums, $core['modified'], CoreFiles::phpFiles($root)) as $id => $item) {
            $job['items'][$id] = $item;
            $job['labels'][$id] = Diff::keyOf($id) . ' · ' . ($item['fp'] === 'extra' ? __('not part of WordPress', 'draco-insomnis') : __('modified', 'draco-insomnis'));
        }
        $job['core'] = null;

        return true;
    }

    /** @param Job $job */
    private static function listUploads(array &$job): void
    {
        $up = wp_upload_dir(null, false);
        $base = wp_normalize_path((string) $up['basedir']);
        if ($base === '' || !is_dir($base)) {
            return;
        }
        $job['uploads']['base'] = untrailingslashit($base);
        try {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if (!$f->isFile() || preg_match(self::PHP_EXT, $f->getFilename()) !== 1) {
                    continue;
                }
                if (count($job['uploads']['files']) >= self::MAX_UPLOAD_FILES) {
                    $job['truncated'] = true;
                    $job['partial'][Diff::UPLOAD_PHP] = 'truncated';
                    break;
                }
                $job['uploads']['files'][] = ltrim(substr(wp_normalize_path($f->getPathname()), strlen(untrailingslashit($base))), '/');
            }
        } catch (\Throwable) {
            // An unreadable folder: what was listed so far is read, the rest is not «gone».
            $job['partial'][Diff::UPLOAD_PHP] = 'unreadable';
        }
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string}> by login: a deleted and re-created account keeps its login, not its ID
     */
    private static function admins(array &$labels): array
    {
        $out = [];
        foreach (get_users(['role' => 'administrator', 'fields' => ['user_login', 'user_email', 'user_registered']]) as $u) {
            $id = Diff::ADMIN . '|' . strtolower((string) $u->user_login);
            $out[$id] = ['fp' => hash('sha256', strtolower((string) $u->user_email))];
            $labels[$id] = (string) $u->user_login . ' · ' . (string) $u->user_registered;
        }

        return $out;
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string}> fingerprint = version (an update is not an alert)
     */
    private static function plugins(array &$labels): array
    {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all = get_plugins();
        $out = [];
        foreach ((array) get_option('active_plugins', []) as $file) {
            $file = (string) $file;
            $id = Diff::PLUGIN . '|' . $file;
            $out[$id] = ['fp' => (string) ($all[$file]['Version'] ?? '')];
            $labels[$id] = (string) ($all[$file]['Name'] ?? $file) . ' ' . (string) ($all[$file]['Version'] ?? '');
        }

        return $out;
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string, danger?: bool}> every file and folder in mu-plugins
     */
    private static function muPlugins(array &$labels): array
    {
        $out = [];
        $dir = defined('WPMU_PLUGIN_DIR') ? (string) WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
        foreach (is_dir($dir) ? (array) scandir($dir) : [] as $name) {
            $name = (string) $name;
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . '/' . $name;
            $id = Diff::MU_PLUGIN . '|' . $name;
            $out[$id] = is_dir($path) ? ['fp' => 'folder'] : self::file($path, false);
            $labels[$id] = $name . (is_dir($path) ? '/' : '');
        }

        return $out;
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string, danger: bool}>
     */
    private static function dropins(array &$labels): array
    {
        $out = [];
        if (!function_exists('_get_dropins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        foreach (array_keys(_get_dropins()) as $name) {
            $path = WP_CONTENT_DIR . '/' . $name;
            if (is_file($path)) {
                $id = Diff::DROPIN . '|' . $name;
                $out[$id] = self::file($path, false);
                $labels[$id] = $name;
            }
        }

        return $out;
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string}>
     */
    private static function critical(array &$labels): array
    {
        $out = [];
        $config = is_file(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php' : dirname(ABSPATH) . '/wp-config.php';
        foreach (['wp-config.php' => $config, '.htaccess' => ABSPATH . '.htaccess', 'index.php' => ABSPATH . 'index.php', '.user.ini' => ABSPATH . '.user.ini'] as $name => $path) {
            if (is_file($path)) {
                $id = Diff::CRITICAL . '|' . $name;
                // Not «danger» for these: wp-config.php legitimately defines and calls things.
                $out[$id] = ['fp' => (string) hash_file('sha256', $path)];
                $labels[$id] = $name;
            }
        }

        return $out;
    }

    /**
     * @param array<string, string> $labels
     * @return array<string, array{fp: string}> scheduled hooks that no loaded code handles
     */
    private static function cron(array &$labels): array
    {
        $out = [];
        foreach ((array) _get_cron_array() as $events) {
            foreach (array_keys((array) $events) as $hook) {
                $hook = (string) $hook;
                if ($hook === '' || has_action($hook)) {
                    continue;
                }
                $id = Diff::CRON . '|' . $hook;
                $out[$id] = ['fp' => ''];
                $labels[$id] = $hook;
            }
        }

        return $out;
    }

    /**
     * A file's fingerprint; with $sniff, whether it holds dangerous calls. Only for uploads: legitimate
     * mu-plugins and drop-ins may use those functions, and flagging them would only be noise.
     *
     * @return array{fp: string, danger: bool}
     */
    private static function file(string $path, bool $sniff): array
    {
        $fp = (string) @hash_file('sha256', $path);
        $danger = false;
        if ($sniff && preg_match(self::PHP_EXT, $path) === 1) {
            $head = @file_get_contents($path, false, null, 0, self::SNIFF);
            $danger = is_string($head) && Diff::dangerous($head);
        }

        return ['fp' => $fp, 'danger' => $danger];
    }
}
