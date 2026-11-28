<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

defined('ABSPATH') || exit;

/**
 * What Guardia watches on this WordPress, as «kind|key» => fingerprint (docs/adr/0001).
 *
 * Read only: nothing here changes a file, an option or a user. Hashes are SHA-256 of the file.
 */
final class Inventory
{
    /** PHP files looked at inside uploads, at most (a hacked site can have thousands: the list says so). */
    public const MAX_UPLOAD_FILES = 5000;
    /** Bytes of each uploads PHP file read to look for dangerous calls. */
    private const SNIFF = 262144;
    private const PHP_EXT = '/\.(php\d?|phtml|phar|pht)$/i';

    /** @var array<string, string> «kind|key» => label shown on screen */
    private static array $labels = [];
    private static bool $truncated = false;
    /** @var array<string, string> kind => why its list is incomplete in this scan */
    private static array $partial = [];

    /**
     * @return array<string, array{fp: string, danger?: bool}>
     */
    public static function collect(): array
    {
        self::$labels = [];
        self::$truncated = false;
        self::$partial = [];

        return self::admins() + self::plugins() + self::muPlugins() + self::dropins() + self::critical() + self::core() + self::uploads() + self::cron();
    }

    /** @return array<string, string> */
    public static function labels(): array
    {
        return self::$labels;
    }

    /**
     * Kinds this scan could not list completely, with the reason: what was not seen of them is not «gone».
     *
     * @return array<string, string>
     */
    public static function partial(): array
    {
        return self::$partial;
    }

    /** @return array<string, array{fp: string, danger: bool}> core files that differ from the release, or are not part of it */
    private static function core(): array
    {
        $found = CoreFiles::collect();
        if ($found === null) {
            self::$partial[Diff::CORE] = CoreFiles::error();

            return [];
        }
        foreach ($found as $id => $item) {
            self::$labels[$id] = Diff::keyOf($id) . ' · ' . ($item['fp'] === 'extra' ? __('not part of WordPress', 'draco-insomnis') : __('modified', 'draco-insomnis'));
        }

        return $found;
    }

    /** True when uploads held more PHP files than are looked at. */
    public static function truncated(): bool
    {
        return self::$truncated;
    }

    /** @return array<string, array{fp: string}> by login: a deleted and re-created account keeps its login, not its ID */
    private static function admins(): array
    {
        $out = [];
        foreach (get_users(['role' => 'administrator', 'fields' => ['user_login', 'user_email', 'user_registered']]) as $u) {
            $id = Diff::ADMIN . '|' . strtolower((string) $u->user_login);
            $out[$id] = ['fp' => hash('sha256', strtolower((string) $u->user_email))];
            self::$labels[$id] = (string) $u->user_login . ' · ' . (string) $u->user_registered;
        }

        return $out;
    }

    /** @return array<string, array{fp: string}> fingerprint = version (an update is not an alert) */
    private static function plugins(): array
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
            self::$labels[$id] = (string) ($all[$file]['Name'] ?? $file) . ' ' . (string) ($all[$file]['Version'] ?? '');
        }

        return $out;
    }

    /** @return array<string, array{fp: string, danger: bool}> every file and folder in mu-plugins */
    private static function muPlugins(): array
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
            self::$labels[$id] = $name . (is_dir($path) ? '/' : '');
        }

        return $out;
    }

    /** @return array<string, array{fp: string, danger: bool}> */
    private static function dropins(): array
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
                self::$labels[$id] = $name;
            }
        }

        return $out;
    }

    /** @return array<string, array{fp: string, danger: bool}> */
    private static function critical(): array
    {
        $out = [];
        $config = is_file(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php' : dirname(ABSPATH) . '/wp-config.php';
        foreach (['wp-config.php' => $config, '.htaccess' => ABSPATH . '.htaccess', 'index.php' => ABSPATH . 'index.php', '.user.ini' => ABSPATH . '.user.ini'] as $name => $path) {
            if (is_file($path)) {
                $id = Diff::CRITICAL . '|' . $name;
                // Not «danger» for these: wp-config.php legitimately defines and calls things.
                $out[$id] = ['fp' => (string) hash_file('sha256', $path)];
                self::$labels[$id] = $name;
            }
        }

        return $out;
    }

    /** @return array<string, array{fp: string, danger: bool}> PHP files inside uploads, where only media belongs */
    private static function uploads(): array
    {
        $up = wp_upload_dir(null, false);
        $base = (string) $up['basedir'];
        if ($base === '' || !is_dir($base)) {
            return [];
        }
        $out = [];
        $seen = 0;
        try {
            $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if (!$f->isFile() || preg_match(self::PHP_EXT, $f->getFilename()) !== 1) {
                    continue;
                }
                if (++$seen > self::MAX_UPLOAD_FILES) {
                    self::$truncated = true;
                    self::$partial[Diff::UPLOAD_PHP] = 'truncated';
                    break;
                }
                $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($base))), '/');
                $id = Diff::UPLOAD_PHP . '|' . $rel;
                $out[$id] = self::file($f->getPathname(), true);
                self::$labels[$id] = $rel . ' · ' . size_format((int) $f->getSize());
            }
        } catch (\Throwable) {
            // An unreadable folder: what was read so far is kept, the rest is not «gone».
            self::$partial[Diff::UPLOAD_PHP] = 'unreadable';
        }

        return $out;
    }

    /** @return array<string, array{fp: string}> scheduled hooks that no loaded code handles */
    private static function cron(): array
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
                self::$labels[$id] = $hook;
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
