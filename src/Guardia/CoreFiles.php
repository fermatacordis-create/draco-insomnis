<?php

declare(strict_types=1);

namespace DracoInsomnis\Guardia;

/**
 * WordPress core files against the official checksums from wordpress.org (docs/adr/0001).
 *
 * Two findings: a core file whose content differs from the release («modified»), and a PHP file inside
 * wp-admin, wp-includes or the site root that no release has («not part of WordPress»), the usual hiding
 * places of a backdoor. Missing core files are not reported (hardening guides delete some). wp-content is
 * left out: bundled themes and plugins are updated on their own.
 */
final class CoreFiles
{
    private const API = 'https://api.wordpress.org/core/checksums/1.0/';
    /** Root files that are the site's own, not WordPress's. */
    private const OWN_ROOT = ['wp-config.php'];

    private static string $error = '';

    /**
     * Pure comparison.
     *
     * @param array<string, string> $sums   path => md5 of the release
     * @param array<string, string> $actual path => md5 of the file on disk (only paths of $sums that exist)
     * @param list<string>          $php    PHP files found in wp-admin, wp-includes and the root
     * @return array<string, array{fp: string, danger: bool}> «core|path» => «modified:md5» or «extra»
     */
    public static function deviations(array $sums, array $actual, array $php): array
    {
        $items = [];
        foreach ($sums as $path => $md5) {
            if (str_starts_with($path, 'wp-content/') || !isset($actual[$path]) || hash_equals(strtolower($md5), strtolower($actual[$path]))) {
                continue;
            }
            $id = Diff::CORE . '|' . $path;
            $items[$id] = ['fp' => 'modified:' . $actual[$path], 'danger' => true];
        }
        foreach ($php as $path) {
            if (isset($sums[$path]) || in_array($path, self::OWN_ROOT, true) || !self::watched($path)) {
                continue;
            }
            $id = Diff::CORE . '|' . $path;
            $items[$id] = ['fp' => 'extra', 'danger' => true];
        }

        return $items;
    }

    /** wp-admin/…, wp-includes/… or a file in the root. */
    public static function watched(string $path): bool
    {
        return str_starts_with($path, 'wp-admin/') || str_starts_with($path, 'wp-includes/') || !str_contains($path, '/');
    }

    /** Why the last check could not run, or ''. */
    public static function error(): string
    {
        return self::$error;
    }

    /**
     * This site's deviations, or null when the checksums could not be had (the caller then leaves the
     * stored core items as they were instead of reporting them gone).
     *
     * @return array<string, array{fp: string, danger: bool}>|null
     */
    public static function collect(): ?array
    {
        self::$error = '';
        $sums = self::sums();
        if ($sums === null) {
            return null;
        }
        $root = wp_normalize_path(ABSPATH);
        $actual = [];
        foreach (array_keys($sums) as $path) {
            if (!str_starts_with($path, 'wp-content/') && is_file($root . $path)) {
                $actual[$path] = (string) md5_file($root . $path);
            }
        }

        return self::deviations($sums, $actual, self::phpFiles($root));
    }

    /** @return list<string> PHP files in wp-admin, wp-includes and the root, relative to ABSPATH */
    private static function phpFiles(string $root): array
    {
        $out = [];
        foreach ((array) glob($root . '*.php') as $f) {
            $out[] = basename((string) $f);
        }
        foreach (['wp-admin', 'wp-includes'] as $dir) {
            if (!is_dir($root . $dir)) {
                continue;
            }
            try {
                $it = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . $dir, \FilesystemIterator::SKIP_DOTS));
                foreach ($it as $f) {
                    if ($f->isFile() && preg_match('/\.(php\d?|phtml|phar)$/i', $f->getFilename()) === 1) {
                        $out[] = ltrim(substr(wp_normalize_path($f->getPathname()), strlen($root)), '/');
                    }
                }
            } catch (\Throwable) {
                // An unreadable folder: what was read so far is kept.
            }
        }

        return $out;
    }

    /** @return array<string, string>|null path => md5 for this version and language, from wordpress.org (kept on disk) */
    private static function sums(): ?array
    {
        global $wp_version, $wp_local_package;
        $version = (string) $wp_version;
        $locale = isset($wp_local_package) && is_string($wp_local_package) && $wp_local_package !== '' ? $wp_local_package : 'en_US';
        if (preg_match('/^\d+\.\d+(\.\d+)?$/', $version) !== 1) {
            /* translators: %s: WordPress version */
            self::$error = sprintf(__('WordPress %s is not a release: there are no official checksums for it.', 'draco-insomnis'), $version);

            return null;
        }
        $file = self::cacheFile($version, $locale);
        if (is_readable($file)) {
            $cached = json_decode((string) file_get_contents($file), true);
            if (is_array($cached) && $cached !== []) {
                return $cached;
            }
        }
        $sums = self::download($version, $locale);
        if ($sums === null && $locale !== 'en_US') {
            $sums = self::download($version, 'en_US');
        }
        if ($sums === null) {
            return null;
        }
        if (wp_mkdir_p(dirname($file))) {
            file_put_contents($file, (string) wp_json_encode($sums));
        }

        return $sums;
    }

    /** @return array<string, string>|null */
    private static function download(string $version, string $locale): ?array
    {
        $res = wp_safe_remote_get(add_query_arg(['version' => $version, 'locale' => $locale], self::API), ['timeout' => 20, 'user-agent' => 'Draco-Insomnis']);
        if (is_wp_error($res)) {
            self::$error = $res->get_error_message();

            return null;
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        $body = json_decode((string) wp_remote_retrieve_body($res), true);
        $sums = is_array($body) ? ($body['checksums'] ?? null) : null;
        // The API answers {"checksums": false} for a version or language it does not know.
        if ($code !== 200 || !is_array($sums) || $sums === []) {
            /* translators: %d: HTTP status code */
            self::$error = $code !== 200 ? sprintf(__('wordpress.org answered HTTP %d.', 'draco-insomnis'), $code) : __('wordpress.org has no checksums for this version.', 'draco-insomnis');

            return null;
        }
        $out = [];
        foreach ($sums as $path => $md5) {
            if (is_string($path) && is_string($md5) && preg_match('/^[a-f0-9]{32}$/i', $md5) === 1) {
                $out[$path] = strtolower($md5);
            }
        }

        return $out !== [] ? $out : null;
    }

    private static function cacheFile(string $version, string $locale): string
    {
        $up = wp_upload_dir(null, false);

        return wp_normalize_path(trailingslashit((string) $up['basedir']) . 'draco-insomnis/core-' . sanitize_file_name($version . '-' . $locale) . '.json');
    }
}
