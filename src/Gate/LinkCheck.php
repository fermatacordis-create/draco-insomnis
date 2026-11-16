<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Input;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Malicious links (URLhaus, by abuse.ch): links in comments and contact forms are checked against
 * URLhaus's list of malware distribution URLs, locally. Nothing a visitor writes is sent anywhere: the
 * site downloads the list twice a day with the owner's own key and looks links up in its own copy.
 *
 * Off by default, and only in the standalone plugin (never when Draco is bundled in another product):
 * the free URLhaus data is for non-profit use; commercial use needs a Spamhaus subscription
 * (abuse.ch terms of use, sections 3 and 4). The owner confirms that before switching it on.
 *
 * The key lives in wp-config.php (DRACO_URLHAUS_KEY), never in the database, on screen or in a log.
 * Exact URLs are matched, not whole domains: URLhaus lists many hacked legitimate sites, and blocking
 * their domain would hit innocent links. Only hosts that are bare IP addresses match as a whole.
 */
final class LinkCheck
{
    public const OPTION_ENABLED = 'draco_urlhaus_enabled';
    public const OPTION_CONFIRMED = 'draco_urlhaus_confirmed';
    public const OPTION_STATE = 'draco_urlhaus_state';
    public const HOOK_UPDATE = 'draco_urlhaus_update';
    public const KEY_CONSTANT = 'DRACO_URLHAUS_KEY';
    /** The export file; the documented one by default. Another can be set with DRACO_URLHAUS_EXPORT. */
    public const DEFAULT_EXPORT = 'recent.csv';
    private const BASE = 'https://urlhaus-api.abuse.ch/v2/files/exports/';
    private const LINE = 17; // 16 hex characters of the hash + "\n"
    private const MAX_LINKS = 50;
    public const TERMS = 'https://abuse.ch/terms-of-use/';
    public const SPAMHAUS = 'https://www.spamhaus.com/data-access/abusech-api/';

    public static function register(): void
    {
        if (Plugin::bundled()) {
            return;
        }
        add_action(self::HOOK_UPDATE, [self::class, 'update']);
        if (!self::active()) {
            return;
        }
        // Before the comment hold (99), so a malicious comment never gets a confirmation e-mail.
        add_filter('pre_comment_approved', [self::class, 'comment'], 98, 2);
        // Before the form hold (10): a malicious message is dropped without a trace for the sender.
        add_filter('pre_wp_mail', [self::class, 'mail'], 5, 2);
        if (!wp_next_scheduled(self::HOOK_UPDATE)) {
            wp_schedule_event(time() + 300, 'twicedaily', self::HOOK_UPDATE);
        }
    }

    /** Available here at all (the standalone plugin only). */
    public static function available(): bool
    {
        return !Plugin::bundled();
    }

    public static function hasKey(): bool
    {
        return self::key() !== '';
    }

    private static function key(): string
    {
        $key = defined(self::KEY_CONSTANT) ? (string) constant(self::KEY_CONSTANT) : '';

        return preg_match('/^[A-Za-z0-9_-]{16,128}$/', $key) === 1 ? $key : '';
    }

    public static function active(): bool
    {
        return self::available() && self::hasKey()
            && get_option(self::OPTION_ENABLED, 'no') === 'yes'
            && get_option(self::OPTION_CONFIRMED, 'no') === 'yes';
    }

    /** @return array{updated: int, count: int, error: string} */
    public static function state(): array
    {
        $s = get_option(self::OPTION_STATE, []);
        $s = is_array($s) ? $s : [];

        return ['updated' => (int) ($s['updated'] ?? 0), 'count' => (int) ($s['count'] ?? 0), 'error' => (string) ($s['error'] ?? '')];
    }

    public static function indexFile(): string
    {
        $up = wp_upload_dir(null, false);

        return wp_normalize_path(trailingslashit((string) $up['basedir']) . 'draco-insomnis/urlhaus.idx');
    }

    /** One URL as it is compared: lower-case scheme and host, no default port, no fragment. */
    public static function normalize(string $url): string
    {
        $url = trim(html_entity_decode($url, ENT_QUOTES | ENT_HTML5));
        $p = wp_parse_url($url);
        if (!is_array($p) || empty($p['host']) || !in_array(strtolower((string) ($p['scheme'] ?? '')), ['http', 'https'], true)) {
            return '';
        }
        $scheme = strtolower((string) $p['scheme']);
        $host = strtolower(trim((string) $p['host'], '[]'));
        $port = isset($p['port']) && !(($scheme === 'http' && (int) $p['port'] === 80) || ($scheme === 'https' && (int) $p['port'] === 443)) ? ':' . (int) $p['port'] : '';
        $path = (string) ($p['path'] ?? '/');
        $query = isset($p['query']) ? '?' . $p['query'] : '';

        return $scheme . '://' . $host . $port . ($path === '' ? '/' : $path) . $query;
    }

    private static function hostOf(string $normalized): string
    {
        return strtolower(trim((string) wp_parse_url($normalized, PHP_URL_HOST), '[]'));
    }

    /** @return list<string> keys to store or look up for one URL: the URL, and its host when it is an IP. */
    private static function keys(string $url): array
    {
        $n = self::normalize($url);
        if ($n === '') {
            return [];
        }
        $keys = ['u|' . $n];
        $host = self::hostOf($n);
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            $keys[] = 'h|' . $host;
        }

        return $keys;
    }

    private static function hash(string $key): string
    {
        return substr(hash('sha256', $key), 0, 16);
    }

    /** @return list<string> the links in a text, at most 50 */
    public static function links(string $text): array
    {
        if (!preg_match_all('~https?://[^\s<>"\'`\]\)\}]+~i', $text, $m)) {
            return [];
        }
        $out = [];
        foreach ($m[0] as $link) {
            $out[] = rtrim($link, '.,;:!?\'"');
            if (count($out) >= self::MAX_LINKS) {
                break;
            }
        }

        return array_values(array_unique($out));
    }

    /** The first listed link in a text, or ''. */
    public static function listed(string $text): string
    {
        $fh = null;
        $file = self::indexFile();
        foreach (self::links($text) as $link) {
            foreach (self::keys($link) as $key) {
                if ($fh === null) {
                    $fh = is_readable($file) ? fopen($file, 'rb') : false;
                }
                if ($fh === false) {
                    return '';
                }
                if (self::lookup($fh, self::hash($key))) {
                    fclose($fh);

                    return $link;
                }
            }
        }
        if (is_resource($fh)) {
            fclose($fh);
        }

        return '';
    }

    /** @param resource $fh */
    private static function lookup($fh, string $want): bool
    {
        $stat = fstat($fh);
        $count = intdiv((int) ($stat['size'] ?? 0), self::LINE);
        $lo = 0;
        $hi = $count - 1;
        while ($lo <= $hi) {
            $mid = intdiv($lo + $hi, 2);
            fseek($fh, $mid * self::LINE);
            $got = (string) fread($fh, 16);
            $cmp = strcmp($got, $want);
            if ($cmp === 0) {
                return true;
            }
            if ($cmp < 0) {
                $lo = $mid + 1;
            } else {
                $hi = $mid - 1;
            }
        }

        return false;
    }

    /**
     * The sorted index from an export (CSV or one URL per line): the first http(s) field of each line.
     *
     * @return array{index: string, count: int}
     */
    public static function buildIndex(string $export): array
    {
        $hashes = [];
        foreach (preg_split('/\r\n|\r|\n/', $export) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $url = '';
            foreach (str_getcsv($line, ',', '"', '\\') as $field) {
                $field = trim((string) $field);
                if (preg_match('~^https?://~i', $field) === 1) {
                    $url = $field;
                    break;
                }
            }
            foreach ($url !== '' ? self::keys($url) : [] as $key) {
                $hashes[self::hash($key)] = true;
            }
        }
        $list = array_keys($hashes);
        sort($list, SORT_STRING);

        return ['index' => $list === [] ? '' : implode("\n", $list) . "\n", 'count' => count($list)];
    }

    /** Downloads the export with the owner's key and replaces the index. Returns '' or the error. */
    public static function update(): string
    {
        if (!self::available() || !self::hasKey()) {
            return self::fail('no key');
        }
        $export = defined('DRACO_URLHAUS_EXPORT') && preg_match('/^[a-z0-9_.-]{3,40}$/', (string) constant('DRACO_URLHAUS_EXPORT')) === 1
            ? (string) constant('DRACO_URLHAUS_EXPORT') : self::DEFAULT_EXPORT;
        $res = wp_remote_get(self::BASE . rawurlencode(self::key()) . '/' . $export, ['timeout' => 60, 'user-agent' => 'Draco-Insomnis']);
        if (is_wp_error($res)) {
            // Never the message itself: it could contain the address, and so the key.
            return self::fail('no answer');
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code !== 200) {
            return self::fail($code === 401 || $code === 403 ? 'key refused (HTTP ' . $code . ')' : 'HTTP ' . $code);
        }
        $body = (string) wp_remote_retrieve_body($res);
        if (str_starts_with($body, 'PK')) {
            $body = self::unzip($body);
        }
        $built = self::buildIndex($body);
        if ($built['count'] === 0) {
            return self::fail('empty list');
        }
        $file = self::indexFile();
        if (!wp_mkdir_p(dirname($file))) {
            return self::fail('folder');
        }
        $part = $file . '.part';
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- index next to the uploads
        if (@file_put_contents($part, $built['index']) === false || !@rename($part, $file)) {
            @unlink($part);

            return self::fail('folder');
        }
        update_option(self::OPTION_STATE, ['updated' => time(), 'count' => $built['count'], 'error' => ''], false);

        return '';
    }

    private static function unzip(string $zip): string
    {
        if (!class_exists(\ZipArchive::class)) {
            return '';
        }
        $tmp = wp_tempnam('draco-urlhaus');
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- temporary file
        file_put_contents($tmp, $zip);
        $z = new \ZipArchive();
        $out = '';
        if ($z->open($tmp) === true) {
            $out = $z->numFiles > 0 ? (string) $z->getFromIndex(0) : '';
            $z->close();
        }
        @unlink($tmp);

        return $out;
    }

    private static function fail(string $error): string
    {
        $s = self::state();
        $s['error'] = $error;
        update_option(self::OPTION_STATE, $s, false);

        return $error;
    }

    /**
     * @param int|string|\WP_Error $approved
     * @param array<string, mixed> $data
     * @return int|string|\WP_Error
     */
    public static function comment($approved, $data)
    {
        $data = is_array($data) ? $data : [];
        if (is_wp_error($approved) || in_array($approved, ['spam', 'trash'], true) || is_user_logged_in()) {
            return $approved;
        }
        $link = self::listed((string) ($data['comment_content'] ?? '') . ' ' . (string) ($data['comment_author_url'] ?? ''));
        if ($link === '') {
            return $approved;
        }
        self::log('urlhaus:comment', $link);

        return 'spam';
    }

    /**
     * @param null|bool $return
     * @param array<string, mixed> $atts
     * @return null|bool
     */
    public static function mail($return, array $atts)
    {
        if ($return !== null || is_user_logged_in() || MailHold::context() === '') {
            return $return;
        }
        $message = is_array($atts['message'] ?? null) ? implode(' ', $atts['message']) : (string) ($atts['message'] ?? '');
        $link = self::listed((string) ($atts['subject'] ?? '') . ' ' . $message);
        if ($link === '') {
            return $return;
        }
        self::log('urlhaus:form', $link);

        // The sender sees the usual "sent": a script learns nothing. Nothing is delivered.
        return true;
    }

    private static function log(string $endpoint, string $link): void
    {
        $ip = Guard::clientIp();
        Store::log($ip, $ip, $endpoint, ['score' => 100, 'verdict' => 'bot', 'reasons' => ['URLHAUS']], substr(Input::server('HTTP_USER_AGENT'), 0, 255), [
            'url' => substr(self::normalize($link), 0, 500),
        ]);
    }
}
