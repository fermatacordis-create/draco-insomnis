<?php

declare(strict_types=1);

namespace DracoInsomnis\Gate;

use DracoInsomnis\Input;
use DracoInsomnis\Plugin;
use DracoInsomnis\Shield\Guard;
use DracoInsomnis\Shield\Store;

defined('ABSPATH') || exit;

/**
 * Malicious links: links in comments and contact forms are checked against public lists, locally.
 * Nothing a visitor writes is sent anywhere: the site downloads each list twice a day and looks links
 * up in its own copy (a sorted index of short hashes, searched without loading it).
 *
 * Two lists (docs/adr/0001), each one only where its terms allow it:
 * - URLhaus (abuse.ch), malware links: standalone plugin only, never when Draco is bundled in another
 *   product. Free use is non-profit; commercial use needs a Spamhaus subscription (abuse.ch terms of
 *   use, sections 3 and 4). The owner's own key, and the owner confirms the use before switching it on.
 * - PhishTank (Cisco Talos), verified phishing still online: everywhere. Its FAQ allows commercial and
 *   non-commercial use; a free key from the owner's account is optional (without one, a few downloads a day).
 *
 * Keys live in wp-config.php (DRACO_URLHAUS_KEY, DRACO_PHISHTANK_KEY), never in the database, on screen
 * or in a log. Exact URLs are matched, not whole domains: the lists hold many hacked legitimate sites.
 * Hosts that are bare IP addresses match as a whole, and so does a PhishTank entry for the front page of a
 * site (a site made for phishing), except on shared services where only the exact link counts.
 */
final class LinkCheck
{
    public const OPTION_ENABLED = 'draco_urlhaus_enabled';
    public const OPTION_CONFIRMED = 'draco_urlhaus_confirmed';
    public const OPTION_STATE = 'draco_urlhaus_state';
    public const HOOK_UPDATE = 'draco_urlhaus_update';
    public const KEY_CONSTANT = 'DRACO_URLHAUS_KEY';
    public const URLHAUS = 'urlhaus';
    public const PHISHTANK = 'phishtank';
    public const PT_OPTION_ENABLED = 'draco_phishtank_enabled';
    public const PT_OPTION_STATE = 'draco_phishtank_state';
    public const PT_KEY_CONSTANT = 'DRACO_PHISHTANK_KEY';
    public const PT_TERMS = 'https://phishtank.org/faq.php';
    private const PT_BASE = 'https://data.phishtank.com/data/';
    /** A list that has not changed for this long is shown as stale. */
    public const STALE_AFTER = 7 * DAY_IN_SECONDS;
    /** Shared services: a front-page entry there never stands for the whole host. */
    private const SHARED_HOSTS = [
        'google.com', 'www.google.com', 'docs.google.com', 'drive.google.com', 'sites.google.com', 'forms.gle',
        'dropbox.com', 'www.dropbox.com', 'onedrive.live.com', '1drv.ms', 'github.com', 'gist.github.com',
        't.me', 'bit.ly', 'tinyurl.com', 'linktr.ee', 'wa.me', 'facebook.com', 'www.facebook.com',
        'instagram.com', 'www.instagram.com', 'x.com', 'twitter.com', 'youtube.com', 'www.youtube.com',
    ];
    /** The export file; the documented one by default. Another can be set with DRACO_URLHAUS_EXPORT. */
    public const DEFAULT_EXPORT = 'recent.csv';
    private const BASE = 'https://urlhaus-api.abuse.ch/v2/files/exports/';
    private const LINE = 17; // 16 hex characters of the hash + "\n"
    private const MAX_LINKS = 50;
    public const TERMS = 'https://abuse.ch/terms-of-use/';
    public const SPAMHAUS = 'https://www.spamhaus.com/data-access/abusech-api/';

    public static function register(): void
    {
        add_action(self::HOOK_UPDATE, [self::class, 'updateAll']);
        if (self::activeFeeds() === []) {
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

    /** PhishTank: allowed everywhere, off until the owner switches it on. */
    public static function phishtankActive(): bool
    {
        return get_option(self::PT_OPTION_ENABLED, 'no') === 'yes';
    }

    public static function phishtankHasKey(): bool
    {
        return self::phishtankKey() !== '';
    }

    private static function phishtankKey(): string
    {
        $key = defined(self::PT_KEY_CONSTANT) ? (string) constant(self::PT_KEY_CONSTANT) : '';

        return preg_match('/^[A-Za-z0-9]{16,128}$/', $key) === 1 ? $key : '';
    }

    /** @return list<string> the lists switched on here */
    public static function activeFeeds(): array
    {
        $out = [];
        if (self::active()) {
            $out[] = self::URLHAUS;
        }
        if (self::phishtankActive()) {
            $out[] = self::PHISHTANK;
        }

        return $out;
    }

    /** @return array{updated: int, count: int, error: string, changed: int} */
    public static function state(string $feed = self::URLHAUS): array
    {
        $s = get_option($feed === self::PHISHTANK ? self::PT_OPTION_STATE : self::OPTION_STATE, []);
        $s = is_array($s) ? $s : [];

        return ['updated' => (int) ($s['updated'] ?? 0), 'count' => (int) ($s['count'] ?? 0), 'error' => (string) ($s['error'] ?? ''), 'changed' => (int) ($s['changed'] ?? 0)];
    }

    /** Downloaded, but its content has not changed for a week: the list may no longer be kept. */
    public static function stale(string $feed, ?int $now = null): bool
    {
        $changed = self::state($feed)['changed'];

        return $changed > 0 && ($now ?? time()) - $changed > self::STALE_AFTER;
    }

    public static function indexFile(string $feed = self::URLHAUS): string
    {
        $up = wp_upload_dir(null, false);

        return wp_normalize_path(trailingslashit((string) $up['basedir']) . 'draco-insomnis/' . ($feed === self::PHISHTANK ? 'phishtank' : 'urlhaus') . '.idx');
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

    /**
     * Keys to store or look up for one URL: the URL, and its host when it is an IP. When storing a list
     * where a front-page entry means the whole site ($rootIsHost, PhishTank), that entry also stores its
     * host, unless the host is a shared service. Looking up always tries the host key too.
     *
     * @return list<string>
     */
    private static function keys(string $url, bool $rootIsHost = false, bool $lookup = false): array
    {
        $n = self::normalize($url);
        if ($n === '') {
            return [];
        }
        $keys = ['u|' . $n];
        $host = self::hostOf($n);
        if (filter_var($host, FILTER_VALIDATE_IP) !== false || $lookup) {
            $keys[] = 'h|' . $host;
        } elseif ($rootIsHost && !in_array($host, self::SHARED_HOSTS, true) && (string) wp_parse_url($n, PHP_URL_PATH) === '/' && (string) wp_parse_url($n, PHP_URL_QUERY) === '') {
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

    // phpcs:disable WordPress.WP.AlternativeFunctions -- random-access reads (fseek) of a read-only index: WP_Filesystem has no seek.

    /** The first listed link in a text, or ''. */
    public static function listed(string $text, ?array $feeds = null): string
    {
        return self::find($text, $feeds)[0];
    }

    /**
     * The first listed link in a text and the list that has it, or ['', ''].
     *
     * @param list<string>|null $feeds the lists to look in; null = every list downloaded here
     * @return array{0: string, 1: string}
     */
    public static function find(string $text, ?array $feeds = null): array
    {
        $links = self::links($text);
        if ($links === []) {
            return ['', ''];
        }
        foreach ($feeds ?? [self::URLHAUS, self::PHISHTANK] as $feed) {
            $file = self::indexFile($feed);
            $fh = is_readable($file) ? fopen($file, 'rb') : false;
            if ($fh === false) {
                continue;
            }
            foreach ($links as $link) {
                foreach (self::keys($link, false, true) as $key) {
                    if (self::lookup($fh, self::hash($key))) {
                        fclose($fh);

                        return [$link, $feed];
                    }
                }
            }
            fclose($fh);
        }

        return ['', ''];
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

    // phpcs:enable WordPress.WP.AlternativeFunctions

    /**
     * The sorted index from an export (CSV or one URL per line): the first http(s) field of each line.
     *
     * @return array{index: string, count: int}
     */
    public static function buildIndex(string $export, bool $rootIsHost = false): array
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
            foreach ($url !== '' ? self::keys($url, $rootIsHost) : [] as $key) {
                $hashes[self::hash($key)] = true;
            }
        }
        $list = array_keys($hashes);
        sort($list, SORT_STRING);

        return ['index' => $list === [] ? '' : implode("\n", $list) . "\n", 'count' => count($list)];
    }

    /** The twice-daily download of every list switched on. */
    public static function updateAll(): void
    {
        foreach (self::activeFeeds() as $feed) {
            self::update($feed);
        }
    }

    /** Downloads one list and replaces its index. Returns '' or the error. */
    public static function update(string $feed = self::URLHAUS): string
    {
        return $feed === self::PHISHTANK ? self::updatePhishtank() : self::updateUrlhaus();
    }

    /** PhishTank's verified phishing still online (CSV, gzip); the owner's key when there is one. */
    private static function updatePhishtank(): string
    {
        $key = self::phishtankKey();
        $url = self::PT_BASE . ($key !== '' ? rawurlencode($key) . '/' : '') . 'online-valid.csv.gz';
        // PhishTank asks for a descriptive user agent that starts with «phishtank/».
        $res = wp_remote_get($url, ['timeout' => 60, 'user-agent' => 'phishtank/draco-insomnis']);
        if (is_wp_error($res)) {
            return self::fail('no answer', self::PHISHTANK);
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        if ($code !== 200) {
            return self::fail($code === 509 ? 'too many downloads today (HTTP 509): a free PhishTank key lifts the limit' : 'HTTP ' . $code, self::PHISHTANK);
        }
        $body = (string) wp_remote_retrieve_body($res);
        if (str_starts_with($body, "\x1f\x8b")) {
            $body = (string) @gzdecode($body);
        }

        return self::store(self::PHISHTANK, self::buildIndex($body, true));
    }

    private static function updateUrlhaus(): string
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
        return self::store(self::URLHAUS, self::buildIndex($body));
    }

    /**
     * Replaces a list's index and notes when its content last changed (for «stale»).
     *
     * @param array{index: string, count: int} $built
     */
    private static function store(string $feed, array $built): string
    {
        if ($built['count'] === 0) {
            return self::fail('empty list', $feed);
        }
        $file = self::indexFile($feed);
        if (!wp_mkdir_p(dirname($file))) {
            return self::fail('folder', $feed);
        }
        $part = $file . '.part';
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- index next to the uploads
        // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- atomic replace, so a lookup never reads half an index.
        if (@file_put_contents($part, $built['index']) === false || !@rename($part, $file)) {
            wp_delete_file($part);

            return self::fail('folder', $feed);
        }
        $old = get_option($feed === self::PHISHTANK ? self::PT_OPTION_STATE : self::OPTION_STATE, []);
        $old = is_array($old) ? $old : [];
        $sha = sha1($built['index']);
        $changed = ($old['sha'] ?? '') === $sha && (int) ($old['changed'] ?? 0) > 0 ? (int) $old['changed'] : time();
        update_option($feed === self::PHISHTANK ? self::PT_OPTION_STATE : self::OPTION_STATE, ['updated' => time(), 'count' => $built['count'], 'error' => '', 'changed' => $changed, 'sha' => $sha], false);

        return '';
    }

    /** Switching a list off removes its index, so nothing is matched against it any more. */
    public static function forget(string $feed): void
    {
        wp_delete_file(self::indexFile($feed));
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
        wp_delete_file($tmp);

        return $out;
    }

    private static function fail(string $error, string $feed = self::URLHAUS): string
    {
        $option = $feed === self::PHISHTANK ? self::PT_OPTION_STATE : self::OPTION_STATE;
        $s = get_option($option, []);
        $s = is_array($s) ? $s : [];
        $s['error'] = $error;
        update_option($option, $s, false);

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
        [$link, $feed] = self::find((string) ($data['comment_content'] ?? '') . ' ' . (string) ($data['comment_author_url'] ?? ''), self::activeFeedsOrAll());
        if ($link === '') {
            return $approved;
        }
        self::log($feed . ':comment', $link, $feed);

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
        [$link, $feed] = self::find((string) ($atts['subject'] ?? '') . ' ' . $message, self::activeFeedsOrAll());
        if ($link === '') {
            return $return;
        }
        self::log($feed . ':form', $link, $feed);

        // The sender sees the usual "sent": a script learns nothing. Nothing is delivered.
        return true;
    }

    /**
     * The lists switched on; when none is (the filters were added by hand, as the tests do), every
     * list downloaded here.
     *
     * @return list<string>|null
     */
    private static function activeFeedsOrAll(): ?array
    {
        $feeds = self::activeFeeds();

        return $feeds === [] ? null : $feeds;
    }

    private static function log(string $endpoint, string $link, string $feed = self::URLHAUS): void
    {
        $ip = Guard::clientIp();
        Store::log($ip, $ip, $endpoint, ['score' => 100, 'verdict' => 'bot', 'reasons' => [strtoupper($feed)]], substr(Input::server('HTTP_USER_AGENT'), 0, 255), [
            'url' => substr(self::normalize($link), 0, 500),
        ]);
    }
}
