<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis;

use DracoInsomnis\Core\EventStore;
use DracoInsomnis\Core\Host;
use DracoInsomnis\Core\Request;
use DracoInsomnis\Core\WafRules;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../engine/autoload.php');

/**
 * The engines in engine/Core, running in Moodle. Settings live in config_plugins (local_dracoinsomnis).
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */
final class moodle_host implements Host {

    /** Settings modes. */
    public const MODES = ['off', 'log', 'block'];

    /** @var self|null */
    private static ?self $instance = null;

    /**
     * The shared instance.
     *
     * @return self
     */
    public static function get(): self {
        return self::$instance ??= new self();
    }

    /**
     * A mode setting: off, log or block.
     *
     * @param string $name
     * @return string
     */
    public static function mode(string $name): string {
        $mode = (string) get_config('local_dracoinsomnis', $name);
        return in_array($mode, self::MODES, true) ? $mode : 'off';
    }

    /**
     * Whether the sign-up shield is on.
     *
     * @return bool
     */
    public static function shield_on(): bool {
        return (bool) get_config('local_dracoinsomnis', 'shield');
    }

    /**
     * The current request as plain values.
     *
     * @return Request
     */
    public static function request(): Request {
        $server = static fn (string $key): string => isset($_SERVER[$key]) && is_string($_SERVER[$key]) ? $_SERVER[$key] : '';
        $method = strtoupper(self::clean($server('REQUEST_METHOD')));
        $method = $method !== '' ? $method : 'GET';
        $uri = $server('REQUEST_URI');
        $post = [];
        foreach ($_POST as $name => $value) {
            if (is_string($name) && is_string($value)) {
                $post[$name] = self::clean($value);
            }
        }
        return new Request(
            $method,
            rawurldecode((string) parse_url($uri, PHP_URL_PATH)),
            urldecode((string) parse_url($uri, PHP_URL_QUERY)),
            WafRules::flatten(array_merge($_GET, $method === 'POST' ? $_POST : [])),
            $post,
            self::clean($server('HTTP_USER_AGENT')),
            $server('HTTP_USER_AGENT'),
            self::clean($server('REMOTE_ADDR')),
            self::clean($server('HTTP_CF_CONNECTING_IP')),
            self::clean($server('HTTP_X_FORWARDED_FOR')),
            self::clean((string) filter_var($server('HTTP_REFERER'), FILTER_SANITIZE_URL)),
        );
    }

    /**
     * One line of plain text: no tags, no control characters.
     *
     * @param string $value
     * @return string
     */
    public static function clean(string $value): string {
        return trim((string) preg_replace('/[\x00-\x1F\x7F]+/', ' ', strip_tags($value)));
    }

    public function secret(): string {
        $secret = (string) get_config('local_dracoinsomnis', 'secret');
        if (strlen($secret) !== 64) {
            $secret = bin2hex(random_bytes(32));
            set_config('secret', $secret, 'local_dracoinsomnis');
        }
        return $secret;
    }

    public function setting(string $name): string {
        global $CFG;
        $value = get_config('local_dracoinsomnis', $name);
        if ($name === 'geo_file' && (!is_string($value) || $value === '')) {
            // Public data, refreshed monthly; in moodledata so plugin updates keep it.
            return $CFG->dataroot . '/local_dracoinsomnis/draco-geo.bin';
        }
        return is_scalar($value) ? (string) $value : '';
    }

    public function adminIps(): array {
        // Plus the addresses a person let through after a review.
        return array_values(array_unique(array_merge(self::stored_admin_ips(), store::active_values('allow'))));
    }

    /**
     * The administrators' addresses kept by remember_admin_ip().
     *
     * @return string[]
     */
    private static function stored_admin_ips(): array {
        $list = json_decode((string) get_config('local_dracoinsomnis', 'adminips'), true);
        return is_array($list) ? array_values(array_filter($list, 'is_string')) : [];
    }

    /**
     * The last ten addresses site administrators worked from: never blocked, never limited.
     *
     * @param string $ip
     */
    public function remember_admin_ip(string $ip): void {
        $list = self::stored_admin_ips();
        if (($list[0] ?? null) === $ip) {
            return;
        }
        set_config('adminips', json_encode(array_slice(array_values(array_unique(array_merge([$ip], $list))), 0, 10)), 'local_dracoinsomnis');
    }

    public function bump(string $key, int $ttl): int {
        return store::bump($key, $ttl);
    }

    public function recall(string $key): ?string {
        return store::recall($key);
    }

    public function remember(string $key, string $value, int $ttl): void {
        store::remember($key, $value, $ttl);
    }

    /**
     * Other plugins change values with a <plugin>_draco_insomnis_filter($name, $value, $args) callback.
     *
     * @param string $name
     * @param mixed $value
     * @param mixed ...$args
     * @return mixed
     */
    public function filter(string $name, $value, ...$args) {
        foreach (get_plugins_with_function('draco_insomnis_filter') as $plugins) {
            foreach ($plugins as $function) {
                $value = $function($name, $value, $args);
            }
        }
        return $value;
    }

    public function text(string $id, int $number): string {
        global $SITE;
        if ($id === 'pwd_short') {
            return get_string('pwdshort', 'local_dracoinsomnis', $number);
        }
        if ($id === 'pwd_breached') {
            return get_string('pwdbreachedrefused', 'local_dracoinsomnis');
        }
        if ($id === 'review_subject') {
            return get_string('reviewsubject', 'local_dracoinsomnis', format_string($SITE->shortname ?? ''));
        }
        if ($id === 'review_body') {
            return get_string('reviewbody', 'local_dracoinsomnis') . "\n\n" . (new \moodle_url('/local/dracoinsomnis/evidence.php'))->out(false);
        }
        return get_string($id === 'waf_block' ? 'wafblock' : 'autoblock', 'local_dracoinsomnis', $number);
    }

    public function notifyOwner(string $subject, string $body): void {
        try {
            email_to_user(get_admin(), \core_user::get_noreply_user(), $subject, $body);
        } catch (\Throwable $e) {
            // A notice that cannot be sent never breaks the visitor's request.
            unset($e);
        }
    }

    public function events(): EventStore {
        return new store();
    }
}
