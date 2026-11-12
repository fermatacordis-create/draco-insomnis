<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Pace;

defined('MOODLE_INTERNAL') || die();

require_once(__DIR__ . '/../engine/autoload.php');

/**
 * Firewall and anti-copy pace limit at the start of every web request.
 *
 * Emergency exit for the owner: define('DRACO_WAF_OFF', true); in config.php.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */
final class hook_callbacks {

    /**
     * Runs at the end of setup, with the session and the user loaded.
     *
     * @param \core\hook\after_config $hook
     */
    public static function after_config(\core\hook\after_config $hook): void {
        global $USER;
        if ((defined('CLI_SCRIPT') && CLI_SCRIPT) || during_initial_install() || !get_config('local_dracoinsomnis', 'version')) {
            return;
        }
        $host = moodle_host::get();
        $request = moodle_host::request();
        $proxy = $host->setting('proxy_header');
        $loggedin = isloggedin() && !isguestuser();

        if ($loggedin && is_siteadmin()) {
            $host->remember_admin_ip($request->via($host));
            return;
        }

        $waf = moodle_host::mode('waf_mode');
        $bypass = $loggedin && has_capability('local/dracoinsomnis:bypassfirewall', \context_system::instance());
        if ($waf !== 'off' && !$bypass && !(defined('DRACO_WAF_OFF') && DRACO_WAF_OFF)) {
            $firewall = new Firewall($host, $waf === 'block');
            if (!$firewall->exempt($request)) {
                // Addresses on the block list may read the site, but not post or log in.
                if ($firewall->refusedAsBlocked($request, ['/login/index.php'])) {
                    self::deny('blocked');
                }
                $rule = $firewall->inspect($request);
                if ($rule !== null && $firewall->blocking()) {
                    self::deny($rule);
                }
            }
        }

        // Only page loads count: one Moodle page makes many AJAX, web service and file requests.
        $pace = moodle_host::mode('pace_mode');
        if ($pace !== 'off' && !$loggedin && !self::not_a_page($request->path)) {
            $engine = new Pace($host);
            $count = $engine->count($request, time());
            if ($count['over'] !== '' && !$engine->exempt($request)) {
                $block = $pace === 'block';
                if ($count['first']) {
                    $engine->record($request, 'rate_' . $count['over'], $block, $request->path);
                }
                if ($block) {
                    self::too_many($count['retry']);
                }
            }
        }
    }

    /**
     * AJAX calls, web services and files are not pages a person reads.
     *
     * @param string $path
     * @return bool
     */
    private static function not_a_page(string $path): bool {
        if (defined('AJAX_SCRIPT') && AJAX_SCRIPT) {
            return true;
        }
        return (bool) preg_match('#/(pluginfile|tokenpluginfile|draftfile|webservice/[^/]+/server)\.php|/lib/ajax/|/webservice/#', $path);
    }

    /**
     * No details for the attacker: what matched stays in the log.
     *
     * @param string $why
     */
    private static function deny(string $why): void {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/html; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex, nofollow');
        }
        echo Firewall::page(get_string('blockedtitle', 'local_dracoinsomnis'), get_string('blockedtext', 'local_dracoinsomnis'), $why);
        die();
    }

    /**
     * Too many pages this minute.
     *
     * @param int $seconds
     */
    private static function too_many(int $seconds): void {
        if (!headers_sent()) {
            http_response_code(429);
            header('Retry-After: ' . max(1, $seconds));
            header('Content-Type: text/plain; charset=UTF-8');
            header('Cache-Control: no-store');
            header('X-Robots-Tag: noindex');
        }
        echo 'Too many requests. Please wait a minute.';
        die();
    }
}
