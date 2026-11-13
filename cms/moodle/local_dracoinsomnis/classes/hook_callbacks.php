<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

namespace local_dracoinsomnis;

use DracoInsomnis\Core\Firewall;
use DracoInsomnis\Core\Gatekeeper;
use DracoInsomnis\Core\SecurityHeaders;

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

        $bypass = $loggedin && has_capability('local/dracoinsomnis:bypassfirewall', \context_system::instance());
        $waf = ($bypass || (defined('DRACO_WAF_OFF') && DRACO_WAF_OFF)) ? 'off' : moodle_host::mode('waf_mode');
        // Only page loads count for the pace limit: one Moodle page makes many AJAX, web service and file requests.
        $answer = (new Gatekeeper($host))->decide($request, $waf, moodle_host::mode('pace_mode'),
            ['/login/index.php', '/login/signup.php', '/login/forgot_password.php'], !$loggedin && !self::not_a_page($request->path));
        if ($answer !== null) {
            $answer['status'] === 429 ? self::too_many($answer['retry']) : self::deny($answer['why']);
        }
    }

    /**
     * Security headers on pages, when switched on; never one Moodle or the server already set.
     *
     * @param \core\hook\output\before_http_headers $hook
     */
    public static function before_http_headers($hook): void {
        global $CFG;
        if (during_initial_install() || !get_config('local_dracoinsomnis', 'version')) {
            return;
        }
        $wanted = SecurityHeaders::wanted(moodle_host::get(), is_https());
        if (empty($CFG->allowframembedding)) {
            unset($wanted['X-Frame-Options']); // Moodle sends its own.
        }
        SecurityHeaders::send($wanted);
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
