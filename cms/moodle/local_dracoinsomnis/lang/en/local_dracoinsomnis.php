<?php
// This file is part of Draco Insomnis for Moodle - https://github.com/fermatacordis-create/draco-insomnis
//
// Draco Insomnis is free software: you can redistribute it and/or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 2 of the
// License, or (at your option) any later version.

/**
 * English strings.
 *
 * @package    local_dracoinsomnis
 * @copyright  2026 Notorius Vision
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v2 or later
 */

defined('MOODLE_INTERNAL') || die();

$string['autoblock'] = 'Automatic: {$a} bot attempts in 24 h';
$string['block'] = 'Block';
$string['blockadd'] = 'Block an address or range';
$string['blockadd_desc'] = 'Never an administrator, nor your own address. Ranges no wider than /16 (IPv4) or /32 (IPv6).';
$string['blockdays'] = 'For';
$string['blockdone'] = 'Blocked: {$a}';
$string['blockedtext'] = 'This request was stopped for security reasons. If you think this is a mistake, contact the owner of the site.';
$string['blockedtitle'] = 'Request blocked';
$string['blockrefused'] = 'Nothing was blocked: the value is not valid, belongs to an administrator, or is your own address.';
$string['blocks'] = 'Blocked addresses';
$string['blockvalue'] = 'IP or range (e.g. 203.0.113.0/24)';
$string['coldata'] = 'Data';
$string['coldate'] = 'Date (UTC)';
$string['colip'] = 'Address';
$string['colreason'] = 'Reason';
$string['colsigns'] = 'Signs';
$string['coluntil'] = 'Until (UTC)';
$string['colvalue'] = 'Address or e-mail';
$string['colverdict'] = 'Verdict';
$string['colwhere'] = 'Where';
$string['days15'] = '15 days';
$string['days30'] = '30 days';
$string['days7'] = '7 days';
$string['days90'] = '90 days';
$string['dracoinsomnis:bypassfirewall'] = 'Bypass the Draco Insomnis firewall';
$string['events'] = 'Last suspicious attempts';
$string['events_help'] = 'Kept for 90 days. Never passwords. The CSV of an address holds everything it did, ready to attach to an abuse report to its network provider.';
$string['evidence'] = 'Draco Insomnis: blocks and evidence';
$string['forever'] = 'Forever';
$string['geo'] = 'Countries';
$string['geo_desc'] = 'Most of your visitors may come from many countries, and an attacker changes country with a VPN. Filter only logging in, signing up and forms, and start with "Log only". Site administrators, people you let through and search engines are never filtered. Needs the firewall on (log or block).';
$string['geoaction'] = 'What to do';
$string['geocountries'] = 'Countries (two-letter codes, e.g. ES, FR, DE)';
$string['geocredit'] = 'IP geolocation by DB-IP (db-ip.com, CC BY 4.0), downloaded when you switch the filter on and looked up on your own server: no address is sent anywhere.';
$string['geomode'] = 'Filter';
$string['geoonly'] = 'Only the countries listed';
$string['georefuse'] = 'Refuse the countries listed';
$string['geoscope'] = 'Where';
$string['geosensitive'] = 'Logging in, signing up and forms (recommended)';
$string['geosite'] = 'The whole site';
$string['headers'] = 'Security headers';
$string['headers_desc'] = 'On pages: no sniffing of file types, no framing by other sites, less referrer data, no camera, microphone or location for embedded content. Never one Moodle already sends.';
$string['hsts'] = 'Force HTTPS for 6 months (HSTS)';
$string['hsts_desc'] = 'Only when the whole site works on HTTPS and will keep working: browsers remember it and refuse plain HTTP until it expires.';
$string['intro'] = '<p><em>Ab insomni custodita dracone.</em> Stops fake sign-ups without captchas: bots get no account, and every suspicious attempt is kept for 90 days as evidence for an abuse report. Nothing is ever sent back to the attacker.</p><p>Blocked addresses and the last attempts: <a href="{$a}">Draco Insomnis: blocks and evidence</a>.</p>';
$string['modeblock'] = 'Block';
$string['modelog'] = 'Log only: record what it would stop';
$string['modeoff'] = 'Off';
$string['nets'] = 'Rented-server networks';
$string['nets_desc'] = 'One range per line (CIDR), added to the ones the plugin already knows. Being on this list only adds points: on its own it never makes anyone a bot.';
$string['noblocks'] = 'Nothing blocked right now.';
$string['noevents'] = 'Nothing yet.';
$string['pace'] = 'Anti-copy pace limit';
$string['pace_desc'] = 'More pages per minute than a person reads get "429 Too many requests" until the minute ends. Logged-in users, your own addresses and search engines verified by DNS (Google, Bing, Apple, Yandex) are never limited. AJAX calls, web services and files do not count.';
$string['pluginname'] = 'Draco Insomnis';
$string['privacy:metadata:blocks'] = 'Addresses and e-mails blocked for a while, by the automatic block or by an administrator.';
$string['privacy:metadata:blocks:value'] = 'The blocked IP address or e-mail.';
$string['privacy:metadata:events'] = 'Suspicious attempts (fake sign-ups, attacks, scraping), kept for 90 days as evidence for abuse reports. Not linked to Moodle accounts. Never passwords.';
$string['privacy:metadata:events:fields'] = 'Username, e-mail and referring page sent with the attempt.';
$string['privacy:metadata:events:ip'] = 'The IP address the attempt came from.';
$string['privacy:metadata:events:timecreated'] = 'When the attempt happened.';
$string['privacy:metadata:events:useragent'] = 'The browser or program name it sent.';
$string['proxy'] = 'Visitor address';
$string['proxy_desc'] = 'Leave "Connection address" unless the site is behind a proxy: a header can be forged by anyone.';
$string['proxycf'] = 'Cloudflare (CF-Connecting-IP)';
$string['proxyignored'] = 'The header is ignored: this connection (<code>{$a}</code>) does not come from Cloudflare or from a trusted proxy. If your proxy is on the internet, add its addresses in "Trusted proxies".';
$string['proxynone'] = 'Connection address (recommended)';
$string['proxyxff'] = 'Other proxy (X-Forwarded-For)';
$string['rateip'] = 'Pages per minute, per address';
$string['ratenet'] = 'Pages per minute, per network';
$string['ratenet_desc'] = 'A /24 network for IPv4 or a /64 for IPv6: what a scraper gets when it rotates addresses next to each other.';
$string['rejected'] = 'The registration could not be completed.';
$string['reviewbody'] = 'A visitor stopped by the firewall asks for a review. Open the Draco Insomnis page to let them through or not.';
$string['reviewsubject'] = '[{$a}] Someone asks you to review a firewall block';
$string['shield'] = 'Protect self-registration';
$string['shield_desc'] = 'Adds an invisible trap and a signed page stamp to the sign-up form (email-based self-registration). Bots get no account; three bot attempts in a day block the address for a week.';
$string['taskcleanup'] = 'Draco Insomnis: remove old evidence and finished blocks';
$string['trusted'] = 'Trusted proxies';
$string['trusted_desc'] = 'Only connections from these addresses may set the visitor address through a header. One address or range per line. Empty: this server and private networks. Cloudflare\'s own ranges are already known.';
$string['unblock'] = 'Unblock';
$string['unblocked'] = 'Address unblocked.';
$string['waf'] = 'Firewall';
$string['waf_desc'] = 'Stops requests with the shape of an attack (database injection, reading server files, running code, scripts in links) and scanners such as sqlmap or Nikto. Start with "Log only" and move to "Block" after a few days. Five attacks in 10 minutes block the address for a week; blocked addresses can still read the site, but not post or log in. Site administrators and users with "Bypass the Draco Insomnis firewall" are never inspected. Emergency exit: define(\'DRACO_WAF_OFF\', true); in config.php.';
$string['wafblock'] = 'Firewall: {$a} attacks in 10 minutes';
$string['yourip'] = 'Your address as the plugin sees it: <code>{$a->ip}</code> (connection address: <code>{$a->remote}</code>). If the site is behind Cloudflare or another proxy and these differ from your real address, choose the matching option in "Visitor address".';
