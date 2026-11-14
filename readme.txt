=== Draco Insomnis ===
Contributors: opnvsole
Tags: security, anti-spam, registration, honeypot, bots
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.1.21
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Ab insomni custodita dracone. Stops fake sign-ups without captchas, feeds bots a fake success and keeps evidence for abuse reports.

== Description ==

Author: Soledad Sánchez Mohamed.

Bots that create fake accounts usually post straight to the registration endpoint, ask for roles that do not exist, fill every field they see and come from rented servers. Draco Insomnis scores every public sign-up on those signs before the account exists.

* **No captcha.** People never solve puzzles. A hidden trap field and a signed page stamp do the work.
* **Bots are fooled, not warned.** A bot is told "registration complete" after a short, capped wait. No account is created.
* **Doubtful is not guilty.** One weak sign alone (a VPN, an odd username) never rejects a person.
* **Evidence for abuse reports.** Every suspicious attempt is kept for 90 days and can be downloaded per address as a CSV file to send to the network provider.
* **Automatic blocks.** Three bot attempts in a day block the address for a week. Administrators' recent addresses are never blocked.
* **Defence only.** Nothing is ever sent back to the attacker's machine.
* **Not security by obscurity.** Field names and the stamp key are unique to each site, so reading this code does not tell a bot what to send.

Protects the registration forms of WordPress, WooCommerce and the RealHomes theme.

= Site mail (SMTP) =

Sends the mail of the site through a real mailbox instead of PHP mail(), so login codes, forms and orders actually arrive.

* **Test before it counts.** Nothing changes until a test message succeeds; changing any setting switches it off until you test again.
* **Encrypted password.** Stored with AES-256-GCM using a key from the site's own security keys.
* **Ready-made settings** for Hostinger, IONOS, OVHcloud, Arsys, GoDaddy, Zoho, Microsoft 365, Google, Brevo, Mailgun, SendGrid, Postmark, Mailjet, Amazon SES and more.
* **Deliverability checks.** Warns when the sender is not on the site's domain or when the domain's DMARC policy will reject PHP mail().
* **Sender that passes DMARC.** The mailbox becomes the visible sender; the original address goes to Reply-To.
* **Log of the last 50 messages** (never their content) and extra addresses for WordPress recovery and password-change alerts.

= Forms and sign-ups =

Holds every contact message, blog comment and new account until the sender confirms from their e-mail. Bots do not confirm, so their spam never reaches you.

* **Works with** Contact Form 7, WPForms, Elementor Pro, Divi and RealHomes forms, WordPress and WooCommerce registration, and blog comments.
* **Nothing is lost.** The message is kept exactly as the form built it, attachments included, and delivered when confirmed. Unconfirmed ones are erased after 48 hours.
* **Mail scanners cannot confirm.** Opening the link changes nothing; the person has to press a button.
* **New accounts stay closed** until confirmed: no login, no password reset, no welcome mail. Unconfirmed accounts are deleted after 48 hours, unless they have content or orders, which a person reviews instead. Accounts created while paying in the shop are never held.
* **Block from any row**, by e-mail or IP, for 7 to 90 days. A blocked sender sees the same answer, so they cannot tell.
* **Never sends what the visitor typed** to the address they wrote, so it cannot be used to send spam to strangers, and it limits how many confirmations an address or IP can trigger.

Needs working site mail: it only switches on when SMTP is set up.

= Two-step login =

After the right password, WordPress asks for a 6-digit code sent by e-mail. A stolen password alone is no longer enough.

* **For administrators by default**, or for everyone who can edit, or for every user.
* **The code is only sent after the right password**, expires in 10 minutes and allows 5 tries. Repeated failures block the address for 15 minutes.
* **Trust this device for 7 days** (optional). Changing the password or e-mail of an account revokes its trusted devices.
* **No lock-outs from missing mail.** It only switches on with SMTP working and switches itself off if that connection is forgotten.
* **Recovery e-mail, like the PUK of a phone.** Everyone who needs a code keeps a second mailbox. The code screen can send the code there instead; "Lost your password?" accepts it too; after a password reset the next code goes only there. Changing it needs a code from the new address and one from the current one, and every change is told to the other mailbox. Administrators set it up before using the dashboard.
* **Emergency exit for the owner:** `define('DRACO_MFA_OFF', true);` in wp-config.php. Only someone with access to the server can use it, unlike a "skip" button a thief could press.

= Firewall =

Stops requests with the shape of an attack, and the scanners that look for weak spots.

* **Precise signatures, not word lists.** Database injection, reading server files, running code and scripts in links are matched by their shape, so ordinary messages with words like "select", "update" or "delete" go through.
* **Scanners and probes.** Tools such as sqlmap, WPScan or Nikto, and requests for .env, .git, wp-config backups, phpinfo or known web shells.
* **Starts in log-only mode**, so you can see what it would stop before it stops anything.
* **Automatic blocks**: five attacks in 10 minutes put the address on the block list for 7 days. Blocked addresses can still read the site, but not log in, post forms or use XML-RPC.
* **Hides the list of user names** from anonymous visitors (?author=1 and the users REST endpoint).
* **Limits failed logins** and always refuses XML-RPC system.multicall (hundreds of passwords in one call) and pingbacks.
* **Never inspects people who can edit the site** and never blocks an address an administrator used recently. Emergency exit: `define('DRACO_WAF_OFF', true);` in wp-config.php.

= Anti-copy =

Makes it harder to copy the whole site in one go, without getting in the way of visitors or search engines.

* **Content API closed to anonymous visitors.** /wp-json/wp/v2/ lists every post, page and image as JSON; reads there need a login, except the routes you keep open. Pages stay public, and other APIs (forms, shop, embeds) are untouched.
* **Pace limit.** More pages per minute than a person reads, from one address or from one network, get "429 Too many requests" until the minute ends.
* **Search engines are verified, not trusted.** Google, Bing, Apple and Yandex pass after a reverse and forward DNS check, kept for a day; a program that only borrows their name does not.
* **Log first.** Both parts have a log-only mode that shows what would be stopped.

= Languages =

English, Spanish (Spain and all Latin American variants), Catalan, German, French, Italian, Portuguese (Portugal and Brazil), Dutch, Polish, Russian, Turkish, Japanese, Simplified Chinese, Korean, Arabic, Hindi, Indonesian, Vietnamese, Bengali, Urdu, Persian, Filipino, Thai, Ukrainian, Swahili, Malay and Tamil. Corrections from native speakers are very welcome, especially for the Asian, African and Middle Eastern languages.

= Who makes it =

Draco Insomnis is made by [Notorius Vision](https://notoriusvision.com), the team behind [OPNV Systems](https://opnv.systems) and OPNV SOLΞ. It is the open-source security core of OPNV.

The code is free software (GPLv2 or later). The names Draco Insomnis, Notorius Vision, OPNV, OPNV Systems and OPNV SOLΞ, and the dragon logo, are not part of that licence: if you publish a modified version, please give it another name and logo.

== Installation ==

1. Install and activate the plugin.
2. Open **Draco Insomnis → Anti-bot shield** and tick **Protect sign-ups**.
3. Open **Draco Insomnis → Site mail (SMTP)**: connect your mailbox, send a test, then switch it on.
4. Open **Draco Insomnis → Forms and sign-ups** and tick **Verify contact forms and sign-ups**.
5. Open **Draco Insomnis → Two-step login** and tick **Ask for a code by e-mail after the password**.
6. Open **Draco Insomnis → Firewall**, switch it on in **Log only**, and move to **Block** after a few days.
7. If the site is behind Cloudflare or another proxy, choose the matching **Visitor address** option and check that "Your address as the plugin sees it" shows your real address.

== Frequently Asked Questions ==

= Will real people be rejected? =

Only if they send a sign that people never send, such as a role the form does not offer or a value in the invisible trap field. People with JavaScript turned off or on a VPN are only marked "doubtful" and go through.

= Does it slow the site down? =

Only bots wait, for at most three seconds, and at most ten slow answers per minute across the whole site.

= What does it store? =

For suspicious attempts only: date, address, browser name, username, e-mail, requested role and referring page. Never passwords. Everything is deleted after 90 days, and all of it is removed when the plugin is deleted.

== Third-party data ==

The country filter uses IP geolocation by DB-IP (https://db-ip.com), "IP to Country Lite", licensed under Creative Commons Attribution 4.0 (https://creativecommons.org/licenses/by/4.0/). It is downloaded from this plugin's GitHub releases only while the filter is on.

== Third-party service ==

Only if "Refuse passwords that appear in known data breaches" is switched on, Draco asks Have I Been Pwned (https://haveibeenpwned.com/Passwords, API at https://api.pwnedpasswords.com) with the first 5 characters of the SHA-1 of a password being chosen or used to log in. The password itself and its full hash are never sent. Terms: https://haveibeenpwned.com/API/v3#AcceptableUse · Privacy: https://haveibeenpwned.com/Privacy

== Changelog ==

= 0.1.21 =
* PrestaShop, Drupal, Joomla, Moodle and Laravel in 9 more languages besides English: Spanish (now complete), French, German, Italian, Portuguese (Brazil), Russian, Chinese (Simplified), Japanese and Arabic. One source per language (i18n/<lang>.json) feeds every package in its own format (Joomla INI, Moodle lang, PrestaShop XLIFF, Drupal .po imported by the locale module, Laravel lang), and bin/i18n-build.php check makes sure no placeholder or HTML is lost. Only complete languages ship; the other 30 languages of the WordPress version follow.

= 0.1.20 =
* CrowdSec, both ways (server edition and Docker add-on). In: Draco is a bouncer of the CrowdSec Local API, and its bans on addresses and ranges become Draco blocks (they may read, not post or log in), copied at most once a minute so no visitor waits; lifting a ban in CrowdSec lifts it in Draco, and administrators' addresses are never imported. Out: with crowdsec_log = 1 Draco writes its attempts as JSON lines, and the parser and scenario shipped in crowdsec/ turn 5 attacks in a short while into a CrowdSec ban for its other bouncers (firewall, nginx…). New command: draco crowdsec [sync].
* CI: tested against a real CrowdSec (Local API and agent).

= 0.1.19 =
* Tested in front of real applications that have no Draco plugin: MediaWiki 1.43 and TYPO3 13 run with the Docker add-on, and CI checks every change against both. The checks: the app works, log mode changes nothing for it, attacks get Draco's 403 without naming the rule, a blocked address can still read but not use the login page, a review request lets it back in, draco test answers, and draco disable gives everything back to the app.

= 0.1.18 =
* Docker: Draco Insomnis as an add-on for PHP containers (ghcr.io/fermatacordis-create/draco-insomnis). It works inside your image, with two Dockerfile lines (COPY --from and install-docker.sh, first settings from DRACO_* variables), or without rebuilding: a service fills a volume that the app mounts and loads through PHP_INI_SCAN_DIR, and upgrades keep the settings and the evidence. Works with images built on the official PHP ones (WordPress, Drupal, Joomla, MediaWiki, Nextcloud…). The draco command finds the container's PHP and reloads Apache or PHP-FPM there.
* CI: both Docker modes are tested end to end (php:8.3-apache and php:8.2-apache).

= 0.1.17 =
* Draco Insomnis Server for RHEL, AlmaLinux, Rocky and Fedora: an .rpm next to the .deb, with the SELinux label that lets PHP-FPM and Apache write their evidence folder (httpd_sys_rw_content_t) and nothing else. Tested end to end on AlmaLinux 9 with PHP 8.0 and 8.3 behind httpd.
* Fix: on a PHP without mbstring (the default on RHEL and AlmaLinux), a review request from the block page was lost. The shared engines no longer need mbstring.
* The packages name a maintainer address: draco@opnv.systems.

= 0.1.16 =
* New: Draco Insomnis Server, the firewall in front of every PHP site on a server, whatever it runs (MediaWiki, TYPO3, Magento, phpBB, Nextcloud, your own code…), without a plugin per site. It loads before every PHP script (auto_prepend_file) with the same engines as the plugins: firewall rules, block list with ranges, country filter, anti-copy pace limit, security headers and the review request on the block page. A .deb for Debian and Ubuntu and a .tar.gz with install.sh for any Linux with PHP 8.0+; the "draco" command (enable, status, set, events, evidence, block, reviews, test, cleanup); settings in /etc/draco-insomnis/draco.ini with per-site sections; evidence in SQLite, one folder per PHP user; a daily systemd timer. Off until "draco enable", the firewall starts in "log", and any error of Draco itself lets the request through.
* CI: the package is installed and tested end to end on Ubuntu 24.04 with nginx and PHP-FPM and on Ubuntu 22.04 with Apache and mod_php, then removed and purged.

= 0.1.15 =
* PrestaShop, Drupal, Joomla, Moodle and Laravel catch up with WordPress (parity 3): password rules, both off by default. A minimum length (8 to 64 characters) and refusing passwords found in known data breaches, asked to Have I Been Pwned with k-anonymity: only 5 characters of the password's SHA-1 leave the site, never the password, and if the service does not answer in 3 seconds the password is accepted. Applied when an account is created or a password is changed: Drupal (sign-up and account forms), Joomla (every user save, next to the rules in Users: Options), Moodle (through its password policy, while "Password policy" is on), PrestaShop (sign-up, "Your personal information" and the reset link) and Laravel (the DracoPassword rule or 'draco_password' in validation, with DRACO_PWD_MIN and DRACO_PWD_BREACHED).
* One shared engine for the rules (Core\Passwords).
* Still WordPress only, for a next version: the 39 languages.

= 0.1.14 =
* Security fix for every version since 0.1.9: the review form on the block page carried the name of the rule that matched (for example "sqli") in a hidden field, and the block page must never say what matched. The rule now travels sealed with the site's secret.
* PrestaShop, Drupal, Joomla, Moodle and Laravel catch up with WordPress (parity 2): a person stopped by the firewall can ask for a review from the block page (signed form, trap field, 3 a day per address, 50 a day per site; the owner gets one e-mail an hour at most and Draco never writes to the person); the owner lets them through for 24 hours, 7 days, 30 days or forever, denies, or marks an attacker. "Test the firewall" sends a harmless attack-shaped request to the site and says what happened, without logging it. A 7-day summary of what the firewall stopped. In Laravel, as Artisan commands: draco:reviews, draco:test and the summary in draco:status.
* Still WordPress only, for the next versions: password rules (0.1.15) and the 39 languages (0.1.16).

= 0.1.13 =
* PrestaShop, Drupal, Joomla, Moodle and Laravel catch up with WordPress (parity 1): country filter (same local DB-IP Lite list, downloaded when the filter is switched on and refreshed by each CMS's daily task), blocks for ranges and "Forever", a form to block an address or range by hand, and security headers. All off by default.
* One request path for every CMS (Core\Gatekeeper): exemptions, block list, country, firewall rules and pace limit in the same order everywhere.
* CI: every change is tested end to end in a fresh install of Drupal 10.3 and 11, Joomla 5 and 6, PrestaShop 8 and 9 and Moodle 4.5 and 5.3, besides WordPress and Laravel.
* Still WordPress only, for a later version: review requests from the block page, the firewall test button and summary, and password rules.

= 0.1.12 =
* Ten more languages, chosen for the countries where cheap hosting and unpatched sites are most common: Vietnamese, Bengali, Urdu, Persian, Filipino, Thai, Ukrainian, Swahili, Malay and Tamil (39 locales in all). Native speakers: corrections are very welcome.

= 0.1.11 =
* Passwords (off by default): a minimum length, and refusing passwords that appear in known data breaches. The check asks Have I Been Pwned with only the first 5 characters of the password's SHA-1 (k-anonymity, padded answer): the password never leaves the site, and if the service does not answer in 3 seconds the password is accepted. At login a breached password is not refused; the person is told on the dashboard to change it. Applied in the profile, the password reset and the WooCommerce sign-up.
* Security headers for public pages (off by default): X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy, never twice if the server or another plugin already sends one. HSTS separately, only over HTTPS, 6 months.

= 0.1.10 =
* Firewall: country filter, off by default. Refuse the countries listed or allow only those, for logging in, signing up and forms (recommended) or for the whole site, and "Log only" first. Administrators, people let through after a review, search engines verified by DNS and addresses without a country are never filtered, and a country never puts an address on the block list. The country list is DB-IP Lite (CC BY 4.0), rebuilt monthly by Draco's own GitHub workflow; the site downloads it only while the filter is on, checks its SHA-256 and looks addresses up locally, without sending them anywhere.

= 0.1.9 =
* Firewall: people it stops can ask for a review from the block page (e-mail and what they were doing). The form is signed, has a trap field and a limit per address and per day; the owner gets one notice an hour at most, and lets them through for 24 hours, 7 days, 30 days or for good, denies, or marks the address as an attacker. Draco never writes to the person who asks.
* Firewall: "Test the firewall" button. It sends a harmless attack-shaped request to the site and says whether it was blocked, only logged, or stopped earlier by the hosting. It is not logged or counted.
* Firewall: summary of the last 7 days (what it stopped and the busiest addresses).
* Block list: ranges (CIDR, no wider than /16 for IPv4 or /32 for IPv6) and "Forever". Never a range that holds an administrator's address or your own.
* For now these are in the WordPress plugin; the other CMS get them once their tests run in CI.

= 0.1.8 =
* With no "Trusted proxies" listed, the front servers of a hosting on carrier-grade NAT (100.64.0.0/10) or link-local addresses (169.254.0.0/16, fe80::/10) are trusted too, like private networks. Sites that chose X-Forwarded-For behind such a front server keep seeing the real visitor address after 0.1.7.

= 0.1.7 =
* Security: the visitor address is read from a proxy header (Cloudflare or X-Forwarded-For) only when the connection really comes from that proxy: Cloudflare's own ranges, or the new "Trusted proxies" list (empty = this server and private networks). Before, anyone could send the header straight to the site and pose as another address, even an administrator's, which is never inspected by the firewall. X-Forwarded-For is now read from the right, skipping trusted proxies, because whatever is on the left was written by the visitor. The settings screens warn when the header is being ignored. Same fix on PrestaShop, Drupal, Joomla, Moodle and Laravel (DRACO_TRUSTED_PROXIES).
* Security: every WordPress counter (two-step login codes, failed logins, account recovery, confirmation e-mails, firewall hits, anti-copy pace) now adds up in one database statement, in a new table. Requests sent at the same moment can no longer all read the same count and get more tries than allowed.
* Firewall: values encoded twice (%2527) are also inspected once decoded again.

= 0.1.6 =
* One release, one package per CMS at the same version: WordPress, PrestaShop, Drupal, Joomla, Moodle and Laravel, all on the shared engines (src/Core).
* The WordPress package is now named draco-insomnis-wordpress-<version>.zip, like the others. The plugin folder inside is still draco-insomnis, so updates keep working.

= 0.1.5 =
* When Draco is bundled inside another plugin, that plugin can place it in its own menu as a single entry (filter `draco_insomnis_menu_parent`); the module screens are reached through Draco's tabs. The standalone plugin always keeps its own menu.

= 0.1.4 =
* New look for every screen: a header with the module tabs and their state, cards, status labels, switches, mode choosers and clearer tables. Works on phones too.
* New Overview screen: what each module is doing, the numbers of the last 7 days and a checklist of what makes the biggest difference.
* The anti-bot shield moved to its own tab (admin.php?page=draco-insomnis-shield); Draco Insomnis now opens on the Overview.
* Translated into all 29 languages.

= 0.1.3 =
* New: Anti-copy. Closes anonymous reads of the content API (/wp-json/wp/v2/), with an allow list, and limits the pace of pages per minute per address and per network with a 429. Search engines verified by reverse DNS (Google, Bing, Apple, Yandex) are never limited. Off by default, with a log-only mode.
* Uninstall also removes the marks of accounts that were waiting for confirmation.

= 0.1.2 =
* Firewall: also catches a UNION SELECT of a single column (`1' union select user_pass from wp_users`), without flagging sentences like "European Union select committee".
* Firewall: its 403 page no longer triggers WordPress's "translation loaded too early" notice.
* Integration and HTTP tests in a real WordPress, run on every change (GitHub Actions).

= 0.1.1 =
* Works when bundled inside another plugin (OPNV-WP): the daily cleanup is scheduled on load, not only on activation.
* If two copies are present (standalone and bundled), only the first one runs.
* New filter `draco_insomnis_other_sender` for plugins that hand their mail over to Draco.

= 0.1.0 =
* First version: anti-bot shield for sign-ups, site mail (SMTP), and e-mail confirmation of forms, comments and new accounts, two-step login by e-mail, and firewall.
