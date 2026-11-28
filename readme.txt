=== Draco Insomnis ===
Contributors: opnvsole
Tags: security, firewall, anti-spam, login, smtp
Requires at least: 6.5
Tested up to: 7.2
Requires PHP: 8.0
Stable tag: 0.1.45
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security for WordPress without captchas: firewall, integrity checks, spam and fake sign-up blocking, two-step login, SMTP and anti-copy.

== Description ==

Draco Insomnis brings together, in one plugin, the protections a WordPress site usually needs several plugins for. Each part is switched on separately. The firewall starts in log-only mode and anti-copy has one too, so you can see what they would stop before they stop anything.

* **Firewall**: stops requests shaped like attacks and the scanners looking for weak spots, and says what each attack was after.
* **Fake sign-ups**: spots bot registrations before the account exists, without captchas, and keeps evidence for abuse reports.
* **Forms and comments confirmed by e-mail**: spam never reaches you, because bots do not confirm.
* **Two-step login**: a stolen password alone is no longer enough.
* **Site mail (SMTP)**: login codes, forms and orders actually arrive.
* **Anti-copy**: makes it harder to copy the whole site in one go, without getting in the way of visitors or search engines.
* **Integrity**: checks core files against WordPress.org and warns when something comes back after you removed it.

Free software, made by Notorius Vision: the open-source security core of OPNV. *Ab insomni custodita dracone.*

= Fake sign-ups =

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
* **Phishing links** (optional): links in comments and contact forms are checked against PhishTank, in a copy kept on your server.

Needs working site mail: it only switches on when SMTP is set up.

= Two-step login =

After the right password, WordPress asks for a 6-digit code sent by e-mail. A stolen password alone is no longer enough.

* **For administrators by default**, or for everyone who can edit, or for every user.
* **The code is only sent after the right password**, expires in 10 minutes and allows 5 tries. Repeated failures block the address for 15 minutes.
* **Trust this device for 7 days** (optional). Changing the password or e-mail of an account revokes its trusted devices.
* **Code did not arrive?** Send it again after 30 seconds, and check the spam folder.
* **Administrator co-sign** (optional): a second approval, by another administrator's password or a one-time link to recovery e-mails 2 and 3. Emergency exit: `define('DRACO_COSIGN_OFF', true);`.
* **No lock-outs from missing mail.** It only switches on with SMTP working and switches itself off if that connection is forgotten.
* **Recovery e-mails, like the PUK of a phone.** Everyone who needs a code keeps up to three other mailboxes, added one at a time and each confirmed with a code; the screen shows the three slots in order, with their state. The last one cannot be removed while the code is required. The code screen can send the code there instead; "Lost your password?" accepts it too; after a password reset the next code goes only there. Changing it needs a code from the new address and one from the current one, and every change is told to the other mailbox. Administrators set it up before using the dashboard.
* **Emergency exit for the owner:** `define('DRACO_MFA_OFF', true);` in wp-config.php. Only someone with access to the server can use it, unlike a "skip" button a thief could press.

= Firewall =

Stops requests with the shape of an attack, and the scanners that look for weak spots.

* **Precise signatures, not word lists.** Database injection, reading server files, running code and scripts in links are matched by their shape, so ordinary messages with words like "select", "update" or "delete" go through.
* **Scanners and probes.** Tools such as sqlmap, WPScan or Nikto, and requests for .env, .git, wp-config backups, phpinfo or known web shells.
* **Files that must never be public.** phpMyAdmin, logs such as error_log and debug.log, and backup or editor copies (.bak, .old, .orig, .swp), when the request reaches WordPress. update.php is never refused. Files that run without WordPress, such as wp-admin/install.php, are out of reach of any plugin: refuse them in the web server.
* **Starts in log-only mode**, so you can see what it would stop before it stops anything.
* **Says what each attack was after**: backups, logs, server information pages, database tools, known exploits or back doors, with the name of well-known attacks (PHPUnit CVE-2017-9841, PHP-CGI, SPIP). Your own tests from an administrator's address are marked and left out of the summary.
* **Automatic blocks**: five attacks in 10 minutes put the address on the block list for 7 days. Blocked addresses can still read the site, but not log in, post forms or use XML-RPC.
* **Hides the list of user names** from anonymous visitors (?author=1 and the users REST endpoint).
* **Limits failed logins** and always refuses XML-RPC system.multicall (hundreds of passwords in one call) and pingbacks.
* **Hide versions** (optional): public pages stop saying which WordPress, theme and plugins they run. The generator tags go, and "?ver=" of styles and scripts becomes a code that still changes on every update. It makes the site harder to list for robots looking for old versions; it does not fix anything, so keep everything updated.
* **security.txt** (optional): publishes /.well-known/security.txt (RFC 9116) with the contact you choose, so whoever finds a weakness knows how to tell you. Its expiry date renews itself.
* **Never inspects people who can edit the site** and never blocks an address an administrator used recently. Emergency exit: `define('DRACO_WAF_OFF', true);` in wp-config.php.

The Overview screen shows every module at a glance, with a checklist of what makes the biggest difference. It also says whether the PHP version of the site still gets security updates from php.net, and warns 90 days before they end.

= Anti-copy =

Makes it harder to copy the whole site in one go, without getting in the way of visitors or search engines.

* **Content API closed to anonymous visitors.** /wp-json/wp/v2/ lists every post, page and image as JSON; reads there need a login, except the routes you keep open. Pages stay public, and other APIs (forms, shop, embeds) are untouched.
* **Pace limit.** More pages per minute than a person reads, from one address or from one network, get "429 Too many requests" until the minute ends.
* **Search engines are verified, not trusted.** Google, Bing, Apple and Yandex pass after a reverse and forward DNS check, kept for a day; a program that only borrows their name does not.
* **Log first.** Both parts have a log-only mode that shows what would be stopped. The log says what kind of route was asked for (content, search or user accounts), what the visitor got (401, 200…) and with which browser.

= Integrity (Guardia) =

Shows what an intruder changed to stay, and what comes back after you removed it. It only looks: it never changes or deletes anything.

* **Core files against the WordPress.org checksums**: a modified core file, or PHP in wp-admin, wp-includes or the root that WordPress does not ship, is high from the first scan.
* **Also watched**: administrators, plugins, must-use plugins, drop-ins, wp-config.php, .htaccess, PHP in uploads and scheduled tasks without code.
* **Known vulnerabilities** (optional): installed plugins, themes and WordPress checked against Wordfence Intelligence (through OPNV) or WPVulnerability.
* **Baseline first**, reviewed once; then only what is new, changes or comes back. Each return raises the level.
* **By itself twice a day**, a few seconds at a time so the site does not slow down, and an **e-mail** when it finds something medium or worse (both optional).

== Installation ==

1. Install and activate the plugin.
2. Open **Draco Insomnis → Anti-bot shield** and tick **Protect sign-ups**.
3. Open **Draco Insomnis → Site mail (SMTP)**: connect your mailbox, send a test, then switch it on.
4. Open **Draco Insomnis → Forms and sign-ups** and tick **Verify contact forms and sign-ups**.
5. Open **Draco Insomnis → Two-step login** and tick **Ask for a code by e-mail after the password**.
6. Open **Draco Insomnis → Firewall**, switch it on in **Log only**, and move to **Block** after a few days.
7. Open **Draco Insomnis → Integrity**, take the baseline and review the list once.
8. If the site is behind Cloudflare or another proxy, the **Anti-bot shield** screen detects it and offers the right **Visitor address** setting with one button; check that "Your address as the plugin sees it" shows your real address.

== Screenshots ==

1. Overview — bots stopped, forms checked, firewall and modules at a glance.
2. Anti-bot shield — protect sign-ups without captchas; evidence for abuse reports.
3. Site mail (SMTP) — real mailbox, encrypted password, DMARC-friendly sender.
4. Two-step login — e-mail codes after the password, recovery e-mail, trusted devices.
5. Firewall — log-only or block; attack signatures without word-list false positives.

== Frequently Asked Questions ==

= Which languages? =

English, Spanish (Spain and all Latin American variants), Catalan, German, French, Italian, Portuguese (Portugal and Brazil), Dutch, Polish, Russian, Turkish, Japanese, Simplified Chinese, Korean, Arabic, Hindi, Indonesian, Vietnamese, Bengali, Urdu, Persian, Filipino, Thai, Ukrainian, Swahili, Malay and Tamil. Corrections from native speakers are very welcome, especially for the Asian, African and Middle Eastern languages.

= Who makes it? =

Draco Insomnis is made by [Notorius Vision](https://notoriusvision.com), the team behind [OPNV Systems](https://opnv.systems) and OPNV SOLΞ. It is the open-source security core of OPNV.

The code is free software (GPLv2 or later). The names Draco Insomnis, Notorius Vision, OPNV, OPNV Systems and OPNV SOLΞ, and the dragon logo, are not part of that licence: if you publish a modified version, please give it another name and logo.

= Will real people be rejected? =

Only if they send a sign that people never send, such as a role the form does not offer or a value in the invisible trap field. People with JavaScript turned off or on a VPN are only marked "doubtful" and go through.

= Does it slow the site down? =

Only bots wait, for at most three seconds, and at most ten slow answers per minute across the whole site.

= What does it store? =

For suspicious attempts only: date, address, browser name, username, e-mail, requested role and referring page. Never passwords. Everything is deleted after 90 days, and all of it is removed when the plugin is deleted.

Guardia keeps, in two tables of its own, the list of what it watches and what each scan found: names, paths, versions and fingerprints (a hash of each file, and of each administrator's e-mail), never the content of files. It is removed when the plugin is deleted.

== External services ==

Draco works on the site itself. It contacts an outside service only for the features below, all of them off by default or started by an administrator, and always through the WordPress HTTP API.

= Country list (GitHub) =

What and why: the country filter needs a list of which country each IP address belongs to. Draco downloads it from this plugin's GitHub releases (https://github.com/fermatacordis-create/draco-insomnis/releases) together with its SHA-256 checksum, and looks addresses up in that local copy.

When: only while the country filter is switched on, when the list is missing or older than 35 days.

Data sent: nothing but an ordinary download request (the server's IP address and WordPress's usual user agent, which includes the site's address). No visitor data is sent.

Service: GitHub, Inc. Terms of service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service · Privacy statement: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement

Data licence: "IP to Country Lite" by DB-IP (https://db-ip.com), Creative Commons Attribution 4.0 (https://creativecommons.org/licenses/by/4.0/).

= Breached passwords (Have I Been Pwned) =

What and why: to refuse passwords that appear in known data breaches.

When: only if "Refuse passwords that appear in known data breaches" is switched on, when a password is chosen (profile, password reset, WooCommerce sign-up) and when someone logs in.

Data sent: the first 5 characters of the SHA-1 hash of that password (k-anonymity). The password itself and its full hash are never sent.

Service: Pwned Passwords, by Have I Been Pwned (https://haveibeenpwned.com/Passwords, API at https://api.pwnedpasswords.com). Terms of use: https://haveibeenpwned.com/TermsOfUse · Acceptable use: https://haveibeenpwned.com/API/v3#AcceptableUse · Privacy policy: https://haveibeenpwned.com/Privacy

= Malicious links (URLhaus, by abuse.ch) =

What and why: to check the links in comments and contact forms against URLhaus, the list of malware distribution sites.

When: only if the administrator adds their own abuse.ch key to wp-config.php, confirms that the site is non-profit or has a Spamhaus subscription, and switches it on. The list is then downloaded twice a day. Not available when Draco is bundled in another product.

Data sent: the administrator's key, to download the list. Nothing visitors write is sent: links are looked up in the local copy.

Free use only for non-profit websites; for commercial use, a Spamhaus subscription (https://www.spamhaus.com/data-access/abusech-api/).

Service: abuse.ch, with Spamhaus Technology Limited. Terms of use: https://abuse.ch/terms-of-use/ · Privacy policy: https://abuse.ch/privacy-policy/

= Phishing links (PhishTank) =

What and why: links in comments and contact forms are checked against PhishTank's list of verified phishing pages.

When: only if switched on in Forms and sign-ups; the list is then downloaded twice a day from data.phishtank.com.

Data sent: a download request, with the administrator's optional key (DRACO_PHISHTANK_KEY in wp-config.php). Nothing visitors write is sent. Commercial use is allowed.

Service: PhishTank, by Cisco Talos. FAQ: https://phishtank.org/faq.php · Terms: https://www.cisco.com/c/en/us/about/legal/cloud-and-software/end_user_license_agreement.html · Privacy: https://www.cisco.com/c/en/us/about/legal/privacy-full.html

= WordPress core checksums (WordPress.org) =

What and why: Integrity compares core files with the official checksums of the installed version.

When: at the first scan after each WordPress update, once per version and language (then kept in uploads).

Data sent: the WordPress version and language, to https://api.wordpress.org/core/checksums/1.0/. Nothing about the site's files or users.

Service: WordPress.org. Privacy policy: https://wordpress.org/about/privacy/

= Known vulnerabilities (Wordfence Intelligence through OPNV, or WPVulnerability) =

What and why: Integrity checks installed plugins, themes and WordPress against known vulnerabilities. Only if switched on; twice a day.

OPNV (default inside OPNV): the whole list is downloaded from https://api.opnv.systems/intel/wordfence/ and searched on the site; nothing about the site is sent. Data: Wordfence Intelligence, Defiant Inc. (https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/), shown with its notices. Privacy: https://opnv.systems/politica-de-privacidad-draco-insomnis/

WPVulnerability: the slugs of installed plugins and themes and the WordPress version are sent. Data CC0: https://www.wpvulnerability.com/license/

= Site mail (SMTP) =

What and why: so the site's e-mail is delivered through a real mailbox.

When: only if the administrator sets up Site mail and it passes a test.

Data sent: the e-mails the site sends (recipients, subject and content) and the SMTP user name and password the administrator saved go to the one mail server the administrator chooses, usually their hosting or mail provider, over SMTP with TLS.

The list of common providers on that screen only fills in the form: nothing is downloaded and no provider is contacted unless saved as the mail server.

Service: the mail provider the administrator has an account with, under the terms and privacy policy the administrator accepted with that provider. Draco has no agreement with any of them.

== Changelog ==

= 0.1.45 =
* Integrity — a PHP file in the root, wp-admin or wp-includes that holds no real code (static HTML such as a hosting's default page, an emptied leftover, Wordfence's firewall loader) is listed as a note, not an alarm. Anything with real code stays high.
* Integrity — a scheduled task that no code handles cannot run anything: a note, never an e-mail.
* Interface — the «Changes saved» notice appears in the middle of the screen, also on phones.

= 0.1.44 =
* Integrity — known vulnerabilities (optional, off by default): installed plugins (also inactive ones), themes and WordPress checked twice a day, with level, CVE, link and the version that fixes each one; new high or critical ones by e-mail. Plugins closed on WordPress.org are listed too.
* Integrity — two sources: Wordfence Intelligence through OPNV (the whole list is downloaded and searched on the site: nothing about the site is sent; default inside OPNV) or WPVulnerability (asked one plugin at a time; default in the standalone plugin). WordPress gets the fix of its own branch.

= 0.1.43 =
* Integrity (new) — Guardia compares WordPress core files with the official checksums from WordPress.org and watches administrators, plugins, must-use plugins, drop-ins, configuration files, PHP in uploads and scheduled tasks without code. The first scan is a baseline you review once; afterwards it shows what is new, changes or comes back after being removed, with a level that rises on each return. It only looks, never changes anything.
* Integrity — scans by itself twice a day, reading files a few seconds at a time, and sends an e-mail when it finds something medium or worse (both optional, on by default). A card in the Overview.
* Two-step login — "Send the code again" after 30 seconds, and a reminder to look in the spam folder.
* Two-step login — administrator co-sign can be approved from recovery e-mails 2 and 3 with a one-time link, without a second administrator account. It cannot be switched on while nobody could approve your next login.
* Forms — links in comments and contact forms checked against PhishTank (optional), also when Draco is bundled in OPNV. URLhaus stays in the standalone plugin.
* Anti-bot shield — detects whether Cloudflare or another proxy sits in front of the site and offers the right "Visitor address" setting with one button.
* Firewall — fixed: the security.txt contact and policy were not saved on the first try when other settings changed too; a wrong value is now kept and explained.
* Screens — "Changes saved" is a floating notice, and the lists of recent attacks read without a horizontal scroll bar (cards on narrow screens).
* Translations — the new texts in all 39 languages.

= 0.1.42 =
* Firewall — the list of recent attacks says what each one was after (configuration and keys, backup copies, logs, server information pages, database tools, installers, known exploits, back doors) and names well-known attacks such as PHPUnit CVE-2017-9841, PHP-CGI or SPIP. It also shows the answer the visitor got and the whole browser string.
* Firewall — rows from an administrator's address, such as your own tests, are marked, cannot be reported and do not count in the 7-day summary.
* Evidence — the CSV for abuse reports has two new columns: what the attack was after and the known attack's name.
* Translations — the new texts in all 39 languages.

= 0.1.41 =
* Firewall — "Hide versions" (off by default): takes the generator tags out of pages and feeds, and turns "?ver=" of styles and scripts into a code that still changes on every update, on public pages only.
* Firewall — "Publish /.well-known/security.txt" (off by default), with the contact you choose; its expiry date renews itself. Only when WordPress is at the root of the domain.
* Anti-copy — the log shows the answer the visitor got, the kind of route (content, search, user accounts) and the whole browser string. In log-only mode the event is written after WordPress answered.
* Server edition — "draco audit" warns before it starts that a firewall may block the address that runs it, and stops and says BLOCKED if that happens.
* Translations — the new texts in all 39 languages.

Full history: [CHANGELOG.md](https://github.com/fermatacordis-create/draco-insomnis/blob/main/CHANGELOG.md).
