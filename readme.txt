=== Draco Insomnis ===
Contributors: opnvsole
Tags: security, anti-spam, registration, honeypot, bots
Requires at least: 6.5
Tested up to: 7.2
Requires PHP: 8.0
Stable tag: 0.1.42
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

== Screenshots ==

1. Overview — bots stopped, forms checked, firewall and modules at a glance.
2. Anti-bot shield — protect sign-ups without captchas; evidence for abuse reports.
3. Site mail (SMTP) — real mailbox, encrypted password, DMARC-friendly sender.
4. Two-step login — e-mail codes after the password, recovery e-mail, trusted devices.
5. Firewall — log-only or block; attack signatures without word-list false positives.

== Frequently Asked Questions ==

= Will real people be rejected? =

Only if they send a sign that people never send, such as a role the form does not offer or a value in the invisible trap field. People with JavaScript turned off or on a VPN are only marked "doubtful" and go through.

= Does it slow the site down? =

Only bots wait, for at most three seconds, and at most ten slow answers per minute across the whole site.

= What does it store? =

For suspicious attempts only: date, address, browser name, username, e-mail, requested role and referring page. Never passwords. Everything is deleted after 90 days, and all of it is removed when the plugin is deleted.

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

= Site mail (SMTP) =

What and why: so the site's e-mail is delivered through a real mailbox.

When: only if the administrator sets up Site mail and it passes a test.

Data sent: the e-mails the site sends (recipients, subject and content) and the SMTP user name and password the administrator saved go to the one mail server the administrator chooses, usually their hosting or mail provider, over SMTP with TLS.

The settings screen offers a list of common providers (for example Amazon SES, Google Workspace, Microsoft 365, Brevo or the administrator's hosting company). Choosing one only fills in the server name and port in the form: the list is part of the plugin, nothing is downloaded, Draco calls no provider API and connects to no server in the list unless the administrator saves it as their own mail server.

Service: the mail provider the administrator has an account with, under the terms and privacy policy the administrator accepted with that provider. Draco has no agreement with any of them.

== Changelog ==

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

= 0.1.40 =
* Firewall — also refuses the installers of a site that is already installed (Drupal and WordPress), phpMyAdmin, logs such as error_log and debug.log, and backup or editor copies (.bak, .old, .orig, .swp). update.php is never refused. Prompted by the Drupal installer flaws exploited in November 2026 (SA-CORE-2026-017 and 019).

= 0.1.39 =
* Site mail — fixed: opening the screen with the server of a known provider put that provider's port and encryption in the form instead of the saved ones; saving then switched SMTP off. They are now filled in only when you choose a provider.
* Site mail — the server, username and sender name fields look like the others.

= 0.1.38 =
* Recovery e-mails — the screen always shows the three slots in order, with their state; a change under way asks for its code inside its own slot. Its tab has a light: green with three addresses, amber with some, grey with none.
* Recovery e-mails — fixed: the last address could be removed while the login code was required. It now stays.
* Overview — the checklist says whether the PHP version of the site still gets security updates, and warns 90 days before they end. Tested with PHP 8.5.
* Translations — the new texts in all 39 languages; curly quotes in Spanish.

= 0.1.37 =
* Translations — every screen added since 0.1.27 (co-signature, trusted devices, recovery e-mails, malicious links, mail provider notes, block list) is now translated in all 39 languages. The Latin American Spanish translations had fallen behind and now match Spanish (Spain).
* Mail — the countries in the provider list are written in English in the code, so each language can translate them on translate.wordpress.org.

= 0.1.36 =
* Forms — forms that Draco does not build can use its shield: draco_insomnis_form_fields() prints the hidden stamp and trap fields, and draco_insomnis_form_check() returns false when the shield judges the sender a bot. Callers check function_exists() first, as older versions do not have them.
* Forms — new filter draco_insomnis_form_held: after its wp_mail(), such a form learns whether the message waits for the sender to confirm, so it can say "check your e-mail". New action draco_insomnis_form_released, with the context, the mail's header lines and the id, when the sender confirmed and the held mail was delivered.

= 0.1.35 =
* Login — a second administrator's co-signature now belongs to the one login attempt that was co-signed (a secret cookie of that browser, bound to its address and browser), not to the account: another login with the same password must be co-signed on its own.
* Login — the co-signature and the e-mail code run after every other login check (WordPress core, lockout and security plugins, Draco's firewall), on WordPress's authenticate filter, and the session is opened with WordPress's own functions and the wp_login action.
* Forms — the response buffer used to replace the success text of Divi, RealHomes and Elementor is always closed at the end of the request, also when another component left a buffer open on top of it.
* Abuse reports — Draco no longer looks up the abuse contact on rdap.org: the administrator writes the address. The abuse report screen contacts no outside service.
* Readme — "Site mail (SMTP)" explains that the provider list only fills in the form and that Draco calls no provider by itself.

= 0.1.34 =
* WordPress — changes asked by the WordPress.org plugin review: one "External services" section in this readme (what each service is, when it is called, what is sent, terms and privacy links); rdap.org is only asked when the administrator presses "Find the abuse contact"; mail held for verification no longer writes attachments to disk; inputs read from the request are sanitised; the output buffer is closed; tables are only marked as created once they exist.
* WordPress — optional URLhaus check (abuse.ch) for links in comments and forms, off by default, with the owner's own key. Free use only for non-profit websites; for commercial use, a Spamhaus subscription.
* Firewall — values past the per-request limit or nested too deep are no longer skipped: they are joined and scanned.
* The WordPress ZIP no longer carries the engine files only the other CMS editions use.

= 0.1.33 =
* WordPress — co-signature by a second administrator (optional, under Two-step login): after the right password, another administrator approves the login before the e-mail code. The session is always the first administrator's; the second one never gets a session. Service accounts and application passwords cannot co-sign, and every approval is one-shot and expires.
* WordPress — up to three recovery e-mails per account (the old single address moves over by itself), and one auth_id that links the co-signature, the code and the session in the evidence. A trusted device skips only the e-mail code, never the co-signature.
* WordPress — Site mail: choose the provider by country, with presets built from each provider's own help pages. Forms and Site mail can clear their recent lists and unblock addresses from the same screen.
* WordPress — optional microphone=(self) in the security headers, only for the site's own voice commands of OPNV-WP (off by default; embeds still cannot use the microphone).
* Amharic and Uzbek in every CMS: 29 languages.
* "Made in Menorca." in the footer of every Draco screen.
* docs/identity/: the policy for administrator identities, the design of the health checks (verification on demand, with a code) and the certification of the identity layer, tied to its commit and CI run.

= 0.1.32 =
* Java and Kotlin: Draco as a Jakarta Servlet filter for Spring Boot 3 and 4, Tomcat, Jetty, Undertow and Jakarta EE servers (settings from application.properties, web.xml or DRACO_INSOMNIS_* variables), and as a Ktor 3 plugin, with no dependencies: firewall, block list, country filter, anti-copy pace, security headers, review requests and CrowdSec. Run inside real Spring Boot (Tomcat) and Ktor (Netty) apps. The two jars are in the release.
* Rust: Draco as a tower layer for axum and as actix-web middleware, with the same features, run inside real axum and actix-web servers. The crate is in the release.
* Both match byte-wise like PHP, check the same shared test cases and use the same store keys as every other edition. All packages are in the signed checksums, the build provenance and the SBOM.

= 0.1.31 =
* Go: Draco as a Caddy module (xcaddy build --with github.com/fermatacordis-create/draco-insomnis/go/caddy@v0.1.31, directive draco_insomnis), a Traefik plugin and net/http middleware, on the standard library only: firewall, block list, country filter, anti-copy pace, security headers, review requests and CrowdSec. Tested inside real Caddy and Traefik 3.6.
* Ruby: Draco as Rack middleware for Rails, Sinatra, Hanami and Roda, with no dependencies, the same features, run inside real Rails and Sinatra on Puma. The gem is in the release.
* .NET: Draco as ASP.NET Core middleware (minimal APIs, MVC, Razor Pages, Blazor Server; .NET 8 or newer), with no dependencies beyond ASP.NET Core, options from appsettings.json, the same features, run inside real Kestrel apps. The NuGet package is in the release.
* Every new edition checks the same shared test cases as PHP, matches byte-wise like PHP, and uses the same store keys, so one Redis can serve apps in several languages. All packages are in the signed checksums, the build provenance and the SBOM.

= 0.1.30 =
* Python: Draco for FastAPI, Starlette, Flask and Django (ASGI and WSGI middleware), with no dependencies: firewall, block list, country filter, anti-copy pace, security headers, review requests and CrowdSec, checked against the same shared test cases as PHP and JavaScript and run inside real FastAPI, Flask and Django. Wheel and source archive in the release; on PyPI as draco-insomnis once a maintainer approves it.
* Static sites: draco-insomnis-static-0.1.30.html, one page that writes, in your browser, the .htaccess (Apache and LiteSpeed), nginx include, Netlify or Vercel headers, or a Cloudflare Worker for a site of plain HTML. It refuses files that should never be public (.git, .env, backups) and known scanners, adds security headers and a Content-Security-Policy. Tested on Apache 2.4, nginx and Hostinger's LiteSpeed, where it also stopped two probes the CDN let through (PHPUnit eval-stdin.php and a web shell name).
* WordPress: the settings pages use the full width, and the panels of Two-step login share one row.

= 0.1.29 =
* JavaScript (Node.js and Cloudflare Workers) now does what the PHP editions do:
  - "This is a mistake": with review: { secret, onRequest }, the 403 page carries the signed review form; the request reaches onRequest. Same signatures, limits and trap as PHP, checked with shared test cases.
  - The visitor's country without Cloudflare: new GeoFile from draco-insomnis/geo reads the same monthly country list as the PHP editions (DB-IP Lite, CC BY 4.0), locally, and keeps it fresh.
  - CrowdSec both ways: with crowdsec: { url, apiKey } the bans of your own CrowdSec join the block list in the background, at most once a minute; crowdsecLine() writes evidence lines for the CrowdSec parser in server/crowdsec.

= 0.1.28 =
* Magento 2.4 and Mage-OS: the module DracoInsomnis_Magento (draco-insomnis-magento-0.1.28.zip, by hand in app/code or with Composer). Firewall, block list, country filter and anti-copy pace limit before the full page cache, for the storefront, the REST API and GraphQL (JSON bodies inspected too); the admin panel is never inspected. Anti-bot shield on "Create an Account", password rules on every customer password (also through the API), security headers, review requests from the block page, and bin/magento draco:status, draco:evidence, draco:block, draco:reviews, draco:test and draco:cleanup. Settings in Stores > Configuration > Advanced > Draco Insomnis; everything starts off. In 25 languages (Magento has no Tamil or Urdu).
* A full SBOM (CycloneDX 1.6) with every release: every package with its SHA-256 and SHA-512 and package URL, the shared engines file by file, the Docker image by digest and its base, the country data, and every outside service Draco can talk to, when and what it sends. Validated against the schema and attested by GitHub.

= 0.1.27 =
* Accounts that can change the site (WordPress, off by default, under Two-step login). Administrators, editors and shop managers only work once the owner approved them: an account created by an attack, by a vulnerable plugin or straight in the database cannot log in, through the login form, cookies, application passwords or XML-RPC. If the site e-mail, its address, the default role or open registration change without an approved administrator, every privileged account is paused and the owner gets a one-time link (24 hours) at the e-mail kept when the lock was switched on. Emergency exit for whoever has the server: define('DRACO_LOCK_OFF', true); in wp-config.php. Not on multisite yet.
* The abuse report screens (0.1.25) and the new lock are translated into the 27 languages.
* JavaScript: draco-insomnis is on npm (npm install draco-insomnis). From this version on, each release stages it on npm from GitHub Actions without any stored token, and a maintainer approves it there with two-factor authentication.

= 0.1.26 =
* Draco for JavaScript: the firewall, block list, country filter, anti-copy pace and security headers for Node.js and Cloudflare Workers, in a package with no dependencies (draco-insomnis-js-0.1.26.tgz in the release, signed like the others). Middleware for Express (also Directus) and Koa (also Strapi), and a wrapper for Workers with Workers KV. The signatures are the same as in PHP: both languages run the same test cases. Not yet in JavaScript: the review request on the block page, the country without Cloudflare, and CrowdSec.

= 0.1.25 =
* Abuse reports, always reviewed by a person. From "Evidence" there is now "Report": Draco finds the abuse contact of the network that owns the address in the public registry (RDAP, through rdap.org, for ARIN, RIPE NCC, APNIC, LACNIC and AFRINIC) and writes a factual draft in English with the evidence (UTC times, what was attempted, the program's name). The administrator reads it, edits it and sends it; replies go to the administrator e-mail. At most 5 a day and one per address every 30 days, and every report sent is listed. The draft reminds the network that the machine is probably compromised: nothing is ever sent to the attacker. Server edition: draco report <ip> prints the draft and sends it only with --send.

= 0.1.24 =
* Supply chain: every release is now signed with Sigstore by GitHub Actions (keyless, nothing stored), each package has a GitHub build provenance attestation, the release carries a CycloneDX SBOM, and the Docker add-on image is signed too. SECURITY.md explains how to verify a download.

= 0.1.23 =
* PrestaShop, Drupal, Joomla, Moodle and Laravel in the last 8 languages of the WordPress version: Bengali, Persian, Malay, Swahili, Tamil, Thai, Tagalog and Urdu. All 27 languages now ship for every CMS (28 with English; the Spanish variants of WordPress share one Spanish).

= 0.1.22 =
* PrestaShop, Drupal, Joomla, Moodle and Laravel in 10 more languages: Dutch, Portuguese (Portugal), Catalan, Polish, Turkish, Indonesian, Ukrainian, Vietnamese, Korean and Hindi (20 with English). The last 8 of the WordPress version follow.

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
