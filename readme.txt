=== Draco Insomnis ===
Contributors: opnvsole
Tags: security, anti-spam, registration, honeypot, bots
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 0.1.5
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
= Languages =

English, Spanish (Spain and all Latin American variants), Catalan, German, French, Italian, Portuguese (Portugal and Brazil), Dutch, Polish, Russian, Turkish, Japanese, Simplified Chinese, Korean, Arabic, Hindi and Indonesian. Corrections from native speakers are very welcome, especially for the Asian and Middle Eastern languages.

= Who makes it =

= Anti-copy =

Makes it harder to copy the whole site in one go, without getting in the way of visitors or search engines.

* **Content API closed to anonymous visitors.** /wp-json/wp/v2/ lists every post, page and image as JSON; reads there need a login, except the routes you keep open. Pages stay public, and other APIs (forms, shop, embeds) are untouched.
* **Pace limit.** More pages per minute than a person reads, from one address or from one network, get "429 Too many requests" until the minute ends.
* **Search engines are verified, not trusted.** Google, Bing, Apple and Yandex pass after a reverse and forward DNS check, kept for a day; a program that only borrows their name does not.
* **Log first.** Both parts have a log-only mode that shows what would be stopped.

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

== Changelog ==

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
