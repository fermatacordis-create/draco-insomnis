# Draco Insomnis

*Ab insomni custodita dracone* — guarded by the dragon that never sleeps.

Author: **Soledad Sánchez Mohamed**.

Open-source security for WordPress, made by [Notorius Vision](https://notoriusvision.com) — the team
behind [OPNV Systems](https://opnv.systems) and OPNV SOLΞ.

Version 0.1:

- **Anti-bot shield** — stops fake sign-ups without captchas: scores every public registration, feeds
  bots a fake success and keeps evidence for abuse reports.
- **Site mail (SMTP)** — sends the site's mail through a real mailbox, only after a successful test,
  with the password encrypted.
- **Forms and sign-ups** — holds contact messages, comments and new accounts until the sender
  confirms from their e-mail.
- **Two-step login** — a 6-digit code by e-mail after the right password, with trusted devices and a
  recovery e-mail (a second mailbox, like the PUK of a phone).
- **Anti-copy** — closes the bulk JSON door (/wp-json/wp/v2/) to anonymous visitors with an allow
  list, and limits pages per minute per address and network; verified search engines are never limited.
- **Firewall** — precise attack signatures and scanner probes, log-only mode first, hidden user list,
  login limits, no XML-RPC multicall.

Also for **PrestaShop** 8 and 9 (module `dracoinsomnis`), **Drupal** 10.3 and 11 (module
`draco_insomnis`), **Joomla** 5 and 6 (plugin `plg_system_dracoinsomnis`) and **Moodle** 4.5 to 5.x
(plugin `local_dracoinsomnis`): the anti-bot shield on sign-ups, the firewall and the anti-copy pace
limit. These CMSs have their own SMTP and two-step login, so those stay WordPress-only. Every package
is built from the same `src/Core`, so an improvement there reaches all of them with the next build.

## Layout

- `src/Core/` — plain PHP, no CMS. The building blocks: scoring (`BotScore`), network lists
  (`NetList`), the signed page stamp (`FormStamp`), firewall signatures (`WafRules`) and crawler
  names (`Crawler`). The engines every CMS shares: `Shield` (judging sign-ups, evidence, automatic
  blocks), `Firewall` and `Pace` (anti-copy), which only talk to the CMS through two small interfaces,
  `Host` and `EventStore`. `tests/unit/MemoryHost.php` is the reference of how an adapter must behave.
- `src/WpHost.php` — the WordPress adapter for the engines.
- `cms/prestashop/dracoinsomnis/` — the PrestaShop module: `PsHost` (adapter), `Store` (its own
  tables, also used for counters), `Front` (hooks), `Settings` and `Admin` (the configuration page).
- `cms/drupal/draco_insomnis/` — the Drupal module: `DrupalHost` (adapter), `Store`, `Guard`, a
  middleware that checks anonymous requests before the page cache, a subscriber for requests with a
  session (after authentication, so users with "Bypass the Draco Insomnis firewall" are left alone),
  the shield on `user_register_form`, and the settings form with the evidence and the block list.
- `cms/joomla/plg_system_dracoinsomnis/` — the Joomla system plugin: `JoomlaHost` (adapter; settings
  are the plugin's parameters, the secret derives from the site's own), `Store`, and the plugin class:
  firewall and pace on `onAfterInitialise`, the shield on `onAfterRoute` (before com_users creates
  the account) and `onAfterRender` (fields into `member-registration`), CSV and unblock via `com_ajax`.
- `cms/moodle/local_dracoinsomnis/` — the Moodle local plugin: `moodle_host` (adapter), `store`,
  firewall and pace on the `\core\hook\after_config` hook (only page loads count: AJAX, web services
  and files do not), the shield through `extend_signup_form` / `validate_extend_signup_form`, admin
  settings plus an evidence page, a daily cleanup task and the privacy metadata.
- `src/Firewall/` — `Waf` (inspection, user list, login limit, XML-RPC) and `Admin`.
- `src/Shield/` — the WordPress side: `Guard` (hooks into the sign-up forms), `Store` (attempts and
  blocks) and `Admin` (the settings screen and the evidence download).
- `src/Mail/` — SMTP: `Settings` (one connection, encrypted password via `Crypto`), `Transport`
  (configures WordPress's PHPMailer), `Log` and `Admin`.
- `src/Gate/` — confirmation by e-mail: `MailHold` (form mail), `CommentHold`, `RegistrationHold`,
  `Verify` (the confirm page), `Store`, `Mailer` and `Admin`. HTML mail lives in `src/Mail/Template.php`.
- `src/Login/` — two-step login: `Mfa` (the flow and the code page), `Challenge`, `TrustedDevice`,
  `Recovery` (the second mailbox) and `Admin`.
- `src/Admin/Brand.php` — the menu and the header shown on the plugin's own screens.

## Building the ZIP

```
bin/build-zip.sh          # writes dist/draco-insomnis-<version>.zip
```

The ZIP holds only what WordPress needs (no tests, Markdown files or tooling). It passes
[Plugin Check](https://wordpress.org/plugins/plugin-check/) with no errors or warnings.

```
bin/build-prestashop.sh   # writes dist/dracoinsomnis-prestashop-<version>.zip
```

The PrestaShop ZIP carries its own copy of `src/Core`, with the `_PS_VERSION_` guard PrestaShop asks
for in every PHP file, and an `index.php` in every folder. Install it from **Modules → Upload a
module**; every part starts off. Spanish translation included (`translations/es-ES`).

```
bin/build-drupal.sh       # writes dist/draco_insomnis-drupal-<version>.zip
```

The Drupal archive carries its own copy of `src/Core` in `lib/Core`. Unpack it in
`modules/custom/` and enable it (`drush en draco_insomnis`); every part starts off. Settings live in
**Configuration → System → Draco Insomnis**. Emergency exit: `$settings['draco_waf_off'] = TRUE;` in
`settings.php`.

```
bin/build-joomla.sh       # writes dist/plg_system_dracoinsomnis-joomla-<version>.zip
```

Install it from **System → Install → Extensions**, then enable **System - Draco Insomnis**; every
part starts off. English and Spanish included. Emergency exit: `define('DRACO_WAF_OFF', true);` in
`defines.php` at the site root.

```
bin/build-moodle.sh       # writes dist/local_dracoinsomnis-moodle-<version>.zip
```

Install it from **Site administration → Plugins → Install plugins** (or unpack it in `local/`
and run the upgrade); every part starts off. Settings: **Site administration → Plugins → Local
plugins → Draco Insomnis**. Moodle plugins ship English only; other languages come through Moodle's
language packs (AMOS) once the plugin is in the Moodle plugins directory. Emergency exit:
`define('DRACO_WAF_OFF', true);` in `config.php`.

## Tests

Every push and pull request runs [CI](.github/workflows/ci.yml): PHP syntax on 8.0–8.4, unit tests,
integration and HTTP tests on the latest WordPress and on 6.5 (the oldest supported), Plugin Check,
and a check that the ZIP holds no development files and matches the tag.

```
composer install
vendor/bin/phpunit                       # unit: tests/unit, plain PHP, no WordPress
```

Integration tests run inside a real, **throwaway** WordPress with the plugin installed from its ZIP.
`bin/ci-wp-setup.sh` creates it and wipes the database you give it, so never point it at a real site:

```
DB_HOST=127.0.0.1 DB_NAME=wp_test DB_USER=root DB_PASS=root bin/ci-wp-setup.sh
vendor/bin/phpunit -c phpunit-integration.xml.dist   # tests/integration: shield, gate, mail, login, firewall
php -S 127.0.0.1:8080 -t /tmp/wordpress tests/ci/router.php &
bin/ci-http-smoke.sh                     # 403 pages, confirmation link, sign-up form, login code over HTTP
```

## Hooks

| Hook | Type | What for |
| --- | --- | --- |
| `draco_insomnis_verdict` | filter | Change the shield's verdict: `($result, $endpoint, $fields, $ip)`; `$result` has `score`, `verdict` (`clean`, `doubtful`, `bot`) and `reasons`. |
| `draco_insomnis_hosting_nets` | filter | The list of data-centre networks (CIDR) that count as a weak bot sign. |
| `draco_insomnis_form_context` | filter | Name a form the gate does not recognise, so its mail waits for confirmation (`''` leaves it alone). |
| `draco_insomnis_skip_user` | filter | Return `true` to let a new account through without confirming its e-mail. |
| `draco_insomnis_skip_comment` | filter | Return `true` to let a comment through without confirming its e-mail. |
| `draco_insomnis_mfa_required` | filter | `($required, $user)`: whether this user needs the login code. |
| `draco_insomnis_other_sender` | filter | Name of another plugin sending the site's mail (Draco then stands aside), or `''` when a plugin that bundles Draco hands its mail over. |
| `draco_insomnis_rest_allow` | filter | Route prefixes of /wp/v2/ that stay open to anonymous visitors when Anti-copy closes the content API. |
| `draco_insomnis_crawler_verified` | filter | `(null, $ip, $crawler)`: return `true`/`false` to decide a crawler check yourself (tests, a local list); `null` runs the DNS check. |
| `draco_insomnis_menu_parent` | filter | Only for a copy bundled inside another plugin (`DRACO_INSOMNIS_BUNDLED`): the menu slug Draco hangs from, as one entry. The standalone plugin ignores it and keeps its own menu. |
| `draco_insomnis_mail_forgotten` | action | Fired when the SMTP connection is deleted; Draco switches the login code off here, since codes might not arrive. |

`wp-config.php` switches for emergencies: `define('DRACO_MFA_OFF', true);` and `define('DRACO_WAF_OFF', true);`.

## Translations

`languages/` holds `draco-insomnis.pot` (the template) and ready-made translations in WordPress's
`.l10n.php` format (WordPress 6.5+): Spanish (Spain and Latin America), Catalan, German, French,
Italian, Portuguese (Portugal and Brazil), Dutch, Polish, Russian, Turkish, Japanese, Simplified
Chinese, Korean, Arabic, Hindi and Indonesian. Native-speaker corrections are welcome, especially for
the Asian and Middle Eastern languages.

## Principles

- Defence only: nothing is ever sent to the attacker's machine.
- One weak sign never rejects a person.
- Nothing depends on the code being secret: field names and keys are unique to each site.

## Licence

Code: GPL-2.0-or-later, see `LICENSE`. Names and logo: see `TRADEMARKS.md`.
Report vulnerabilities as described in `SECURITY.md`.
