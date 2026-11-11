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
## Layout

- `src/Core/` — plain PHP, no WordPress: scoring (`BotScore`), network lists (`NetList`), the signed
  page stamp (`FormStamp`) and the firewall signatures (`WafRules`). Easy to test and to reuse.
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
