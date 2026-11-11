# Draco Insomnis

*Ab insomni custodita dracone* — guarded by the dragon that never sleeps.

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

## Tests

```
composer install
vendor/bin/phpunit tests/unit
```

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
