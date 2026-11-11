# Draco Insomnis

*Ab insomni custodita dracone* — guarded by the dragon that never sleeps.

Open-source security for WordPress, made by [Notorius Vision](https://notoriusvision.com) — the team
behind [OPNV Systems](https://opnv.systems) and OPNV SOLΞ.

Version 0.1:

- **Anti-bot shield** — stops fake sign-ups without captchas: scores every public registration, feeds
  bots a fake success and keeps evidence for abuse reports.
- **Site mail (SMTP)** — sends the site's mail through a real mailbox, only after a successful test,
  with the password encrypted.

Planned modules: firewall, two-step login by e-mail, and confirmation of forms and new accounts by
e-mail.

## Layout

- `src/Core/` — plain PHP, no WordPress: scoring (`BotScore`), network lists (`NetList`) and the signed
  page stamp (`FormStamp`). Easy to test and to reuse.
- `src/Shield/` — the WordPress side: `Guard` (hooks into the sign-up forms), `Store` (attempts and
  blocks) and `Admin` (the settings screen and the evidence download).
- `src/Mail/` — SMTP: `Settings` (one connection, encrypted password via `Crypto`), `Transport`
  (configures WordPress's PHPMailer), `Log` and `Admin`.
- `src/Admin/Brand.php` — the menu and the header shown on the plugin's own screens.

## Tests

```
composer install
vendor/bin/phpunit tests/unit
```

## Principles

- Defence only: nothing is ever sent to the attacker's machine.
- One weak sign never rejects a person.
- Nothing depends on the code being secret: field names and keys are unique to each site.

## Licence

Code: GPL-2.0-or-later, see `LICENSE`. Names and logo: see `TRADEMARKS.md`.
Report vulnerabilities as described in `SECURITY.md`.
