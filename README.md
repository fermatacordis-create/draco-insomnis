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
limit. These CMSs have their own SMTP and two-step login, so those stay WordPress-only. And for
**Laravel** 11 to 13 apps, as a Composer package (`notoriusvision/draco-insomnis-laravel`), and for
**Magento** 2.4 and **Mage-OS** shops (module `DracoInsomnis_Magento`). Every
package is built from the same `src/Core`, so an improvement there reaches all of them with the next
build.

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
bin/build-zip.sh          # writes dist/draco-insomnis-wordpress-<version>.zip
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

## Magento and Mage-OS

`cms/magento` is the module `DracoInsomnis_Magento` for Magento Open Source and Adobe Commerce 2.4
and Mage-OS (`core/` is a link to `src/Core`, copied into the ZIP by `bin/build-magento.sh`). Install
it by hand (the contents of the ZIP's folder go to `app/code/DracoInsomnis/Magento`) or with Composer
from the release ZIP:

```
composer config repositories.draco '{"type": "artifact", "url": "path/to/folder-with-the-zip"}'
composer require notoriusvision/draco-insomnis-magento
bin/magento module:enable DracoInsomnis_Magento && bin/magento setup:upgrade
```

- Settings: **Stores → Configuration → Advanced → Draco Insomnis**. Every part starts off.
- **Firewall, country filter and pace limit**: the outermost plugin on the front controller, so they
  run before the built-in full page cache answers, for the storefront, the REST API and GraphQL
  (JSON bodies are inspected too). The admin panel is never inspected, and the addresses
  administrators log in from are never blocked or limited. Only HTML page loads by visitors who are
  not logged in count towards the pace limit. A cache in front (Varnish, a CDN) answers cached pages
  before Magento, so those never reach Draco. Emergency exit: `'draco_waf_off' => true` in
  `app/etc/env.php`.
- **Sign-up shield** on **Create an Account**: the trap and the page stamp go into the form (that
  page is no longer kept in the full page cache); a bot gets "The registration could not be
  completed." and no account.
- **Password rules** on every customer password: sign-up, account page, reset link, REST and GraphQL.
- **Security headers**, never replacing one the shop already sends.
- **bin/magento**: `draco:status`, `draco:evidence <ip>` (CSV for an abuse report), `draco:block`
  (`--unblock=<id>`), `draco:reviews` (requests from the block page), `draco:test` and
  `draco:cleanup` (cron runs it daily and refreshes the country list monthly).
- Shop code can change the engines' values through the `draco_insomnis_filter` event.
- Languages: `i18n/<locale>.csv` for 25 of the 27 languages, under every Magento locale of each one
  (Magento has no Tamil or Urdu locale), generated by `bin/i18n-build.php write`.

## Laravel

`cms/laravel` is a Composer package (Laravel 11, 12 and 13; `core/` is a link to `src/Core`, copied
into the ZIP by `bin/build-laravel.sh`). Install it from the release ZIP with an artifact repository:

```
composer config repositories.draco '{"type": "artifact", "url": "path/to/folder-with-the-zip"}'
composer require notoriusvision/draco-insomnis-laravel
php artisan migrate                       # draco_events and draco_blocks
php artisan vendor:publish --tag=draco-config   # optional: config/draco.php
```

- **Firewall and pace limit** switch on from `.env` (`DRACO_WAF_MODE=log`, then `block`;
  `DRACO_PACE_MODE`). A global middleware checks requests without a session before routing, so
  probes for paths like `/.env` are seen too; the same middleware at the end of the `web` and `api`
  groups checks requests with a session once the user is known. Users who pass the Gate ability in
  `DRACO_BYPASS_ABILITY` are never inspected and their addresses are never blocked. Only HTML page
  loads count towards the pace limit, never JSON API calls. `/up` is excepted (`except` in the config).
- **Sign-up shield** (`DRACO_SHIELD=true`): add `->middleware('draco.signup')` to the registration
  route and `@dracoFields` inside its form. A bot gets an ordinary validation error on the e-mail
  field (422 for JSON clients) and no account.
- **Artisan**: `draco:status`, `draco:evidence <ip>` (CSV for an abuse report), `draco:block <ip|email>`
  / `draco:block --unblock=<id>`, and `draco:cleanup` (scheduled daily by the package).
- Counters live in the app's cache store (`DRACO_CACHE_STORE`; Redis or database with several servers).
- English and Spanish messages. Emergency exit: `DRACO_WAF_OFF=true`.

## Server edition

`server/` is **Draco Insomnis Server**: the same engines loaded before every PHP script on a
Linux server (`auto_prepend_file`), so any PHP site gets the firewall, block list, country filter,
pace limit, security headers and review requests without a plugin — MediaWiki, TYPO3, Magento,
phpBB, Nextcloud or custom code. `bin/build-server.sh` makes the `.deb` (Debian, Ubuntu) and a
`.tar.gz` with `install.sh` for other Linux; `tests/e2e/server.sh` runs against nginx + PHP-FPM and
Apache + mod_php in CI. See [server/README.md](server/README.md).

## JavaScript

`js/` is the firewall, block list, country filter, anti-copy pace and security headers for
**Node.js** and **Cloudflare Workers**: TypeScript with no dependencies. It has middleware for
Express (also Directus) and Koa (also Strapi), plus a wrapper for Workers. The firewall signatures are
a port of `src/Core/WafRules.php`, and both languages run the same cases from
`tests/vectors/waf.json`, so a rule changed in one and not in the other fails CI. `bin/build-js.sh`
makes the npm tarball. CI also runs it on Node.js 20 with real Express 5 and Koa. See
[js/README.md](js/README.md).

## Python

`python/` is the same engine for **Python** 3.9 and newer, with no dependencies: an ASGI middleware
(FastAPI, Starlette, Django ASGI) and a WSGI one (Flask, Django). It has the firewall, block list,
country filter (`GeoFile`), anti-copy pace, security headers, review requests and the CrowdSec
bridge. It runs the same shared cases as PHP and JavaScript (`tests/vectors/waf.json`,
`review.json`), and CI runs the built wheel inside real FastAPI, Flask and Django.
`bin/build-python.sh` makes the wheel and the source archive. See [python/README.md](python/README.md).

## Ruby

`ruby/` is the same engine for **Ruby** 3.1 and newer, with no dependencies, as Rack middleware:
Rails, Sinatra, Hanami and Roda. It has the firewall, block list, country filter, anti-copy pace,
security headers, review requests and the CrowdSec bridge, runs the shared vectors, and CI runs the
built gem inside real Rails and Sinatra on Puma. `bin/build-ruby.sh` makes the gem. See
[ruby/README.md](ruby/README.md).

## .NET: ASP.NET Core

`dotnet/` is the same engine for **.NET** 8 and newer, with no dependencies beyond ASP.NET Core, as
middleware: `builder.Services.AddDracoInsomnis(...)` and `app.UseDracoInsomnis()` for minimal APIs, MVC,
Razor Pages and Blazor Server, with the options bound from `appsettings.json`. It has the firewall,
block list, country filter, anti-copy pace, security headers, review requests and the CrowdSec bridge,
runs the shared vectors (with PHP's byte-wise ASCII classes), and CI runs the built package inside real
Kestrel apps. `bin/build-dotnet.sh` makes the `.nupkg`. See [dotnet/README.md](dotnet/README.md).

## Java and Kotlin: Spring Boot, Servlet containers and Ktor

`java/` is the same engine for the **JVM** (Java 17 and newer), with no dependencies: a Jakarta Servlet 6
filter for Spring Boot 3 and 4 (Spring MVC), Tomcat 10.1+, Jetty 12, Undertow and any Jakarta EE 10
server, with the options bound from `application.properties` or a `web.xml`; and a **Ktor 3** plugin
for Kotlin. It has the firewall, block list, country filter, anti-copy pace, security headers, review
requests and the CrowdSec bridge, runs the shared vectors (with PHP's byte-wise ASCII classes), and CI
runs the built jars inside real Spring Boot (Tomcat) and Ktor (Netty) apps. `bin/build-java.sh` makes
the two jars. See [java/README.md](java/README.md).

## Go: Caddy, Traefik and net/http

`go/draco` is the same engine in **Go**, standard library only, and `go/caddy` the Caddy module. With
them Draco runs in the proxy in front of an app in **any language**: as a Caddy directive
(`draco_insomnis`, built with `xcaddy`), as a Traefik v3 plugin (run by Yaegi), or as `net/http`
middleware. It has the firewall, block list, country filter, anti-copy pace, security headers,
review requests and the CrowdSec bridge, runs the shared vectors, and CI runs it inside a real Caddy
and a real Traefik in front of an app. Releases tag the modules `go/draco/vX.Y.Z` and
`go/caddy/vX.Y.Z`. See [go/README.md](go/README.md).

## Static sites

Plain HTML has no code on the server to run Draco, so `static/` is a **generator**: one HTML page
(`draco-insomnis-static-X.Y.Z.html` in every release, made by `bin/build-static.sh`) that you open in
a browser. You choose where the site lives and what to switch on, and it writes the file for that
place: `.htaccess` (Apache and LiteSpeed, most shared hosting), an nginx include, Netlify `_headers`,
`vercel.json`, or a Cloudflare Worker project that puts the whole of Draco in front of the HTML.
Nothing is sent anywhere and nothing of Draco stays on the server.

On a static site there is no database to inject into, so the generator does not pretend to block SQL
injection. It refuses files that should never be public (`.git`, `.env`, backups uploaded by
mistake) and known scanners, adds security headers and a Content-Security-Policy (report-only first),
and — with the Worker — the anti-copy pace limit and review requests. The patterns are those of
`js/src/core/waf.ts` (a test checks they stay equal). CI serves a site that really holds those files
with the generated `.htaccess` on Apache 2.4 and the generated include on nginx: every probe and
scanner of `tests/vectors/waf.json` gets 403, ordinary pages 200. It also runs the page in Chromium.
Netlify and Vercel cannot refuse requests by pattern, so there it only sets headers.

## Releasing

Every release carries one package per platform with the same version, built from the same commit
(the Laravel package takes the version at build time):

```
bin/set-version.sh 0.2.0     # WordPress header, constant and Stable tag; PrestaShop, Drupal, Joomla, Moodle
# add "= 0.2.0 =" to the changelog in readme.txt, open a PR, wait for a green CI, merge
git tag v0.2.0 && git push origin v0.2.0
```

The tag starts [Release](.github/workflows/release.yml): it refuses to go on unless the tag and the
five versions agree (`bin/versions.sh --check`), runs the unit tests, builds the five ZIPs
(`bin/build-all.sh`) and publishes one GitHub release with them, their SHA-256 sums and the changelog
entry of that version.

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
Chinese, Korean, Arabic, Hindi, Indonesian, Vietnamese, Bengali, Urdu, Persian, Filipino, Thai,
Ukrainian, Swahili, Malay and Tamil (39 locales). Native-speaker corrections are welcome, especially for
the Asian, African and Middle Eastern languages.

## Principles

- Defence only: nothing is ever sent to the attacker's machine.
- One weak sign never rejects a person.
- Nothing depends on the code being secret: field names and keys are unique to each site.

## Licence

Code: GPL-2.0-or-later, see `LICENSE`. Names and logo: see `TRADEMARKS.md`.
Report vulnerabilities as described in `SECURITY.md`.
