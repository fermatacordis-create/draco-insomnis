# ADR 0001 — Guardia P1 (integrity and persistence) and link-check feeds

- **Status:** accepted by the owner, 2026-11-28
- **Scope:** Draco Insomnis for WordPress (standalone and bundled in OPNV WP)
- **Inputs:** proposals from other assistants (Guardia P1 Persistence Detector, its API/RBAC/test plans, a first ADR draft), checked against the code, the terms of each feed and the owner's ten sites.

## 1. Malicious-link feeds

### Facts (checked on each provider's own pages, 2026-11-28)

| Feed | Commercial use | Key | Notes |
|---|---|---|---|
| URLhaus (abuse.ch) | Paid Spamhaus subscription | Auth-Key | Free only for not-for-profit use (terms §3.1, §4.1). |
| ThreatFox (abuse.ch) | Paid Spamhaus subscription | Auth-Key | Same terms as URLhaus; **not** free for commercial use. |
| Phishing.Database | Allowed (MIT) | None | **Rejected:** its `phishing-links-ACTIVE.txt` is 66 MB (789,054 lines) and was last changed on **2025-12-22**; it still lists 000webhost pages (service closed in 2024). Aggregates other sources; provenance not verified. |
| PhishTank (Cisco Talos) | Allowed (FAQ) | Optional (free account) | `online-valid.csv.gz`: 1.5 MB, ~42k verified phishing URLs still online, changed the same day it was checked. Downloads without a key work, limited to a few a day per server. |
| OpenPhish community | Not allowed | — | Terms forbid commercial use. |
| Google Safe Browsing | Not allowed | — | Commercial use goes through Web Risk (paid). |

### Decision

- Link checking becomes **provider-based**: each feed is a provider that says whether it may run where Draco runs.
- **Standalone Draco:** URLhaus (owner confirms non-profit or Spamhaus subscription, as today) and PhishTank.
- **Draco bundled in OPNV (commercial):** PhishTank only. URLhaus and ThreatFox stay hidden.
- Phishing.Database was in the first version of this decision and is dropped: measured on 2026-11-28, the list is almost a year old and 66 MB to download twice a day on every site.
- Only **exact links** are matched (lists contain hacked legitimate sites; whole domains would hit innocent links). Bare IP hosts match as a whole. A PhishTank entry for a site's front page (a site made for phishing) also matches the whole host, except on shared services (Google Docs, Dropbox, GitHub, link shorteners…).
- If a list has not changed for **7 days**, the screen says so: it may no longer be kept.
- Everything is downloaded and checked on the site's own server; nothing a visitor writes is sent anywhere.

## 2. Guardia P1 — integrity and persistence

### What was kept from the proposals

Look for what **comes back** after a clean-up (an administrator, a PHP file in uploads, a mu-plugin, a scheduled task) instead of malware signatures. Works without root on shared hosting.

### What was dropped from phase 1

Public REST API and custom capabilities (no consumer yet; more attack surface), «restart coordinator» (impossible on shared hosting), Trust Score (no other inputs yet), quarantine and clean-up, systemd/SSH/Docker (server phase, MiniPC/nodes), coverage ≥ 90 % plus mutation testing and maximum PHPStan (beyond Draco's current bar), «50,000 files in < 30 s» in one request (impossible on shared hosting: scans go in chunks through WP-Cron).

### Corrections made after checking the owner's sites

1. **«OPNV has no legitimate mu-plugins» is false in practice.** 6 of 10 sites have mu-plugins (Hostinger's own, All In One Security's loader, and site-specific ones). An «any mu-plugin = alert» rule would fire on day one.
2. **«PHP in uploads = suspicious» would fire on all 10 sites.** All found were benign: `index.php` guards, WPML's Twig cache, WP Hide's `environment.php`, WP All Import's `functions.php`, Mailchimp's PHP-guarded log.

Therefore the **first scan is the baseline**: what exists is accepted and listed once for review; afterwards Guardia reports what is **new** or **comes back**. In uploads, a new PHP file that does not match a known guard/cache pattern, or contains dangerous calls (`eval`, `base64_decode`, `gzinflate`, `assert`, `shell_exec`…), is reported at once.

### Model

States per watched item: `present` → `missing` → `reappeared`. A reappearance needs a recorded absence (seen by a later scan, or a WordPress removal hook such as `delete_user`, `deleted_plugin`).

Watched items: administrators (ID, login, e-mail hash, role); active plugins (slug, version); mu-plugins and drop-ins (path, SHA-256); `wp-config.php`, `.htaccess`, root `index.php` (SHA-256); PHP files in uploads; scheduled hooks that no loaded plugin, theme or core handles (WordPress stores only the hook name: «handled» is checked with `has_action()` at scan time). Core files are compared with WordPress.org's official checksums.

A plugin whose version changed is an update, not a reappearance. Many items returning in the same scan are one «restore» finding for review, not many alerts.

### Severity

| Event | Level |
|---|---|
| New administrator, new mu-plugin or drop-in, modified core file, new PHP in uploads with dangerous calls | High, at once |
| Item reappeared once | Medium |
| Twice | High |
| Three times or more | Critical |
| Many items back in one scan | One «restore» finding to review |

Alerts go to the screen, the Overview and the existing security e-mail addresses.

### Storage

Two tables created with `dbDelta` (no foreign keys, `ENUM` or `JSON` column types): **items** (type, key, fingerprint, state, first/last seen, reappearance count) and **observations** (item, state, time, short details). No separate baselines or alerts tables: the baseline is the items table after the first scan; alerts use Draco's log and mail.

### Delivery

1. Link lists per provider (PhishTank everywhere, URLhaus where allowed).
2. Guardia foundation: tables, first scan as baseline, «Integrity» screen with the review list.
3. Core checksums and uploads/mu-plugin/drop-in rules.
4. Reappearance state machine and severity.
5. Twice-daily scan in chunks, resumable; alerts by e-mail.

## 3. PHP policy

- PHP 8.1 is out of security support (2025-12-31); **8.2 ends 2026-12-31**; 8.3 ends 2027-12-31.
- **OPNV:** requires PHP 8.3 or newer from January 2027; 8.4 and 8.5 validated, 8.5 certified.
- **Draco:** keeps its current minimum (8.0) to stay installable from WordPress.org, and keeps warning in the Overview when PHP has ended or ends within 90 days (already implemented).
