# Draco Insomnis Server

The Draco Insomnis firewall in front of **every PHP site on a server**, whatever it runs: WordPress, Drupal, Joomla, Moodle, PrestaShop, MediaWiki, TYPO3, Magento, phpBB, Nextcloud or your own code. It loads before every PHP script through `auto_prepend_file`, so no site needs a plugin.

What it does, with the same engines as the CMS plugins:

- **Firewall:** SQL injection, file inclusion, path traversal and scanner rules. Starts in `log`; switch to `block` when the log looks right.
- **Block list:** addresses and ranges, for days or forever. A blocked address may still read the site, but cannot post or use the login and sign-up pages. Five attacks in 10 minutes block an address automatically.
- **Country filter** (off by default): DB-IP Lite (CC BY 4.0), downloaded once and refreshed monthly. Looked up on your own server, so no address is sent anywhere.
- **Anti-copy pace limit** (off by default) for pages a person reads. Your own addresses and search engines verified by DNS are never limited.
- **Security headers** (off by default). It never sends a header the application already sends.
- **Review requests:** the block page lets a person explain what they were doing. You decide with `draco reviews`.

It does not judge sign-up forms: each application has its own. The CMS plugins do that, and they can run on the same server.

## Install (Debian 11+, Ubuntu 22.04+)

```sh
sudo apt install ./draco-insomnis-server_0.1.16_all.deb
sudo draco enable          # loads it in every PHP-FPM / Apache PHP and reloads them
sudo draco test https://example.com/
sudo draco set waf_mode block
```

Other Linux (PHP 8.0+ with pdo_sqlite): unpack the `.tar.gz` and run `sudo sh install.sh`, then `sudo draco enable`. Where `draco enable` finds no PHP, add `auto_prepend_file = /usr/share/draco-insomnis/guard.php` to your php.ini.

## Everyday commands

```text
draco status                 what is on, and what was stopped in 7 days, per PHP user
draco events | blocks        last attempts | blocks in force
draco evidence <ip>          everything from one address, for an abuse report
draco block <ip|range> [7|15|30|90|0] [reason]      draco unblock <id>
draco reviews [<id> --approve=1|7|30|0 | --deny | --attacker]
draco set <key> <value> [--site=example.com]          draco get [key]
draco disable                stop loading it (the package also does this on removal)
```

Settings live in `/etc/draco-insomnis/draco.ini`. A `[site:example.com]` section overrides them for one site and its subdomains.

## How it keeps sites safe

- **Fails open.** Any error of Draco itself goes to the PHP log, and the request continues.
- **Nothing on the command line.** Cron jobs and CLI scripts are never touched.
- **Separate evidence per PHP user.** Each PHP-FPM pool user writes only its own folder, `/var/lib/draco-insomnis/u<uid>` (mode 0700), with its own secret. One site cannot read another's evidence.
- **Your own `auto_prepend_file` wins.** A site that sets one in `.user.ini` or `.htaccess` (for example, another firewall) replaces Draco there.
- **No passwords stored.** Evidence is kept for 90 days. The daily systemd timer (`draco cleanup`) removes older rows.
