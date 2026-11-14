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
sudo apt install ./draco-insomnis-server_0.1.17_all.deb
sudo draco enable          # loads it in every PHP-FPM / Apache PHP and reloads them
sudo draco test https://example.com/
sudo draco set waf_mode block
```

RHEL, AlmaLinux, Rocky, Fedora: `sudo dnf install ./draco-insomnis-server-0.1.17-1.noarch.rpm`, then `sudo draco enable` (the package labels its folder for SELinux). To get the review e-mail from PHP under SELinux: `setsebool -P httpd_can_sendmail 1`.

Other Linux (PHP 8.0+ with pdo_sqlite): unpack the `.tar.gz` and run `sudo sh install.sh`, then `sudo draco enable`. Where `draco enable` finds no PHP, add `auto_prepend_file = /usr/share/draco-insomnis/guard.php` to your php.ini.

## Docker: an add-on for PHP containers

`ghcr.io/fermatacordis-create/draco-insomnis` is not an app of its own but an add-on for any container built on the official PHP images. That includes `php:*-apache` and `php:*-fpm`, and the official `wordpress`, `drupal`, `joomla`, `mediawiki`, `nextcloud` and `matomo` images.

**A. Inside your image**: two lines in your Dockerfile.

```dockerfile
FROM wordpress:php8.3-apache
COPY --from=ghcr.io/fermatacordis-create/draco-insomnis:latest /draco /opt/draco
RUN sh /opt/draco/install-docker.sh        # ENV DRACO_WAF_MODE=block etc. before it set the first settings
```

Then use `docker exec <app> draco status`, `draco set waf_mode block`, `draco reviews`… To keep the settings and the evidence when the container is replaced, put `/etc/draco-insomnis` and `/var/lib/draco-insomnis` on volumes.

**B. Without rebuilding**: a `draco` service fills a volume. The app mounts it at `/opt/draco` and adds `PHP_INI_SCAN_DIR=":/opt/draco/conf.d"`. See [docker/docker-compose.example.yml](docker/docker-compose.example.yml). The commands are `docker compose exec app php /opt/draco/share/bin/draco …`. A new image tag updates the files and keeps `draco.ini` and the evidence.

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
