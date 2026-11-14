#!/bin/sh
# Draco Insomnis inside a PHP image (mode A). Run once in your Dockerfile, as root:
#   COPY --from=ghcr.io/fermatacordis-create/draco-insomnis:latest /draco /opt/draco
#   RUN sh /opt/draco/install-docker.sh
# Optional build arguments as environment: DRACO_WAF_MODE, DRACO_PACE_MODE, DRACO_HEADERS… become
# the first settings. Keep /etc/draco-insomnis and /var/lib/draco-insomnis on volumes to keep your
# settings and the evidence when the container is replaced.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
command -v php >/dev/null 2>&1 || { echo "Draco: no php in this image." >&2; exit 1; }
php -r 'exit(PHP_VERSION_ID >= 80000 && extension_loaded("pdo_sqlite") ? 0 : 1);' || {
  echo "Draco: needs PHP 8.0+ with pdo_sqlite (official images have it; else docker-php-ext-install pdo_sqlite)." >&2; exit 1; }

mkdir -p /usr/share/draco-insomnis /etc/draco-insomnis /var/lib/draco-insomnis
cp -R "$here/share/." /usr/share/draco-insomnis/
chmod 755 /usr/share/draco-insomnis/bin/draco
ln -sf /usr/share/draco-insomnis/bin/draco /usr/local/bin/draco
[ -f /etc/draco-insomnis/draco.ini ] || cp "$here/draco.ini" /etc/draco-insomnis/draco.ini
chmod 1733 /var/lib/draco-insomnis

# Where this PHP reads extra .ini files: the official images say PHP_INI_DIR.
scan="${PHP_INI_DIR:+$PHP_INI_DIR/conf.d}"
[ -n "$scan" ] && [ -d "$scan" ] || scan=$(php --ini | sed -n 's/^Scan for additional .ini files in: *//p')
[ -n "$scan" ] && [ "$scan" != "(none)" ] || { echo "Draco: this PHP reads no conf.d; add auto_prepend_file = /usr/share/draco-insomnis/guard.php to php.ini." >&2; exit 1; }
mkdir -p "$scan"
printf '; Draco Insomnis (docker)\nauto_prepend_file = /usr/share/draco-insomnis/guard.php\n' > "$scan/99-draco-insomnis.ini"

# First settings from the build environment, e.g. ARG/ENV DRACO_WAF_MODE=block.
for key in waf_mode pace_mode anticopy_rate_ip anticopy_rate_net proxy_header trusted_proxies hosting_nets geo_mode geo_countries geo_scope geo_action headers hsts admin_ips notify lang except; do
  var="DRACO_$(echo "$key" | tr a-z A-Z)"
  eval "val=\${$var:-}"
  [ -n "$val" ] && draco set "$key" "$val" >/dev/null && echo "Draco: $key = $val"
done
rm -rf "$here"
echo "Draco Insomnis $(draco version) loaded in $scan. Inside the container: draco status"
