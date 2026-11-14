#!/bin/sh
# Draco Insomnis Server — install from the .tar.gz on any Linux with PHP 8.0+ and pdo_sqlite
# (Debian and Ubuntu: prefer the .deb). Run as root from the unpacked folder:  sh install.sh
# Then: draco enable   (and later: sh install.sh --uninstall)
set -eu
SHARE=/usr/share/draco-insomnis
here=$(cd "$(dirname "$0")" && pwd)

if [ "${1:-}" = "--uninstall" ]; then
  [ -x /usr/bin/draco ] && /usr/bin/draco disable || true
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now draco-insomnis-cleanup.timer 2>/dev/null || true; fi
  rm -f /usr/bin/draco /etc/systemd/system/draco-insomnis-cleanup.service /etc/systemd/system/draco-insomnis-cleanup.timer
  rm -rf "$SHARE"
  echo "Removed. Settings (/etc/draco-insomnis) and evidence (/var/lib/draco-insomnis) were kept."
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "Run as root." >&2; exit 1; }
command -v php >/dev/null 2>&1 || { echo "PHP command line not found." >&2; exit 1; }
php -r 'exit(PHP_VERSION_ID >= 80000 && extension_loaded("pdo_sqlite") ? 0 : 1);' || { echo "Needs PHP 8.0+ with pdo_sqlite (package php-sqlite3 or php-pdo)." >&2; exit 1; }

rm -rf "$SHARE"; mkdir -p "$SHARE"
cp -R "$here/share/." "$SHARE/"
ln -sf "$SHARE/bin/draco" /usr/bin/draco
mkdir -p /etc/draco-insomnis
[ -f /etc/draco-insomnis/draco.ini ] || cp "$here/draco.ini" /etc/draco-insomnis/draco.ini
mkdir -p /var/lib/draco-insomnis && chmod 1733 /var/lib/draco-insomnis
if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd/system ]; then
  cp "$here/systemd/"draco-insomnis-cleanup.* /etc/systemd/system/
  systemctl daemon-reload && systemctl enable --now draco-insomnis-cleanup.timer >/dev/null 2>&1 || true
else
  echo "No systemd: add a daily cron line:  /usr/bin/draco cleanup"
fi
echo "Installed Draco Insomnis Server $(draco version). Next: draco enable"
