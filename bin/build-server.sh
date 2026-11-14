#!/usr/bin/env bash
# Builds Draco Insomnis Server: dist/draco-insomnis-server_<v>_all.deb (Debian, Ubuntu) and
# dist/draco-insomnis-server-<v>.tar.gz (any Linux with PHP 8.0+, through install.sh).
set -euo pipefail
cd "$(dirname "$0")/.."
v=$(sed -n "s/^define('DRACO_SERVER_VERSION', '\([^']*\)');/\1/p" server/bin/draco)
[ -n "$v" ] || { echo "No version in server/bin/draco" >&2; exit 1; }
out="${1:-dist}"; mkdir -p "$out"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# The files under /usr/share/draco-insomnis.
share="$work/share"
mkdir -p "$share/bin" "$share/src" "$share/core"
cp server/guard.php server/autoload.php "$share/"
cp server/src/*.php "$share/src/"
cp src/Core/*.php "$share/core/"
cp server/bin/draco "$share/bin/draco"; chmod 755 "$share/bin/draco"
cp LICENSE "$share/LICENSE"
for f in "$share"/*.php "$share"/src/*.php "$share"/core/*.php "$share/bin/draco"; do php -l "$f" >/dev/null; done

# .tar.gz
t="$work/draco-insomnis-server-$v"
mkdir -p "$t/systemd"
cp -R "$share" "$t/share"
cp server/etc/draco.ini "$t/draco.ini"
cp server/packaging/install.sh "$t/install.sh"; chmod 755 "$t/install.sh"
cp server/packaging/systemd/* "$t/systemd/"
cp server/README.md "$t/README.md"
tar -C "$work" --owner=0 --group=0 -czf "$out/draco-insomnis-server-$v.tar.gz" "draco-insomnis-server-$v"

# .deb
d="$work/deb"
mkdir -p "$d/DEBIAN" "$d/usr/share/draco-insomnis" "$d/usr/bin" "$d/etc/draco-insomnis" "$d/lib/systemd/system" "$d/usr/share/doc/draco-insomnis-server"
cp -R "$share/." "$d/usr/share/draco-insomnis/"
ln -s /usr/share/draco-insomnis/bin/draco "$d/usr/bin/draco"
cp server/etc/draco.ini "$d/etc/draco-insomnis/draco.ini"
cp server/packaging/systemd/* "$d/lib/systemd/system/"
cp server/README.md "$d/usr/share/doc/draco-insomnis-server/README.md"
cp server/packaging/debian/postinst server/packaging/debian/prerm server/packaging/debian/postrm "$d/DEBIAN/"
chmod 755 "$d/DEBIAN/postinst" "$d/DEBIAN/prerm" "$d/DEBIAN/postrm"
echo /etc/draco-insomnis/draco.ini > "$d/DEBIAN/conffiles"
size=$(du -sk "$d" | cut -f1)
sed -e "s/@VERSION@/$v/" -e "s/@SIZE@/$size/" server/packaging/debian/control > "$d/DEBIAN/control"
dpkg-deb --root-owner-group --build "$d" "$out/draco-insomnis-server_${v}_all.deb" >/dev/null
echo "$out/draco-insomnis-server_${v}_all.deb"
echo "$out/draco-insomnis-server-$v.tar.gz"
