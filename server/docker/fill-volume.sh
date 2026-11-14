#!/bin/sh
# Mode B: fills the shared volume (mounted here at $1, /opt/draco) with the current Draco files.
# The app container mounts the same volume at /opt/draco and sets PHP_INI_SCAN_DIR=":/opt/draco/conf.d".
# draco.ini and state/ (settings and evidence) are kept from one version to the next.
set -eu
dest="${1:-/opt/draco}"
src=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dest/conf.d" "$dest/state"
rm -rf "$dest/share.new" && cp -R "$src/share" "$dest/share.new" && rm -rf "$dest/share" && mv "$dest/share.new" "$dest/share"
chmod 755 "$dest/share/bin/draco"
printf '; Draco Insomnis (docker volume)\nauto_prepend_file = %s/share/guard.php\n' "$dest" > "$dest/conf.d/99-draco-insomnis.ini"
[ -f "$dest/draco.ini" ] || cp "$src/draco.ini" "$dest/draco.ini"
# Each PHP user of the app makes its own folder inside, like /tmp; the settings file is world-writable
# only through the draco command run as root (docker exec), so it stays root's.
chmod 1733 "$dest/state"
chmod 644 "$dest/draco.ini"
echo "Draco Insomnis $(cat "$src/VERSION") ready in $dest"
