#!/usr/bin/env bash
# Builds the Moodle plugin ZIP (folder "dracoinsomnis", for local/): cms/moodle/local_dracoinsomnis plus
# the shared engines in engine/Core, with the MOODLE_INTERNAL guard after the namespace.
# Usage: bin/build-moodle.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
src=cms/moodle/local_dracoinsomnis
version=$(sed -n "s/^\$plugin->release = '\([0-9.]*\)';.*/\1/p" "$src/version.php")
[ -n "$version" ] || { echo "No release in $src/version.php" >&2; exit 1; }
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/dracoinsomnis"
cp -r "$src" "$dest"
mkdir -p "$dest/engine/Core"
for f in src/Core/*.php; do
  awk '{ print } /^namespace [A-Za-z\\]+;$/ && !done { print ""; print "defined('"'"'MOODLE_INTERNAL'"'"') || die();"; done = 1 }' "$f" > "$dest/engine/Core/$(basename "$f")"
  grep -q "MOODLE_INTERNAL" "$dest/engine/Core/$(basename "$f")" || { echo "No guard added to $f" >&2; exit 1; }
done
cp LICENSE "$dest/LICENSE.txt"
zip_path="$(cd "$out" && pwd)/local_dracoinsomnis-moodle-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" dracoinsomnis)
echo "$zip_path"
