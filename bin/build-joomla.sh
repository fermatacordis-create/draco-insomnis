#!/usr/bin/env bash
# Builds the Joomla plugin package: cms/joomla/plg_system_dracoinsomnis plus the shared engines in
# lib/Core, with the _JEXEC guard Joomla asks for in every PHP file. The manifest sits at the ZIP root.
# Usage: bin/build-joomla.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
src=cms/joomla/plg_system_dracoinsomnis
version=$(sed -n 's/.*<version>\([0-9.]*\)<\/version>.*/\1/p' "$src/dracoinsomnis.xml")
[ -n "$version" ] || { echo "No version in $src/dracoinsomnis.xml" >&2; exit 1; }
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp -r "$src/." "$tmp/"
mkdir -p "$tmp/lib/Core"
for f in src/Core/*.php; do
  awk '{ print } /^namespace [A-Za-z\\]+;$/ && !done { print ""; print "\\defined('"'"'_JEXEC'"'"') or die;"; done = 1 }' "$f" > "$tmp/lib/Core/$(basename "$f")"
  grep -q "_JEXEC" "$tmp/lib/Core/$(basename "$f")" || { echo "No guard added to $f" >&2; exit 1; }
done
cp LICENSE "$tmp/LICENSE.txt"
zip_path="$(cd "$out" && pwd)/plg_system_dracoinsomnis-joomla-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" .)
echo "$zip_path"
