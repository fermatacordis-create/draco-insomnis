#!/usr/bin/env bash
# Builds the PrestaShop module ZIP: cms/prestashop/dracoinsomnis plus the shared engines in src/Core.
# The engines are copied, not linked, with the _PS_VERSION_ guard PrestaShop asks for in every PHP file.
# Usage: bin/build-prestashop.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
src=cms/prestashop/dracoinsomnis
version=$(sed -n "s/.*\$this->version = '\([0-9.]*\)'.*/\1/p" "$src/dracoinsomnis.php")
[ -n "$version" ] || { echo "No version in $src/dracoinsomnis.php" >&2; exit 1; }
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/dracoinsomnis"
cp -r "$src" "$dest"
mkdir -p "$dest/src/Core"
for f in src/Core/*.php; do
  awk '{ print } /^namespace [A-Za-z\\]+;$/ && !done { print ""; print "if (!defined('"'"'_PS_VERSION_'"'"')) {"; print "    exit;"; print "}"; done = 1 }' "$f" > "$dest/src/Core/$(basename "$f")"
  grep -q "_PS_VERSION_" "$dest/src/Core/$(basename "$f")" || { echo "No guard added to $f" >&2; exit 1; }
done
cp LICENSE "$dest/LICENSE"
cp .wordpress-org/icon-256x256.png "$dest/logo.png"
# PrestaShop convention: an index.php in every folder, so none can be listed.
find "$dest" -type d | while read -r dir; do
  [ -f "$dir/index.php" ] || cat > "$dir/index.php" <<'PHP'
<?php
header('Expires: Mon, 26 Jul 1997 05:00:00 GMT');
header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Location: ../');
exit;
PHP
done
zip_path="$(cd "$out" && pwd)/dracoinsomnis-prestashop-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" dracoinsomnis)
echo "$zip_path"
