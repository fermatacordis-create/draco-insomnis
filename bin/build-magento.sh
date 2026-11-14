#!/usr/bin/env bash
# Builds the Magento 2 / Mage-OS module ZIP: cms/magento with the shared engines copied into core/
# (the symlink is followed) and the release version written into composer.json. It installs from a
# Composer "artifact" repository, or by hand: the folder's contents go to app/code/DracoInsomnis/Magento.
# Usage: bin/build-magento.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/draco-insomnis-magento"
mkdir -p "$dest"
(cd cms/magento && tar --dereference -cf - .) | tar -xf - -C "$dest"
[ -f "$dest/core/Shield.php" ] && [ ! -L "$dest/core" ] || { echo "core/ was not copied" >&2; exit 1; }
php -r '$f = $argv[1]; $j = json_decode(file_get_contents($f), true); $j = ["name" => $j["name"], "version" => $argv[2]] + $j; file_put_contents($f, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");' "$dest/composer.json" "$version"
cp LICENSE "$dest/LICENSE"
zip_path="$(cd "$out" && pwd)/draco-insomnis-magento-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" draco-insomnis-magento)
echo "$zip_path"
