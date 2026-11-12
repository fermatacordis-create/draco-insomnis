#!/usr/bin/env bash
# Builds the Laravel package ZIP: cms/laravel with the shared engines copied into core/ (the symlink
# is followed) and the release version written into composer.json, so it installs from a Composer
# "artifact" or "path" repository.
# Usage: bin/build-laravel.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/draco-insomnis-laravel"
mkdir -p "$dest"
(cd cms/laravel && tar --exclude=./vendor --exclude=./composer.lock --exclude=./.phpunit.cache --dereference -cf - .) | tar -xf - -C "$dest"
[ -f "$dest/core/Shield.php" ] && [ ! -L "$dest/core" ] || { echo "core/ was not copied" >&2; exit 1; }
php -r '$f = $argv[1]; $j = json_decode(file_get_contents($f), true); $j = ["name" => $j["name"], "version" => $argv[2]] + $j; file_put_contents($f, json_encode($j, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");' "$dest/composer.json" "$version"
cp LICENSE "$dest/LICENSE"
zip_path="$(cd "$out" && pwd)/draco-insomnis-laravel-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" draco-insomnis-laravel)
echo "$zip_path"
