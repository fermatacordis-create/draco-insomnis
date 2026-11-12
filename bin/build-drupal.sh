#!/usr/bin/env bash
# Builds the Drupal module archive: cms/drupal/draco_insomnis plus the shared engines in lib/Core.
# Usage: bin/build-drupal.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
src=cms/drupal/draco_insomnis
version=$(sed -n "s/^version: *'\([0-9.]*\)'.*/\1/p" "$src/draco_insomnis.info.yml")
[ -n "$version" ] || { echo "No version in $src/draco_insomnis.info.yml" >&2; exit 1; }
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/draco_insomnis"
cp -r "$src" "$dest"
mkdir -p "$dest/lib/Core"
cp src/Core/*.php "$dest/lib/Core/"
cp LICENSE "$dest/LICENSE.txt"
zip_path="$(cd "$out" && pwd)/draco_insomnis-drupal-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" draco_insomnis)
echo "$zip_path"
