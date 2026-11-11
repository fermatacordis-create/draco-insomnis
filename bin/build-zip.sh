#!/usr/bin/env bash
# Builds the installable ZIP: only what WordPress needs, without development files.
# Usage: bin/build-zip.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
stable=$(sed -n 's/^Stable tag: *//p' readme.txt | tr -d '[:space:]')
if [ "$version" != "$stable" ]; then
  echo "Version ($version) and Stable tag ($stable) differ" >&2
  exit 1
fi
out="${1:-dist}"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/draco-insomnis"
cp -r draco-insomnis.php uninstall.php readme.txt LICENSE src languages assets "$tmp/draco-insomnis/"
zip_path="$(cd "$out" && pwd)/draco-insomnis-$version.zip"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" draco-insomnis)
echo "$zip_path"
