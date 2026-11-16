#!/usr/bin/env bash
# Builds the installable ZIP: only what WordPress needs, without development files.
# Usage: bin/build-zip.sh [output-dir]   (default: ./dist)
#   WPORG=1 bin/build-zip.sh [output-dir]  the WordPress.org upload: also without the bundled
#   translations (translate.wordpress.org serves them there) and without load_plugin_textdomain().
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
# Engine parts only the other CMS editions use (they download with their own HTTP code); WordPress
# has its own versions on its HTTP API.
rm -f "$tmp/draco-insomnis/src/Core/GeoUpdate.php" "$tmp/draco-insomnis/src/Core/Passwords.php" "$tmp/draco-insomnis/src/Core/TestProbe.php"
name="draco-insomnis-wordpress-$version.zip"
if [ "${WPORG:-}" = "1" ]; then
  rm -rf "$tmp/draco-insomnis/languages"
  php -r '$f = $argv[1]; $s = file_get_contents($f); $s = preg_replace("/add_action\(\x27plugins_loaded\x27, static function \(\): void \{\n.*?load_plugin_textdomain\(.*?\n\}, 0\);\n/s", "", $s, 1, $n); if ($n !== 1) { fwrite(STDERR, "load_plugin_textdomain block not found\n"); exit(1); } file_put_contents($f, $s);' "$tmp/draco-insomnis/draco-insomnis.php"
  php -l "$tmp/draco-insomnis/draco-insomnis.php" >/dev/null
  name="draco-insomnis-wordpress-org-$version.zip"
fi
zip_path="$(cd "$out" && pwd)/$name"
rm -f "$zip_path"
(cd "$tmp" && zip -qr "$zip_path" draco-insomnis)
echo "$zip_path"
