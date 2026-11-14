#!/usr/bin/env bash
# Builds every package (WordPress, PrestaShop, Drupal, Joomla, Moodle, Laravel, Server) from the same commit
# and the same src/Core, after checking that they all carry the same version. The Laravel package
# takes the WordPress version at build time.
# Usage: bin/build-all.sh [output-dir]   (default: ./dist)
set -euo pipefail
cd "$(dirname "$0")/.."
bin/versions.sh --check >&2
out="${1:-dist}"
bin/build-zip.sh "$out"
bin/build-prestashop.sh "$out"
bin/build-drupal.sh "$out"
bin/build-joomla.sh "$out"
bin/build-moodle.sh "$out"
bin/build-laravel.sh "$out"
bin/build-server.sh "$out"
