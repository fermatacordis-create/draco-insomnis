#!/usr/bin/env bash
# Builds the five packages from the same commit (and the same src/Core), after checking that they all
# carry the same version.
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
