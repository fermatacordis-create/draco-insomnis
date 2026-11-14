#!/usr/bin/env bash
# Sets the same version on every package: the WordPress plugin (header, constant, Stable tag) and the
# PrestaShop, Drupal, Joomla and Moodle packages. Moodle's own build number (YYYYMMDDXX) goes up too.
# Usage: bin/set-version.sh X.Y.Z     (then add a changelog entry in readme.txt)
set -euo pipefail
cd "$(dirname "$0")/.."
v="${1:-}"
[[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Usage: bin/set-version.sh X.Y.Z" >&2; exit 1; }

sed -i "s/^\( \* Version: *\)[0-9.]*$/\1$v/" draco-insomnis.php
sed -i "s/^define('DRACO_INSOMNIS_VERSION', '[^']*');/define('DRACO_INSOMNIS_VERSION', '$v');/" draco-insomnis.php
sed -i "s/^Stable tag: .*/Stable tag: $v/" readme.txt
sed -i "s/\(\$this->version = '\)[^']*'/\1$v'/" cms/prestashop/dracoinsomnis/dracoinsomnis.php
sed -i "s/^version: '[^']*'/version: '$v'/" cms/drupal/draco_insomnis/draco_insomnis.info.yml
sed -i "s/<version>[^<]*<\/version>/<version>$v<\/version>/" cms/joomla/plg_system_dracoinsomnis/dracoinsomnis.xml

sed -i "s/^define('DRACO_SERVER_VERSION', '[^']*');/define('DRACO_SERVER_VERSION', '$v');/" server/bin/draco
sed -i "s/^define('DRACO_SERVER_GUARD', '[^']*');/define('DRACO_SERVER_GUARD', '$v');/" server/guard.php

moodle=cms/moodle/local_dracoinsomnis/version.php
sed -i "s/^\(\$plugin->release = '\)[^']*'/\1$v'/" "$moodle"
current=$(sed -n 's/^\$plugin->version = \([0-9]*\);.*/\1/p' "$moodle")
build=$(( $(date -u +%Y%m%d) * 100 ))
[ "$build" -gt "$current" ] || build=$(( current + 1 ))
sed -i "s/^\(\$plugin->version = \)[0-9]*;/\1$build;/" "$moodle"

bin/versions.sh --check "$v"
grep -q "^= $v =" readme.txt || echo "Remember: add a '= $v =' entry to the changelog in readme.txt" >&2
