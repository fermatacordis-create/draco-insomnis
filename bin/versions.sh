#!/usr/bin/env bash
# Prints the version of each package, one per line: "<cms> <version>".
# With --check [X.Y.Z]: fails unless all five agree (and match X.Y.Z when given).
set -euo pipefail
cd "$(dirname "$0")/.."
wp=$(sed -n 's/^ \* Version: *//p' draco-insomnis.php | tr -d '[:space:]')
wp_const=$(sed -n "s/^define('DRACO_INSOMNIS_VERSION', '\([^']*\)');/\1/p" draco-insomnis.php)
wp_stable=$(sed -n 's/^Stable tag: *//p' readme.txt | tr -d '[:space:]')
presta=$(sed -n "s/.*\$this->version = '\([^']*\)'.*/\1/p" cms/prestashop/dracoinsomnis/dracoinsomnis.php)
drupal=$(sed -n "s/^version: *'\([^']*\)'.*/\1/p" cms/drupal/draco_insomnis/draco_insomnis.info.yml)
joomla=$(sed -n 's/.*<version>\([^<]*\)<\/version>.*/\1/p' cms/joomla/plg_system_dracoinsomnis/dracoinsomnis.xml)
moodle=$(sed -n "s/^\$plugin->release = '\([^']*\)';.*/\1/p" cms/moodle/local_dracoinsomnis/version.php)
server=$(sed -n "s/^define('DRACO_SERVER_VERSION', '\([^']*\)');/\1/p" server/bin/draco)
js=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' js/package.json | head -1)
js_lock=$(sed -n 's/^  "version": "\([^"]*\)",$/\1/p' js/package-lock.json | head -1)
js_const=$(sed -n "s/^export const VERSION = '\([^']*\)';/\1/p" js/src/index.ts)
guard=$(sed -n "s/^define('DRACO_SERVER_GUARD', '\([^']*\)');/\1/p" server/guard.php)
printf '%s %s\n' wordpress "$wp" wordpress-constant "$wp_const" wordpress-stable-tag "$wp_stable" \
  prestashop "$presta" drupal "$drupal" joomla "$joomla" moodle "$moodle" server "$server" server-guard "$guard" \
  javascript "$js" javascript-lock "$js_lock" javascript-constant "$js_const"
if [ "${1:-}" = "--check" ]; then
  want="${2:-$wp}"
  for v in "$wp" "$wp_const" "$wp_stable" "$presta" "$drupal" "$joomla" "$moodle" "$server" "$guard" "$js" "$js_lock" "$js_const"; do
    if [ "$v" != "$want" ]; then
      echo "Versions differ: every package must be $want (run bin/set-version.sh $want)" >&2
      exit 1
    fi
  done
  echo "All packages at $want"
fi
