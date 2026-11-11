#!/usr/bin/env bash
# Installs a throwaway WordPress and installs Draco Insomnis into it from the same ZIP a user would
# download, for the integration and HTTP tests. It wipes the database it is given: test sites only.
#
# Env: DB_HOST DB_NAME DB_USER DB_PASS   database for the test site (required)
#      WP_DIR      where to install (default /tmp/wordpress)
#      WP_URL      address of the site (default http://127.0.0.1:8080)
#      WP_VERSION  WordPress version (default latest)
set -euo pipefail
cd "$(dirname "$0")/.."
: "${DB_HOST:?}" "${DB_NAME:?}" "${DB_USER:?}" "${DB_PASS?}"
WP_DIR=${WP_DIR:-/tmp/wordpress}
WP_URL=${WP_URL:-http://127.0.0.1:8080}
WP_VERSION=${WP_VERSION:-latest}
wp() { command wp --path="$WP_DIR" --allow-root "$@"; }

if [ -e "$WP_DIR" ] && [ ! -e "$WP_DIR/.draco-ci" ]; then
  echo "$WP_DIR exists and was not made by this script: refusing to touch it" >&2
  exit 1
fi
mkdir -p "$WP_DIR"
touch "$WP_DIR/.draco-ci"
wp core download --version="$WP_VERSION" --force --skip-content
mkdir -p "$WP_DIR/wp-content/plugins" "$WP_DIR/wp-content/themes" "$WP_DIR/wp-content/mu-plugins"
wp config create --dbhost="$DB_HOST" --dbname="$DB_NAME" --dbuser="$DB_USER" --dbpass="$DB_PASS" --skip-check --force \
  --extra-php <<'PHP'
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', true);
define('WP_DEBUG_DISPLAY', false);
PHP
wp db reset --yes
wp core install --url="$WP_URL" --title="Draco CI" --admin_user=admin --admin_password=Admin-Pass-CI-1 \
  --admin_email=admin@example.org --skip-email
wp theme install twentytwentyfive --activate >/dev/null 2>&1 || wp theme install twentytwentyfour --activate
cp tests/ci/mail-capture.php "$WP_DIR/wp-content/mu-plugins/"

zip=$(bin/build-zip.sh "$(mktemp -d)")
wp plugin install "$zip" --force --activate
wp plugin list --name=draco-insomnis --fields=name,status,version
