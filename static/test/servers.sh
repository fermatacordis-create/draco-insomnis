#!/usr/bin/env bash
# The generated .htaccess and nginx file on real Apache 2.4 and nginx, serving a static site that
# really contains the secret files (so a pass means refused, not missing): every probe and scanner
# of tests/vectors/waf.json must get 403, ordinary pages 200, and the headers must be there.
set -uo pipefail
cd "$(dirname "$0")/../.."
work=$(mktemp -d)
trap 'docker rm -f draco-static-apache draco-static-nginx >/dev/null 2>&1; rm -rf "$work"' EXIT
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (expected $2, got $3)"; fails=$((fails + 1)); fi; }

# The site, with what people upload by mistake.
site="$work/site"
mkdir -p "$site/.git" "$site/app" "$site/wp-content/uploads" "$site/vendor/phpunit/phpunit/src/Util/PHP" "$site/blog/environment-friendly-homes" "$site/info" "$site/drupal/core" "$site/wp-admin" "$site/phpMyAdmin" "$site/storage/logs"
echo '<!doctype html><title>home</title>home' > "$site/index.html"
echo 'post' > "$site/blog/environment-friendly-homes/index.html"
echo 'info' > "$site/info/index.html"
echo 'update' > "$site/drupal/update.php"
for f in .env app/.env.production .git/config wp-config.php.bak 'wp-config.php~' vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php backup.sql.gz wp-content/debug.log wp-content/uploads/alfa-rex.php drupal/core/install.php wp-admin/install.php phpMyAdmin/index.php .htpasswd error_log storage/logs/laravel.log index.php.bak backup-2026-11-25.zip; do
  echo secret > "$site/$f"
done
chmod -R a+rX "$work"

node --input-type=module -e "
import { writeFileSync } from 'node:fs';
import { apache, nginx } from './static/generator.mjs';
const o = { hsts: true, csp: { enforce: true } };
writeFileSync('$site/.htaccess', apache(o));
writeFileSync('$work/draco.conf', nginx(o));
"

# Apache 2.4 with mod_rewrite and mod_headers, and .htaccess allowed (as on shared hosting).
cat > "$work/httpd-extra.conf" <<'CONF'
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule headers_module modules/mod_headers.so
<Directory "/usr/local/apache2/htdocs">
    AllowOverride All
    Require all granted
</Directory>
CONF
docker run -d --name draco-static-apache -p 18091:80 -v "$site:/usr/local/apache2/htdocs:ro" -v "$work/httpd-extra.conf:/usr/local/apache2/conf/extra/draco.conf:ro" \
  httpd:2.4 sh -c 'echo "Include conf/extra/draco.conf" >> conf/httpd.conf && httpd-foreground' >/dev/null

cat > "$work/nginx.conf" <<'CONF'
server {
    listen 80;
    root /usr/share/nginx/html;
    include /etc/nginx/snippets/draco-insomnis.conf;
    location / { try_files $uri $uri/ =404; }
}
CONF
docker run -d --name draco-static-nginx -p 18092:80 -v "$site:/usr/share/nginx/html:ro" -v "$work/nginx.conf:/etc/nginx/conf.d/default.conf:ro" \
  -v "$work/draco.conf:/etc/nginx/snippets/draco-insomnis.conf:ro" nginx:stable >/dev/null

for port in 18091 18092; do
  for i in $(seq 1 40); do curl -s -o /dev/null "http://127.0.0.1:$port/" && break; sleep 0.5; done
done

UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36'
vectors=$(node -e '
const v = require("./tests/vectors/waf.json");
for (const c of v.attacks) if (c.rule === "probe" || c.rule === "scanner") console.log([c.rule, c.request.path, c.request.userAgent].join("\t"));
')
for server in apache:18091 nginx:18092; do
  name=${server%%:*}; port=${server##*:}
  echo "# $name"
  while IFS=$'\t' read -r rule path ua; do
    check "$name: $rule $path" 403 "$(curl -s -o /dev/null -w '%{http_code}' -A "$ua" "http://127.0.0.1:$port$path")"
  done <<< "$vectors"
  check "$name: the home page" 200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/")"
  check "$name: a post whose name starts with env" 200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/blog/environment-friendly-homes/")"
  check "$name: update.php is never refused" 200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/drupal/update.php")"
  check "$name: /info/ is a page, not info.php" 200 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/info/")"
  h=$(curl -s -D - -o /dev/null -A "$UA" "http://127.0.0.1:$port/")
  check "$name: nosniff" 1 "$(grep -ci '^x-content-type-options: nosniff' <<< "$h")"
  check "$name: Content-Security-Policy" 1 "$(grep -ci "^content-security-policy: default-src 'self'" <<< "$h")"
  check "$name: HSTS" 1 "$(grep -ci '^strict-transport-security: max-age=15552000' <<< "$h")"
  check "$name: no folder listing" 1 "$(c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/wp-content/uploads/"); [ "$c" = 403 ] || [ "$c" = 404 ] && echo 1 || echo "0 ($c)")"
done

echo
if [ "$fails" -gt 0 ]; then
  docker logs draco-static-apache 2>&1 | tail -5
  echo "$fails check(s) failed"; exit 1
fi
echo "all static-site checks passed"
