#!/usr/bin/env bash
# Real HTTP requests against the throwaway site made by bin/ci-wp-setup.sh, served at WP_URL.
# Covers what ends a request (403 pages, redirects, the confirmation page, the login code) and so
# cannot run inside PHPUnit.
set -uo pipefail
cd "$(dirname "$0")/.."
WP_DIR=${WP_DIR:-/tmp/wordpress}
BASE=${WP_URL:-http://127.0.0.1:8080}
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36'
[ -e "$WP_DIR/.draco-ci" ] || { echo "$WP_DIR is not a test site" >&2; exit 1; }
wp() { command wp --path="$WP_DIR" --allow-root "$@"; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; fails=$((fails + 1)); }
expect() { # name expected actual
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
contains() { # name needle file
  if grep -q -- "$2" "$3"; then pass "$1"; else fail "$1 (no '$2')"; fi
}
code() { curl -s -A "$UA" -o "$tmp/body" -w '%{http_code}' "$@"; }
prefix=$(wp db prefix)
reset() {
  wp db query "TRUNCATE ${prefix}draco_events; TRUNCATE ${prefix}draco_blocks;" >/dev/null 2>&1 || true
  wp transient delete --all >/dev/null
  for o in draco_waf_enabled draco_waf_mode draco_mfa_enabled draco_shield_enabled draco_anticopy_rest draco_anticopy_rest_allow draco_anticopy_rate draco_anticopy_rate_ip; do wp option delete "$o" >/dev/null 2>&1; done
  : > "$WP_DIR/wp-content/ci-mail.jsonl"
}

echo "# site"
reset
expect "home page answers" 200 "$(code "$BASE/")"

echo "# firewall, blocking mode"
wp option update draco_waf_enabled yes >/dev/null
wp option update draco_waf_mode block >/dev/null
expect "SQL injection gets 403" 403 "$(code "$BASE/?q=1%27%20UNION%20SELECT%20user_pass%20FROM%20wp_users--%20")"
contains "403 page says why" "Request blocked" "$tmp/body"
expect "ordinary search still works" 200 "$(code "$BASE/?s=european+union+select+committee")"
expect ".env probe gets 403" 403 "$(code "$BASE/.env")"
multicall='<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data></data></array></value></param></params></methodCall>'
expect "XML-RPC system.multicall gets 403" 403 "$(code -X POST -H 'Content-Type: text/xml' --data "$multicall" "$BASE/xmlrpc.php")"
expect "author scan is redirected" 301 "$(code "$BASE/?author=1")"
expect "user list hidden from visitors" 404 "$(code "$BASE/?rest_route=/wp/v2/users")"
expect "attacks are logged" 3 "$(wp db query "SELECT COUNT(*) FROM ${prefix}draco_events WHERE endpoint LIKE 'waf:%'" --skip-column-names)"
reset

echo "# confirmation link"
token=$(wp eval 'DracoInsomnis\Gate\Store::ensureTable(); echo DracoInsomnis\Gate\Store::create("form", "cf7", "ana@example.org", "127.0.0.1")["token"];')
link="$BASE/wp-admin/admin-ajax.php?action=draco_verify&t=$token"
expect "opening the link answers" 200 "$(code "$link")"
contains "opening the link only shows a button" 'type="submit"' "$tmp/body"
expect "opening the link confirms nothing (mail scanners open links)" pending \
  "$(wp db query "SELECT status FROM ${prefix}draco_submissions ORDER BY id DESC LIMIT 1" --skip-column-names)"
code -X POST --data "action=draco_verify&t=$token" "$BASE/wp-admin/admin-ajax.php" >/dev/null
contains "pressing the button sends it" "has been sent" "$tmp/body"
code -X POST --data "action=draco_verify&t=$token" "$BASE/wp-admin/admin-ajax.php" >/dev/null
contains "a link works once" "already used" "$tmp/body"
reset

echo "# anti-bot shield on the WordPress sign-up form"
wp option update users_can_register 1 >/dev/null
wp option update draco_shield_enabled yes >/dev/null
trap_field=$(wp eval 'echo DracoInsomnis\Shield\Guard::trapField();')
code -X POST --data "user_login=usru88w16kx&user_email=bot@spam.example&$trap_field=http://spam.example&wp-submit=Register" \
  "$BASE/wp-login.php?action=register" >/dev/null
contains "a bot is turned away" "could not be completed" "$tmp/body"
expect "no account for the bot" "" "$(wp user get bot@spam.example --field=ID 2>/dev/null)"
code -c "$tmp/jar" "$BASE/wp-login.php?action=register" >/dev/null
stamp_field=$(wp eval 'echo DracoInsomnis\Shield\Guard::stampField();')
stamp=$(grep -o "name=\"$stamp_field\" value=\"[^\"]*\"" "$tmp/body" | sed 's/.*value="\([^"]*\)"/\1/')
[ -n "$stamp" ] && pass "the form carries the page stamp" || fail "the form carries the page stamp"
sleep 4
code -b "$tmp/jar" -X POST --data "user_login=maria1985&user_email=maria1985@example.org&$stamp_field=$stamp&$trap_field=&wp-submit=Register" \
  "$BASE/wp-login.php?action=register" >/dev/null
person=$(wp user get maria1985 --field=ID 2>/dev/null || true)
[ -n "$person" ] && pass "a person signs up" || fail "a person signs up"
[ -n "$person" ] && wp user delete "$person" --yes >/dev/null
wp option update users_can_register 0 >/dev/null
reset

echo "# anti-copy"
wp option update draco_anticopy_rest block >/dev/null
expect "content API closed to anonymous visitors" 401 "$(code "$BASE/?rest_route=/wp/v2/posts")"
expect "a program calling itself Googlebot is not let in" 401 "$(code -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$BASE/?rest_route=/wp/v2/posts")"
expect "the API index stays open" 200 "$(code "$BASE/?rest_route=/")"
wp option update draco_anticopy_rest_allow /wp/v2/posts >/dev/null
expect "a route on the allow list opens" 200 "$(code "$BASE/?rest_route=/wp/v2/posts")"
wp option update draco_anticopy_rest off >/dev/null
wp option update draco_anticopy_rate block >/dev/null
wp option update draco_anticopy_rate_ip 10 >/dev/null
codes=""
for i in $(seq 1 25); do codes="$codes $(curl -s -A "$UA" -o /dev/null -D "$tmp/head$i" -w '%{http_code}' "$BASE/?s=page$i")"; done
case "$codes" in *429*) pass "too many pages in a minute get 429";; *) fail "too many pages in a minute get 429 (got$codes)";; esac
if grep -qil '^retry-after:' "$tmp"/head*; then pass "the 429 says when to come back"; else fail "the 429 says when to come back"; fi
case "$codes" in *200*) pass "the first pages were served";; *) fail "the first pages were served";; esac
reset

echo "# login code by e-mail"
wp option update draco_mfa_enabled yes >/dev/null
login() { # password
  curl -s -A "$UA" -c "$tmp/jar" -b "$tmp/jar" -b 'wordpress_test_cookie=WP%20Cookie%20check' -o "$tmp/body" -D "$tmp/head" \
    --data-urlencode "log=admin" --data-urlencode "pwd=$1" --data "testcookie=1&wp-submit=Log+In" "$BASE/wp-login.php"
}
rm -f "$tmp/jar"
login wrong-password
expect "a wrong password earns no code" 0 "$(grep -c . "$WP_DIR/wp-content/ci-mail.jsonl")"
login Admin-Pass-CI-1
contains "the right password leads to the code step" "action=draco_mfa" "$tmp/head"
if grep -qi '^set-cookie: wordpress_logged_in' "$tmp/head"; then fail "no session before the code"; else pass "no session before the code"; fi
mfa_code=$(php -r '$l = file($argv[1]); $m = json_decode(end($l), true); preg_match("/(?<!\d)(\d{6})(?!\d)/", strip_tags($m["message"]), $x); echo $x[1] ?? "";' "$WP_DIR/wp-content/ci-mail.jsonl")
[ -n "$mfa_code" ] && pass "the code arrives by e-mail" || fail "the code arrives by e-mail"
curl -s -A "$UA" -c "$tmp/jar" -b "$tmp/jar" -o "$tmp/body" "$BASE/wp-login.php?action=draco_mfa"
nonce=$(grep -o 'name="_wpnonce" value="[^"]*"' "$tmp/body" | head -1 | sed 's/.*value="\([^"]*\)"/\1/')
curl -s -A "$UA" -c "$tmp/jar" -b "$tmp/jar" -o "$tmp/body" -D "$tmp/head" \
  --data "code=000000&_wpnonce=$nonce" "$BASE/wp-login.php?action=draco_mfa"
contains "a wrong code is refused" "Wrong code" "$tmp/body"
curl -s -A "$UA" -c "$tmp/jar" -b "$tmp/jar" -o "$tmp/body" -D "$tmp/head" \
  --data "code=$mfa_code&_wpnonce=$nonce" "$BASE/wp-login.php?action=draco_mfa"
if grep -qi '^set-cookie: wordpress_logged_in' "$tmp/head"; then pass "the right code logs in"; else fail "the right code logs in"; fi
reset

echo
if [ "$fails" -gt 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all HTTP checks passed"
