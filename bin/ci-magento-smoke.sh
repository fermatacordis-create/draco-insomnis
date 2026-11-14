#!/usr/bin/env bash
# Real HTTP requests against a throwaway Magento (or Mage-OS) shop with Draco Insomnis installed.
#   MAGENTO   how to run bin/magento (default: "php bin/magento" in MAGENTO_DIR)
#   MAGE_URL  the shop's base URL (default http://127.0.0.1:18080)
#   MYSQL     a mysql client command for the shop's database (to check and remove test customers)
# Only for test shops: it changes the settings and creates customers.
set -uo pipefail
BASE=${MAGE_URL:-http://127.0.0.1:18080}
BASE=${BASE%/}
MAGENTO_DIR=${MAGENTO_DIR:-.}
MAGENTO=${MAGENTO:-php $MAGENTO_DIR/bin/magento}
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36'
mg() { $MAGENTO "$@"; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { echo "ok   - $1"; }
fail() { echo "FAIL - $1"; fails=$((fails + 1)); }
expect() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi; }
contains() { if grep -q -- "$2" "$3"; then pass "$1"; else fail "$1 (no '$2')"; fi; }
code() { curl -s -A "$UA" -o "$tmp/body" -D "$tmp/head" -w '%{http_code}' "$@"; }
set_() { mg config:set "draco_insomnis/$1" "$2" >/dev/null; }
reset() {
  for p in firewall/mode anticopy/mode; do set_ "$p" off; done
  set_ shield/enabled 0; set_ headers/enabled 0; set_ passwords/min_length 0; set_ anticopy/rate_ip 120
  sql "TRUNCATE draco_events; TRUNCATE draco_blocks; TRUNCATE draco_cache;"
  mg cache:clean config full_page >/dev/null
}
MYSQL=${MYSQL:-mysql -h127.0.0.1 -uroot -proot magento}
sql() { $MYSQL -N -e "$1" 2>/dev/null; }

echo "# shop"
reset
expect "home page answers" 200 "$(code "$BASE/")"
expect "draco:status runs" 0 "$(mg draco:status >/dev/null 2>&1; echo $?)"

echo "# firewall, blocking mode"
set_ firewall/mode block; mg cache:clean config >/dev/null
expect "SQL injection gets 403" 403 "$(code "$BASE/?q=1%27%20UNION%20SELECT%20password_hash%20FROM%20customer_entity--%20")"
contains "403 page says why" "Request blocked" "$tmp/body"
contains "403 page offers a review" "Ask for a review" "$tmp/body"
hidden=()
while read -r pair; do hidden+=(--data-urlencode "$pair"); done < <(grep -o '<input type="hidden" name="[a-z_]*" value="[^"]*"' "$tmp/body" | sed 's/.*name="\([^"]*\)" value="\([^"]*\)"/\1=\2/' | sed 's/&amp;/\&/g')
sleep 3
code -X POST "${hidden[@]}" --data-urlencode "draco_email=ana@example.org" --data-urlencode "draco_message=I was searching for a product" --data-urlencode "draco_website=" \
  "$BASE/?q=1%27%20UNION%20SELECT%20password_hash%20FROM%20customer_entity--%20" >/dev/null
contains "the review request is thanked" "Request sent" "$tmp/body"
contains "the review request waits in draco:reviews" "ana@example.org" <(mg draco:reviews)
expect "ordinary search still works" 200 "$(code "$BASE/catalogsearch/result/?q=european+union+select+committee")"
expect ".env probe gets 403" 403 "$(code "$BASE/.env")"
expect "SQL injection in a REST JSON body gets 403" 403 "$(code -X POST -H 'Content-Type: application/json' --data '{"username":"x","password":"1'"'"' UNION SELECT password_hash FROM admin_user-- "}' "$BASE/rest/V1/integration/customer/token")"
expect "the admin panel is never inspected" 1 "$(code "$BASE/admin/?q=1%27%20UNION%20SELECT%20password%20FROM%20admin_user--%20" >/dev/null; [ "$(cat "$tmp/head" | head -1 | grep -c ' 403')" = 0 ] && echo 1 || echo 0)"
mg config:set general/locale/code es_ES >/dev/null; mg cache:clean config translate >/dev/null
code "$BASE/?q=1%27%20UNION%20SELECT%201--%20" >/dev/null
contains "the block page speaks the shop's language" "Petición bloqueada" "$tmp/body"
mg config:set general/locale/code en_US >/dev/null; mg cache:clean config translate >/dev/null
expect "draco:test recognises and blocks" 0 "$(mg draco:test "$BASE/" >/dev/null 2>&1; echo $?)"
attacks=$(mg draco:status | grep -o '[0-9]* attacks seen' | grep -o '^[0-9]*')
[ "${attacks:-0}" -ge 3 ] && pass "attacks are logged ($attacks)" || fail "attacks are logged (got ${attacks:-0})"

echo "# firewall, log mode"
set_ firewall/mode log; mg cache:clean config >/dev/null
expect "log mode stops nothing" 200 "$(code "$BASE/?q=1%27%20UNION%20SELECT%20password_hash%20FROM%20customer_entity--%20")"
reset

echo "# block list"
set_ firewall/mode block; mg cache:clean config >/dev/null
# The address the shop sees for us: the firewall writes it down.
code "$BASE/?q=1%27%20UNION%20SELECT%201--%20" >/dev/null
seen=$(sql "SELECT ip FROM draco_events WHERE endpoint LIKE 'waf:%' ORDER BY id DESC LIMIT 1" | tr -d '[:space:]')
if [ -n "$seen" ]; then
  mg draco:block "$seen" --days=7 --reason=CI >/dev/null
  expect "a blocked address may read the shop" 200 "$(code "$BASE/")"
  expect "a blocked address may not log in" 403 "$(code "$BASE/customer/account/login/")"
  id=$(sql "SELECT id FROM draco_blocks WHERE kind = 'ip' AND value = '$seen' LIMIT 1" | tr -d '[:space:]')
  mg draco:block --unblock="$id" >/dev/null
  expect "a lifted block lets it in again" 200 "$(code "$BASE/customer/account/login/")"
else
  fail "the shop's view of our address was found"
fi
reset

echo "# anti-copy pace limit"
set_ anticopy/mode block; set_ anticopy/rate_ip 10; mg cache:clean config >/dev/null
codes=""
for i in $(seq 1 25); do codes="$codes $(curl -s -A "$UA" -H 'Accept: text/html' -o /dev/null -D "$tmp/h$i" -w '%{http_code}' "$BASE/?p=$i")"; done
case "$codes" in *429*) pass "too many pages in a minute get 429";; *) fail "too many pages in a minute get 429 (got$codes)";; esac
if grep -qil '^retry-after:' "$tmp"/h*; then pass "the 429 says when to come back"; else fail "the 429 says when to come back"; fi
case "$codes" in *200*) pass "the first pages were served";; *) fail "the first pages were served";; esac
expect "the REST API is not counted as pages" 1 "$(c=$(curl -s -o /dev/null -w '%{http_code}' -H 'Accept: application/json' "$BASE/rest/V1/directory/countries"); [ "$c" != 429 ] && echo 1 || echo "0 ($c)")"
reset

echo "# security headers"
set_ headers/enabled 1; mg cache:clean config full_page >/dev/null
code "$BASE/" >/dev/null
if grep -qi '^x-content-type-options: nosniff' "$tmp/head"; then pass "nosniff is sent"; else fail "nosniff is sent"; fi
if grep -qi '^permissions-policy:' "$tmp/head"; then pass "Permissions-Policy is sent"; else fail "Permissions-Policy is sent"; fi
[ "$(grep -ci '^x-frame-options:' "$tmp/head")" = 1 ] && pass "X-Frame-Options only once (the shop's own is kept)" || fail "X-Frame-Options only once"
reset

echo "# sign-up shield and password rules"
set_ shield/enabled 1; mg cache:clean config full_page >/dev/null
signup() { # jar email first extra-fields...
  local jar=$1 email=$2 first=$3; shift 3
  curl -s -A "$UA" -c "$jar" -b "$jar" -o "$tmp/form" "$BASE/customer/account/create/"
  local fk; fk=$(grep -o 'name="form_key" type="hidden" value="[^"]*"' "$tmp/form" | head -1 | sed 's/.*value="\([^"]*\)"/\1/')
  [ -n "$fk" ] || fk=$(grep -o '"formKey":"[^"]*"' "$tmp/form" | head -1 | cut -d'"' -f4)
  curl -s -A "$UA" -c "$jar" -b "$jar" -o "$tmp/post" -D "$tmp/posthead" -X POST \
    --data-urlencode "form_key=$fk" --data-urlencode "firstname=$first" --data-urlencode "lastname=Garcia" \
    --data-urlencode "email=$email" --data-urlencode "password=$PW" --data-urlencode "password_confirmation=$PW" "$@" \
    "$BASE/customer/account/createpost/"
}
customer() { sql "SELECT COUNT(*) FROM customer_entity WHERE email = '$1'" | grep -o '[0-9]*' | tail -1; }
curl -s -A "$UA" -o "$tmp/form" "$BASE/customer/account/create/"
stamp_field=$(grep -o 'name="[a-z0-9_]*" value="[0-9]*\.[0-9a-f]*"' "$tmp/form" | head -1 | cut -d'"' -f2)
[ -n "$stamp_field" ] && pass "the form carries the page stamp" || fail "the form carries the page stamp"
trap_field=$(grep -o 'tabindex="-1"' "$tmp/form" >/dev/null && grep -o 'name="[a-z0-9_]*" value="" tabindex="-1"' "$tmp/form" | head -1 | cut -d'"' -f2)
[ -n "$trap_field" ] && pass "the form carries the trap" || fail "the form carries the trap"
PW='Long-Pass-123!'
signup "$tmp/jar1" bot@spam.example usru88w16kx --data-urlencode "$trap_field=http://spam.example"
expect "no account for the bot" 0 "$(customer bot@spam.example)"
rm -f "$tmp/jar2"; curl -s -A "$UA" -c "$tmp/jar2" -b "$tmp/jar2" -o /dev/null "$BASE/customer/account/create/"
sleep 4
# A person: the stamp comes with the form (signup reads the page again with the same cookies).
signup_person() {
  local jar=$1 email=$2 first=$3
  curl -s -A "$UA" -c "$jar" -b "$jar" -o "$tmp/form" "$BASE/customer/account/create/"
  local stamp; stamp=$(grep -o "name=\"$stamp_field\" value=\"[^\"]*\"" "$tmp/form" | sed 's/.*value="\([^"]*\)"/\1/')
  sleep 4
  local fk; fk=$(grep -o 'name="form_key" type="hidden" value="[^"]*"' "$tmp/form" | head -1 | sed 's/.*value="\([^"]*\)"/\1/')
  curl -s -A "$UA" -c "$jar" -b "$jar" -o "$tmp/post" -D "$tmp/posthead" -X POST \
    --data-urlencode "form_key=$fk" --data-urlencode "firstname=$first" --data-urlencode "lastname=Garcia" \
    --data-urlencode "email=$email" --data-urlencode "password=$PW" --data-urlencode "password_confirmation=$PW" \
    --data-urlencode "$stamp_field=$stamp" --data-urlencode "$trap_field=" "$BASE/customer/account/createpost/"
}
signup_person "$tmp/jar2" maria1985@example.org Maria
expect "a person signs up" 1 "$(customer maria1985@example.org)"
set_ passwords/min_length 16; mg cache:clean config >/dev/null
PW='Short-Pass-1!'
signup_person "$tmp/jar3" lucia1990@example.org Lucia
expect "a password shorter than the minimum is refused" 0 "$(customer lucia1990@example.org)"
sql "DELETE FROM customer_entity WHERE email IN ('maria1985@example.org', 'lucia1990@example.org', 'bot@spam.example')" >/dev/null
reset

echo
if [ "$fails" -gt 0 ]; then echo "$fails check(s) failed"; exit 1; fi
echo "all HTTP checks passed"
