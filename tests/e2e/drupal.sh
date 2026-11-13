#!/usr/bin/env bash
# End-to-end test of the Drupal module against a real Drupal (CI or a lab). Requests come from this
# machine, so any automatic block only hits its own address.
#   BASE=http://127.0.0.1:8080 DRUSH="vendor/bin/drush" PHP=php tests/e2e/drupal.sh   (run in the Drupal root)
# Every request carries its own cb= so a page cache in front never answers for Drupal.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BASE:?BASE is required}"
D="${DRUSH:-vendor/bin/drush}"
PHPBIN="${PHP:-php}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
n=0; cb() { n=$((n+1)); echo "cb=$$-$n-$RANDOM"; }
attack() { echo "$BASE/?$(cb)&q=1%27%20union%20select%20pass%20from%20users_field_data--%20"; }
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }
sql() { $D sqlq "$1" 2>/dev/null; }
cset() { $D cset -y --input-format=yaml draco_insomnis.settings "$1" "$2" >/dev/null 2>&1; }
reset() { sql "DELETE FROM draco_insomnis_events"; sql "DELETE FROM draco_insomnis_blocks"; sql "DELETE FROM draco_insomnis_cache"; $D sdel draco_insomnis.admin_ips >/dev/null 2>&1; }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }
val() { echo "$1" | grep -o "name=\"$2\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="\([^"]*\)"/\1/'; }

echo "== install"
[ "$(sql "SELECT COUNT(*) FROM key_value WHERE collection='state' AND name='draco_insomnis.secret'")" = 1 ] && ok "per-site secret in state" || ko "secret"
reset

echo "== everything off"
cset shield false; cset waf_mode off; cset pace_mode off
c=$(code "$BASE/?$(cb)"); [ "$c" = 200 ] && ok "home 200" || ko "home $c"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "attack passes while off" || ko "off attack $c"

echo "== firewall: log only"
cset waf_mode log
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "log only lets it through" || ko "log $c"
r=$(sql "SELECT CONCAT(endpoint,'|',verdict) FROM draco_insomnis_events ORDER BY id DESC LIMIT 1"); [ "$r" = "waf:sqli|doubtful" ] && ok "logged as $r" || ko "log row: $r"
c=$(code "$BASE/?$(cb)&q=union+select+committee"); [ "$c" = 200 ] && ok "ordinary words pass" || ko "words $c"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events")" = 1 ] && ok "ordinary words leave no trace" || ko "false positive logged"

echo "== firewall: block"
cset waf_mode block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$(attack)")
[ "$(echo "$out" | tail -1)" = 403 ] && ok "attack gets 403" || ko "block $(echo "$out" | tail -1)"
echo "$out" | grep -q 'Ref\.' && ok "403 page without details" || ko "403 page"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.8' "$BASE/?$(cb)"); [ "$c" = 403 ] && ok "scanner gets 403" || ko "scanner $c"
c=$(code -b 'SSESSfake=abc' "$(attack)"); [ "$c" = 403 ] && ok "a fake session cookie does not dodge the firewall" || ko "fake cookie $c"
for i in 1 2 3; do code "$(attack)" >/dev/null; done
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_blocks WHERE kind='ip'")" -ge 1 ] && ok "5 attacks block the address: $(sql "SELECT reason FROM draco_insomnis_blocks LIMIT 1")" || ko "auto block"
c=$(code "$BASE/?$(cb)"); [ "$c" = 200 ] && ok "blocked address can still read" || ko "read $c"
c=$(code -X POST -d 'x=1' "$BASE/node?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot post" || ko "post $c"
c=$(code "$BASE/user/login?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot open the login page" || ko "login page $c"
cset waf_mode off
reset

echo "== shield on sign-up"
orig_register=$($D cget user.settings register --format=string 2>/dev/null)
$D cset -y user.settings register visitors >/dev/null 2>&1
cset shield true
$D cr >/dev/null 2>&1
jar=$(mktemp)
page=$(curl -s -c "$jar" -b "$jar" -A "$UA" "$BASE/user/register?$(cb)")
stampf=$(echo "$page" | grep -o 'name="dr_[a-f0-9]\{8\}"' | head -1 | sed 's/name="\(.*\)"/\1/')
trapf=$(echo "$page" | grep -o 'name="[a-z_]*_[a-f0-9]\{4\}" value="" tabindex="-1"' | head -1 | sed 's/name="\([^"]*\)".*/\1/')
[ -n "$stampf" ] && ok "form has the page stamp" || ko "no stamp in form"
[ -n "$trapf" ] && ok "form has the trap field ($trapf)" || ko "no trap in form"
users() { sql "SELECT COUNT(*) FROM users_field_data WHERE mail LIKE '%@spam.example' OR mail LIKE 'maria.lab%'"; }
submit() { # jar ua page name mail extra...
  local jar=$1 ua=$2 p=$3 name=$4 mail=$5; shift 5
  curl -s -o /dev/null -w '%{http_code}' -c "$jar" -b "$jar" -A "$ua" -d form_id=user_register_form -d "form_build_id=$(val "$p" form_build_id)" \
    -d "name=$name" -d "mail=$mail" -d "op=Create new account" "$@" "$BASE/user/register?$(cb)"
}
c=$(submit "$jar" "$UA" "$page" usru88w16kx "bot$RANDOM@spam.example" -d "$trapf=http://spam.example")
[ "$(users)" = 0 ] && ok "bot gets no account ($c)" || ko "bot account created"
r=$(sql "SELECT CONCAT(endpoint,'|',verdict,'|',reasons) FROM draco_insomnis_events ORDER BY id DESC LIMIT 1"); [[ "$r" == drupal_register\|bot\|*honeypot* ]] && ok "kept as evidence: $r" || ko "evidence: $r"
spage=$(curl -s -A 'python-requests/2.32' "$BASE/user/register?$(cb)")
c=$(submit /dev/null 'python-requests/2.32' "$spage" verifrw8mfsrh "script$RANDOM@spam.example")
[ "$(users)" = 0 ] && ok "script posting without the page stamp gets no account ($c)" || ko "script account created"
page=$(curl -s -c "$jar.p" -b "$jar.p" -A "$UA" "$BASE/user/register?$(cb)"); sval=$(val "$page" "$stampf"); sleep 4
defaults=$(echo "$page" | "$PHPBIN" "$HERE/formfields.php" user-register-form)
c=$(curl -s -o /dev/null -w '%{http_code}' -c "$jar.p" -b "$jar.p" -A "$UA" -d "$defaults" -d "name=maria.lab$RANDOM" -d "mail=maria.lab$RANDOM@example.org" -d "op=Create new account" "$BASE/user/register?$(cb)")
[ -n "$sval" ] || ko "no stamp value"
[ "$(sql "SELECT COUNT(*) FROM users_field_data WHERE mail LIKE 'maria.lab%'")" = 1 ] && ok "person signs up normally ($c)" || ko "person could not sign up ($c)"
$D php:eval '$s = \Drupal::entityTypeManager()->getStorage("user"); $q = $s->getQuery()->accessCheck(FALSE); $or = $q->orConditionGroup()->condition("mail", "%@spam.example", "LIKE")->condition("mail", "maria.lab%", "LIKE"); $ids = $q->condition($or)->execute(); $s->delete($s->loadMultiple($ids)); echo count($ids), " test users removed\n";' 2>/dev/null | sed 's/^/     /'
cset shield false
$D cset -y user.settings register "$orig_register" >/dev/null 2>&1
echo "     registration back to: $($D cget user.settings register --format=string 2>/dev/null)"
reset

echo "== anti-copy pace"
cset pace_mode block
cset anticopy_rate_ip 10
codes=""
for i in $(seq 1 12); do codes="$codes $(code "$BASE/?$(cb)")"; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events WHERE endpoint='anticopy:rate_ip'")" = 1 ] && ok "one evidence line per minute" || ko "pace evidence"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$BASE/?$(cb)"); [ "$c" = 429 ] && ok "fake Googlebot is not trusted" || ko "fake googlebot $c"

echo "== administrator (last: logging in remembers this address as an administrator's)"
cset pace_mode off
uli=$($D uli --uri="$BASE" --no-browser 2>/dev/null | tail -1)
curl -s -o /dev/null -L -c "$jar.a" -b "$jar.a" -A "$UA" "$uli"
grep -q 'SESS' "$jar.a" && ok "administrator logged in" || ko "no session"
cset pace_mode block
cset waf_mode block
for i in $(seq 1 12); do code "$BASE/?$(cb)" >/dev/null; done
c=$(code -b "$jar.a" "$BASE/?$(cb)"); [ "$c" = 200 ] && ok "logged-in administrator is never limited" || ko "admin limited $c"
c=$(code -b "$jar.a" "$(attack)"); [ "$c" = 200 ] && ok "administrator with bypass is not inspected" || ko "admin inspected $c"
[ -n "$($D sget draco_insomnis.admin_ips --format=json 2>/dev/null | grep -o '[0-9a-f:.]\{7,\}')" ] && ok "administrator address remembered" || ko "admin address not remembered"
cset waf_mode off
cset pace_mode off
cset anticopy_rate_ip 120
reset
rm -f "$jar" "$jar".*
echo "     admin addresses after cleanup: $($D sget draco_insomnis.admin_ips 2>/dev/null)"

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
