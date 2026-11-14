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

echo "== password rules"
orig_register=$($D cget user.settings register --format=string 2>/dev/null)
orig_verify=$($D cget user.settings verify_mail --format=string 2>/dev/null)
$D cset -y user.settings register visitors >/dev/null 2>&1
$D cset -y --input-format=yaml user.settings verify_mail false >/dev/null 2>&1
cset shield false
dreg() { # password -> the answer page
  local jar p u; jar=$(mktemp); u="maria.lab$RANDOM"
  p=$(curl -s -c "$jar" -b "$jar" -A "$UA" "$BASE/user/register?$(cb)")
  curl -s -c "$jar" -b "$jar" -A "$UA" -d "$(echo "$p" | "$PHPBIN" "$HERE/formfields.php" user-register-form)" -d "name=$u" -d "mail=$u@example.org" \
    --data-urlencode "pass[pass1]=$1" --data-urlencode "pass[pass2]=$1" -d "op=Create new account" "$BASE/user/register?$(cb)"
  rm -f "$jar"
}
labs() { sql "SELECT COUNT(*) FROM users_field_data WHERE mail LIKE 'maria.lab%'"; }
cset pwd_min 20; $D cr >/dev/null 2>&1
out=$(dreg 'Draco-Lab-2026!x'); [ "$(labs)" = 0 ] && echo "$out" | grep -qE "at least 20 characters|al menos 20 caracteres" && ok "short password refused with the reason" || ko "min length (users $(labs))"
cset pwd_min 0; cset pwd_breached true
out=$(dreg 'passwordpassword'); [ "$(labs)" = 0 ] && echo "$out" | grep -qE "data breaches|filtraciones" && ok "breached password refused with the reason" || ko "breached (users $(labs))"
dreg 'Draco-Lab-2026!x' >/dev/null; [ "$(labs)" = 1 ] && ok "good password: account created" || ko "good password (users $(labs))"
$D php:eval '$s = \Drupal::entityTypeManager()->getStorage("user"); $ids = $s->getQuery()->accessCheck(FALSE)->condition("mail", "maria.lab%", "LIKE")->execute(); $s->delete($s->loadMultiple($ids)); echo count($ids), " test users removed\n";' 2>/dev/null | sed 's/^/     /'
cset pwd_breached false
$D cset -y user.settings register "$orig_register" >/dev/null 2>&1
$D cset -y --input-format=yaml user.settings verify_mail "$orig_verify" >/dev/null 2>&1
echo "     registration back to: $($D cget user.settings register --format=string 2>/dev/null), verify_mail $($D cget user.settings verify_mail --format=string 2>/dev/null)"
reset

echo "== anti-copy pace"
cset pace_mode block
cset anticopy_rate_ip 10
codes=""
# Counters are per calendar minute: a burst cut in two by the minute change needs a few more.
for i in $(seq 1 25); do c=$(code "$BASE/?$(cb)"); codes="$codes $c"; [ "$c" = 429 ] && break; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events WHERE endpoint='anticopy:rate_ip'")" = 1 ] && ok "one evidence line per minute" || ko "pace evidence"
gcodes=""; for i in $(seq 1 25); do c=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$BASE/?$(cb)"); gcodes="$gcodes $c"; [ "$c" = 429 ] && break; done
echo "     fake Googlebot codes:$gcodes"
[[ "$gcodes" == *429* ]] && ok "fake Googlebot is not trusted" || ko "fake googlebot never limited"

echo "== security headers"
cset pace_mode off
cset anticopy_rate_ip 120
reset
cset headers true
h=$(curl -s -D - -o /dev/null -A "$UA" "$BASE/?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-content-type-options: nosniff' && ok "security headers sent when on" || ko "no security headers"
cset headers false
h=$(curl -s -D - -o /dev/null -A "$UA" "$BASE/?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^permissions-policy:' && ko "headers still sent when off" || ok "no headers when off"

echo "== range blocked forever"
cset waf_mode log
code "$(attack)" >/dev/null
me=$(sql "SELECT ip FROM draco_insomnis_events ORDER BY id DESC LIMIT 1")
net=$("$PHPBIN" -r '$b = inet_pton($argv[1]); $v6 = strlen($b) === 16; $keep = $v6 ? 6 : 3; $b = substr($b, 0, $keep) . str_repeat("\0", strlen($b) - $keep); echo inet_ntop($b), $v6 ? "/48" : "/24";' "$me")
$D php:eval "echo (new \\Drupal\\draco_insomnis\\Store())->block('ip', '$net', 0, 'e2e range', TRUE) ? 'ok' : 'refused';" 2>/dev/null | grep -q ok && ok "range $net stored" || ko "range refused ($net, me=$me)"
[ "$(sql "SELECT CONCAT(kind,'|',until_at) FROM draco_insomnis_blocks WHERE value='$net'")" = "net|9999-12-31 23:59:59" ] && ok "kept as a range, forever" || ko "range row: $(sql "SELECT CONCAT(kind,'|',until_at) FROM draco_insomnis_blocks WHERE value='$net'")"
c=$(code "$BASE/?$(cb)"); [ "$c" = 200 ] && ok "an address in the range can still read" || ko "range read $c"
c=$(code -X POST -d 'x=1' "$BASE/node?$(cb)"); [ "$c" = 403 ] && ok "an address in the range cannot post" || ko "range post $c"
$D php:eval '(new \Drupal\draco_insomnis\Store())->block("ip", "10.0.0.0/8", 30, "too wide", TRUE) ? print("stored") : print("refused");' 2>/dev/null | grep -q refused && ok "a range wider than /16 is refused" || ko "wide range stored"
reset

echo "== country filter"
geo=$($D php:eval 'echo \Drupal\draco_insomnis\DrupalHost::get()->setting("geo_file");' 2>/dev/null)
"$PHPBIN" -r '$ip = inet_pton($argv[2]); $v6 = strlen($ip) === 16; $n = $v6 ? 16 : 4; $zero = str_repeat("\0", $n); $next = $ip; for ($i = $n - 1; $i >= 0; $i--) { $c = ord($next[$i]); if ($c < 255) { $next[$i] = chr($c + 1); break; } $next[$i] = "\0"; } $rows = [[$zero, "--"], [$ip, "CN"], [$next, "--"]]; $bin = "DRGEO1" . gmdate("Ymd") . pack("NN", $v6 ? 0 : 3, $v6 ? 3 : 0); foreach ($rows as [$a, $c]) { $bin .= $a . $c; } @mkdir(dirname($argv[1]), 0777, true); file_put_contents($argv[1], $bin);' "$geo" "$me"
cset waf_mode log
cset geo_countries CN
cset geo_action block
cset geo_mode block
c=$(code "$BASE/?$(cb)"); [ "$c" = 200 ] && ok "country filter leaves reading alone" || ko "geo read $c"
c=$(code "$BASE/user/login?$(cb)"); [ "$c" = 403 ] && ok "a listed country cannot open the login page" || ko "geo login $c"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events WHERE endpoint='waf:geo'")" -ge 1 ] && ok "kept as evidence (waf:geo)" || ko "geo evidence"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_blocks")" = 0 ] && ok "a country never blocks the address" || ko "geo blocked the address"
cset geo_mode allow
c=$(code "$BASE/user/login?$(cb)"); [ "$c" = 200 ] && ok "only-listed mode lets the listed country in" || ko "geo allow $c"
cset geo_mode off
cset geo_countries ''
cset geo_action log
cset waf_mode off
rm -f "$geo"
reset

echo "== review request from the block page"
cset pace_mode off
cset waf_mode block
page=$(curl -s -A "$UA" "$(attack)")
echo "$page" | grep -q 'name="draco_review"' && ok "the block page has the review form" || ko "no review form"
rts=$(val "$page" draco_ts); rsig=$(val "$page" draco_sig); rrule=$(val "$page" draco_rule)
c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -d draco_review=1 -d "draco_rule=$rrule" -d "draco_ts=$rts" -d "draco_sig=$rsig" -d draco_email=ana@example.org -d 'draco_message=I was searching' "$BASE/?$(cb)")
[ "$c" = 200 ] && ok "review request answered ($c)" || ko "review request $c"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events WHERE endpoint='review' AND verdict='pending'")" = 1 ] && ok "kept as a pending review" || ko "review not kept"
curl -s -o /dev/null -A "$UA" -d draco_review=1 -d "draco_rule=$rrule" -d "draco_ts=$rts" -d draco_sig=forged -d draco_email=bot@spam.example -d 'draco_message=spam' "$BASE/?$(cb)"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events WHERE endpoint='review'")" = 1 ] && ok "a forged review is dropped" || ko "forged review kept"
me=$(sql "SELECT ip FROM draco_insomnis_events WHERE endpoint='review' LIMIT 1")
$D php:eval "echo \\Drupal\\draco_insomnis\\Store::allow('$me', 1, 'e2e') ? 'ok' : 'no';" 2>/dev/null | grep -q ok && ok "let through for 24 hours" || ko "allow failed"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "an address let through is not inspected" || ko "allowed address still blocked ($c)"
sql "DELETE FROM draco_insomnis_blocks WHERE kind='allow'"

echo "== firewall test button"
tok=$($D php:eval 'echo \DracoInsomnis\Core\TestProbe::token(\Drupal\draco_insomnis\DrupalHost::get(), time());' 2>/dev/null)
before=$(sql "SELECT COUNT(*) FROM draco_insomnis_events")
h=$(curl -s -D - -o /dev/null -A "$UA" -H "X-Draco-Test: $tok" "$BASE/?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-draco-test-result: sqli|block' && ok "signed test answered: blocked" || ko "test answer: $(echo "$h" | grep -i 'draco-test' | head -1)"
h=$(curl -s -D - -o /dev/null -A "$UA" -H "X-Draco-Test: 1.forged" "$BASE/?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-draco-test-result:' && ko "a forged test header was answered" || ok "a forged test header is ignored"
[ "$(sql "SELECT COUNT(*) FROM draco_insomnis_events")" = "$before" ] && ok "a test is never logged" || ko "test logged"
n=$($D php:eval 'echo \DracoInsomnis\Core\Summary::waf(\Drupal\draco_insomnis\Store::wafRows(86400))["total"];' 2>/dev/null)
[ "${n:-0}" -ge 1 ] && ok "summary counts the attacks ($n)" || ko "summary empty"
cset waf_mode off
reset

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
