#!/usr/bin/env bash
# End-to-end test of the Joomla plugin against a real Joomla (CI or a lab). Requests come from this
# machine, so any automatic block only hits its own address. Run in the Joomla root:
#   BASE=http://127.0.0.1:8080 PHP=php tests/e2e/joomla.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BASE:?BASE is required}"
PHP="${PHP:-php}"
JLH=$(mktemp --suffix=.php)
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
n=0; cb() { n=$((n+1)); echo "cb=$$-$n-$RANDOM"; }
attack() { echo "$BASE/index.php?$(cb)&q=1%27%20union%20select%20password%20from%20jl_users--%20"; }
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }
val() { echo "$1" | grep -o "name=\"$2\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="\([^"]*\)"/\1/'; }

cat > "$JLH" <<'PHP'
<?php
// php jl.php sql "<query>" | php jl.php param <key> <value> | php jl.php users <key> <value>
require getcwd() . "/configuration.php"; $c = new JConfig;
$db = new mysqli($c->host, $c->user, $c->password, $c->db);
[$cmd, $a, $b] = array_pad(array_slice($argv, 1), 3, null);
if ($cmd === 'sql') {
    $r = $db->query(str_replace('#__', $c->dbprefix, $a));
    if ($r instanceof mysqli_result) { foreach ($r as $row) echo implode('|', $row), "\n"; }
} elseif ($cmd === 'param' || $cmd === 'users') {
    $where = $cmd === 'param' ? 'type="plugin" AND element="dracoinsomnis"' : 'type="component" AND element="com_users"';
    $p = json_decode($db->query("SELECT params FROM {$c->dbprefix}extensions WHERE $where")->fetch_row()[0], true);
    $p[$a] = $b;
    $st = $db->prepare("UPDATE {$c->dbprefix}extensions SET params=? WHERE $where");
    $j = json_encode($p); $st->bind_param('s', $j); $st->execute();
}
PHP
sql() { $PHP "$JLH" sql "$1"; }
param() { $PHP "$JLH" param "$1" "$2"; }
reset() { sql "DELETE FROM #__dracoinsomnis_events"; sql "DELETE FROM #__dracoinsomnis_blocks"; sql "DELETE FROM #__dracoinsomnis_cache WHERE k <> 'draco_admin_ips'"; }
reset

echo "== everything off"
param shield 0; param waf_mode off; param pace_mode off
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "home 200" || ko "home $c"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "attack passes while off" || ko "off attack $c"

echo "== firewall: log only"
param waf_mode log
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "log only lets it through" || ko "log $c"
r=$(sql "SELECT endpoint, verdict FROM #__dracoinsomnis_events ORDER BY id DESC LIMIT 1"); [ "$r" = "waf:sqli|doubtful" ] && ok "logged as $r" || ko "log row: $r"
c=$(code "$BASE/index.php?$(cb)&q=union+select+committee"); [ "$c" = 200 ] && ok "ordinary words pass" || ko "words $c"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events")" = 1 ] && ok "ordinary words leave no trace" || ko "false positive logged"

echo "== firewall: block"
param waf_mode block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$(attack)")
[ "$(echo "$out" | tail -1)" = 403 ] && ok "attack gets 403" || ko "block $(echo "$out" | tail -1)"
echo "$out" | grep -q 'Ref\.' && ok "403 page without details" || ko "403 page"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.8' "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "scanner gets 403" || ko "scanner $c"
for i in 1 2 3 4; do code "$(attack)" >/dev/null; done
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_blocks WHERE kind='ip'")" -ge 1 ] && ok "5 attacks block the address: $(sql "SELECT reason FROM #__dracoinsomnis_blocks LIMIT 1")" || ko "auto block"
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "blocked address can still read" || ko "read $c"
c=$(code -X POST -d 'x=1' "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot post" || ko "post $c"
param waf_mode off
reset

echo "== shield on sign-up"
$PHP "$JLH" users allowUserRegistration 1
param shield 1
jar=$(mktemp)
REG="$BASE/index.php?option=com_users&view=registration"
page=$(curl -sL -c "$jar" -b "$jar" -A "$UA" "$REG&$(cb)")
stampf=$(echo "$page" | grep -o 'name="dr_[a-f0-9]\{8\}"' | head -1 | sed 's/name="\(.*\)"/\1/')
trapf=$(echo "$page" | grep -o 'name="[a-z_]*_[a-f0-9]\{4\}" value="" tabindex="-1"' | head -1 | sed 's/name="\([^"]*\)".*/\1/')
[ -n "$stampf" ] && ok "form has the page stamp" || ko "no stamp in form"
[ -n "$trapf" ] && ok "form has the trap field ($trapf)" || ko "no trap in form"
users() { sql "SELECT COUNT(*) FROM #__users WHERE email LIKE '%@spam.example' OR email LIKE 'maria.lab%'"; }
action="$BASE/index.php?option=com_users&task=registration.register&$(cb)"
signup() { # jar ua page username email extra...
  local jar=$1 ua=$2 p=$3 u=$4 m=$5; shift 5
  local defaults; defaults=$(echo "$p" | $PHP "$HERE/formfields.php" member-registration)
  curl -s -o /dev/null -w '%{http_code}' -c "$jar" -b "$jar" -A "$ua" -d "$defaults" \
    --data-urlencode "jform[name]=$u" --data-urlencode "jform[username]=$u" --data-urlencode "jform[email1]=$m" \
    --data-urlencode "jform[password1]=Draco-Lab-2026!x" --data-urlencode "jform[password2]=Draco-Lab-2026!x" "$@" "$BASE/index.php?option=com_users&task=registration.register&$(cb)"
}
c=$(signup "$jar" "$UA" "$page" usru88w16kx "bot$RANDOM@spam.example" -d "$trapf=http://spam.example")
[ "$(users)" = 0 ] && ok "bot gets no account ($c)" || ko "bot account created"
r=$(sql "SELECT CONCAT(endpoint,'|',verdict,'|',reasons) FROM #__dracoinsomnis_events ORDER BY id DESC LIMIT 1"); [[ "$r" == joomla_register\|bot\|*honeypot* ]] && ok "kept as evidence: $r" || ko "evidence: $r"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'python-requests/2.32' --data-urlencode "jform[username]=verifrw8mfsrh" --data-urlencode "jform[email1]=script$RANDOM@spam.example" "$action")
[ "$(users)" = 0 ] && ok "script posting straight to the form gets no account ($c)" || ko "script account created"
page=$(curl -sL -c "$jar.p" -b "$jar.p" -A "$UA" "$REG&$(cb)"); sleep 4
c=$(signup "$jar.p" "$UA" "$page" "maria.lab$RANDOM" "maria.lab$RANDOM@example.org")
[ "$(sql "SELECT COUNT(*) FROM #__users WHERE email LIKE 'maria.lab%'")" = 1 ] && ok "person signs up normally ($c)" || ko "person could not sign up ($c)"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events WHERE fields LIKE '%maria.lab%'")" = 0 ] && ok "the person leaves no trace" || ko "person logged"
for id in $(sql "SELECT id FROM #__users WHERE email LIKE '%@spam.example' OR email LIKE 'maria.lab%'"); do sql "DELETE FROM #__user_usergroup_map WHERE user_id=$id"; sql "DELETE FROM #__users WHERE id=$id"; echo "     test user $id removed"; done
param shield 0
$PHP "$JLH" users allowUserRegistration 0
echo "     registration back to: $(sql "SELECT params FROM #__extensions WHERE element='com_users' AND type='component'" | grep -o '"allowUserRegistration":"[0-9]"')"
reset

echo "== security headers"
param pace_mode off
param headers 1
h=$(curl -s -D - -o /dev/null -A "$UA" "$BASE/index.php?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-content-type-options: nosniff' && ok "security headers sent when on" || ko "no security headers"
param headers 0
h=$(curl -s -D - -o /dev/null -A "$UA" "$BASE/index.php?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^permissions-policy:' && ko "headers still sent when off" || ok "no headers when off"

echo "== range blocked forever"
param waf_mode log
code "$(attack)" >/dev/null
me=$(sql "SELECT ip FROM #__dracoinsomnis_events ORDER BY id DESC LIMIT 1")
net=$($PHP -r '$b = inet_pton($argv[1]); $v6 = strlen($b) === 16; $keep = $v6 ? 6 : 3; $b = substr($b, 0, $keep) . str_repeat("\0", strlen($b) - $keep); echo inet_ntop($b), $v6 ? "/48" : "/24";' "$me")
sql "INSERT INTO #__dracoinsomnis_blocks (kind, value, reason, created_at, until_at) VALUES ('net', '$net', 'e2e range', UTC_TIMESTAMP(), '9999-12-31 23:59:59')"
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "an address in the range $net can still read" || ko "range read $c"
c=$(code -X POST -d 'x=1' "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "an address in the range cannot post" || ko "range post $c"
reset

echo "== country filter"
geo="media/plg_system_dracoinsomnis/draco-geo.bin"
$PHP -r '$ip = inet_pton($argv[2]); $v6 = strlen($ip) === 16; $n = $v6 ? 16 : 4; $zero = str_repeat("\0", $n); $next = $ip; for ($i = $n - 1; $i >= 0; $i--) { $c = ord($next[$i]); if ($c < 255) { $next[$i] = chr($c + 1); break; } $next[$i] = "\0"; } $rows = [[$zero, "--"], [$ip, "CN"], [$next, "--"]]; $bin = "DRGEO1" . gmdate("Ymd") . pack("NN", $v6 ? 0 : 3, $v6 ? 3 : 0); foreach ($rows as [$a, $c]) { $bin .= $a . $c; } @mkdir(dirname($argv[1]), 0777, true); file_put_contents($argv[1], $bin);' "$geo" "$me"
param waf_mode log; param geo_countries CN; param geo_action block; param geo_mode block
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "country filter leaves reading alone" || ko "geo read $c"
c=$(code "$BASE/index.php?option=com_users&view=login&$(cb)"); [ "$c" = 403 ] && ok "a listed country cannot open the login page" || ko "geo login $c"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events WHERE endpoint='waf:geo'")" -ge 1 ] && ok "kept as evidence (waf:geo)" || ko "geo evidence"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_blocks")" = 0 ] && ok "a country never blocks the address" || ko "geo blocked the address"
param geo_mode allow
c=$(code "$BASE/index.php?option=com_users&view=login&$(cb)"); [ "$c" = 200 ] && ok "only-listed mode lets the listed country in" || ko "geo allow $c"
param geo_mode off; param geo_countries ''; param geo_action log; param waf_mode off
rm -f "$geo"
reset

echo "== review request from the block page"
param pace_mode off
param waf_mode block
page=$(curl -s -A "$UA" "$(attack)")
echo "$page" | grep -q 'name="draco_review"' && ok "the block page has the review form" || ko "no review form"
rts=$(val "$page" draco_ts); rsig=$(val "$page" draco_sig); rrule=$(val "$page" draco_rule)
c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -d draco_review=1 -d "draco_rule=$rrule" -d "draco_ts=$rts" -d "draco_sig=$rsig" -d draco_email=ana@example.org -d 'draco_message=I was searching' "$BASE/index.php?$(cb)")
[ "$c" = 200 ] && ok "review request answered ($c)" || ko "review request $c"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events WHERE endpoint='review' AND verdict='pending'")" = 1 ] && ok "kept as a pending review" || ko "review not kept"
curl -s -o /dev/null -A "$UA" -d draco_review=1 -d "draco_rule=$rrule" -d "draco_ts=$rts" -d draco_sig=forged -d draco_email=bot@spam.example -d 'draco_message=spam' "$BASE/index.php?$(cb)"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events WHERE endpoint='review'")" = 1 ] && ok "a forged review is dropped" || ko "forged review kept"
me=$(sql "SELECT ip FROM #__dracoinsomnis_events WHERE endpoint='review' LIMIT 1")
sql "INSERT INTO #__dracoinsomnis_blocks (kind, value, reason, created_at, until_at) VALUES ('allow', '$me', 'e2e', UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 DAY)"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "an address let through is not inspected" || ko "allowed address still blocked ($c)"
sql "DELETE FROM #__dracoinsomnis_blocks WHERE kind='allow'"

echo "== firewall test button"
tok=$($PHP -r 'require getcwd() . "/configuration.php"; $c = new JConfig; $ts = time(); echo $ts, ".", hash_hmac("sha256", "waf-test|" . $ts, hash("sha256", "draco-insomnis|" . $c->secret));')
before=$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events")
h=$(curl -s -D - -o /dev/null -A "$UA" -H "X-Draco-Test: $tok" "$BASE/index.php?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-draco-test-result: sqli|block' && ok "signed test answered: blocked" || ko "test answer: $(echo "$h" | grep -i 'draco-test' | head -1)"
h=$(curl -s -D - -o /dev/null -A "$UA" -H "X-Draco-Test: 1.forged" "$BASE/index.php?$(cb)" | tr -d '\r')
echo "$h" | grep -qi '^x-draco-test-result:' && ko "a forged test header was answered" || ok "a forged test header is ignored"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events")" = "$before" ] && ok "a test is never logged" || ko "test logged"
param waf_mode off
reset

echo "== anti-copy pace"
param pace_mode block
param anticopy_rate_ip 10
codes=""
# Counters are per calendar minute: a burst cut in two by the minute change needs a few more.
for i in $(seq 1 25); do c=$(code "$BASE/index.php?$(cb)"); codes="$codes $c"; [ "$c" = 429 ] && break; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
[ "$(sql "SELECT COUNT(*) FROM #__dracoinsomnis_events WHERE endpoint='anticopy:rate_ip'")" = 1 ] && ok "one evidence line per minute" || ko "pace evidence"
sql "DELETE FROM #__dracoinsomnis_cache WHERE k LIKE 'draco_rl_%'"
gcodes=""; for i in $(seq 1 25); do c=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$BASE/index.php?$(cb)"); gcodes="$gcodes $c"; [ "$c" = 429 ] && break; done
echo "     fake Googlebot codes:$gcodes"
[[ "$gcodes" == *429* ]] && ok "fake Googlebot is not trusted" || ko "fake googlebot never limited"
param pace_mode off
param anticopy_rate_ip 120
reset
rm -f "$jar" "$jar".* "$JLH"

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
