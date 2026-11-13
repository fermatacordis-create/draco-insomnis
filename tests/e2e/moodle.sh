#!/usr/bin/env bash
# End-to-end test of the Moodle plugin against a real Moodle (CI or a lab). Requests come from this
# machine, so any automatic block only hits its own address. Run in the Moodle root (where config.php is):
#   BASE=http://127.0.0.1:8080 PHP=php tests/e2e/moodle.sh
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${BASE:?BASE is required}"
P="${PHP:-php}"
MDH=$(mktemp --suffix=.php)
RESP=$(mktemp)
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
n=0; cb() { n=$((n+1)); echo "cb=$$-$n-$RANDOM"; }
LOGIN="$BASE/login/index.php"
attack() { echo "$LOGIN?$(cb)&q=1%27%20union%20select%20password%20from%20mdl_user--%20"; }
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }
val() { echo "$1" | grep -o "name=\"$2\" value=\"[^\"]*\"" | head -1 | sed 's/.*value="\([^"]*\)"/\1/'; }
cfg() { $P admin/cli/cfg.php --component=local_dracoinsomnis --name="$1" --set="$2" >/dev/null; }

cat > "$MDH" <<'PHP'
<?php
// php md.php sql "<query>" | php md.php deltest
define('CLI_SCRIPT', true);
require getcwd() . '/config.php';
[$cmd, $a] = array_pad(array_slice($argv, 1), 2, null);
if ($cmd === 'sql') {
    foreach ($DB->get_records_sql($a) as $row) { echo implode('|', (array) $row), "\n"; }
} elseif ($cmd === 'count') {
    echo $DB->count_records_sql($a), "\n";
} elseif ($cmd === 'deltest') {
    require_once $CFG->dirroot . '/user/lib.php';
    $users = $DB->get_records_select('user', "email LIKE '%@spam.example' OR email LIKE 'maria.lab%'");
    foreach ($users as $u) { delete_user($u); }
    echo count($users), " test users removed\n";
}
PHP
q() { $P "$MDH" sql "$1"; }
cnt() { $P "$MDH" count "$1"; }
reset() { cnt "SELECT 1" >/dev/null; $P -r 'define("CLI_SCRIPT", true); require getcwd()."/config.php"; $DB->delete_records("local_dracoinsomnis_events"); $DB->delete_records("local_dracoinsomnis_blocks"); $DB->delete_records("local_dracoinsomnis_cache");'; }
reset

echo "== everything off"
cfg shield 0; cfg waf_mode off; cfg pace_mode off
c=$(code "$LOGIN?$(cb)"); [ "$c" = 200 ] && ok "login page 200" || ko "login $c"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "attack passes while off" || ko "off attack $c"

echo "== firewall: log only"
cfg waf_mode log
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "log only lets it through" || ko "log $c"
r=$(q "SELECT id, endpoint, verdict FROM {local_dracoinsomnis_events} ORDER BY id DESC LIMIT 1" | cut -d'|' -f2-); [ "$r" = "waf:sqli|doubtful" ] && ok "logged as $r" || ko "log row: $r"
c=$(code "$LOGIN?$(cb)&q=union+select+committee"); [ "$c" = 200 ] && ok "ordinary words pass" || ko "words $c"
[ "$(cnt "SELECT COUNT(*) FROM {local_dracoinsomnis_events}")" = 1 ] && ok "ordinary words leave no trace" || ko "false positive logged"

echo "== firewall: block"
cfg waf_mode block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$(attack)")
[ "$(echo "$out" | tail -1)" = 403 ] && ok "attack gets 403" || ko "block $(echo "$out" | tail -1)"
echo "$out" | grep -q 'Ref\.' && ok "403 page without details" || ko "403 page"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.8' "$LOGIN?$(cb)"); [ "$c" = 403 ] && ok "scanner gets 403" || ko "scanner $c"
for i in 1 2 3 4; do code "$(attack)" >/dev/null; done
[ "$(cnt "SELECT COUNT(*) FROM {local_dracoinsomnis_blocks} WHERE kind = 'ip'")" -ge 1 ] && ok "5 attacks block the address: $(q "SELECT id, reason FROM {local_dracoinsomnis_blocks}" | head -1 | cut -d'|' -f2)" || ko "auto block"
c=$(code "$BASE/course/index.php?$(cb)"); [[ "$c" =~ ^(200|303)$ ]] && ok "blocked address can still read ($c)" || ko "read $c"
c=$(code "$LOGIN?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot open the login page" || ko "login page $c"
c=$(code -X POST -d 'x=1' "$BASE/course/index.php?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot post" || ko "post $c"
cfg waf_mode off
reset

echo "== shield on self-registration"
orig=$($P admin/cli/cfg.php --name=registerauth)
restore() { $P admin/cli/cfg.php --name=registerauth --set="$orig" >/dev/null; cfg shield 0; }
trap restore EXIT
$P admin/cli/cfg.php --name=registerauth --set=email >/dev/null
cfg shield 1
jar=$(mktemp)
SIGNUP="$BASE/login/signup.php"
FORM='//form[.//input[@name="_qf__login_signup_form"]]'
page=$(curl -sL -c "$jar" -b "$jar" -A "$UA" "$SIGNUP?$(cb)")
stampf=$(echo "$page" | grep -o 'name="dr_[a-f0-9]\{8\}"' | head -1 | sed 's/name="\(.*\)"/\1/')
trapf=$(echo "$page" | grep -o 'name="[a-z_]*_[a-f0-9]\{4\}" value="" tabindex="-1"' | head -1 | sed 's/name="\([^"]*\)".*/\1/')
[ -n "$stampf" ] && ok "form has the page stamp" || ko "no stamp in form"
[ -n "$trapf" ] && ok "form has the trap field ($trapf)" || ko "no trap in form"
users() { cnt "SELECT COUNT(*) FROM {user} WHERE email LIKE '%@spam.example' OR email LIKE 'maria.lab%'"; }
signup() { # jar ua page username email extra...
  local jar=$1 ua=$2 p=$3 u=$4 m=$5; shift 5
  local defaults; defaults=$(echo "$p" | $P "$HERE/formfields.php" "$FORM")
  curl -s -o "$RESP" -w '%{http_code}' -c "$jar" -b "$jar" -A "$ua" -d "$defaults" \
    --data-urlencode "username=$u" --data-urlencode "password=Draco-Lab-2026!x" --data-urlencode "email=$m" --data-urlencode "email2=$m" \
    --data-urlencode "firstname=Maria" --data-urlencode "lastname=Garcia" --data-urlencode "city=Mahon" --data-urlencode "country=ES" "$@" "$SIGNUP?$(cb)"
}
c=$(signup "$jar" "$UA" "$page" usru88w16kx "bot$RANDOM@spam.example" -d "$trapf=http://spam.example")
[ "$(users)" = 0 ] && ok "bot gets no account ($c)" || ko "bot account created"
r=$(q "SELECT id, endpoint, verdict, reasons FROM {local_dracoinsomnis_events} ORDER BY id DESC LIMIT 1" | cut -d'|' -f2-); [[ "$r" == moodle_signup\|bot\|*honeypot* ]] && ok "kept as evidence: $r" || ko "evidence: $r"
spage=$(curl -sL -c "$jar.s" -b "$jar.s" -A 'python-requests/2.32' "$SIGNUP?$(cb)")
c=$(signup "$jar.s" 'python-requests/2.32' "$(echo "$spage" | sed -E 's/name="(dr_[a-f0-9]{8})" value="[^"]*"/name="\1" value=""/')" verifrw8mfsrh "script$RANDOM@spam.example")
[ "$(users)" = 0 ] && ok "script posting without the page stamp gets no account ($c)" || ko "script account created"
page=$(curl -sL -c "$jar.p" -b "$jar.p" -A "$UA" "$SIGNUP?$(cb)"); sleep 4
r=$RANDOM
c=$(signup "$jar.p" "$UA" "$page" "marialab$r" "maria.lab$r@example.org")
[ "$(cnt "SELECT COUNT(*) FROM {user} WHERE email LIKE 'maria.lab%'")" = 1 ] && ok "person signs up normally ($c)" || { ko "person could not sign up ($c)"; grep -o 'class="[^"]*invalid-feedback[^"]*"[^>]*>[^<]\+' "$RESP" | head -3; }
[ "$(cnt "SELECT COUNT(*) FROM {local_dracoinsomnis_events} WHERE fields LIKE '%maria.lab%'")" = 0 ] && ok "the person leaves no trace" || ko "person logged"
$P "$MDH" deltest | sed 's/^/     /'
cfg shield 0
$P admin/cli/cfg.php --name=registerauth --set="$orig" >/dev/null
echo "     registerauth back to: [$($P admin/cli/cfg.php --name=registerauth)]"
reset

echo "== anti-copy pace"
cfg pace_mode block
cfg anticopy_rate_ip 10
while [ $(date +%S | sed "s/^0//") -gt 35 ]; do sleep 1; done
codes=""
# Counters are per calendar minute: a burst cut in two by the minute change needs a few more.
for i in $(seq 1 25); do c=$(code "$LOGIN?$(cb)"); codes="$codes $c"; [ "$c" = 429 ] && break; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
pe=$(cnt "SELECT COUNT(*) FROM {local_dracoinsomnis_events} WHERE endpoint LIKE 'anticopy_rate_ip'"); [ "$pe" = 1 ] && ok "one evidence line per minute" || ko "pace evidence: $pe lines"
$P -r 'define("CLI_SCRIPT", true); require getcwd()."/config.php"; $DB->delete_records_select("local_dracoinsomnis_cache", "k LIKE ?", ["draco_rl_%"]);'
while [ $(date +%S | sed "s/^0//") -gt 35 ]; do sleep 1; done
gcodes=""; for i in $(seq 1 25); do c=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$LOGIN?$(cb)"); gcodes="$gcodes $c"; [ "$c" = 429 ] && break; done
echo "     fake Googlebot codes:$gcodes"
[[ "$gcodes" == *429* ]] && ok "fake Googlebot is not trusted" || ko "fake googlebot never limited"
cfg pace_mode off
cfg anticopy_rate_ip 120
reset
rm -f "$jar" "$jar".* "$MDH" "$RESP"

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
