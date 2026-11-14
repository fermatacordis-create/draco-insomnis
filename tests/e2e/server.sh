#!/usr/bin/env bash
# End-to-end test of Draco Insomnis Server on a real web server with the package installed and
# "draco enable" done. BASE is a PHP page of a site served by PHP-FPM or Apache:
#   BASE=http://127.0.0.1 DRACO="sudo draco" tests/e2e/server.sh
set -uo pipefail
: "${BASE:?BASE is required}"
DRACO="${DRACO:-sudo draco}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
n=0; cb() { n=$((n+1)); echo "cb=$$-$n-$RANDOM"; }
attack() { echo "$BASE/index.php?$(cb)&q=1%27%20union%20select%20password%20from%20users--%20"; }
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }
val() { grep -o "name=\"$2\" value=\"[^\"]*\"" <<< "$1" | head -1 | sed 's/.*value="\([^"]*\)"/\1/'; }
U=(); [ -n "${PHPUSER:-}" ] && U=(--user="$PHPUSER")
d() { $DRACO "$@" "${U[@]}"; }
dset() { $DRACO set "$@" >/dev/null; }
q() { # one SQL query on the evidence of the site's PHP user
  sudo php -r '$f = glob("/var/lib/draco-insomnis/u*/draco.sqlite"); $db = new PDO("sqlite:" . $f[0]); foreach ($db->query($argv[1])->fetchAll(PDO::FETCH_NUM) as $r) echo implode("|", $r), "\n";' "$1"
}
reset() { q "DELETE FROM events" >/dev/null; q "DELETE FROM blocks" >/dev/null; q "DELETE FROM cache" >/dev/null; }

echo "== installed and loaded"
$DRACO status | sed 's/^/     /'
$DRACO status | grep -q 'Loaded in: /etc' && ok "loaded in PHP" || ko "not loaded"
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "site answers 200" || ko "site $c"
[ -n "$(q 'SELECT 1')" ] && ok "evidence store made by the site's PHP user" || ko "no store"
reset

echo "== firewall: log only (the default)"
dset waf_mode log
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "log only lets it through" || ko "log $c"
r=$(q "SELECT endpoint, verdict FROM events ORDER BY id DESC LIMIT 1"); [ "$r" = "waf:sqli|doubtful" ] && ok "logged as $r" || ko "log row: $r"
c=$(code "$BASE/index.php?$(cb)&q=union+select+committee"); [ "$c" = 200 ] && ok "ordinary words pass" || ko "words $c"
[ "$(q 'SELECT COUNT(*) FROM events')" = 1 ] && ok "ordinary words leave no trace" || ko "false positive logged"
php -r 'echo 1;' >/dev/null && ok "command line PHP is never touched"

echo "== firewall: block"
dset waf_mode block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$(attack)")
[ "$(tail -1 <<< "$out")" = 403 ] && ok "attack gets 403" || ko "block $(tail -1 <<< "$out")"
grep -q 'Ref\.' <<< "$out" && ok "403 page without details" || ko "403 page"
grep -q 'sqli' <<< "$out" && ko "the block page names the rule" || ok "the block page never says which rule matched"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.8' "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "scanner gets 403" || ko "scanner $c"
for i in 1 2 3 4; do code "$(attack)" >/dev/null; done
[ "$(q "SELECT COUNT(*) FROM blocks WHERE kind='ip'")" -ge 1 ] && ok "5 attacks block the address: $(q 'SELECT reason FROM blocks LIMIT 1')" || ko "auto block"
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "blocked address can still read" || ko "read $c"
c=$(code -X POST -d 'x=1' "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "blocked address cannot post" || ko "post $c"
reset

echo "== review request from the block page"
page=$(curl -s -A "$UA" "$(attack)")
ts=$(val "$page" draco_ts); sig=$(val "$page" draco_sig); rule=$(val "$page" draco_rule)
[ -n "$sig" ] && ok "block page carries the signed review form" || ko "no review form"
c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -d draco_review=1 -d "draco_rule=$rule" -d "draco_ts=$ts" -d "draco_sig=$sig" -d draco_website= \
  -d draco_email=maria@example.org -d 'draco_message=I was searching the shop' "$BASE/index.php?$(cb)")
[ "$c" = 200 ] && ok "review request accepted" || ko "review $c"
r=$(q "SELECT verdict, reasons FROM events WHERE endpoint='review'"); [[ "$r" == pending\|*sqli* ]] && ok "queued for the owner with the rule: $r" || ko "queue: $r"
id=$(q "SELECT id FROM events WHERE endpoint='review'")
d reviews | grep -q 'maria@example.org' && ok "draco reviews lists it" || ko "reviews list"
d reviews "$id" --approve=1 >/dev/null && ok "approved for 1 day" || ko "approve"
c=$(code "$(attack)"); [ "$c" = 200 ] && ok "approved address passes the firewall" || ko "approved still $c"
reset

echo "== firewall test"
out=$(d test "$BASE/index.php"); [[ "$out" == Works:*blocked* ]] && ok "draco test: $out" || ko "test: $out"
[ "$(q "SELECT COUNT(*) FROM events")" = 0 ] && ok "the test leaves no evidence" || ko "test logged"

echo "== range blocked forever, by hand"
me=$(q "SELECT 1" >/dev/null; curl -s "$BASE/ip.php")
net=$(php -r '$b = inet_pton($argv[1]); $v6 = strlen($b) === 16; $keep = $v6 ? 6 : 3; $b = substr($b, 0, $keep) . str_repeat("\0", strlen($b) - $keep); echo inet_ntop($b), $v6 ? "/48" : "/24";' "$me")
d block "$net" 0 "e2e range" >/dev/null && ok "draco block $net forever" || ko "block range"
c=$(code "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "range can read" || ko "range read $c"
c=$(code -X POST -d x=1 "$BASE/index.php?$(cb)"); [ "$c" = 403 ] && ok "range cannot post" || ko "range post $c"
d block 10.0.0.0/8 30 wide >/dev/null 2>&1 && ko "a /8 was accepted" || ok "a range wider than /16 is refused"
reset

echo "== security headers"
dset headers 1
h=$(curl -sI -A "$UA" "$BASE/index.php?$(cb)")
grep -qi '^X-Content-Type-Options: nosniff' <<< "$h" && ok "nosniff sent" || ko "no nosniff"
grep -qi '^X-Frame-Options: DENY' <<< "$(curl -sI -A "$UA" "$BASE/own-header.php")" && ok "the application's own header wins" || ko "own header replaced"
dset headers 0

echo "== per-site settings"
dset waf_mode log
$DRACO set waf_mode block --site=127.0.0.1 >/dev/null
c=$(code "$(attack)"); [ "$c" = 403 ] && ok "[site:127.0.0.1] blocks while the default only logs" || ko "site section $c"
sudo sed -i '/^\[site:127.0.0.1\]/,$d' /etc/draco-insomnis/draco.ini
reset

echo "== anti-copy pace"
dset waf_mode off; dset pace_mode block; dset anticopy_rate_ip 10
codes=""
for i in $(seq 1 25); do c=$(code -H 'Accept: text/html' "$BASE/index.php?$(cb)"); codes="$codes $c"; [ "$c" = 429 ] && break; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
c=$(code -H 'Accept: application/json' "$BASE/index.php?$(cb)"); [ "$c" = 200 ] && ok "API calls do not count" || ko "api $c"
dset pace_mode off; dset anticopy_rate_ip 120; dset waf_mode log
reset

echo "== disable"
$DRACO disable >/dev/null
c=$(code "$(attack)"); [ "$c" = 200 ] && [ "$(q 'SELECT COUNT(*) FROM events')" = 0 ] && ok "after draco disable nothing is inspected" || ko "still active ($c)"
$DRACO enable >/dev/null

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
