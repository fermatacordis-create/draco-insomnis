#!/usr/bin/env bash
# End-to-end test of Draco Insomnis in front of a real PHP application that has no Draco plugin of its
# own (MediaWiki, TYPO3…), loaded by the server edition or the Docker add-on.
#   APP=MediaWiki BASE=http://127.0.0.1:8090 HOME_PATH=/index.php MARK="Draco Wiki" LOGIN_PATH=/index.php/Special:UserLogin \
#   DRACO="docker exec mw php /opt/draco/share/bin/draco" SUDO="docker exec mw" STATE=/opt/draco/state INI=/opt/draco/draco.ini \
#   RELOAD="docker exec mw apachectl -k graceful" TEST_URL=http://127.0.0.1/index.php tests/e2e/apps.sh
set -uo pipefail
: "${BASE:?}" "${APP:?}" "${HOME_PATH:?}" "${MARK:?}" "${LOGIN_PATH:?}" "${DRACO:?}"
SUDO="${SUDO-sudo}"; STATE="${STATE:-/var/lib/draco-insomnis}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
n=0; cb() { n=$((n+1)); echo "cb=$$-$n-$RANDOM"; }
sep() { [[ "$1" == *\?* ]] && echo '&' || echo '?'; }
HOME_URL="$BASE$HOME_PATH"
attack() { echo "$HOME_URL$(sep "$HOME_PATH")$(cb)&search=1%27%20union%20select%20password%20from%20users--%20"; }
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }
val() { grep -o "name=\"$2\" value=\"[^\"]*\"" <<< "$1" | head -1 | sed 's/.*value="\([^"]*\)"/\1/'; }
reload() { if [ -n "${RELOAD:-}" ]; then eval "$RELOAD" >/dev/null 2>&1; sleep 2; fi; }
q() { $SUDO php -r '$f = glob($argv[2] . "/u*/draco.sqlite"); if (!$f) exit; $db = new PDO("sqlite:" . $f[0]); foreach ($db->query($argv[1])->fetchAll(PDO::FETCH_NUM) as $r) echo implode("|", $r), "\n";' "$1" "$STATE"; }
reset() { q "DELETE FROM events" >/dev/null; q "DELETE FROM blocks" >/dev/null; q "DELETE FROM cache" >/dev/null; }
dset() { $DRACO set "$@" >/dev/null; }

echo "== $APP works with Draco loaded"
page=$(curl -s -L -A "$UA" "$HOME_URL")
grep -q "$MARK" <<< "$page" && ok "$APP answers ($MARK)" || ko "$APP page without \"$MARK\""
st=$($DRACO status); grep -q 'Loaded in: /' <<< "$st" && ok "Draco loaded in the app's PHP" || ko "not loaded"
c=$(code -L "$BASE$LOGIN_PATH"); [ "$c" = 200 ] && ok "login page 200" || ko "login page $c"
reset

echo "== log first: nothing changes for the app"
dset waf_mode log
c=$(code -L "$(attack)"); [[ "$c" != 403 ]] && ok "attack only written down ($c)" || ko "log mode blocked"
r=$(q "SELECT endpoint FROM events ORDER BY id DESC LIMIT 1"); [ "$r" = "waf:sqli" ] && ok "evidence: $r" || ko "no evidence: [$r]"
c=$(code -L "$HOME_URL$(sep "$HOME_PATH")$(cb)&search=union+select+committee+from+the+city"); [ "$c" != 403 ] && ok "ordinary search words pass ($c from the app)" || ko "words $c"
[ "$(q 'SELECT COUNT(*) FROM events')" = 1 ] && ok "and leave no trace" || ko "false positive"

echo "== block"
dset waf_mode block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$(attack)")
[ "$(tail -1 <<< "$out")" = 403 ] && ok "attack gets Draco's 403" || ko "block $(tail -1 <<< "$out")"
grep -q 'sqli' <<< "$out" && ko "the block page names the rule" || ok "the block page never says which rule matched"
for i in 1 2 3 4; do code "$(attack)" >/dev/null; done
[ "$(q "SELECT COUNT(*) FROM blocks WHERE kind='ip'")" -ge 1 ] && ok "5 attacks block the address" || ko "auto block"
page=$(curl -s -L -A "$UA" "$HOME_URL")
grep -q "$MARK" <<< "$page" && ok "a blocked address can still read $APP" || ko "blocked address cannot read"
c=$(code -X POST -d 'wpName=x&username=x' "$BASE$LOGIN_PATH"); [ "$c" = 403 ] && ok "but cannot use the login page" || ko "login post $c"

echo "== review request from the block page"
page=$(curl -s -A "$UA" "$(attack)")
ts=$(val "$page" draco_ts); sig=$(val "$page" draco_sig); rule=$(val "$page" draco_rule)
c=$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -d draco_review=1 -d "draco_rule=$rule" -d "draco_ts=$ts" -d "draco_sig=$sig" -d draco_website= \
  -d draco_email=maria@example.org -d 'draco_message=I was searching' "$HOME_URL")
[ "$c" = 200 ] && [ "$(q "SELECT verdict FROM events WHERE endpoint='review'")" = pending ] && ok "review queued for the owner" || ko "review ($c)"
id=$(q "SELECT id FROM events WHERE endpoint='review'")
$DRACO reviews "$id" --approve=1 >/dev/null && c=$(code -X POST -d 'wpName=x' "$BASE$LOGIN_PATH") && [ "$c" != 403 ] && ok "approved: the login page works again ($c)" || ko "approve ($c)"
reset

echo "== firewall test"
out=$($DRACO test "${TEST_URL:-$HOME_URL}" 2>&1); [[ "$out" == Works:*blocked* ]] && ok "draco test: $out" || ko "test: $out"

echo "== disable"
$DRACO disable >/dev/null; reload
c=$(code "$(attack)"); [ "$c" != 403 ] && ok "after draco disable $APP gets everything ($c)" || ko "still blocking"
$DRACO enable >/dev/null; reload
dset waf_mode log
reset

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
