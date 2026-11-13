#!/usr/bin/env bash
# End-to-end test of the PrestaShop module against a real shop (CI or a lab). Requests come from this
# machine, so any automatic block only hits its own address.
#   BASE=http://127.0.0.1 MYSQL="mysql -h127.0.0.1 -uroot -proot prestashop" tests/e2e/prestashop.sh
# Without MYSQL, run it in the shop root: the database is read through app/config/parameters.php.
set -uo pipefail
: "${BASE:?BASE is required}"
PHP="${PHP:-php}"
REG="${REGISTER_URL:-$BASE/index.php?controller=registration}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
pass=0; fail=0
ok() { echo "  OK   $1"; pass=$((pass+1)); }
ko() { echo "  FAIL $1"; fail=$((fail+1)); }

sql() {
  if [ -n "${MYSQL:-}" ]; then $MYSQL -N -B -e "$1" 2>/dev/null | tr '\t' '|'; return; fi
  $PHP -r '
    $p = (require "app/config/parameters.php")["parameters"];
    $db = new PDO("mysql:host=".$p["database_host"].";dbname=".$p["database_name"].";charset=utf8mb4", $p["database_user"], $p["database_password"]);
    $st = $db->query($argv[1]);
    if ($st && $st->columnCount()) { foreach ($st->fetchAll(PDO::FETCH_NUM) as $r) echo implode("|", $r), "\n"; }
  ' "$1"
}
setcfg() { sql "UPDATE ps_configuration SET value='$2', date_upd=NOW() WHERE name='$1'"; [ "$(sql "SELECT COUNT(*) FROM ps_configuration WHERE name='$1'")" = 1 ] || sql "INSERT INTO ps_configuration (name, value, date_add, date_upd) VALUES ('$1', '$2', NOW(), NOW())"; }
reset() { sql "DELETE FROM ps_draco_events"; sql "DELETE FROM ps_draco_blocks"; sql "DELETE FROM ps_draco_cache"; }
code() { curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$@"; }

echo "== tables"
[ "$(sql "SHOW TABLES LIKE 'ps_draco_%'" | wc -l)" = 3 ] && ok "3 tables created" || ko "tables"
[ "$(sql "SELECT LENGTH(value) FROM ps_configuration WHERE name='DRACO_SECRET'")" = 64 ] && ok "per-shop secret" || ko "secret"
reset

echo "== everything off: the shop works as before"
setcfg DRACO_SHIELD 0; setcfg DRACO_WAF_MODE off; setcfg DRACO_PACE_MODE off
c=$(code "$BASE/"); [ "$c" = 200 ] && ok "home 200" || ko "home $c"
c=$(code "$BASE/?q=1%27%20union%20select%20passwd%20from%20ps_employee--%20"); [ "$c" = 200 ] && ok "attack passes while off ($c)" || ko "off attack $c"

echo "== firewall: log only"
setcfg DRACO_WAF_MODE log
c=$(code "$BASE/?q=1%27%20union%20select%20passwd%20from%20ps_employee--%20"); [ "$c" = 200 ] && ok "log only lets it through" || ko "log $c"
r=$(sql "SELECT endpoint, verdict FROM ps_draco_events ORDER BY id_event DESC LIMIT 1"); [ "$r" = "waf:sqli|doubtful" ] && ok "logged as $r" || ko "log row: $r"
c=$(code "$BASE/?q=union+select+committee"); [ "$c" = 200 ] && ok "ordinary words pass" || ko "words $c"

echo "== firewall: block"
setcfg DRACO_WAF_MODE block
out=$(curl -s -w '\n%{http_code}' -A "$UA" "$BASE/?q=1%27%20union%20select%20passwd%20from%20ps_employee--%20")
[ "$(echo "$out" | tail -1)" = 403 ] && ok "attack gets 403" || ko "block $(echo "$out" | tail -1)"
echo "$out" | grep -q 'Ref\.' && ok "403 page without details" || ko "403 page"
c=$(curl -s -o /dev/null -w '%{http_code}' -A 'sqlmap/1.8' "$BASE/"); [ "$c" = 403 ] && ok "scanner gets 403" || ko "scanner $c"
c=$(code "$BASE/.env"); [ "$c" != 200 ] && ok ".env probe not served ($c)" || ko ".env $c"
for i in 1 2 3 4 5; do code "$BASE/?q=1%27%20union%20select%20passwd%20from%20ps_employee--%20" >/dev/null; done
[ "$(sql "SELECT COUNT(*) FROM ps_draco_blocks WHERE kind='ip'")" -ge 1 ] && ok "5 attacks block the address: $(sql "SELECT reason FROM ps_draco_blocks LIMIT 1")" || ko "auto block"
c=$(code "$BASE/"); [ "$c" = 200 ] && ok "blocked address can still browse" || ko "browse $c"
c=$(code -X POST -d 'x=1' "$BASE/"); [ "$c" = 403 ] && ok "blocked address cannot post" || ko "post $c"
setcfg DRACO_WAF_MODE off
reset

echo "== shield on sign-up"
setcfg DRACO_SHIELD 1
jar=$(mktemp)
page=$(curl -sL -c "$jar" -b "$jar" -A "$UA" "$REG")
stampf=$(echo "$page" | grep -o 'name="dr_[a-f0-9]\{8\}" value="[0-9]*\.[a-f0-9]*"' | head -1)
trapf=$(echo "$page" | grep -o 'name="[a-z_]*_[a-f0-9]\{4\}" value="" tabindex="-1"' | head -1 | sed 's/name="\([^"]*\)".*/\1/')
[ -n "$stampf" ] && ok "form has the page stamp" || ko "no stamp in form"
[ -n "$trapf" ] && ok "form has the trap field ($trapf)" || ko "no trap in form"
sname=$(echo "$stampf" | sed 's/name="\([^"]*\)".*/\1/'); sval=$(echo "$stampf" | sed 's/.*value="\([^"]*\)"/\1/')
fields=$(echo "$page" | grep -o 'name="\(psgdpr\|customer_privacy\|id_gender\)"' | sort -u | tr '\n' ' ')
echo "     extra fields in this form: $fields"
common=(-d submitCreate=1 -d id_gender=1 -d password=Draco-Lab-2026! -d psgdpr=1 -d customer_privacy=1)

before=$(sql "SELECT COUNT(*) FROM ps_customer")
curl -s -o /dev/null -c "$jar" -b "$jar" -A "$UA" "${common[@]}" -d firstname=Usru -d lastname=Qmqzydgrkv -d email="bot$RANDOM@spam.example" -d "$trapf=http://spam.example" "$REG"
[ "$(sql "SELECT COUNT(*) FROM ps_customer")" = "$before" ] && ok "bot gets no account" || ko "bot account created"
r=$(sql "SELECT endpoint, verdict, reasons FROM ps_draco_events ORDER BY id_event DESC LIMIT 1"); [[ "$r" == ps_register\|bot\|*honeypot* ]] && ok "kept as evidence: $r" || ko "evidence: $r"

curl -s -o /dev/null -A 'python-requests/2.32' "${common[@]}" -d firstname=Verifrw8 -d lastname=Mfsrh -d email="script$RANDOM@spam.example" "$REG"
[ "$(sql "SELECT COUNT(*) FROM ps_customer")" = "$before" ] && ok "script posting straight to the form gets no account" || ko "script account created"

sleep 4
email="maria.lab$RANDOM@example.org"
curl -s -o /dev/null -c "$jar" -b "$jar" -A "$UA" "${common[@]}" -d firstname=Maria -d lastname=Garcia -d email="$email" -d "$sname=$sval" "$REG"
[ "$(sql "SELECT COUNT(*) FROM ps_customer WHERE email='$email'")" = 1 ] && ok "person signs up normally" || ko "person could not sign up"
for id in $(sql "SELECT id_customer FROM ps_customer WHERE email LIKE 'maria.lab%@example.org' OR email LIKE '%@spam.example'"); do sql "DELETE FROM ps_customer_group WHERE id_customer=$id"; sql "DELETE FROM ps_customer WHERE id_customer=$id"; done; echo "     test accounts removed"
setcfg DRACO_SHIELD 0
rm -f "$jar"
reset

echo "== anti-copy pace"
setcfg DRACO_PACE_MODE block
setcfg DRACO_ANTICOPY_RATE_IP 10
codes=""
# Counters are per calendar minute: a burst cut in two by the minute change needs a few more.
for i in $(seq 1 25); do c=$(code "$BASE/"); codes="$codes $c"; [ "$c" = 429 ] && break; done
echo "     codes:$codes"
[[ "$codes" == *429* ]] && ok "past 10 pages a minute: 429" || ko "no 429"
[ "$(sql "SELECT COUNT(*) FROM ps_draco_events WHERE endpoint='anticopy:rate_ip'")" = 1 ] && ok "one evidence line per minute" || ko "pace evidence"
gcodes=""; for i in $(seq 1 25); do c=$(curl -s -o /dev/null -w '%{http_code}' -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "$BASE/"); gcodes="$gcodes $c"; [ "$c" = 429 ] && break; done
echo "     fake Googlebot codes:$gcodes"
[[ "$gcodes" == *429* ]] && ok "fake Googlebot is not trusted" || ko "fake googlebot never limited"
setcfg DRACO_PACE_MODE off
setcfg DRACO_ANTICOPY_RATE_IP 120
reset

echo "== done: $pass ok, $fail failed"
[ "$fail" = 0 ]
