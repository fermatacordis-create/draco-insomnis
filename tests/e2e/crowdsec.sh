#!/usr/bin/env bash
# End-to-end: Draco (Docker add-on, volume mode) and a real CrowdSec, both ways.
set -uo pipefail
cd "$(dirname "$0")/../.."
P=${PORT:-8080}
pass=0; fail=0; ok() { echo "  OK   $1"; pass=$((pass+1)); }; ko() { echo "  FAIL $1"; fail=$((fail+1)); }
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36'
docker rm -f cs csapp >/dev/null 2>&1; docker volume rm -f draco-cs cs-data >/dev/null 2>&1; docker network rm dnet >/dev/null 2>&1
docker network create dnet >/dev/null
bin/build-docker.sh draco-insomnis:test >/dev/null 2>&1
docker run --rm -v draco-cs:/opt/draco draco-insomnis:test >/dev/null
C=server/crowdsec; W=$(mktemp -d); chmod 755 "$W"
printf '<?php echo "app ok";\n' > "$W/index.php"; printf '<?php echo $_SERVER["REMOTE_ADDR"];\n' > "$W/ip.php"
printf 'filenames:\n  - /opt/draco/state/u*/events.log\nlabels:\n  type: draco-insomnis\n' > "$W/acquis.yaml"
docker run -d --name cs --network dnet -e DISABLE_ONLINE_API=true -v cs-data:/var/lib/crowdsec/data -v draco-cs:/opt/draco:ro \
  -v "$PWD/$C/draco-insomnis-raw.yaml:/etc/crowdsec/parsers/s00-raw/draco-insomnis-raw.yaml:ro" \
  -v "$PWD/$C/draco-insomnis-logs.yaml:/etc/crowdsec/parsers/s01-parse/draco-insomnis-logs.yaml:ro" \
  -v "$PWD/$C/draco-insomnis-attacks.yaml:/etc/crowdsec/scenarios/draco-insomnis-attacks.yaml:ro" \
  -v "$W/acquis.yaml:/etc/crowdsec/acquis.d/draco-insomnis.yaml:ro" crowdsecurity/crowdsec:latest >/dev/null
docker run -d --name csapp --network dnet -p $P:80 -e PHP_INI_SCAN_DIR=:/opt/draco/conf.d -v draco-cs:/opt/draco -v "$W":/var/www/html:ro php:8.2-apache >/dev/null
for i in $(seq 1 60); do docker exec cs cscli lapi status >/dev/null 2>&1 && break; sleep 2; done
docker exec cs cscli lapi status >/dev/null 2>&1 && ok "CrowdSec Local API up" || ko "CrowdSec not ready"
KEY=$(docker exec cs cscli bouncers add draco -o raw 2>/dev/null | tail -1)
D="docker exec csapp php /opt/draco/share/bin/draco"
B=http://127.0.0.1:$P
curl -s $B/index.php >/dev/null
me=$(curl -s $B/ip.php); echo "     the app sees us as $me"
$D set waf_mode block >/dev/null; $D set crowdsec_lapi_url http://cs:8080 >/dev/null; $D set crowdsec_api_key "$KEY" >/dev/null; $D set crowdsec_log 1 >/dev/null
st=$($D crowdsec); grep -q 'Bouncer key: set' <<< "$st" && ok "draco crowdsec: configured" || ko "config: $st"

echo "== in: a CrowdSec ban becomes a Draco block"
docker exec cs cscli decisions add -i "$me" -d 10m -R "e2e test" >/dev/null 2>&1
out=$($D crowdsec sync); grep -q '+1 bans' <<< "$out" && ok "sync: $out" || ko "sync: $out"
c=$(curl -s -o /dev/null -w %{http_code} -A "$UA" $B/index.php); [ "$c" = 200 ] && ok "banned address can still read" || ko "read $c"
c=$(curl -s -o /dev/null -w %{http_code} -A "$UA" -X POST -d x=1 $B/index.php); [ "$c" = 403 ] && ok "but not post (403)" || ko "post $c"
grep -q '1 CrowdSec bans in force' <<< "$($D crowdsec)" && ok "draco crowdsec counts it" || ko "count"
docker exec cs cscli decisions delete -i "$me" >/dev/null 2>&1
out=$($D crowdsec sync); grep -q -- '-1' <<< "$out" && ok "lifted in CrowdSec, lifted in Draco: $out" || ko "unsync: $out"
c=$(curl -s -o /dev/null -w %{http_code} -A "$UA" -X POST -d x=1 $B/index.php); [ "$c" = 200 ] && ok "posting works again" || ko "post after lift $c"
docker exec cs cscli decisions add -i "$me" -d 10m -R "e2e auto" >/dev/null 2>&1
$D crowdsec >/dev/null; sleep 61
c=$(curl -s -o /dev/null -w %{http_code} -A "$UA" -X POST -d x=1 $B/index.php); [ "$c" = 403 ] && ok "without the command, the guard syncs by itself within a minute" || ko "auto sync $c"
docker exec cs cscli decisions delete -i "$me" >/dev/null 2>&1; $D crowdsec sync >/dev/null

echo "== out: Draco's attacks reach CrowdSec"
for i in 1 2 3; do curl -s -o /dev/null -A "$UA" "$B/index.php?q=1%27%20union%20select%20password%20from%20users--%20"; done
log=$(docker exec csapp sh -c 'cat /opt/draco/state/u*/events.log'); n=$(grep -c '"verdict":"bot"' <<< "$log")
[ "$n" -ge 3 ] && ok "events.log has the attacks ($n lines)" || ko "events.log: $log"
# CrowdSec watches the folders that exist when it starts: reload it once the PHP user's folder is there.
docker restart cs >/dev/null; for i in $(seq 1 60); do docker exec cs cscli lapi status >/dev/null 2>&1 && break; sleep 2; done; sleep 3
# The test runs from a private address, which CrowdSec whitelists; a public test address shows the scenario.
docker exec csapp sh -c 'f=$(ls /opt/draco/state/u*/events.log | head -1); for i in 1 2 3 4 5 6; do echo "{\"time\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"ip\":\"203.0.113.77\",\"host\":\"example.org\",\"endpoint\":\"waf:sqli\",\"verdict\":\"bot\",\"reasons\":\"waf_sqli\",\"user_agent\":\"sqlmap\"}" >> "$f"; done'
for i in $(seq 1 30); do docker exec cs cscli alerts list -o raw 2>/dev/null | grep -q 'draco-insomnis/attacks' && break; sleep 2; done
alerts=$(docker exec cs cscli alerts list -o raw 2>/dev/null)
grep -q 'draco-insomnis/attacks' <<< "$alerts" && ok "CrowdSec alert from Draco's scenario: $(grep draco-insomnis <<< "$alerts" | head -1 | cut -c1-90)" || ko "no alert"
docker exec cs cscli decisions list -o raw 2>/dev/null | grep -q '203.0.113.77' && ok "and CrowdSec bans 203.0.113.77 for its other bouncers" || ko "no ban"
docker exec cs cscli metrics 2>/dev/null | grep -i 'draco' | head -4 | sed 's/^/     /'
echo "== done: $pass ok, $fail failed"
docker rm -f cs csapp >/dev/null; docker volume rm draco-cs cs-data >/dev/null; docker network rm dnet >/dev/null; rm -rf "$W"
[ "$fail" = 0 ]
