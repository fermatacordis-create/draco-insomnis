#!/usr/bin/env bash
# Draco in real Caddy (built with xcaddy and the module) and real Traefik v3 (local plugin, run by
# Yaegi), both in front of the same small app. Needs Docker and python3.
set -uo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
work=$(mktemp -d)
cleanup() { docker rm -f draco-caddy draco-traefik >/dev/null 2>&1; kill "$app" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   - $1"; else echo "FAIL - $1 (expected '$2', got '$3')"; fails=$((fails + 1)); fi; }
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36'
SECRET=owner-secret-0123456789

# The app behind the proxies: echoes the "name" field of a posted form; /own sets its own X-Frame-Options.
cat > "$work/app.py" <<'PY'
import http.server, urllib.parse
class H(http.server.BaseHTTPRequestHandler):
    def reply(self, body):
        self.send_response(200)
        if self.path.startswith("/own"):
            self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        self.reply("page")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(n).decode())
        self.reply("name=" + form.get("name", [""])[0])
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", 18100), H).serve_forever()
PY
python3 "$work/app.py" & app=$!

# Caddy with the module, built by xcaddy from this checkout.
mkdir -p "$work/bin"
docker run --rm -e GOTOOLCHAIN=auto -e GOFLAGS=-mod=mod -v draco-gomod:/root/go -v "$root/go":/src/go -v "$work/bin":/out golang:1.26 sh -c '
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest >/dev/null 2>&1 &&
  xcaddy build --output /out/caddy \
    --with github.com/fermatacordis-create/draco-insomnis/go/draco=/src/go/draco \
    --with github.com/fermatacordis-create/draco-insomnis/go/caddy=/src/go/caddy >/tmp/build.log 2>&1 || { tail -20 /tmp/build.log; exit 1; }
  chown '"$(id -u):$(id -g)"' /out/caddy' || { echo "xcaddy build failed"; exit 1; }
cat > "$work/Caddyfile" <<CADDY
{
	admin off
	auto_https off
}
:18101 {
	draco_insomnis {
		waf block
		pace block
		rate_ip 10
		headers
		review_secret $SECRET
		log_events
	}
	reverse_proxy 127.0.0.1:18100
}
CADDY
docker run -d --name draco-caddy --network host -v "$work/bin/caddy":/caddy:ro -v "$work/Caddyfile":/Caddyfile:ro debian:stable-slim /caddy run --config /Caddyfile --adapter caddyfile >/dev/null

# Traefik v3 with Draco as a local plugin (interpreted by Yaegi, as from the plugin catalog).
cat > "$work/dynamic.yml" <<YML
http:
  routers:
    app:
      rule: PathPrefix(\`/\`)
      entryPoints: [web]
      middlewares: [draco]
      service: app
  middlewares:
    draco:
      plugin:
        draco:
          waf: block
          pace: block
          rateIp: 10
          headers: true
          logEvents: true
          review:
            secret: $SECRET
  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:18100
YML
docker run -d --name draco-traefik --network host \
  -v "$root/go/draco":/plugins-local/src/github.com/fermatacordis-create/draco-insomnis/go/draco:ro -v "$work/dynamic.yml":/dynamic.yml:ro \
  traefik:v3.6 --entryPoints.web.address=:18102 --providers.file.filename=/dynamic.yml \
  --experimental.localPlugins.draco.moduleName=github.com/fermatacordis-create/draco-insomnis/go/draco --log.level=INFO >/dev/null

for port in 18101 18102; do
  for i in $(seq 1 60); do [ "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "http://127.0.0.1:$port/")" = 200 ] && break; sleep 1; done
done

ATTACK='/search?q=1%27%20union%20select%20password%20from%20users--%20'
for proxy in caddy:18101 traefik:18102; do
  name=${proxy%%:*}; port=${proxy##*:}; base="http://127.0.0.1:$port"
  echo "# $name"
  h=$(curl -s -D - -o /dev/null -A "$UA" "$base/")
  check "$name: an ordinary page passes" 1 "$(grep -c '^HTTP/1.1 200' <<< "$h")"
  check "$name: security headers are added" 1 "$(grep -ci '^x-content-type-options: nosniff' <<< "$h")"
  check "$name: the app's own header wins" DENY "$(curl -s -D - -o /dev/null -A "$UA" "$base/own" | grep -i '^x-frame-options:' | tr -d '\r' | awk '{print $2}')"
  page=$(curl -s -w '\n%{http_code}' -A "$UA" "$base$ATTACK")
  check "$name: SQL injection gets 403" 403 "$(tail -1 <<< "$page")"
  check "$name: the page never names the rule" 0 "$(grep -c sqli <<< "$page")"
  check "$name: .env probe gets 403" 403 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" "$base/.env")"
  check "$name: a posted form is inspected" 403 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" --data-urlencode "message=x'; DROP TABLE users; --" "$base/contact")"
  check "$name: a JSON body is inspected" 403 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -H 'Content-Type: application/json' --data "{\"q\": \"' OR '1'='1\"}" "$base/api")"
  check "$name: the app still reads the body" "name=Ana" "$(curl -s -A "$UA" --data 'name=Ana' "$base/echo")"
  fields=$(grep -o '<input type="hidden" name="[a-z_]*" value="[^"]*"' <<< "$page" | sed 's/.*name="\([^"]*\)" value="\([^"]*\)"/--data-urlencode \1=\2/' | tr '\n' ' ')
  thanks=$(curl -s -w '\n%{http_code}' -A "$UA" $fields --data-urlencode draco_email=ana@example.org --data-urlencode "draco_message=I was searching" --data-urlencode draco_website= "$base$ATTACK")
  check "$name: the review request is thanked" 200 "$(tail -1 <<< "$thanks")"
  sleep 1
  check "$name: and reaches the log" 1 "$(docker logs "draco-$name" 2>&1 | grep -c 'ana@example.org' | awk '{print ($1 > 0)}')"
  codes=""
  for i in $(seq 1 14); do codes="$codes $(curl -s -o /dev/null -w '%{http_code}' -A "$UA" -H 'Accept: text/html' "$base/p$i")"; done
  check "$name: too many pages in a minute get 429" 1 "$(grep -c 429 <<< "$codes")"
done

echo
if [ "$fails" -gt 0 ]; then
  docker logs draco-traefik 2>&1 | grep -i -E "panic|error|ERR" | head -12
  echo "$fails check(s) failed"; exit 1
fi
echo "all proxy checks passed"
