# Draco Insomnis for Go: Caddy, Traefik and net/http

The Draco Insomnis firewall in front of **any app, in any language**, from the proxy that already sits
in front of it. Same signatures and limits as the WordPress, CMS, server, JavaScript and Python
editions: the Go engine runs the same shared test cases (`tests/vectors/waf.json`, `review.json`).

| Where | How |
| --- | --- |
| **Caddy** | `xcaddy build --with github.com/fermatacordis-create/draco-insomnis/go/caddy@vX.Y.Z`, then the `draco_insomnis` directive |
| **Traefik** v3 | the plugin in `go/draco` (local plugin, interpreted by Yaegi) |
| **Go apps** | `draco.NewGatekeeper(cfg, nil).Handler(mux)` |

`go/draco` is the engine, standard library only (Traefik interprets plugins and allows no other
dependency). `go/caddy` is the Caddy module, a separate Go module so Caddy's dependencies never reach
the engine.

What it does, in this order: blocked addresses may read but not post or open sensitive pages; the
country filter (behind Cloudflare from its header, otherwise from the monthly country list with
`geo.file`); the firewall signatures (log or block; 5 attacks in 10 minutes block the address for 7
days); the anti-copy pace limit (HTML pages only; Google, Bing, Apple and Yandex once the reverse DNS
proves them). Security headers are added when the answer starts and never replace the app's own.
Forms and JSON bodies up to 64 KB are read once and handed on unchanged; streaming and WebSockets
keep working. If Draco itself fails, the request goes through.

## Caddy

```
example.com {
	draco_insomnis {
		waf block              # off | log (default) | block
		pace block             # off (default) | log | block
		rate_ip 120
		headers                # nosniff, frames, referrer, permissions
		hsts
		proxy xff              # only behind another proxy; believed from trusted_proxies
		trusted_proxies 10.0.0.0/8
		admin_ips 203.0.113.7
		except /webhooks
		geo_mode block
		geo_countries XX YY
		geo_action block
		geo_file /var/lib/caddy/draco-geo.bin
		review_secret {env.DRACO_SECRET}
		crowdsec_url http://127.0.0.1:8080
		crowdsec_api_key {env.CROWDSEC_KEY}
		log_events             # evidence and review requests in Caddy's log
	}
	reverse_proxy localhost:8080
}
```

The directive runs before `header`, `reverse_proxy` and `file_server`. JSON config: the handler
`draco_insomnis` takes the same fields as `draco.Config`.

## Traefik

Traefik's plugin catalog only lists repositories whose root is the plugin, so for now run it as a
**local plugin**: copy `go/draco` of a release to
`plugins-local/src/github.com/fermatacordis-create/draco-insomnis/go/draco` next to Traefik, and:

```yaml
# static configuration
experimental:
  localPlugins:
    draco:
      moduleName: github.com/fermatacordis-create/draco-insomnis/go/draco

# dynamic configuration
http:
  middlewares:
    draco:
      plugin:
        draco:
          waf: block
          pace: block
          headers: true
          logEvents: true
          review:
            secret: a-secret-of-16-or-more-characters
```

`logEvents` writes every line of evidence and every review request as JSON to Traefik's log.

## net/http

```go
gate := draco.NewGatekeeper(draco.Config{WAF: "block", Pace: "block", Headers: true}, nil)
gate.LogTo(log.Default())
http.ListenAndServe(":8080", gate.Handler(mux))
```

`Store` is an interface (`Bump`, `Get`, `Set`, `Delete`) with the same keys as the JavaScript and
Python editions: one Redis can hold the block list of apps in all three languages.

## Tests

```sh
cd go/draco && go test -race ./...     # the engine and the shared vectors
go/test/proxies.sh                      # real Caddy (xcaddy) and Traefik v3 in front of an app (Docker)
```
