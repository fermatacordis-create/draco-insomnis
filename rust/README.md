# Draco Insomnis for Rust

The Draco Insomnis firewall for Rust web apps: a **tower Layer** for axum (and any tower or hyper
stack) and **actix-web middleware**. Same signatures and limits as the WordPress, CMS, server,
JavaScript, Python, Go, Ruby, .NET and Java editions; the Rust engine runs the same shared test cases
(`tests/vectors`), byte-wise with ASCII classes like PHP.

Until it is on crates.io, take `draco-insomnis-X.crate` from the release (a gzipped tar of the
sources), unpack it and point Cargo at it:

```sh
mkdir -p vendor/draco-insomnis && tar -xzf draco-insomnis-X.crate -C vendor/draco-insomnis --strip-components=1
```

```toml
[dependencies]
draco-insomnis = { path = "vendor/draco-insomnis", features = ["axum"] }   # or "actix"
```

Rust 1.85 or newer (the `actix` feature follows actix-web's own minimum).

## axum

```rust
use draco_insomnis::{DracoLayer, Gatekeeper, Options};
use std::{net::SocketAddr, sync::Arc};

let gate = Arc::new(Gatekeeper::new(Options { waf: "block".into(), pace: "block".into(), headers: true, ..Options::default() }));
let app = axum::Router::new()
    .route("/", axum::routing::get(|| async { "page" }))
    .layer(DracoLayer::new(gate)); // last, so it runs first
axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
```

`into_make_service_with_connect_info` lets Draco see the visitor's address. On other tower stacks,
put a `draco_insomnis::RemoteAddr(peer)` in the request extensions.

## actix-web

```rust
use draco_insomnis::{DracoMiddleware, Gatekeeper, Options};

let gate = std::sync::Arc::new(Gatekeeper::new(Options::from_env())); // DRACO_INSOMNIS_WAF=block ...
HttpServer::new(move || App::new().wrap(DracoMiddleware::new(gate.clone())).service(...))
```

## What it does

In this order: blocked addresses may read but not post or open sensitive pages; the country filter
(behind Cloudflare from its header, otherwise `geo.file`, a local list that downloads itself and is
checked against its published SHA-256); the firewall signatures (log or block; 5 attacks in 10
minutes block the address for 7 days); the anti-copy pace limit (HTML pages only; Google, Bing, Apple
and Yandex once the reverse DNS proves them). Forms and JSON bodies up to 64 KB are read once and
handed on unchanged. Security headers never replace the app's own. If Draco itself fails, the
request goes through.

| `Options` field | Default | |
| --- | --- | --- |
| `waf` | `"log"` | `"off"`, `"log"` or `"block"` |
| `pace` | `"off"` | `"off"`, `"log"` or `"block"`; `rate_ip`, `rate_net` (at least 10) |
| `proxy`, `trusted_proxies` | connection | `"cf"` or `"xff"`, and who may set them |
| `admin_ips`, `except`, `sensitive` | | never inspected; path prefixes never inspected; your own sensitive endings |
| `headers`, `hsts` | off | nosniff, frames, referrer, permissions; HSTS over HTTPS |
| `geo` | off | `GeoOptions { mode: "block" or "allow", countries, action: "log" or "block", scope: "sensitive" or "site", file }` |
| `review_secret` | off | 16+ characters; requests reach `on_review` (and the log) |
| `crowdsec_url`, `crowdsec_api_key` | off | the owner's CrowdSec Local API (`cscli bouncers add draco`) |
| `log_events` | off | every line of evidence as a JSON line on standard error |
| `texts` | English | the page texts, by key |

`Options::from_env()` reads `DRACO_INSOMNIS_WAF`, `DRACO_INSOMNIS_GEO_COUNTRIES` and so on (only
variables with that prefix); `Options::from_pairs` reads any flat key/value source.

The counters and the block list live in memory (one process). For several servers, implement `Store`
(`bump`, `get`, `set`, `delete`) on Redis and use `Gatekeeper::with_store`: the keys are the same as in
the other editions, so one Redis can serve apps in several languages.

`Gatekeeper` has `on_event`, `on_review`, `blocks()` (add, remove, list) and `crowdsec()` (`sync`).

Features: `dns` (default; the search-engine proof), `fetch` (default; country-list download and
CrowdSec, with ureq), `tower`, `axum`, `actix`.

## Building and tests

`bin/build-rust.sh` builds the `.crate`. `cargo test --all-features` in `rust/` runs the engine, the
shared vectors, the layer in axum and the middleware in actix-web; `rust/e2e/run.sh` runs the
packaged crate inside real axum and actix-web servers.
