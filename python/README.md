# Draco Insomnis for Python

The Draco Insomnis firewall for Python web apps, with **no dependencies**. It uses the same signatures
and limits as the WordPress, PrestaShop, Drupal, Joomla, Moodle, Laravel, Magento, server and
JavaScript editions, and runs the same shared test cases (`tests/vectors`), so every edition gives
the same answer to the same request.

| Where | How |
| --- | --- |
| FastAPI, Starlette, Django (ASGI), Quart, Litestar | `app.add_middleware(DracoASGI, …)` or `DracoASGI(app, …)` |
| Flask | `app.wsgi_app = DracoWSGI(app.wsgi_app, …)` |
| Django (WSGI) | `application = DracoWSGI(get_wsgi_application(), …)` |
| Anything else | `Gatekeeper(…).decide(DracoRequest(…))` |

Python 3.9 or newer.

## What it does

Draco checks requests in this order:

1. **Blocked addresses** can still read the site. They cannot post anything or open sensitive pages
   (login, sign-up and admin).
2. **Countries**, by default only for sensitive requests. Behind Cloudflare the country comes from
   Cloudflare; without it, from the monthly country list (see below).
3. **Firewall signatures**: SQL injection, path traversal, code injection, XSS in the URL, known
   scanners and probes for files like `.env` or `.git`, in the path, the query and the posted form or
   JSON (also when URL-encoded twice).
   - In `log` mode it only keeps evidence; in `block` mode it answers 403 with a page that never says
     which rule matched.
   - Five attacks in 10 minutes block the address for 7 days.
4. **Anti-copy pace**: pages a minute per address (default 120) and per /24 or /64 network (600),
   429 over the limit. Only HTML pages count. Google, Bing, Apple and Yandex may go faster once the
   reverse DNS proves who they are.

The visitor's address is the connection's own unless you choose `proxy="xff"` or `proxy="cf"`, and
even then the header is only believed from a trusted proxy (local and private networks by default,
`trusted_proxies` when you list them, Cloudflare's ranges for `cf`). If Draco itself fails, the
request goes through.

## FastAPI

```python
from fastapi import FastAPI
from draco_insomnis.asgi import DracoASGI

app = FastAPI()
app.add_middleware(DracoASGI, waf="block", pace="block", headers=True)
```

The engine runs in a worker thread, so the event loop never waits on it (it may ask the DNS to prove a
search engine). Forms and JSON bodies up to 64 KB are read once and handed to your app unchanged.

## Flask and Django

```python
from draco_insomnis.wsgi import DracoWSGI

app.wsgi_app = DracoWSGI(app.wsgi_app, waf="block")             # Flask
application = DracoWSGI(get_wsgi_application(), waf="block")    # Django, wsgi.py
```

## Options

| Option | Default | |
| --- | --- | --- |
| `waf` | `"log"` | `"off"`, `"log"` or `"block"` |
| `pace` | `"off"` | `"off"`, `"log"` or `"block"`; `rate_ip`, `rate_net` (at least 10) |
| `proxy`, `trusted_proxies` | connection | `"cf"` or `"xff"`, and who may set them |
| `admin_ips` | none | addresses never inspected nor limited |
| `except_paths` | none | path prefixes never inspected (health checks, signed webhooks) |
| `sensitive` | login, sign-up, admin, `/token` | path endings that count as sensitive, besides any POST |
| `headers`, `hsts` | off | nosniff, SAMEORIGIN, referrer and permissions policy; HSTS over HTTPS |
| `geo` | off | `{"mode": "block" or "allow", "countries": [...], "action": "log" or "block", "scope": "sensitive" or "site", "lookup": GeoFile(...)}` |
| `review` | off | `{"secret": "16+ characters", "on_request": callable}` |
| `crowdsec` | off | `{"url": "http://127.0.0.1:8080", "api_key": "..."}` |
| `store` | memory | anything with `bump`, `get`, `set`, `delete` (see below) |
| `on_event` | none | every line of evidence, as it is written |
| `texts` | English | the texts of the pages |

## Countries without Cloudflare

```python
from draco_insomnis import GeoFile

geo = GeoFile("/var/lib/myapp/draco-geo.bin")
app.add_middleware(DracoASGI, waf="block", geo={"mode": "block", "countries": ["XX"], "lookup": geo})
```

The same list as the other editions: DB-IP "IP to Country Lite" (CC BY 4.0), built monthly by this
project. It is downloaded on start when missing or older than 35 days, then checked once a day, and
only replaces the old file when the published SHA-256 matches. The lookup is local.

## "This is a mistake": review requests

```python
def mail_me(r):
    send_mail("Review", f"{r.email} ({r.ip}, rule {r.rule}): {r.message}")

app.add_middleware(DracoASGI, waf="block", review={"secret": os.environ["DRACO_SECRET"], "on_request": mail_me})
```

The 403 page carries a short form, signed for the address and the moment it was shown, with the rule
sealed, a trap field and 3 requests a day per address (50 per site). The visitor always gets the same
"Request sent" page. Draco never writes to the person who asks. Let someone through with
`gate.blocks.remove(ip)` or by adding the address to `admin_ips`.

## CrowdSec

```python
app.add_middleware(DracoASGI, waf="block", crowdsec={"url": "http://127.0.0.1:8080", "api_key": os.environ["CROWDSEC_KEY"]})
```

Bans from your own CrowdSec (key from `cscli bouncers add draco`) join the block list, synced in a
background thread at most once a minute. Ranges wider than /16 or /32 and `admin_ips` are never
imported; blocks you set yourself are never lifted by it. The other way, `crowdsec_line(event)` writes
evidence lines for the parser and scenario in `server/crowdsec`.

## Several processes

The default `MemoryStore` serves one process. With several workers or servers, give every one the
same `store`: any object with `bump(key, ttl) -> int`, `get(key)`, `set(key, value, ttl)` (ttl 0 = for
good) and `delete(key)`. With Redis that is `INCR` + `EXPIRE NX`, `GET`, `SET EX` and `DEL`. The keys
are the same as in the JavaScript edition, so a Node and a Python app can share one block list.

## Tests

```sh
cd python
PYTHONPATH=src python -m unittest discover -s tests -p "test_*.py"   # the engine, shared vectors
pip install fastapi uvicorn python-multipart flask django
PYTHONPATH=src python tests/e2e_frameworks.py                         # real FastAPI, Flask and Django
```
