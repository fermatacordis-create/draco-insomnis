# Draco Insomnis for JavaScript

The Draco Insomnis firewall for Node.js and Cloudflare Workers, with **no dependencies**. It uses the same
signatures as the WordPress, PrestaShop, Drupal, Joomla, Moodle, Laravel and server editions. Both
languages run the same test cases (`tests/vectors/waf.json`), so they give the same answer to every
request in that file.

| Where | Import |
| --- | --- |
| Express 4/5, Connect, plain `node:http` | `draco-insomnis/express` → `draco()` |
| Directus (hook extension) | `draco-insomnis/express` → `directus()` |
| Koa | `draco-insomnis/koa` → `draco()` |
| Strapi 4/5 (Koa middleware) | `draco-insomnis/koa` → `strapi` |
| Cloudflare Workers, Deno, Bun (`fetch` handlers) | `draco-insomnis/worker` → `withDraco()` |
| Anything else | `draco-insomnis` → `Gatekeeper` |

## What it does

Draco checks requests in this order:

1. **Blocked addresses** can still read the site. They cannot post anything or open sensitive pages
   (login, sign-up and admin).
2. **Countries**. Behind Cloudflare the country comes from Cloudflare (`request.cf.country` in
   Workers, `CF-IPCountry` when the request really comes from Cloudflare). In Node.js without
   Cloudflare, give it the country list (see [Countries without Cloudflare](#countries-without-cloudflare)).
   By default it applies to sensitive requests only.
3. **Firewall signatures** look for SQL injection, path traversal, code injection, XSS in the URL,
   known scanners and probes for files like `.env` or `.git`. They read the path, the query and the
   parsed body, including nested JSON, and also check values that were URL-encoded twice.
   - In `log` mode it only writes evidence.
   - In `block` mode it answers 403 with a page that never says which rule matched.
   - Five attacks in 10 minutes block the address for 7 days.
4. **Anti-copy pace** limits pages a minute per address (default 120) and per /24 or /64 network
   (default 600), and answers 429 over the limit.
   - Only HTML pages count, not API calls, images or scripts.
   - Google, Bing, Apple and Yandex may go faster, but only once the reverse DNS proves who they are.

The **visitor's address** is the connection's own unless you choose `proxy: 'xff'` or `proxy: 'cf'`.
Even then, Draco only believes the header when the connection comes from a trusted proxy: local and
private networks by default, `trustedProxies` when you list them, and Cloudflare's published ranges
for `cf`. X-Forwarded-For is read from the right. Anyone can send these headers, so a forged one never
gets someone else blocked.

If Draco itself fails (for example, the store is unreachable), the request goes through. Draco never
takes the site down with it.

## Install

```sh
npm install draco-insomnis
# or the same file from the GitHub release (signed, see SECURITY.md):
npm install ./draco-insomnis-js-X.Y.Z.tgz
```

Building the package needs Node.js 22 or newer; the built package runs on Node.js 20 or newer.

It is an ES module. A CommonJS project (`require`) needs Node.js 20.19 or 22.12 or newer, which load
ES modules with `require()`.

## Express

```js
import express from 'express';
import { draco } from 'draco-insomnis/express';

const app = express();
app.use(express.urlencoded({ extended: false }), express.json()); // lets the firewall read forms and JSON
app.use(draco({
  waf: 'block',            // 'log' (default) | 'block' | 'off'
  pace: 'log',             // 'off' (default) | 'log' | 'block'
  proxy: 'xff',            // behind nginx or a load balancer
  headers: true,           // nosniff, SAMEORIGIN, referrer and permissions policy
  onEvent: (e) => console.log(JSON.stringify(e)),
}));
```

Put the body parsers before Draco if you want posted forms and JSON inspected. Without them Draco only
reads the URL, and it never consumes the request stream itself.

## Directus

Create a hook extension (`extensions/directus-extension-draco/index.js`):

```js
import { directus } from 'draco-insomnis/express';
export default directus({ waf: 'block' });
```

## Koa and Strapi

```js
import { draco } from 'draco-insomnis/koa';
app.use(draco({ waf: 'block' }));
```

For Strapi, create `src/middlewares/draco.js`:

```js
import { strapi } from 'draco-insomnis/koa';
export default strapi;
```

Then add `{ name: 'global::draco', config: { waf: 'block' } }` right after `strapi::body` in
`config/middlewares.js`, so Draco sees the parsed body.

## Cloudflare Workers

```js
import { withDraco, KVStore } from 'draco-insomnis/worker';

export default withDraco(
  { async fetch(request, env, ctx) { return fetch(request); } },   // your Worker
  (env) => ({ waf: 'block', geo: { mode: 'block', countries: ['XX'] }, store: new KVStore(env.DRACO) }),
);
```

In Workers the visitor's address is the one Cloudflare sets, and the country comes for free.

`KVStore` keeps blocks and verified crawlers in KV. Counters stay in the isolate's memory: KV has no
atomic increment, and each isolate counts on its own. Without a store, everything stays in memory.
Form and JSON bodies up to 64 KB are read from a copy of the request.

## Countries without Cloudflare

In Node.js, `GeoFile` reads the same country list as the PHP editions: DB-IP "IP to Country Lite"
(CC BY 4.0), built monthly by this project. The lookup is local and sends nothing anywhere.

```js
import { GeoFile } from 'draco-insomnis/geo';

const lookup = new GeoFile('/var/lib/myapp/draco-geo.bin');
app.use(draco({ waf: 'block', geo: { mode: 'block', countries: ['XX'], action: 'log', lookup } }));
```

- **Download:** the file (about 9 MB) is fetched on start when it is missing or older than 35 days,
  then checked once a day. It only replaces the old file when the published SHA-256 matches. Pass
  `{ update: false }` to manage the file yourself.
- **Lookup:** a binary search over the file, about 20 small reads per address.
- **No country:** private, reserved and unknown addresses have none, so they are never filtered.

## "This is a mistake": review requests

With a secret of your own, the 403 page carries a short form: the person who was stopped leaves an
e-mail and what they were doing, and the request reaches you.

```js
draco({
  waf: 'block',
  review: {
    secret: process.env.DRACO_SECRET,          // 16+ characters, the same on every server
    onRequest: (r) => mailMe(`Review: ${r.email} (${r.ip}, rule ${r.rule}): ${r.message}`),
  },
});
```

It works like the PHP editions, and both languages check the same cases (`tests/vectors/review.json`):

- The form is signed for the address and the moment it was shown, and is valid for a day.
- The rule that stopped the request travels sealed, so the page never says what matched.
- A hidden trap field catches bots; one address may send 3 requests a day, the site 50.
- The visitor always gets the same "Request sent" page, whether the request was kept or not.
- Draco never writes to the person who asks: that would let anyone make your site send mail. Let
  someone through with `gate.blocks.remove(ip)` or by adding the address to `adminIps`.

The body must be parsed: `express.urlencoded()` in Express, a body parser before Draco in Koa
(Strapi: after `strapi::body`). Workers read it themselves. The texts of the pages are in `texts`
(`reviewEmail`, `reviewMessage`, `reviewButton`, `reviewSentTitle`, `reviewSentText`,
`textWithReview`).

## CrowdSec

If you run CrowdSec, Draco can enforce its bans and feed it evidence.

**Enforcing its bans.** Create a key with `cscli bouncers add draco` and give Draco your Local API:

```js
draco({ waf: 'block', crowdsec: { url: 'http://127.0.0.1:8080', apiKey: process.env.CROWDSEC_KEY } });
```

- Bans on an address or a range join Draco's block list, which works as usual: the address may read
  the site but not post or log in.
- The decisions are copied in the background, at most once a minute, so no request waits for
  CrowdSec. When a decision is deleted or expires in CrowdSec, the block goes too; blocks you set
  yourself are never touched.
- Ranges wider than /16 (IPv4) or /32 (IPv6) and the addresses in `adminIps` are never imported.
- In Workers, background work ends with the request, so call `gate.crowdsec.sync()` from a scheduled
  handler instead.

**Feeding it evidence.** `crowdsecLine(event)` writes one line in the format read by the parser and
scenario in [`server/crowdsec`](../server/crowdsec):

```js
import { appendFileSync } from 'node:fs';
import { crowdsecLine } from 'draco-insomnis';

draco({ onEvent: (e) => appendFileSync('/var/log/draco/events.log', crowdsecLine(e, 'shop.example') + '\n') });
```

## Several servers

The default `MemoryStore` serves a single process. For several processes or servers, give every one
the same `store`. Any object with these four methods works:

```ts
interface Store {
  bump(key: string, ttl: number): Promise<number>;   // +1, expires after ttl seconds
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttl: number): Promise<void>; // ttl 0 = for good
  delete(key: string): Promise<void>;
}
```

With Redis that is `INCR` + `EXPIRE NX`, `GET`, `SET EX` and `DEL`.

## Blocking by hand

```js
const mw = draco({ waf: 'block' });
await mw.gate.blocks.add('203.0.113.0/24', 0, 'scraper', false); // days: 0 = for good; no wider than /16 or /32
await mw.gate.blocks.remove('203.0.113.0/24');
mw.gate.events();                                                  // the last 200 lines of evidence
```

## Options

| Option | Default | |
| --- | --- | --- |
| `waf` | `'log'` | `'off'`, `'log'` or `'block'` |
| `pace` | `'off'` | `'off'`, `'log'` or `'block'` (429) |
| `rateIp` / `rateNet` | 120 / 600 | pages a minute (minimum 10) |
| `proxy` | `''` | `'xff'` or `'cf'` |
| `trustedProxies` | local networks | CIDRs or addresses |
| `adminIps` | `[]` | never inspected |
| `except` | `[]` | path prefixes never inspected (health checks, webhooks) |
| `sensitive` | login, sign-up and admin paths | path endings treated like a POST |
| `geo` | off | `{ mode: 'block' \| 'allow', countries, action: 'log' \| 'block', scope: 'sensitive' \| 'site' }` |
| `headers`, `hsts` | `false` | security headers; HSTS only over HTTPS |
| `store` | memory | see above |
| `resolver` | `node:dns` (none in Workers) | proves search engines |
| `onEvent` | — | every line of evidence |
| `texts` | English | `{ title, text, tooMany }` of the 403 and 429 answers |

## Development

```sh
cd js
npm ci
npm test            # the shared vectors, the engine and the adapters
npm run typecheck
../bin/build-js.sh  # the release tarball
```

Licence: GPL-2.0-or-later, like the rest of Draco Insomnis.
