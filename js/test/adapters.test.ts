// The adapters against real requests: node:http with the Express-shaped middleware, a Koa-shaped
// context, and the Worker wrapper with the fetch API built into Node.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { draco } from '../src/express.ts';
import { draco as koa, type KoaContext } from '../src/koa.ts';
import { withDraco, KVStore, type KVNamespace } from '../src/worker.ts';

const ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20";

async function serve(middleware: ReturnType<typeof draco>): Promise<{ url: string; server: Server }> {
  const server = createServer((req, res) => {
    middleware(req, res, () => {
      if (req.url?.startsWith('/own')) res.setHeader('X-Frame-Options', 'DENY');
      res.end('page');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, server };
}

test('express: log, block, headers', async () => {
  const seen: string[] = [];
  const mw = draco({ waf: 'block', headers: true, onEvent: (e) => { seen.push(e.endpoint); } });
  const { url, server } = await serve(mw);
  try {
    const ok = await fetch(`${url}/?q=union+select+committee`);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('x-content-type-options'), 'nosniff');
    const own = await fetch(`${url}/own`);
    assert.equal(own.headers.get('x-frame-options'), 'DENY', "the application's own header wins");
    const blocked = await fetch(`${url}${ATTACK}`);
    assert.equal(blocked.status, 403);
    const body = await blocked.text();
    assert.match(body, /Ref\. [0-9a-f]{10}/);
    assert.doesNotMatch(body, /sqli/, 'the page never names the rule');
    const encodedTwice = await fetch(`${url}/?q=1%2527%2520or%25201%253D1`);
    assert.equal(encodedTwice.status, 403);
    const scanner = await fetch(url, { headers: { 'User-Agent': 'Nuclei - Open-source project' } });
    assert.equal(scanner.status, 403);
    const probe = await fetch(`${url}/.env`);
    assert.equal(probe.status, 403);
    assert.deepEqual(seen, ['waf:sqli', 'waf:sqli', 'waf:scanner', 'waf:probe']);
    // The parsed body is inspected too (Express puts it in req.body).
  } finally {
    server.close();
  }
});

test('express: a parsed form body is inspected', async () => {
  const mw = draco({ waf: 'block' });
  let status = 0;
  const res = { statusCode: 200, setHeader() {}, hasHeader: () => false, end() { status = this.statusCode; } };
  const req = { method: 'POST', url: '/contact', headers: {}, socket: { remoteAddress: '203.0.113.9' }, body: { message: "x'; DROP TABLE users; --" } };
  await new Promise<void>((resolve) => {
    mw(req as never, res as never, () => resolve());
    setTimeout(resolve, 50);
  });
  assert.equal(status, 403);
});

test('koa / strapi', async () => {
  const mw = koa({ waf: 'block' });
  const ctx = (url: string): KoaContext & { headers: Record<string, string> } => {
    const headers: Record<string, string> = {};
    return {
      req: { method: 'GET', url, headers: {}, socket: { remoteAddress: '203.0.113.10' } } as never,
      res: { hasHeader: () => false, setHeader() {} } as never,
      url,
      request: {},
      status: 404,
      body: undefined,
      headers,
      set(k: string, v: string) { headers[k] = v; },
    };
  };
  let reached = 0;
  const bad = ctx(ATTACK);
  await mw(bad, async () => { reached++; });
  assert.equal(bad.status, 403);
  assert.equal(bad.headers['Cache-Control'], 'no-store');
  const good = ctx('/articles?sort=title');
  await mw(good, async () => { reached++; });
  assert.equal(reached, 1);
});

class FakeKV implements KVNamespace {
  data = new Map<string, string>();
  async get(k: string) { return this.data.get(k) ?? null; }
  async put(k: string, v: string) { this.data.set(k, v); }
  async delete(k: string) { this.data.delete(k); }
}

test('cloudflare worker', async () => {
  const kv = new FakeKV();
  const worker = withDraco(
    { fetch: () => new Response('origin') },
    (env: { DRACO: FakeKV }) => ({ waf: 'block', headers: true, hsts: true, geo: { mode: 'block', countries: ['RU'], action: 'block' }, store: new KVStore(env.DRACO) }),
  );
  const env = { DRACO: kv };
  const call = (path: string, init: RequestInit & { country?: string } = {}) => {
    const r = new Request(`https://example.org${path}`, { ...init, headers: { 'cf-connecting-ip': '198.51.100.30', ...(init.headers as Record<string, string>) } });
    Object.defineProperty(r, 'cf', { value: { country: init.country ?? 'ES' } });
    return worker.fetch(r, env, {});
  };
  const ok = await call('/');
  assert.equal(await ok.text(), 'origin');
  assert.equal(ok.headers.get('strict-transport-security'), 'max-age=15552000');
  assert.equal((await call(ATTACK)).status, 403);
  const json = await call('/api', { method: 'POST', body: JSON.stringify({ q: "' OR '1'='1" }), headers: { 'content-type': 'application/json' } });
  assert.equal(json.status, 403, 'JSON bodies are inspected');
  assert.equal((await call('/login', { country: 'RU' })).status, 403);
  assert.equal((await call('/', { country: 'RU' })).status, 200, 'reading from a refused country is fine');
  for (let i = 0; i < 3; i++) await call(ATTACK);
  assert.ok([...kv.data.keys()].includes('draco:block:198.51.100.30'), 'the block lives in KV');
});
