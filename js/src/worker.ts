/**
 * Cloudflare Workers (and any runtime with fetch-style handlers: Deno, Bun).
 *
 *   import { withDraco, KVStore } from 'draco-insomnis/worker';
 *   export default withDraco(
 *     { async fetch(request, env, ctx) { return fetch(request); } },
 *     (env) => ({ waf: 'block', store: new KVStore(env.DRACO) }),
 *   );
 *
 * In Workers the connecting address IS the visitor (CF-Connecting-IP is set by Cloudflare itself)
 * and request.cf.country gives the country without any database.
 */
import { Gatekeeper, TEXTS, page, type Answer, type DracoOptions } from './core/gatekeeper.ts';
import { urlDecode, type DracoRequest } from './core/request.ts';
import type { Store } from './core/store.ts';
import { flatten } from './core/waf.ts';

type Handler<E> = { fetch(request: Request, env: E, ctx: unknown): Response | Promise<Response> };

/** Workers KV: blocks and verified crawlers. Counters are approximate (KV has no atomic increment, and keeps keys at least 60 s). */
export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

export class KVStore implements Store {
  private readonly kv: KVNamespace;
  /** Counters stay in the isolate's memory: KV is too slow and too eventual for them. */
  private readonly counters = new Map<string, { n: number; until: number }>();
  constructor(kv: KVNamespace) {
    this.kv = kv;
  }
  async bump(key: string, ttl: number): Promise<number> {
    const now = Date.now() / 1000;
    const c = this.counters.get(key);
    const next = c === undefined || c.until <= now ? { n: 1, until: now + ttl } : { n: c.n + 1, until: c.until };
    this.counters.set(key, next);
    if (this.counters.size > 20_000) for (const [k, v] of this.counters) if (v.until <= now) this.counters.delete(k);
    return next.n;
  }
  get(key: string): Promise<string | null> {
    return this.kv.get(key);
  }
  set(key: string, value: string, ttl: number): Promise<void> {
    return this.kv.put(key, value, ttl === 0 ? {} : { expirationTtl: Math.max(60, ttl) });
  }
  delete(key: string): Promise<void> {
    return this.kv.delete(key);
  }
}

/** The request as Draco reads it; form and JSON bodies (up to 64 KB) are read from a copy. */
export async function fromFetch(request: Request): Promise<DracoRequest> {
  const url = new URL(request.url);
  const rawQuery = url.search.replace(/^\?/, '');
  const params = flatten(Object.fromEntries(url.searchParams));
  const type = (request.headers.get('content-type') ?? '').toLowerCase();
  const length = Number(request.headers.get('content-length') ?? '0');
  if (request.body !== null && length <= 65536 && (type.includes('json') || type.includes('x-www-form-urlencoded'))) {
    try {
      const text = await request.clone().text();
      if (type.includes('json')) params.push(...flatten(JSON.parse(text) as unknown));
      else params.push(...flatten(Object.fromEntries(new URLSearchParams(text))));
    } catch {
      // Unreadable body: the URL is still inspected.
    }
  }
  const cf = (request as Request & { cf?: { country?: string } }).cf;
  return {
    method: request.method.toUpperCase(),
    path: urlDecode(url.pathname),
    query: urlDecode(rawQuery, true),
    params,
    userAgent: request.headers.get('user-agent') ?? '',
    remoteAddr: request.headers.get('cf-connecting-ip') ?? '',
    country: cf?.country ?? '',
    accept: request.headers.get('accept') ?? '',
    ajax: (request.headers.get('x-requested-with') ?? '').toLowerCase() === 'xmlhttprequest',
  };
}

export function response(gate: Gatekeeper, answer: Answer): Response {
  const texts = { ...TEXTS, ...gate.options.texts };
  if (answer.status === 429) {
    return new Response(texts.tooMany, {
      status: 429,
      headers: { 'Retry-After': String(answer.retry), 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' },
    });
  }
  return new Response(page(texts.title, texts.text), {
    status: 403,
    headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' },
  });
}

/** Wraps a Worker: Draco answers first, the Worker only sees what Draco lets through. */
export function withDraco<E>(handler: Handler<E>, options: DracoOptions | ((env: E) => DracoOptions) = {}): Handler<E> {
  let gate: Gatekeeper | null = null;
  return {
    async fetch(request: Request, env: E, ctx: unknown): Promise<Response> {
      // One gatekeeper per isolate, made on the first request (env is only known then).
      gate ??= new Gatekeeper(typeof options === 'function' ? options(env) : options);
      let answer: Answer | null = null;
      try {
        answer = await gate.decide(await fromFetch(request));
      } catch {
        // Draco itself failing never takes the site with it.
      }
      if (answer !== null) return response(gate, answer);
      const res = await handler.fetch(request, env, ctx);
      const extra = gate.headers(new URL(request.url).protocol === 'https:');
      if (Object.keys(extra).length === 0) return res;
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(extra)) if (!out.headers.has(k)) out.headers.set(k, v);
      return out;
    },
  };
}
