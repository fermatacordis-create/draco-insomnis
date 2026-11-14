/**
 * What the Node.js adapters (Express, Koa, Strapi, Directus) share: reading a request from
 * node:http and the DNS used to prove search engines.
 */
import { promises as dns } from 'node:dns';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { TEXTS, page, type Answer, type Gatekeeper } from './core/gatekeeper.ts';
import { CLOUDFLARE, contains } from './core/net.ts';
import { remote, urlDecode, type DracoRequest } from './core/request.ts';
import { flatten } from './core/waf.ts';

export const nodeResolver = {
  reverse: (ip: string): Promise<string[]> => dns.reverse(ip),
  async lookup(host: string): Promise<string[]> {
    return (await dns.lookup(host, { all: true })).map((a) => a.address);
  },
};

const header = (req: IncomingMessage, name: string): string => {
  const v = req.headers[name];
  return Array.isArray(v) ? v.join(', ') : (v ?? '');
};

/**
 * The request as Draco reads it. `url` is the full path and query as received (Express keeps it in
 * originalUrl); `query` and `body` are whatever the framework already parsed, if anything.
 */
export function fromNode(req: IncomingMessage, url: string, query?: unknown, body?: unknown): DracoRequest {
  const at = url.indexOf('?');
  const rawPath = at < 0 ? url : url.slice(0, at);
  const rawQuery = at < 0 ? '' : url.slice(at + 1);
  const params = flatten(query !== undefined && query !== null && typeof query === 'object' ? query : Object.fromEntries(new URLSearchParams(rawQuery)));
  if (body !== undefined && body !== null && typeof body === 'object' && !(body instanceof Uint8Array)) {
    params.push(...flatten(body, 200 - Math.min(params.length, 200)));
  } else if (typeof body === 'string') {
    params.push(body.slice(0, 65536));
  }
  const r: DracoRequest = {
    method: (req.method ?? 'GET').toUpperCase(),
    path: urlDecode(rawPath),
    query: urlDecode(rawQuery, true),
    params,
    userAgent: header(req, 'user-agent'),
    remoteAddr: req.socket?.remoteAddress ?? '',
    cfConnectingIp: header(req, 'cf-connecting-ip'),
    forwardedFor: header(req, 'x-forwarded-for'),
    accept: header(req, 'accept'),
    ajax: header(req, 'x-requested-with').toLowerCase() === 'xmlhttprequest',
  };
  // Cloudflare's country header, only when the connection really comes from Cloudflare.
  if (contains(CLOUDFLARE, remote(r))) r.country = header(req, 'cf-ipcountry');
  return r;
}

export const https = (req: IncomingMessage): boolean => (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true;

/** The answer as status, headers and body, for any framework. */
export function reply(gate: Gatekeeper, answer: Answer): { status: number; headers: Record<string, string>; body: string } {
  const texts = { ...TEXTS, ...gate.options.texts };
  if (answer.status === 429) {
    return {
      status: 429,
      headers: { 'Retry-After': String(answer.retry), 'Content-Type': 'text/plain; charset=UTF-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' },
      body: texts.tooMany,
    };
  }
  return {
    status: 403,
    headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' },
    body: page(texts.title, texts.text),
  };
}

/** Sends the answer on a plain node:http response. */
export function send(res: ServerResponse, out: ReturnType<typeof reply>): void {
  res.statusCode = out.status;
  for (const [k, v] of Object.entries(out.headers)) res.setHeader(k, v);
  res.end(out.body);
}

/** Sets the security headers; whatever the application sets later replaces them. */
export function secure(gate: Gatekeeper, req: IncomingMessage, res: ServerResponse): void {
  for (const [k, v] of Object.entries(gate.headers(https(req)))) {
    if (!res.hasHeader(k)) res.setHeader(k, v);
  }
}
