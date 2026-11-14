/**
 * One visitor request in plain values, as an adapter (Express, Koa, Workers) read it — the same
 * fields as src/Core/Request.php, so the engines can be tested without a server.
 */
import { CLOUDFLARE, LOCAL_PROXIES, contains, isIP, parse, unmap } from './net.ts';

export interface DracoRequest {
  method: string;
  /** URL path, decoded once. */
  path: string;
  /** Query string without "?", decoded once. */
  query: string;
  /** Decoded query and body values (and keys), for the firewall only. */
  params: string[];
  userAgent: string;
  /** The address of the connection itself. */
  remoteAddr: string;
  cfConnectingIp?: string;
  forwardedFor?: string;
  /** Two-letter country the platform already knows (Cloudflare's request.cf.country), if any. */
  country?: string;
  /** Whatever the "Accept" header says: only pages count for the anti-copy pace. */
  accept?: string;
  /** Sent with "X-Requested-With: XMLHttpRequest". */
  ajax?: boolean;
}

export type ProxyMode = '' | 'cf' | 'xff';

/** Decodes like PHP's urldecode: "+" is a space and malformed "%" sequences are left as they are. */
export function urlDecode(value: string, plusIsSpace = false): string {
  const s = plusIsSpace ? value.replace(/\+/g, ' ') : value;
  try {
    return decodeURIComponent(s);
  } catch {
    // Byte by byte, then read as UTF-8 where it can be.
    const bytes: number[] = [];
    for (let i = 0; i < s.length; i++) {
      const m = /^%([0-9a-f]{2})/i.exec(s.slice(i, i + 3));
      if (m) { bytes.push(parseInt(m[1]!, 16)); i += 2; continue; }
      for (const b of new TextEncoder().encode(s[i]!)) bytes.push(b);
    }
    return new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(bytes));
  }
}

export function remote(r: DracoRequest): string {
  const ip = unmap((r.remoteAddr ?? '').trim());
  return isIP(ip) ? ip : '0.0.0.0';
}

const proxies = (trusted: readonly string[]): readonly string[] => {
  const listed = parse(trusted);
  return listed.length > 0 ? listed : LOCAL_PROXIES;
};

/** Whether the chosen proxy header may be read at all: the connection comes from a trusted proxy. */
export function fromTrustedProxy(r: DracoRequest, mode: ProxyMode, trusted: readonly string[] = []): boolean {
  const addr = remote(r);
  if (mode === 'cf') {
    return (r.cfConnectingIp ?? '') !== '' && (contains(CLOUDFLARE, addr) || contains(parse(trusted), addr));
  }
  if (mode === 'xff') {
    return (r.forwardedFor ?? '').trim() !== '' && contains(proxies(trusted), addr);
  }
  return false;
}

/**
 * The visitor's address: the connection's own, unless a proxy header is chosen AND the connection
 * comes from a trusted proxy. X-Forwarded-For is read from the right: the first address that is not
 * a trusted proxy is the visitor; whatever is on its left was written by the visitor.
 */
export function clientIp(r: DracoRequest, mode: ProxyMode, trusted: readonly string[] = []): string {
  let addr = remote(r);
  if (!fromTrustedProxy(r, mode, trusted)) return addr;
  if (mode === 'cf') {
    const ip = (r.cfConnectingIp ?? '').trim();
    return isIP(ip) ? ip : addr;
  }
  const list = proxies(trusted);
  const hops = (r.forwardedFor ?? '').split(',').map((h) => h.trim()).reverse();
  for (const hop of hops) {
    if (!isIP(hop)) return addr;
    if (!contains(list, hop)) return hop;
    addr = hop;
  }
  return addr;
}

/** A page (HTML) rather than an API call, an image or a script: only pages count for the pace. */
export function wantsPage(r: DracoRequest): boolean {
  const accept = (r.accept ?? '').toLowerCase();
  return ['GET', 'HEAD'].includes(r.method) && (accept === '' || accept.includes('text/html')) && !r.ajax;
}
