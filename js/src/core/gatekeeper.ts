/**
 * The decision for one request — the same order and limits as src/Core/Gatekeeper.php:
 *   1. blocked addresses may read, but not post or open sensitive pages;
 *   2. countries (only where the platform knows the country, e.g. Cloudflare);
 *   3. firewall signatures (log or block; 5 hits in 10 minutes block the address for 7 days);
 *   4. anti-copy pace (pages a minute per address and per /24 or /64).
 */
import { claimed, resolvesBack, type Resolver } from './crawler.ts';
import { network, parse } from './net.ts';
import { clientIp, remote, wantsPage, type DracoRequest, type ProxyMode } from './request.ts';
import { Blocks, MemoryStore, type DracoEvent, type Store } from './store.ts';
import { inspect } from './waf.ts';

export type Mode = 'off' | 'log' | 'block';

export interface DracoOptions {
  /** Firewall: "log" (default) writes evidence only, "block" answers 403. */
  waf?: Mode;
  /** Anti-copy pace: "off" (default), "log" or "block" (429). */
  pace?: Mode;
  /** Pages a minute per address (default 120) and per network (600); at least 10. */
  rateIp?: number;
  rateNet?: number;
  /** "cf" = CF-Connecting-IP, "xff" = X-Forwarded-For; only believed from a trusted proxy. */
  proxy?: ProxyMode;
  /** Proxies whose header is believed (CIDR or address); empty = local and private networks. */
  trustedProxies?: string[];
  /** Addresses that are never inspected (the owner's). */
  adminIps?: string[];
  /** Path endings that count as sensitive (login, sign-up…), besides any POST. */
  sensitive?: string[];
  /** Path prefixes never inspected: health checks, webhooks. */
  except?: string[];
  geo?: {
    /** "block" = refuse the countries listed; "allow" = refuse all others. */
    mode?: 'off' | 'block' | 'allow';
    countries?: string[];
    /** "log" (default) or "block". */
    action?: 'log' | 'block';
    /** "sensitive" (default) or the whole "site". */
    scope?: 'sensitive' | 'site';
  };
  /** Security headers (nosniff, SAMEORIGIN, referrer and permissions policy) and HSTS on HTTPS. */
  headers?: boolean;
  hsts?: boolean;
  store?: Store;
  resolver?: Resolver;
  /** Every line of evidence, as it is written (send it to your logs, a SIEM or CrowdSec). */
  onEvent?: (event: DracoEvent) => void | Promise<void>;
  /** The text of the 403 page. */
  texts?: { title?: string; text?: string; tooMany?: string };
}

export const SENSITIVE = [
  '/wp-login.php', '/login', '/register', '/signup', '/user/login', '/user/register', '/admin',
  '/auth/login', '/api/auth/local', '/api/auth/local/register', '/admin/login',
];

export interface Answer {
  status: 403 | 429;
  /** The rule, "blocked", "geo" or "pace": for the evidence, never shown to the visitor. */
  why: string;
  retry: number;
}

const HITS_TO_BLOCK = 5;
const HIT_WINDOW = 600;
const BLOCK_DAYS = 7;
const WINDOW = 60;
const VERIFIED_FOR = 86400;

export class Gatekeeper {
  readonly options: DracoOptions;
  readonly store: Store;
  readonly blocks: Blocks;
  private readonly recent: DracoEvent[] = [];
  private readonly now: () => number;

  constructor(options: DracoOptions = {}, now: () => number = () => Date.now() / 1000) {
    this.options = options;
    this.store = options.store ?? new MemoryStore(now);
    this.blocks = new Blocks(this.store);
    this.now = now;
  }

  ip(r: DracoRequest): string {
    return clientIp(r, this.options.proxy ?? '', this.options.trustedProxies ?? []);
  }

  /** The last 200 lines of evidence of this process (newest last). */
  events(): readonly DracoEvent[] {
    return this.recent;
  }

  async decide(r: DracoRequest): Promise<Answer | null> {
    const o = this.options;
    const ip = this.ip(r);
    if ((o.adminIps ?? []).includes(ip) || this.excepted(r.path)) return null;
    const waf = o.waf ?? 'log';
    if (waf !== 'off') {
      if (this.sensitive(r) && (await this.blocks.isBlocked(ip, this.now()))) {
        return { status: 403, why: 'blocked', retry: 0 };
      }
      const country = await this.refusedCountry(r, ip);
      if (country !== '') {
        const blocking = o.geo?.action === 'block';
        await this.log(r, ip, 'waf:geo', blocking, ['waf_geo'], `${country} ${r.path}`);
        if (blocking) return { status: 403, why: 'geo', retry: 0 };
      }
      const rule = inspect({ path: r.path, query: r.query, params: r.params, userAgent: r.userAgent });
      if (rule !== null) {
        await this.record(r, ip, rule, waf === 'block');
        if (waf === 'block') return { status: 403, why: rule, retry: 0 };
      }
    }
    const pace = o.pace ?? 'off';
    if (pace !== 'off' && wantsPage(r)) {
      const now = this.now();
      const minute = Math.floor(now / WINDOW);
      const ipHits = await this.store.bump(`draco:rl:i:${ip}:${minute}`, WINDOW * 2);
      const netHits = await this.store.bump(`draco:rl:n:${network(ip)}:${minute}`, WINDOW * 2);
      const ipLimit = limit(o.rateIp, 120);
      const netLimit = limit(o.rateNet, 600);
      const over = ipHits > ipLimit ? 'ip' : netHits > netLimit ? 'net' : '';
      if (over !== '' && !(await this.verifiedCrawler(ip, r.userAgent))) {
        const block = pace === 'block';
        // One line per address and minute is enough evidence; the rest only counts.
        if (ipHits === ipLimit + 1 || netHits === netLimit + 1) {
          await this.log(r, ip, `anticopy:${over}`, false, [`anticopy_${over}_${block ? 'block' : 'log'}`], r.path);
        }
        if (block) return { status: 429, why: 'pace', retry: Math.max(1, WINDOW - (Math.floor(now) % WINDOW)) };
      }
    }
    return null;
  }

  /** Security headers to add, unless the application already set them. */
  headers(https: boolean): Record<string, string> {
    const out: Record<string, string> = {};
    if (this.options.headers) {
      out['X-Content-Type-Options'] = 'nosniff';
      out['X-Frame-Options'] = 'SAMEORIGIN';
      out['Referrer-Policy'] = 'strict-origin-when-cross-origin';
      out['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), interest-cohort=()';
    }
    if (https && this.options.hsts) out['Strict-Transport-Security'] = 'max-age=15552000';
    return out;
  }

  private excepted(path: string): boolean {
    return (this.options.except ?? []).some((p) => {
      const prefix = `/${p.replace(/^\/+/, '')}`;
      return prefix !== '/' && path.startsWith(prefix);
    });
  }

  private sensitive(r: DracoRequest): boolean {
    if (r.method === 'POST') return true;
    return (this.options.sensitive ?? SENSITIVE).some((end) => end !== '' && r.path.endsWith(end));
  }

  private async refusedCountry(r: DracoRequest, ip: string): Promise<string> {
    const geo = this.options.geo;
    const mode = geo?.mode ?? 'off';
    const list = (geo?.countries ?? []).map((c) => c.trim().toUpperCase()).filter((c) => /^[A-Z]{2}$/.test(c));
    if (mode === 'off' || list.length === 0) return '';
    if (geo?.scope !== 'site' && !this.sensitive(r)) return '';
    const country = (r.country ?? '').toUpperCase();
    // Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
    if (!/^[A-Z]{2}$/.test(country) || country === 'XX' || country === 'T1') return '';
    const listed = list.includes(country);
    if ((mode === 'block' && !listed) || (mode === 'allow' && listed)) return '';
    // Last: it may ask the DNS, and only matters for a request that would be refused.
    if (await this.verifiedCrawler(ip, r.userAgent)) return '';
    return country;
  }

  private async record(r: DracoRequest, ip: string, rule: string, blocking: boolean): Promise<void> {
    await this.log(r, ip, `waf:${rule}`, blocking, [`waf_${rule}`], r.path + (r.query !== '' ? `?${r.query}` : ''));
    if (!blocking) return;
    const hits = await this.store.bump(`draco:waf:${ip}`, HIT_WINDOW);
    // An address read from a header nobody vouches for is never blocked: it could be anybody's.
    const trusted = ip === remote(r) || (this.options.proxy ?? '') !== '';
    if (hits >= HITS_TO_BLOCK && trusted && !(await this.blocks.isBlocked(ip, this.now()))) {
      await this.blocks.add(ip, BLOCK_DAYS, `Firewall: ${hits} attacks in 10 minutes`, true, this.now());
    }
  }

  async verifiedCrawler(ip: string, userAgent: string): Promise<boolean> {
    const token = claimed(userAgent);
    const resolver = this.options.resolver;
    if (token === '' || resolver === undefined) return false;
    const key = `draco:crawler:${ip}:${token}`;
    const cached = await this.store.get(key);
    if (cached === 'y' || cached === 'n') return cached === 'y';
    const ok = await resolvesBack(resolver, ip, token);
    await this.store.set(key, ok ? 'y' : 'n', VERIFIED_FOR);
    return ok;
  }

  private async log(r: DracoRequest, ip: string, endpoint: string, blocking: boolean, reasons: string[], detail: string): Promise<void> {
    const event: DracoEvent = {
      time: Math.floor(this.now()),
      ip,
      remote: remote(r),
      endpoint,
      verdict: blocking ? 'bot' : 'doubtful',
      reasons,
      userAgent: r.userAgent.slice(0, 255),
      detail: detail.slice(0, 200),
    };
    this.recent.push(event);
    if (this.recent.length > 200) this.recent.shift();
    try {
      await this.options.onEvent?.(event);
    } catch {
      // A broken log sink must never break the site.
    }
  }
}

const limit = (value: number | undefined, fallback: number): number => (value !== undefined && value >= 10 ? Math.floor(value) : fallback);

/** Trusted proxies, admin addresses and lists may be given as text too ("a, b # comment"). */
export const list = (value: string | string[] | undefined): string[] => (value === undefined ? [] : parse(value));

/** The 403 page: says nothing about which rule matched; the reference ties it to the evidence. */
export function page(title: string, text: string): string {
  const h = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
  const ref = Array.from(crypto.getRandomValues(new Uint8Array(5)), (b) => b.toString(16).padStart(2, '0')).join('');
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>'
    + '<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}</style></head><body><main>'
    + `<h1 style="font-size:20px">${h(title)}</h1><p>${h(text)}</p>`
    + `<p style="color:#64748b;font-size:13px">Ref. ${ref}</p></main></body></html>`;
}

export const TEXTS = {
  title: 'Request blocked',
  text: 'This request was blocked by the site\'s security. If you think this is a mistake, contact the site owner.',
  tooMany: 'Too many pages in a short time. Please wait a moment and try again.',
};
