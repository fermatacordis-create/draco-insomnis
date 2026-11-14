/**
 * Search engines that may go past the pace limit, but only when the reverse DNS proves who they are
 * (the same list and rules as src/Core/Crawler.php).
 */

import { fromBytes, toBytes } from './net.ts';

/** One spelling per address ("2001:DB8:0::1" and "2001:db8::1" are the same). */
const same = (ip: string): string => {
  const b = toBytes(ip);
  return b === null ? `?${ip}` : fromBytes(b);
};

const GOOGLE = ['googlebot.com', 'google.com', 'googleusercontent.com'];

export const KNOWN: Readonly<Record<string, readonly string[]>> = {
  googlebot: GOOGLE,
  'google-inspectiontool': GOOGLE,
  googleother: GOOGLE,
  'adsbot-google': GOOGLE,
  'mediapartners-google': GOOGLE,
  bingbot: ['search.msn.com'],
  msnbot: ['search.msn.com'],
  adidxbot: ['search.msn.com'],
  applebot: ['applebot.apple.com'],
  yandex: ['yandex.ru', 'yandex.net', 'yandex.com'],
};

/** Looks names up; Node gets one from node:dns, Workers have none unless you pass one (DNS over HTTPS). */
export interface Resolver {
  reverse(ip: string): Promise<string[]>;
  /** Every A and AAAA address of the name. */
  lookup(host: string): Promise<string[]>;
}

export function claimed(userAgent: string): string {
  const ua = userAgent.toLowerCase();
  return Object.keys(KNOWN).find((token) => ua.includes(token)) ?? '';
}

export function hostMatches(token: string, host: string): boolean {
  const h = host.trim().toLowerCase().replace(/\.+$/, '');
  const domains = KNOWN[token];
  if (h === '' || domains === undefined || /^[\d.]+$/.test(h) || h.includes(':')) return false;
  return domains.some((d) => h === d || h.endsWith(`.${d}`));
}

/** The name the address points back to must belong to the engine, and that name must point to the address. */
export async function resolvesBack(resolver: Resolver, ip: string, token: string): Promise<boolean> {
  try {
    for (const name of (await resolver.reverse(ip)).slice(0, 3)) {
      if (!hostMatches(token, name)) continue;
      const want = same(ip);
      if ((await resolver.lookup(name)).some((a) => same(a) === want)) return true;
    }
  } catch {
    // No answer: not proven.
  }
  return false;
}
