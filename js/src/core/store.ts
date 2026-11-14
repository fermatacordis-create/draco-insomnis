/**
 * Where Draco keeps counters, the block list and recent evidence. Asynchronous, so it can live in
 * memory (one process), in Redis (several) or in Cloudflare KV / Durable Objects (Workers).
 */
import { inNet } from './net.ts';

export interface Store {
  /** Adds one to the counter and returns the new value; the counter disappears after ttl seconds. */
  bump(key: string, ttl: number): Promise<number>;
  get(key: string): Promise<string | null>;
  /** ttl 0 = keep for good. */
  set(key: string, value: string, ttl: number): Promise<void>;
  delete(key: string): Promise<void>;
}

/** One process, nothing to install. Counters are lost on restart; fine for one server. */
export class MemoryStore implements Store {
  private items = new Map<string, { value: string; until: number }>();
  private readonly now: () => number;
  constructor(now: () => number = () => Date.now() / 1000) {
    this.now = now;
  }

  private live(key: string): string | null {
    const item = this.items.get(key);
    if (item === undefined) return null;
    if (item.until !== 0 && item.until <= this.now()) {
      this.items.delete(key);
      return null;
    }
    return item.value;
  }

  private sweep(): void {
    // Keep memory bounded: drop what expired once the map grows.
    if (this.items.size < 50_000) return;
    for (const key of [...this.items.keys()]) this.live(key);
  }

  async bump(key: string, ttl: number): Promise<number> {
    const current = this.live(key);
    const n = (current === null ? 0 : Number(current)) + 1;
    const until = current === null ? this.now() + ttl : this.items.get(key)!.until;
    this.items.set(key, { value: String(n), until });
    this.sweep();
    return n;
  }

  async get(key: string): Promise<string | null> {
    return this.live(key);
  }

  async set(key: string, value: string, ttl: number): Promise<void> {
    this.items.set(key, { value, until: ttl === 0 ? 0 : this.now() + ttl });
    this.sweep();
  }

  async delete(key: string): Promise<void> {
    this.items.delete(key);
  }
}

/** A line of evidence, the same fields the PHP editions write to their events table. */
export interface DracoEvent {
  time: number;
  ip: string;
  remote: string;
  /** "waf:sqli", "waf:geo", "anticopy:ip"… */
  endpoint: string;
  verdict: 'bot' | 'doubtful';
  reasons: string[];
  userAgent: string;
  /** Path and query, or country and path. */
  detail: string;
}

export interface BlockEntry {
  value: string;
  until: number;
  reason: string;
  automatic: boolean;
}

export const FOREVER = 253402300799;
const MIN_PREFIX = { 4: 16, 6: 32 } as const;

/** Whether a network may be blocked: no wider than /16 (IPv4) or /32 (IPv6), as in Blocklist.php. */
export function validNet(cidr: string): boolean {
  const m = /^([0-9a-f.:]+)\/(\d+)$/i.exec(cidr.trim());
  if (!m) return false;
  const v6 = m[1]!.includes(':');
  const bits = Number(m[2]);
  return inNet(`${m[1]}/0`, m[1]!) && bits >= MIN_PREFIX[v6 ? 6 : 4] && bits <= (v6 ? 128 : 32);
}

/** The block list on top of any Store: one key per address, and one key holding the blocked networks. */
export class Blocks {
  private readonly store: Store;
  constructor(store: Store) {
    this.store = store;
  }

  async add(value: string, days: number, reason: string, automatic: boolean, now = Date.now() / 1000): Promise<boolean> {
    const until = days === 0 ? FOREVER : Math.floor(now) + days * 86400;
    const entry: BlockEntry = { value, until, reason, automatic };
    if (value.includes('/')) {
      if (!validNet(value)) return false;
      const nets = (await this.nets(now)).filter((n) => n.value !== value);
      nets.push(entry);
      await this.store.set('draco:nets', JSON.stringify(nets), 0);
      return true;
    }
    await this.store.set(`draco:block:${value}`, JSON.stringify(entry), days === 0 ? 0 : days * 86400);
    return true;
  }

  async remove(value: string): Promise<void> {
    if (value.includes('/')) {
      const nets = (await this.nets()).filter((n) => n.value !== value);
      await this.store.set('draco:nets', JSON.stringify(nets), 0);
      return;
    }
    await this.store.delete(`draco:block:${value}`);
  }

  async nets(now = Date.now() / 1000): Promise<BlockEntry[]> {
    const raw = await this.store.get('draco:nets');
    if (raw === null) return [];
    try {
      return (JSON.parse(raw) as BlockEntry[]).filter((n) => n.until > now);
    } catch {
      return [];
    }
  }

  async isBlocked(ip: string, now = Date.now() / 1000): Promise<boolean> {
    if ((await this.store.get(`draco:block:${ip}`)) !== null) return true;
    return (await this.nets(now)).some((n) => inNet(n.value, ip));
  }
}
