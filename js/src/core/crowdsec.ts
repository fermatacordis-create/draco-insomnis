/**
 * CrowdSec, both ways — like server/src/CrowdSec.php.
 *
 * In: Draco is a bouncer of your own CrowdSec Local API (url + the key from
 * "cscli bouncers add draco"). The decisions stream is copied into Draco's block list at most once a
 * minute, in the background: no request ever waits for CrowdSec. Bans on an address or a range (no
 * wider than /16 or /32) become Draco blocks — the address may read but not post or log in. The
 * owner's addresses (adminIps) are never imported.
 *
 * Out: crowdsecLine(event) is one JSON line in the format the parser and scenario in server/crowdsec
 * read (acquisition type draco-insomnis): append it to a file the CrowdSec agent watches, from onEvent.
 */
import { isIP } from './net.ts';
import { Blocks, validNet, type DracoEvent, type Store } from './store.ts';

export const REASON = 'CrowdSec';
const EVERY = 60;
const IMPORTED = 'draco:crowdsec:imported';

/** What /v1/decisions/stream answers. */
type Stream = { new?: unknown; deleted?: unknown };

export interface CrowdSecOptions {
  /** The Local API, e.g. http://127.0.0.1:8080 */
  url: string;
  apiKey: string;
  /** Seconds to wait for an answer (default 2). */
  timeout?: number;
}

export interface SyncResult {
  added: number;
  removed: number;
  error: string;
}

/** Go durations as CrowdSec sends them: "3h59m40.5s", "45m", "1.5s"… */
export function seconds(duration: string): number {
  if (duration.trim().startsWith('-')) return 0;
  let total = 0;
  let any = false;
  for (const m of duration.matchAll(/(\d+(?:\.\d+)?)(h|ms|m|s)/g)) {
    any = true;
    total += Number(m[1]) * { h: 3600, m: 60, s: 1, ms: 0.001 }[m[2] as 'h' | 'm' | 's' | 'ms'];
  }
  return any ? Math.ceil(total) : 0;
}

export class CrowdSec {
  private readonly options: CrowdSecOptions;
  private readonly store: Store;
  private readonly blocks: Blocks;
  private readonly admins: () => readonly string[];
  private readonly now: () => number;
  private running: Promise<SyncResult> | null = null;

  constructor(options: CrowdSecOptions, store: Store, admins: () => readonly string[] = () => [], now: () => number = () => Date.now() / 1000) {
    this.options = options;
    this.store = store;
    this.blocks = new Blocks(store);
    this.admins = admins;
    this.now = now;
  }

  /** From the gatekeeper: one sync a minute at most (across processes sharing the store), never awaited. */
  async maybeSync(): Promise<void> {
    if (this.running !== null || (await this.store.bump('draco:crowdsec:sync', EVERY)) !== 1) return;
    await this.sync();
  }

  sync(): Promise<SyncResult> {
    this.running ??= this.pull().finally(() => { this.running = null; });
    return this.running;
  }

  private async pull(): Promise<SyncResult> {
    const out: SyncResult = { added: 0, removed: 0, error: '' };
    // The first call asks for everything in force; later ones only for changes.
    const startup = (await this.store.get('draco:crowdsec:started')) === null;
    const url = `${this.options.url.replace(/\/+$/, '')}/v1/decisions/stream?startup=${startup}&scopes=ip,range`;
    let data = null as Stream | null;
    try {
      const res = await fetch(url, {
        headers: { 'X-Api-Key': this.options.apiKey, 'User-Agent': 'Draco-Insomnis' },
        signal: AbortSignal.timeout((this.options.timeout ?? 2) * 1000),
      });
      if (res.status !== 200) out.error = `HTTP ${res.status}`;
      else data = (await res.json()) as Stream;
    } catch (e) {
      out.error = e instanceof SyntaxError ? 'not JSON' : 'no answer';
    }
    if (out.error !== '' || data === null || typeof data !== 'object') {
      out.error ||= 'not JSON';
      await this.store.set('draco:crowdsec:last', `${Math.floor(this.now())}|${out.error}`, 86400 * 30);
      return out;
    }
    let imported = await this.imported();
    if (startup) {
      for (const value of imported) if (await this.removeIfOurs(value)) out.removed++;
      imported = [];
    }
    for (const d of Array.isArray(data.deleted) ? data.deleted : []) {
      const value = String((d as { value?: unknown }).value ?? '').toLowerCase();
      if (value !== '' && imported.includes(value) && (await this.removeIfOurs(value))) {
        out.removed++;
        imported = imported.filter((v) => v !== value);
      }
    }
    const admins = this.admins();
    for (const d of Array.isArray(data.new) ? data.new : []) {
      const decision = d as { type?: unknown; value?: unknown; duration?: unknown; scenario?: unknown; origin?: unknown };
      if (String(decision.type ?? '').toLowerCase() !== 'ban') continue;
      const value = String(decision.value ?? '').trim().toLowerCase();
      const ttl = seconds(String(decision.duration ?? ''));
      const allowed = value.includes('/') ? validNet(value) : isIP(value);
      if (ttl <= 0 || !allowed || admins.includes(value)) continue;
      const reason = `${REASON}: ${String(decision.scenario ?? decision.origin ?? '').slice(0, 150)}`;
      if (await this.blocks.addUntil(value, Math.floor(this.now()) + ttl, reason, true, this.now())) {
        out.added++;
        if (!imported.includes(value)) imported.push(value);
      }
    }
    await this.store.set(IMPORTED, JSON.stringify(imported.slice(-20_000)), 0);
    await this.store.set('draco:crowdsec:started', '1', 86400 * 365);
    await this.store.set('draco:crowdsec:last', `${Math.floor(this.now())}|ok +${out.added} -${out.removed}`, 86400 * 30);
    return out;
  }

  private async imported(): Promise<string[]> {
    try {
      const list = JSON.parse((await this.store.get(IMPORTED)) ?? '[]') as unknown;
      return Array.isArray(list) ? list.filter((v): v is string => typeof v === 'string') : [];
    } catch {
      return [];
    }
  }

  /** Only blocks that came from CrowdSec are lifted: a block the owner set stays. */
  private async removeIfOurs(value: string): Promise<boolean> {
    const entry = await this.blocks.entry(value, this.now());
    if (entry === null || !entry.reason.startsWith(REASON)) return false;
    await this.blocks.remove(value);
    return true;
  }
}

/** One line for the CrowdSec agent (server/crowdsec: parser draco-insomnis-logs, scenario draco-insomnis/attacks). */
export function crowdsecLine(event: DracoEvent, host = ''): string {
  return JSON.stringify({
    time: new Date(event.time * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z'),
    ip: event.ip,
    host,
    endpoint: event.endpoint,
    verdict: event.verdict,
    reasons: event.reasons.join(','),
    user_agent: event.userAgent,
  });
}
