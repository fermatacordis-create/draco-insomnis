/**
 * The visitor's country without Cloudflare, for Node.js: the same file and lookup as
 * src/Core/Geo.php (DB-IP "IP to Country Lite", CC BY 4.0, built monthly by this project). A binary
 * search over fixed-size records, about 20 small reads, nothing sent anywhere. Private, reserved and
 * unknown addresses have no country, so they are never filtered by country.
 *
 *   import { GeoFile } from 'draco-insomnis/geo';
 *   const geo = new GeoFile('/var/lib/myapp/draco-geo.bin');   // downloaded now and kept fresh
 *   app.use(draco({ waf: 'block', geo: { mode: 'block', countries: ['XX'], lookup: geo } }));
 *
 * Behind Cloudflare the country header is used and this file is not needed.
 */
import { createHash } from 'node:crypto';
import { closeSync, existsSync, fstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { toBytes, unmap } from './core/net.ts';

export const SOURCE = 'https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin';
export const MAX_AGE_DAYS = 35;
const HEADER = 22;
const DAY = 86_400_000;

interface Opened {
  fd: number;
  v4: number;
  v6: number;
  built: string;
}

export interface GeoFileOptions {
  /**
   * Download the list when it is missing or older than 35 days, now and then once a day (the timer
   * does not keep the process alive). Default true; false if you refresh the file yourself.
   */
  update?: boolean;
  /** Where to download from (tests, mirrors). The SHA-256 is read from the same address + ".sha256". */
  source?: string;
}

export class GeoFile {
  readonly path: string;
  private readonly source: string;
  private db: Opened | null = null;
  private triedAt = 0;
  /** Why the last download failed ('' when it did not, or none was needed). */
  lastError = '';

  constructor(path: string, options: GeoFileOptions = {}) {
    this.path = path;
    this.source = options.source ?? SOURCE;
    if (options.update ?? true) {
      void this.refresh();
      setInterval(() => void this.refresh(), DAY).unref();
    }
  }

  /** Two-letter country of the address, or null (no file yet, private or unknown address). */
  country(ip: string): string | null {
    const addr = toBytes(unmap(ip.trim()));
    const db = addr === null ? null : this.open();
    if (addr === null || db === null) return null;
    const v4 = addr.length === 4;
    const count = v4 ? db.v4 : db.v6;
    const size = v4 ? 6 : 18;
    const width = size - 2;
    const base = HEADER + (v4 ? 0 : db.v4 * 6);
    const buf = new Uint8Array(size);
    let lo = 0;
    let hi = count - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      readSync(db.fd, buf, 0, width, base + mid * size);
      if (compare(buf.subarray(0, width), addr) <= 0) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (found < 0) return null;
    readSync(db.fd, buf, 0, 2, base + found * size + width);
    const cc = String.fromCharCode(buf[0]!, buf[1]!);
    return /^[A-Z]{2}$/.test(cc) ? cc : null;
  }

  /** The date the file was built (YYYYMMDD), or '' when it is missing or not a Draco file. */
  built(): string {
    return this.open()?.built ?? '';
  }

  stale(now = Date.now()): boolean {
    const b = this.built();
    if (b === '') return true;
    const built = Date.UTC(Number(b.slice(0, 4)), Number(b.slice(4, 6)) - 1, Number(b.slice(6, 8)));
    return now - built > MAX_AGE_DAYS * DAY;
  }

  /** Downloads the list when it is missing or stale. '' when done or not needed, otherwise why not. */
  async refresh(): Promise<string> {
    if (!this.stale()) return (this.lastError = '');
    return (this.lastError = await this.update());
  }

  /**
   * Downloads the list, checks the SHA-256 published next to it and only then replaces the old file.
   * '' when done; otherwise "checksum", "download", "format" or "folder".
   */
  async update(): Promise<string> {
    const get = async (url: string): Promise<Uint8Array | null> => {
      try {
        const res = await fetch(url, { headers: { 'User-Agent': 'Draco-Insomnis' }, signal: AbortSignal.timeout(120_000) });
        return res.ok ? new Uint8Array(await res.arrayBuffer()) : null;
      } catch {
        return null;
      }
    };
    const sum = await get(`${this.source}.sha256`);
    const want = sum === null ? '' : new TextDecoder().decode(sum).trim().slice(0, 64).toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(want)) return 'checksum';
    const body = await get(this.source);
    if (body === null || createHash('sha256').update(body).digest('hex') !== want) return 'download';
    if (readHead(body, body.length) === null) return 'format';
    const part = `${this.path}.part`;
    try {
      mkdirSync(dirname(this.path), { recursive: true });
      writeFileSync(part, body);
      renameSync(part, this.path);
    } catch {
      try { unlinkSync(part); } catch { /* nothing to remove */ }
      return 'folder';
    }
    this.close();
    return '';
  }

  close(): void {
    if (this.db !== null) closeSync(this.db.fd);
    this.db = null;
    this.triedAt = 0;
  }

  private open(): Opened | null {
    if (this.db !== null) return this.db;
    // A missing file is looked for again at most once a minute.
    if (Date.now() - this.triedAt < 60_000) return null;
    this.triedAt = Date.now();
    if (!existsSync(this.path)) return null;
    let fd = -1;
    try {
      fd = openSync(this.path, 'r');
      const head = new Uint8Array(HEADER);
      readSync(fd, head, 0, HEADER, 0);
      const info = readHead(head, fstatSync(fd).size);
      if (info === null) {
        closeSync(fd);
        return null;
      }
      return (this.db = { fd, ...info });
    } catch {
      if (fd >= 0) closeSync(fd);
      return null;
    }
  }
}

/** The header of a Draco country file, when the size matches it. */
function readHead(bytes: Uint8Array, size: number): { v4: number; v6: number; built: string } | null {
  if (bytes.length < HEADER || new TextDecoder().decode(bytes.subarray(0, 6)) !== 'DRGEO1') return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, HEADER);
  const v4 = view.getUint32(14);
  const v6 = view.getUint32(18);
  if (size !== HEADER + v4 * 6 + v6 * 18) return null;
  return { v4, v6, built: new TextDecoder().decode(bytes.subarray(6, 14)) };
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}
