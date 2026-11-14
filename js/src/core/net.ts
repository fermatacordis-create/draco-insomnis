/**
 * Addresses and networks — the same behaviour as src/Core/NetList.php and Crawler::network(), with
 * no dependency on node:net so it also runs in Cloudflare Workers.
 */

/** The address as bytes (4 or 16), or null when it is not a valid IPv4 or IPv6 address. */
export function toBytes(ip: string): Uint8Array | null {
  const value = ip.trim();
  if (value.includes(':')) return v6(value);
  return v4(value);
}

function v4(value: string): Uint8Array | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    // Like PHP's filter_var: decimal only, no leading zeros.
    if (!/^(0|[1-9]\d{0,2})$/.test(parts[i]!)) return null;
    const n = Number(parts[i]);
    if (n > 255) return null;
    out[i] = n;
  }
  return out;
}

function v6(value: string): Uint8Array | null {
  if (value.includes('%') || !/^[0-9a-f:.]+$/i.test(value)) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const words = (s: string): number[] | null => {
    if (s === '') return [];
    const out: number[] = [];
    const items = s.split(':');
    for (let i = 0; i < items.length; i++) {
      const item = items[i]!;
      if (i === items.length - 1 && item.includes('.')) {
        const b = v4(item);
        if (b === null) return null;
        out.push((b[0]! << 8) | b[1]!, (b[2]! << 8) | b[3]!);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(item)) return null;
        out.push(parseInt(item, 16));
      }
    }
    return out;
  };
  const head = words(halves[0]!);
  const tail = halves.length === 2 ? words(halves[1]!) : [];
  if (head === null || tail === null) return null;
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null;
  const all = [...head, ...new Array<number>(halves.length === 2 ? missing : 0).fill(0), ...tail];
  const out = new Uint8Array(16);
  all.forEach((w, i) => {
    out[i * 2] = w >> 8;
    out[i * 2 + 1] = w & 0xff;
  });
  return out;
}

export const isIP = (ip: string): boolean => toBytes(ip) !== null;

/** The bytes back as text: dotted IPv4, or compressed lower-case IPv6 (like inet_ntop). */
export function fromBytes(b: Uint8Array): string {
  if (b.length === 4) return Array.from(b).join('.');
  const w: number[] = [];
  for (let i = 0; i < 16; i += 2) w.push((b[i]! << 8) | b[i + 1]!);
  // The longest run of two or more zero words becomes "::".
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (w[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && w[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
    i = j;
  }
  const hex = (xs: number[]): string => xs.map((x) => x.toString(16)).join(':');
  if (best < 0) return hex(w);
  return `${hex(w.slice(0, best))}::${hex(w.slice(best + bestLen))}`;
}

/** Whether the address is inside the network ("10.0.0.0/8", "2001:db8::/32" or a single address). */
export function inNet(cidr: string, ip: string): boolean {
  const [baseText, bitsText] = cidr.trim().split('/', 2) as [string, string | undefined];
  const base = toBytes(baseText);
  const addr = toBytes(ip);
  if (base === null || addr === null || base.length !== addr.length) return false;
  const max = base.length * 8;
  const bits = bitsText !== undefined && /^\d+$/.test(bitsText) ? Number(bitsText) : max;
  if (bits > max) return false;
  const whole = Math.floor(bits / 8);
  for (let i = 0; i < whole; i++) if (base[i] !== addr[i]) return false;
  const rest = bits % 8;
  if (rest === 0) return true;
  const mask = (0xff << (8 - rest)) & 0xff;
  return (base[whole]! & mask) === (addr[whole]! & mask);
}

export const contains = (nets: readonly string[], ip: string): boolean => nets.some((n) => inNet(n, ip));

/** Networks and addresses from text: one per line or separated by commas, "#" starts a comment. */
export function parse(text: string | readonly string[]): string[] {
  const lines = typeof text === 'string' ? text.split(/\r\n|\r|\n/) : text;
  const out: string[] = [];
  for (const line of lines) {
    for (const item of line.replace(/#.*/, '').split(/[\s,]+/)) {
      if (item !== '' && isIP(item.split('/', 1)[0]!) && !out.includes(item)) out.push(item);
    }
  }
  return out;
}

/** The /24 (IPv4) or /64 (IPv6) the address belongs to; '' when it is not an address. */
export function network(ip: string): string {
  const b = toBytes(ip);
  if (b === null) return '';
  if (b.length === 4) return `${b[0]}.${b[1]}.${b[2]}.0/24`;
  const keep = new Uint8Array(16);
  keep.set(b.subarray(0, 8));
  return `${fromBytes(keep)}/64`;
}

/** Cloudflare's published ranges (https://www.cloudflare.com/ips/), as in Request::CLOUDFLARE. */
export const CLOUDFLARE: readonly string[] = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32',
];

/** Proxies trusted when none are listed: the machine itself and networks unreachable from the internet. */
export const LOCAL_PROXIES: readonly string[] = [
  '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16',
  '::1/128', 'fc00::/7', 'fe80::/10',
];

/** Strips the "::ffff:" prefix Node puts on IPv4 connections to dual-stack sockets. */
export const unmap = (ip: string): string => (/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(ip) ? ip.slice(7) : ip);
