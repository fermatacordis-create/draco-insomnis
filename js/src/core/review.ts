/**
 * "This is a mistake": a person the firewall stopped asks the owner to look again, from the 403
 * page — the same form, signatures and limits as src/Core/Review.php (tests/vectors/review.json).
 *
 * The form is signed for the address and the moment it was shown, carries the rule sealed (the page
 * never says what matched), has a trap field and is limited per address (3 a day) and per site (50 a
 * day). Draco never writes to the person who asks: that would let anyone make the site send mail.
 */
import type { Store } from './store.ts';

export const FIELD = 'draco_review';
export const ENDPOINT = 'review';
const MAX_PER_IP_DAY = 3;
const MAX_PER_DAY = 50;
const VALID_FOR = 86400;

export interface ReviewLabels {
  email: string;
  message: string;
  button: string;
}

/** One accepted request, for the owner's queue (see DracoOptions.review.onRequest). */
export interface ReviewRequest {
  time: number;
  ip: string;
  /** The rule that stopped the visitor ("sqli", "blocked", "geo"…); '' when it could not be read. */
  rule: string;
  email: string;
  message: string;
  userAgent: string;
}

const enc = new TextEncoder();

async function hmac(secret: string, data: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

const hex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const cleanRule = (rule: string): string => rule.toLowerCase().replace(/[^a-z0-9_]/g, '');

/** The rule hidden from the visitor: XOR with a key from the secret, the address and the moment. */
export async function seal(secret: string, ip: string, ts: string, rule: string): Promise<string> {
  const plain = new Uint8Array(32);
  plain.set(enc.encode(cleanRule(rule).slice(0, 32)));
  const key = await hmac(secret, `review-rule|${ip}|${ts}`);
  return hex(plain.map((b, i) => b ^ key[i]!));
}

/** The rule from seal(), or '' when the value is not one. */
export async function open(secret: string, ip: string, ts: string, sealed: string): Promise<string> {
  if (!/^[0-9a-f]{64}$/i.test(sealed)) return '';
  const key = await hmac(secret, `review-rule|${ip}|${ts}`);
  const bytes = Uint8Array.from(sealed.match(/../g)!, (h, i) => parseInt(h, 16) ^ key[i]!);
  let end = bytes.length;
  while (end > 0 && bytes[end - 1] === 0) end--;
  const rule = new TextDecoder().decode(bytes.subarray(0, end));
  return /^[a-z0-9_]*$/.test(rule) ? rule : '';
}

export async function sign(secret: string, ip: string, rule: string, ts: string): Promise<string> {
  return hex(await hmac(secret, `review|${ip}|${rule}|${ts}`));
}

/** Equal strings, compared in constant time. */
function same(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

const h = (s: string): string => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

/** The form under the 403 text, already escaped. */
export async function form(secret: string, ip: string, why: string, now: number, labels: ReviewLabels): Promise<string> {
  const ts = String(Math.floor(now));
  const rule = cleanRule(why);
  return '<form method="post" action="">'
    + `<input type="hidden" name="${FIELD}" value="1">`
    + `<input type="hidden" name="draco_rule" value="${h(await seal(secret, ip, ts, rule))}">`
    + `<input type="hidden" name="draco_ts" value="${h(ts)}">`
    + `<input type="hidden" name="draco_sig" value="${h(await sign(secret, ip, rule, ts))}">`
    + '<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>'
    + `<label for="draco-r-email">${h(labels.email)}</label>`
    + '<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">'
    + `<label for="draco-r-msg">${h(labels.message)}</label>`
    + '<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>'
    + `<button type="submit">${h(labels.button)}</button>`
    + '</form>';
}

export function isRequest(method: string, form: Record<string, string> | undefined): boolean {
  return method === 'POST' && (form?.[FIELD] ?? '') === '1';
}

// The same checks as PHP's FILTER_VALIDATE_EMAIL for what people really type; no quoted local parts.
const EMAIL = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

/** Checks a request and returns it when it passes; the visitor gets the same thanks either way. */
export async function accept(store: Store, secret: string, ip: string, userAgent: string, post: Record<string, string>, now: number): Promise<ReviewRequest | null> {
  const ts = post.draco_ts ?? '';
  const rule = await open(secret, ip, ts, post.draco_rule ?? '');
  const email = (post.draco_email ?? '').trim().toLowerCase();
  const message = Array.from(
    (post.draco_message ?? '')
      .replace(/<(script|style)[^>]*?>[\s\S]*?<\/\1>|<[^>]*>/gi, '')
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
      .trim(),
  ).slice(0, 500).join('');
  const fresh = /^\d+$/.test(ts) && Number(ts) <= now && now - Number(ts) < VALID_FOR;
  const ok = fresh && same(await sign(secret, ip, rule, ts), post.draco_sig ?? '') && (post.draco_website ?? '') === ''
    && EMAIL.test(email) && email.length <= 190 && message !== '';
  if (!ok) return null;
  const day = new Date(now * 1000).toISOString().slice(0, 10).replace(/-/g, '');
  if ((await store.bump(`draco:review:ip:${ip}`, VALID_FOR)) > MAX_PER_IP_DAY) return null;
  if ((await store.bump(`draco:review:day:${day}`, VALID_FOR)) > MAX_PER_DAY) return null;
  return { time: Math.floor(now), ip, rule, email, message, userAgent: userAgent.slice(0, 255) };
}
