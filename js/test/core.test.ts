import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Gatekeeper } from '../src/core/gatekeeper.ts';
import { contains, fromBytes, inNet, isIP, network, parse, toBytes } from '../src/core/net.ts';
import { clientIp, urlDecode, type DracoRequest } from '../src/core/request.ts';
import { MemoryStore, validNet } from '../src/core/store.ts';
import { hostMatches } from '../src/core/crawler.ts';

const req = (over: Partial<DracoRequest> = {}): DracoRequest => ({
  method: 'GET', path: '/', query: '', params: [], userAgent: 'Mozilla/5.0', remoteAddr: '203.0.113.7', accept: 'text/html', ...over,
});
const attack = (over: Partial<DracoRequest> = {}): DracoRequest => req({ query: "q=1' union select password from users-- ", ...over });

test('addresses', () => {
  for (const ip of ['1.2.3.4', '::1', '2001:db8::1', '::ffff:1.2.3.4', 'fe80::1:2']) assert.ok(isIP(ip), ip);
  for (const ip of ['1.2.3', '1.2.3.256', '01.2.3.4', '1::2::3', 'abc', '', '1.2.3.4/24']) assert.ok(!isIP(ip), ip);
  assert.equal(fromBytes(toBytes('2001:0db8:0000:0000:0000:0000:0000:0001')!), '2001:db8::1');
  assert.ok(inNet('10.0.0.0/8', '10.200.1.1'));
  assert.ok(!inNet('10.0.0.0/8', '11.0.0.1'));
  assert.ok(inNet('2001:db8::/32', '2001:db8:ffff::1'));
  assert.ok(!inNet('2001:db8::/32', '1.2.3.4'));
  assert.ok(inNet('172.16.0.0/12', '172.31.255.255') && !inNet('172.16.0.0/12', '172.32.0.0'));
  assert.equal(network('198.51.100.77'), '198.51.100.0/24');
  assert.equal(network('2001:db8:1:2:3:4:5:6'), '2001:db8:1:2::/64');
  assert.deepEqual(parse('10.0.0.0/8, 1.2.3.4 # office\nnot-an-ip\n10.0.0.0/8'), ['10.0.0.0/8', '1.2.3.4']);
  assert.ok(contains(['192.168.0.0/16', '::1'], '::1'));
  assert.ok(validNet('203.0.113.0/24') && !validNet('10.0.0.0/8') && validNet('2001:db8::/48') && !validNet('2001::/16'));
});

test('the visitor address behind proxies', () => {
  // No proxy chosen: the header is ignored.
  assert.equal(clientIp(req({ forwardedFor: '6.6.6.6' }), ''), '203.0.113.7');
  // X-Forwarded-For from a local proxy: read from the right, skipping trusted proxies.
  assert.equal(clientIp(req({ remoteAddr: '127.0.0.1', forwardedFor: '6.6.6.6, 198.51.100.9, 10.0.0.2' }), 'xff'), '198.51.100.9');
  // From an untrusted connection the header is not believed.
  assert.equal(clientIp(req({ forwardedFor: '6.6.6.6' }), 'xff'), '203.0.113.7');
  // Cloudflare: only from Cloudflare's ranges.
  assert.equal(clientIp(req({ remoteAddr: '172.64.1.1', cfConnectingIp: '198.51.100.20' }), 'cf'), '198.51.100.20');
  assert.equal(clientIp(req({ cfConnectingIp: '198.51.100.20' }), 'cf'), '203.0.113.7');
  // Node's dual-stack spelling.
  assert.equal(clientIp(req({ remoteAddr: '::ffff:203.0.113.8' }), ''), '203.0.113.8');
});

test('decoding never throws', () => {
  assert.equal(urlDecode('a%20b+c', true), 'a b c');
  assert.equal(urlDecode('100%'), '100%');
  assert.equal(urlDecode('%E2%9C%93%zz'), '✓%zz');
});

test('search engine names', () => {
  assert.ok(hostMatches('googlebot', 'crawl-66-249-66-1.googlebot.com.'));
  assert.ok(!hostMatches('googlebot', 'googlebot.com.evil.example'));
  assert.ok(!hostMatches('bingbot', '157.55.39.1'));
});

test('firewall: log only lets attacks through and writes evidence', async () => {
  const events: string[] = [];
  const gate = new Gatekeeper({ onEvent: (e) => { events.push(`${e.endpoint}|${e.verdict}`); } });
  assert.equal(await gate.decide(attack()), null);
  assert.deepEqual(events, ['waf:sqli|doubtful']);
  assert.equal(await gate.decide(req({ query: 'q=union select committee' })), null);
  assert.equal(events.length, 1, 'ordinary words leave no trace');
});

test('firewall: block, then 5 attacks block the address for posting', async () => {
  const gate = new Gatekeeper({ waf: 'block' });
  assert.deepEqual(await gate.decide(attack()), { status: 403, why: 'sqli', retry: 0 });
  assert.equal((await gate.decide(req({ userAgent: 'sqlmap/1.8' })))?.why, 'scanner');
  for (let i = 0; i < 4; i++) await gate.decide(attack());
  assert.ok(await gate.blocks.isBlocked('203.0.113.7'));
  assert.equal(await gate.decide(req()), null, 'a blocked address can still read');
  assert.equal((await gate.decide(req({ method: 'POST' })))?.why, 'blocked');
  assert.equal((await gate.decide(req({ path: '/wp-login.php' })))?.why, 'blocked');
});

test('a forged X-Forwarded-For blocks the sender, never the address it names', async () => {
  const gate = new Gatekeeper({ waf: 'block' });
  for (let i = 0; i < 6; i++) await gate.decide(attack({ forwardedFor: '6.6.6.6' }));
  assert.ok(!(await gate.blocks.isBlocked('6.6.6.6')));
  assert.ok(await gate.blocks.isBlocked('203.0.113.7'));
});

test('admin addresses and excepted paths are never inspected', async () => {
  const gate = new Gatekeeper({ waf: 'block', adminIps: ['203.0.113.7'], except: ['/health'] });
  assert.equal(await gate.decide(attack()), null);
  const other = new Gatekeeper({ waf: 'block', except: ['/health'] });
  assert.equal(await other.decide(attack({ path: '/health/check' })), null);
  assert.notEqual(await other.decide(attack({ path: '/status' })), null);
});

test('blocked ranges, by hand', async () => {
  const gate = new Gatekeeper({ waf: 'log' });
  assert.ok(await gate.blocks.add('203.0.113.0/24', 0, 'by hand', false));
  assert.ok(!(await gate.blocks.add('10.0.0.0/8', 30, 'too wide', false)));
  assert.equal((await gate.decide(req({ method: 'POST' })))?.why, 'blocked');
  await gate.blocks.remove('203.0.113.0/24');
  assert.equal(await gate.decide(req({ method: 'POST' })), null);
});

test('countries: only sensitive requests by default, and only in block mode', async () => {
  const events: string[] = [];
  const gate = new Gatekeeper({ waf: 'log', geo: { mode: 'block', countries: ['zz', 'RU'], action: 'block' }, onEvent: (e) => { events.push(e.detail); } });
  assert.equal(await gate.decide(req({ country: 'RU' })), null, 'reading is fine');
  assert.equal((await gate.decide(req({ country: 'RU', path: '/login' })))?.why, 'geo');
  assert.equal(await gate.decide(req({ country: 'ES', path: '/login' })), null);
  assert.equal(await gate.decide(req({ country: 'T1', method: 'POST' })), null, 'Tor is not a country');
  assert.deepEqual(events, ['RU /login']);
  const allow = new Gatekeeper({ geo: { mode: 'allow', countries: ['ES'], scope: 'site' } });
  assert.equal(await allow.decide(req({ country: 'FR' })), null, 'action log: evidence only');
});

test('anti-copy pace: pages only, per minute', async () => {
  let now = 1_800_000_000;
  const gate = new Gatekeeper({ waf: 'off', pace: 'block', rateIp: 10 }, () => now);
  const codes: (number | null)[] = [];
  for (let i = 0; i < 12; i++) codes.push((await gate.decide(req()))?.status ?? null);
  assert.equal(codes.filter((c) => c === 429).length, 2);
  assert.equal(await gate.decide(req({ accept: 'application/json' })), null, 'API calls do not count');
  assert.equal(await gate.decide(req({ accept: '*/*' })), null, 'images and scripts do not count');
  now += 60;
  assert.equal(await gate.decide(req()), null, 'a new minute');
});

test('verified search engines go past the pace; pretenders do not', async () => {
  const resolver = {
    reverse: async (ip: string) => (ip === '66.249.66.1' ? ['crawl-66-249-66-1.googlebot.com'] : ['evil.example']),
    lookup: async (host: string) => (host === 'crawl-66-249-66-1.googlebot.com' ? ['66.249.66.1'] : []),
  };
  const gate = new Gatekeeper({ waf: 'off', pace: 'block', rateIp: 10, resolver });
  const google = req({ remoteAddr: '66.249.66.1', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1)' });
  const fake = req({ remoteAddr: '198.51.100.66', userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1)' });
  for (let i = 0; i < 11; i++) { await gate.decide(google); await gate.decide(fake); }
  assert.equal(await gate.decide(google), null);
  assert.equal((await gate.decide(fake))?.status, 429);
});

test('security headers', () => {
  assert.deepEqual(new Gatekeeper().headers(true), {});
  const h = new Gatekeeper({ headers: true, hsts: true });
  assert.equal(h.headers(true)['X-Content-Type-Options'], 'nosniff');
  assert.equal(h.headers(false)['Strict-Transport-Security'], undefined);
});

test('memory store expires keys', async () => {
  let now = 1000;
  const s = new MemoryStore(() => now);
  assert.equal(await s.bump('k', 10), 1);
  assert.equal(await s.bump('k', 10), 2);
  now += 11;
  assert.equal(await s.bump('k', 10), 1);
  await s.set('p', 'v', 0);
  now += 1e6;
  assert.equal(await s.get('p'), 'v');
});
