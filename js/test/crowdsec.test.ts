import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { test } from 'node:test';
import { crowdsecLine, seconds } from '../src/core/crowdsec.ts';
import { Gatekeeper } from '../src/core/gatekeeper.ts';

test('Go durations, as CrowdSec sends them', () => {
  assert.equal(seconds('3h59m40.5s'), 14381);
  assert.equal(seconds('45m'), 2700);
  assert.equal(seconds('1.5s'), 2);
  assert.equal(seconds('250ms'), 1);
  assert.equal(seconds('-3s'), 0);
  assert.equal(seconds('soon'), 0);
});

test('bans from the Local API join the block list; deletions and restarts lift only them', async () => {
  const asked: string[] = [];
  let answer: unknown = {
    new: [
      { type: 'ban', scope: 'Ip', value: '198.51.100.66', duration: '4h', scenario: 'crowdsecurity/http-probing' },
      { type: 'ban', scope: 'Range', value: '203.0.113.0/24', duration: '1h', scenario: 'crowdsecurity/ssh-bf' },
      { type: 'ban', scope: 'Range', value: '10.0.0.0/8', duration: '1h', scenario: 'too wide' },
      { type: 'ban', scope: 'Ip', value: '192.0.2.1', duration: '4h', scenario: 'the owner' },
      { type: 'captcha', scope: 'Ip', value: '198.51.100.67', duration: '4h' },
      { type: 'ban', scope: 'Ip', value: '198.51.100.68', duration: '-1s' },
    ],
    deleted: null,
  };
  const lapi = createServer((req, res) => {
    asked.push(`${req.url} key=${req.headers['x-api-key']}`);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(answer));
  });
  await new Promise<void>((resolve) => lapi.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(lapi.address() as AddressInfo).port}`;
  try {
    const gate = new Gatekeeper({ waf: 'block', adminIps: ['192.0.2.1'], crowdsec: { url, apiKey: 'k3y' } });
    const req = (ip: string, path: string, method = 'GET') => ({ method, path, query: '', params: [], userAgent: 'Mozilla/5.0', remoteAddr: ip });
    // Owner-made block, to check a CrowdSec deletion never lifts it.
    await gate.blocks.add('203.0.113.200', 7, 'Manual', false);

    const first = await gate.crowdsec!.sync();
    assert.deepEqual(first, { added: 2, removed: 0, error: '' });
    assert.match(asked[0]!, /startup=true&scopes=ip,range key=k3y$/);
    assert.equal((await gate.decide(req('198.51.100.66', '/login')))?.why, 'blocked');
    assert.equal(await gate.decide(req('198.51.100.66', '/')), null, 'a banned address may still read');
    assert.equal((await gate.decide(req('203.0.113.9', '/', 'POST')))?.why, 'blocked', 'the range is blocked too');
    assert.equal(await gate.decide(req('10.1.2.3', '/login')), null, 'a /8 is never imported');
    assert.equal(await gate.decide(req('198.51.100.67', '/login')), null, 'only bans');

    answer = { new: [], deleted: [{ type: 'ban', value: '198.51.100.66' }, { type: 'ban', value: '203.0.113.200' }] };
    const second = await gate.crowdsec!.sync();
    assert.deepEqual(second, { added: 0, removed: 1, error: '' });
    assert.match(asked[1]!, /startup=false/);
    assert.equal(await gate.decide(req('198.51.100.66', '/login')), null);
    assert.ok(await gate.blocks.isBlocked('203.0.113.200'), "the owner's block stays");

    // In the background: the first request triggers one sync, the next ones within a minute do not.
    answer = { new: [], deleted: [] };
    const before = asked.length;
    const fresh = new Gatekeeper({ waf: 'block', crowdsec: { url, apiKey: 'k3y' } });
    await fresh.decide(req('198.51.100.1', '/'));
    await fresh.decide(req('198.51.100.1', '/'));
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(asked.length - before, 1);
  } finally {
    lapi.close();
  }
});

test('a Local API that is down never breaks a request', async () => {
  const gate = new Gatekeeper({ waf: 'block', crowdsec: { url: 'http://127.0.0.1:9', apiKey: 'x', timeout: 1 } });
  const res = await gate.crowdsec!.sync();
  assert.equal(res.error, 'no answer');
  assert.equal(await gate.decide({ method: 'GET', path: '/', query: '', params: [], userAgent: 'Mozilla/5.0', remoteAddr: '198.51.100.5' }), null);
});

test('evidence lines in the format of the CrowdSec parser in server/crowdsec', () => {
  const line = JSON.parse(crowdsecLine({ time: 1_800_000_000, ip: '198.51.100.9', remote: '198.51.100.9', endpoint: 'waf:sqli', verdict: 'bot', reasons: ['waf_sqli'], userAgent: 'curl/8', detail: '/?q=1' }, 'shop.example'));
  assert.deepEqual(line, { time: '2027-01-15T08:00:00Z', ip: '198.51.100.9', host: 'shop.example', endpoint: 'waf:sqli', verdict: 'bot', reasons: 'waf_sqli', user_agent: 'curl/8' });
});
