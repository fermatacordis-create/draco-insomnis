import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { Gatekeeper, render } from '../src/core/gatekeeper.ts';
import type { DracoRequest } from '../src/core/request.ts';
import { open, seal, sign, type ReviewRequest } from '../src/core/review.ts';

const vectors = JSON.parse(readFileSync(new URL('../../tests/vectors/review.json', import.meta.url), 'utf8')) as {
  secret: string;
  cases: { ip: string; ts: number; rule: string; opened: string; sealed: string; sig: string }[];
};

test('the same signatures as the PHP engine (tests/vectors/review.json)', async () => {
  for (const c of vectors.cases) {
    assert.equal(await seal(vectors.secret, c.ip, String(c.ts), c.rule), c.sealed, `seal ${c.ip}`);
    assert.equal(await open(vectors.secret, c.ip, String(c.ts), c.sealed), c.opened, `open ${c.ip}`);
    assert.equal(await sign(vectors.secret, c.ip, c.rule, String(c.ts)), c.sig, `sign ${c.ip}`);
  }
  assert.equal(await open(vectors.secret, '198.51.100.99', String(vectors.cases[0]!.ts), vectors.cases[0]!.sealed) === 'sqli', false, 'another address cannot open it');
  assert.equal(await open(vectors.secret, '1.2.3.4', '1', 'zz'), '');
});

const NOW = 1_800_000_000;
const SECRET = 'a-secret-of-the-site-owner-0123456789';
const visitor = (over: Partial<DracoRequest> = {}): DracoRequest => ({
  method: 'GET', path: '/', query: '', params: [], userAgent: 'Mozilla/5.0 Chrome/131.0', remoteAddr: '198.51.100.20', ...over,
});
const fields = (html: string): Record<string, string> => Object.fromEntries(
  [...html.matchAll(/<input type="hidden" name="([a-z_]+)" value="([^"]*)">/g)].map((m) => [m[1]!, m[2]!]),
);

function gatekeeper(now = NOW) {
  const requests: ReviewRequest[] = [];
  const gate = new Gatekeeper({ waf: 'block', review: { secret: SECRET, onRequest: (r) => { requests.push(r); } } }, () => now);
  return { gate, requests };
}

test('the 403 page carries a signed review form that says nothing about the rule', async () => {
  const { gate } = gatekeeper();
  const answer = await gate.decide(visitor({ query: "q=1' union select password from users-- ", params: ["1' union select password from users-- "] }));
  assert.equal(answer?.status, 403);
  const page = render(gate, answer!).body;
  assert.match(page, /name="draco_review" value="1"/);
  assert.match(page, /name="draco_website"/);
  assert.match(page, /Ask for a review/);
  assert.doesNotMatch(page, /sqli/);
  assert.equal(await open(SECRET, '198.51.100.20', String(NOW), fields(page).draco_rule!), 'sqli');
});

test('a review request is accepted once, with the rule, and the visitor only sees thanks', async () => {
  const { gate, requests } = gatekeeper();
  const blocked = await gate.decide(visitor({ query: '../../etc/passwd', params: ['../../etc/passwd'] }));
  const form = { ...fields(blocked!.form!), draco_email: 'Ana@Example.org', draco_message: 'I was <b>looking</b> for a recipe', draco_website: '' };
  const answer = await gate.decide(visitor({ method: 'POST', form }));
  assert.equal(answer?.status, 200);
  assert.match(render(gate, answer!).body, /Request sent/);
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.email, 'ana@example.org');
  assert.equal(requests[0]!.message, 'I was looking for a recipe');
  assert.notEqual(requests[0]!.rule, '');
  assert.equal(gate.events().at(-1)?.verdict, 'pending');
  assert.equal(gate.events().at(-1)?.endpoint, 'review');
});

test('forged, stale, trapped or empty requests get the same thanks and reach nobody', async () => {
  const { gate, requests } = gatekeeper();
  const blocked = await gate.decide(visitor({ query: '../../etc/passwd', params: ['../../etc/passwd'] }));
  const good = { ...fields(blocked!.form!), draco_email: 'ana@example.org', draco_message: 'Hello', draco_website: '' };
  const bad: Record<string, string>[] = [
    { ...good, draco_sig: '0'.repeat(64) },
    { ...good, draco_rule: await seal(SECRET, '198.51.100.20', good.draco_ts!, 'none') },
    { ...good, draco_website: 'http://spam.example' },
    { ...good, draco_email: 'not-an-address' },
    { ...good, draco_message: '   ' },
  ];
  for (const form of bad) {
    const answer = await gate.decide(visitor({ method: 'POST', form }));
    assert.equal(answer?.status, 200);
  }
  // From another address the signature is not valid either.
  await gate.decide(visitor({ method: 'POST', form: good, remoteAddr: '203.0.113.7' }));
  assert.equal(requests.length, 0);
  // A day later the form has expired.
  const later = gatekeeper(NOW + 86400);
  await later.gate.decide(visitor({ method: 'POST', form: good }));
  assert.equal(later.requests.length, 0);
});

test('at most 3 requests a day from one address', async () => {
  const { gate, requests } = gatekeeper();
  const blocked = await gate.decide(visitor({ query: '../../etc/passwd', params: ['../../etc/passwd'] }));
  const form = { ...fields(blocked!.form!), draco_email: 'ana@example.org', draco_message: 'Hello', draco_website: '' };
  for (let i = 0; i < 5; i++) await gate.decide(visitor({ method: 'POST', form }));
  assert.equal(requests.length, 3);
});

test('without a secret there is no form and a review POST is just another request', async () => {
  const gate = new Gatekeeper({ waf: 'block' }, () => NOW);
  const answer = await gate.decide(visitor({ query: '../../etc/passwd', params: ['../../etc/passwd'] }));
  assert.equal(answer?.form, undefined);
  assert.doesNotMatch(render(gate, answer!).body, /<form/);
  assert.equal(await gate.decide(visitor({ method: 'POST', form: { draco_review: '1' } })), null);
});
