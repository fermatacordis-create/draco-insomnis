import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Gatekeeper } from '../src/core/gatekeeper.ts';
import { toBytes } from '../src/core/net.ts';
import { GeoFile } from '../src/geo.ts';

// The same handful of ranges as tests/unit/GeoTest.php, in the format bin/build-geo.php writes.
function fixture(built = '20261113'): Uint8Array {
  const v4: [string, string][] = [['0.0.0.0', '--'], ['1.0.0.0', 'AU'], ['1.0.1.0', 'CN'], ['1.0.4.0', '--'], ['203.0.113.0', 'ES'], ['203.0.114.0', '--']];
  const v6: [string, string][] = [['::', '--'], ['2a00::', 'ES'], ['2a01::', '--']];
  const parts: number[] = [...new TextEncoder().encode(`DRGEO1${built}`)];
  const n = (x: number) => [x >>> 24, (x >>> 16) & 255, (x >>> 8) & 255, x & 255];
  parts.push(...n(v4.length), ...n(v6.length));
  for (const [ip, cc] of [...v4, ...v6]) parts.push(...toBytes(ip)!, cc.charCodeAt(0), cc.charCodeAt(1));
  return new Uint8Array(parts);
}

const dir = mkdtempSync(join(tmpdir(), 'draco-geo-'));
test.after(() => rmSync(dir, { recursive: true, force: true }));

test('addresses get the country of their range, like Geo.php', () => {
  const file = join(dir, 'a.bin');
  writeFileSync(file, fixture());
  const geo = new GeoFile(file, { update: false });
  assert.equal(geo.country('1.0.0.200'), 'AU');
  assert.equal(geo.country('1.0.1.0'), 'CN');
  assert.equal(geo.country('1.0.3.255'), 'CN');
  assert.equal(geo.country('1.0.4.0'), null, 'a gap has no country');
  assert.equal(geo.country('203.0.113.10'), 'ES');
  assert.equal(geo.country('::ffff:203.0.113.10'), 'ES');
  assert.equal(geo.country('2a00:1450::1'), 'ES');
  assert.equal(geo.country('2a01::1'), null);
  assert.equal(geo.country('not an ip'), null);
  assert.equal(geo.built(), '20261113');
  geo.close();
});

test('a missing or foreign file gives no country', () => {
  assert.equal(new GeoFile(join(dir, 'missing.bin'), { update: false }).country('1.0.1.1'), null);
  const junk = join(dir, 'junk.bin');
  writeFileSync(junk, 'x'.repeat(100));
  const geo = new GeoFile(junk, { update: false });
  assert.equal(geo.built(), '');
  assert.equal(geo.country('1.0.1.1'), null);
});

test('the gatekeeper uses the file when the platform gives no country', async () => {
  const file = join(dir, 'g.bin');
  writeFileSync(file, fixture());
  const lookup = new GeoFile(file, { update: false });
  const gate = new Gatekeeper({ waf: 'block', geo: { mode: 'block', countries: ['CN'], action: 'block', lookup } });
  const req = (ip: string, path = '/login') => ({ method: 'GET', path, query: '', params: [], userAgent: 'Mozilla/5.0', remoteAddr: ip });
  assert.equal((await gate.decide(req('1.0.2.3')))?.why, 'geo');
  assert.equal(await gate.decide(req('1.0.2.3', '/')), null, 'only sensitive pages by default');
  assert.equal(await gate.decide(req('1.0.0.9')), null);
  assert.equal(await gate.decide({ ...req('1.0.2.3'), country: 'ES' }), null, "the platform's country wins");
  lookup.close();
});

test('downloads the list once the checksum matches, and keeps the old one otherwise', async () => {
  let body = fixture('20991231');
  let sum = createHash('sha256').update(body).digest('hex');
  const server = createServer((req, res) => {
    res.end(req.url?.endsWith('.sha256') ? `${sum}  draco-geo.bin\n` : body);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const source = `http://127.0.0.1:${(server.address() as AddressInfo).port}/draco-geo.bin`;
  try {
    const file = join(dir, 'sub', 'dl.bin');
    const geo = new GeoFile(file, { update: false, source });
    assert.equal(await geo.refresh(), '');
    assert.equal(geo.built(), '20991231');
    assert.equal(geo.country('203.0.113.1'), 'ES');
    assert.equal(await geo.refresh(), '', 'a fresh file is not downloaded again');
    body = fixture('20991230');
    sum = '0'.repeat(64);
    assert.equal(await geo.update(), 'download');
    assert.equal(readFileSync(file).subarray(6, 14).toString(), '20991231', 'the old file stays');
    geo.close();
  } finally {
    server.close();
  }
});
