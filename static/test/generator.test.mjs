// The generator's output, and that its patterns are the firewall's own (js/src/core/waf.ts).
// Run: node --experimental-strip-types --test static/test/
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PROBES as JS_PROBES, SCANNERS as JS_SCANNERS } from '../../js/src/core/waf.ts';
import { PROBES, SCANNERS, apache, cloudflare, cspValue, generate, headers, netlify, nginx, vercel } from '../generator.mjs';

test('the patterns are the firewall signatures, unchanged', () => {
  // "\/" in a JavaScript regex literal is the same as "/".
  assert.equal(PROBES, JS_PROBES.source.replaceAll('\\/', '/'));
  assert.equal(SCANNERS, JS_SCANNERS.source);
});

test('.htaccess: rewrite rules, headers, no listings', () => {
  const out = apache({ hsts: true, csp: { enforce: false, scripts: 'https://cdn.example.com' }, today: '2026-11-15' });
  assert.match(out, /^Options -Indexes$/m);
  assert.match(out, /RewriteCond %\{REQUEST_URI\} "\(\^\|\/\)\(\\\.env/);
  assert.match(out, /RewriteCond %\{HTTP_USER_AGENT\} ".*sqlmap.*" \[NC\]/);
  assert.match(out, /Header always set X-Content-Type-Options "nosniff"/);
  assert.match(out, /Header always set Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self' https:\/\/cdn\.example\.com;/);
  assert.match(out, /Strict-Transport-Security "max-age=15552000"/);
  assert.doesNotMatch(apache({ probes: false, scanners: false }), /RewriteEngine/);
});

test('nginx, Netlify and Vercel', () => {
  assert.match(nginx(), /if \(\$uri ~\* "\(\^\|\/\)/);
  assert.match(nginx(), /add_header X-Frame-Options "SAMEORIGIN" always;/);
  assert.match(netlify({ frame: 'DENY' }), /^\/\*\n {2}X-Content-Type-Options: nosniff\n {2}X-Frame-Options: DENY/m);
  const v = JSON.parse(vercel());
  assert.equal(v.headers[0].source, '/(.*)');
  assert.ok(v.headers[0].headers.some((h) => h.key === 'Referrer-Policy'));
});

test('Cloudflare: a Worker project with the real Draco', () => {
  const files = cloudflare({ csp: { enforce: true } });
  assert.deepEqual(Object.keys(files).sort(), ['package.json', 'public/_headers', 'worker.js', 'wrangler.toml']);
  assert.match(files['worker.js'], /import \{ withDraco, KVStore \} from 'draco-insomnis\/worker';/);
  assert.match(files['worker.js'], /pace: 'block'/);
  assert.match(files['wrangler.toml'], /\[assets\]\ndirectory = "\.\/public"/);
  assert.match(files['public/_headers'], /Content-Security-Policy: default-src 'self'/);
  assert.deepEqual(Object.keys(generate('cloudflare', {})).includes('public/_headers'), false);
});

test('CSP: only plausible origins get in', () => {
  const v = cspValue({ scripts: 'https://a.example.com, javascript:alert(1) "x"; evil', images: 'https:' }, 'DENY');
  assert.match(v, /script-src 'self' https:\/\/a\.example\.com evil;/);
  assert.doesNotMatch(v, /javascript:|"x"/);
  assert.match(v, /frame-ancestors 'none'/);
  assert.match(v, /img-src 'self' data: https:/);
});

test('headers can be switched off', () => {
  assert.deepEqual(headers({ headers: false }), []);
});
