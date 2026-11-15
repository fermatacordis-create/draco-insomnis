// The built generator page in a real browser (Chromium through Playwright): it loads with no error
// and no request, switches language, and the files it shows and downloads are the generator's own.
// Run: node static/test/browser.mjs path/to/draco-insomnis-static-X.html   (needs: npm i playwright)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';
import { apache, cloudflare } from '../generator.mjs';

const file = process.argv[2];
// DRACO_CHROMIUM: a Chromium already on the machine, instead of the one Playwright downloads.
const browser = await chromium.launch(process.env.DRACO_CHROMIUM ? { executablePath: process.env.DRACO_CHROMIUM } : {});
const page = await browser.newPage({ acceptDownloads: true, locale: 'en-US' });
const errors = [];
const requests = [];
page.on('pageerror', (e) => errors.push(String(e)));
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('request', (r) => { if (!r.url().startsWith('file:') && !r.url().startsWith('blob:')) requests.push(r.url()); });
await page.goto(pathToFileURL(file).href);

let failed = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`ok   - ${name}`); } catch (e) { failed++; console.log(`FAIL - ${name}: ${e.message.split('\n')[0]}`); }
};

await check('loads with no error', async () => assert.deepEqual(errors, []));
await check('the default is .htaccess with report-only CSP', async () => {
  const shown = await page.textContent('#output');
  const want = apache({ csp: { enforce: false, scripts: '', styles: '', images: '', fonts: '', connect: '', frames: '', forms: '' }, frame: 'SAMEORIGIN', hsts: false, pace: true, today: new Date().toISOString().slice(0, 10) });
  assert.equal(shown, want);
});
await check('options change the file', async () => {
  await page.check('#hsts');
  await page.fill('#c_scripts', 'https://cdn.example.com');
  await page.check('input[name=csp][value=enforce]');
  const shown = await page.textContent('#output');
  assert.match(shown, /Strict-Transport-Security/);
  assert.match(shown, /Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https:\/\/cdn\.example\.com;/);
});
await check('download gives the shown file', async () => {
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#download')]);
  assert.equal(download.suggestedFilename(), 'htaccess.txt', 'browsers refuse hidden files; the steps say to rename it');
  assert.equal(readFileSync(await download.path(), 'utf8'), await page.textContent('#output'));
});
await check('Cloudflare shows the Worker project', async () => {
  await page.check('input[name=platform][value=cloudflare]');
  const tabs = await page.$$eval('#fileTabs button', (b) => b.map((x) => x.textContent));
  assert.deepEqual(tabs, Object.keys(cloudflare({ csp: { enforce: true } })));
  assert.match(await page.textContent('#output'), /withDraco/);
  assert.ok(await page.isVisible('#paceRow'));
});
await check('Spanish', async () => {
  await page.click('[data-lang=es]');
  assert.equal(await page.textContent('h1'), 'Draco Insomnis para webs estáticas');
  assert.match(await page.textContent('#steps'), /wrangler deploy/);
  assert.equal(await page.getAttribute('html', 'lang'), 'es');
});
await check('nothing was requested from the network', async () => assert.deepEqual(requests, []));
await check('still no error', async () => assert.deepEqual(errors, []));

await browser.close();
console.log(failed ? `\n${failed} check(s) failed` : '\nall browser checks passed');
process.exit(failed ? 1 : 0);
