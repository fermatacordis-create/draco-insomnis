// End-to-end with the real frameworks and the built package (CI installs express, koa and
// @koa/bodyparser next to it): `node e2e-frameworks.mjs` from that folder.
import express from 'express';
import Koa from 'koa';
import { bodyParser } from '@koa/bodyparser';
import { draco } from 'draco-insomnis/express';
import { draco as koaDraco } from 'draco-insomnis/koa';

let pass = 0, fail = 0;
const check = (ok, what) => { console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${what}`); ok ? pass++ : fail++; };
const ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
const listen = (app) => new Promise((resolve) => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });

async function suite(name, server) {
  const url = `http://127.0.0.1:${server.address().port}`;
  console.log(`== ${name}`);
  check((await fetch(`${url}/?q=union+select+committee`)).status === 200, 'ordinary words pass');
  const page = await fetch(`${url}/`);
  check(page.headers.get('x-content-type-options') === 'nosniff', 'security headers sent');
  check((await fetch(`${url}/own`)).headers.get('x-frame-options') === 'DENY', "the application's own header wins");
  const blocked = await fetch(`${url}${ATTACK}`);
  check(blocked.status === 403 && !(await blocked.text()).includes('sqli'), 'attack gets 403 without naming the rule');
  const form = await fetch(`${url}/contact`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'message=x%27%3B%20DROP%20TABLE%20users%3B%20--' });
  check(form.status === 403, 'posted form inspected');
  const json = await fetch(`${url}/api`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ filter: { name: "' OR '1'='1" } }) });
  check(json.status === 403, 'nested JSON inspected');
  const ok = await fetch(`${url}/api`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name: 'María', note: 'select the best from the union' }) });
  check(ok.status === 200, 'ordinary JSON passes');
  server.close();
}

const app = express();
app.use(express.urlencoded({ extended: false }), express.json());
app.use(draco({ waf: 'block', headers: true }));
app.get('/own', (_q, res) => { res.set('X-Frame-Options', 'DENY'); res.send('own'); });
app.all('*splat', (_q, res) => res.send('page'));
await suite('Express', await listen(app));

const k = new Koa();
k.use(bodyParser());
k.use(koaDraco({ waf: 'block', headers: true }));
k.use((ctx) => { if (ctx.path === '/own') ctx.set('X-Frame-Options', 'DENY'); ctx.body = 'page'; });
await suite('Koa (Strapi)', await listen(k));

console.log(`== done: ${pass} ok, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
