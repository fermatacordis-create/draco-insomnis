/**
 * Draco Insomnis for static sites: the configuration for the server or CDN in front of plain HTML.
 * Pure functions, no dependencies; the page (static/index.html) and the tests both use them.
 *
 * A static site has no database and no code on the server, so blocking SQL injection or XSS in the
 * URL protects nothing there. What matters is: files that should not be public (.git, .env, .sql
 * backups uploaded by mistake), known scanners, security headers and a Content-Security-Policy for
 * the people who visit, and — only with a Cloudflare Worker in front — the anti-copy pace limit.
 *
 * PROBES and SCANNERS are the patterns of js/src/core/waf.ts (a test checks they stay the same).
 */

export const PROBES = String.raw`(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|[\w.-]+\.log(\.\d+|\.gz)?$|error_log$|(storage|var)/logs?/|\.ht(access|passwd)$|core/install\.php$|wp-admin/(install|setup-config)\.php$|(phpmyadmin|phppgadmin)[\w.-]*(/|$)|pma(/|$)|[\w.-]+\.(bak|old|orig|save|swp)$|(backup|backups|dump|database)[\w.-]*\.(zip|tar|tgz|gz|bz2|7z|rar)$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)`;

export const SCANNERS = String.raw`\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b`;

export const PLATFORMS = {
  apache: { file: '.htaccess', label: 'Apache or LiteSpeed (most shared hosting)' },
  nginx: { file: 'draco-insomnis.conf', label: 'nginx' },
  netlify: { file: '_headers', label: 'Netlify' },
  vercel: { file: 'vercel.json', label: 'Vercel' },
  cloudflare: { file: 'worker.js', label: 'Cloudflare Worker (full Draco)' },
};

/**
 * @typedef {object} Options
 * @property {boolean} [probes=true]   Refuse requests for secret files (.git, .env, backups…).
 * @property {boolean} [scanners=true] Refuse known scanners by their User-Agent.
 * @property {boolean} [headers=true]  nosniff, frame, referrer and permissions policy.
 * @property {'SAMEORIGIN'|'DENY'} [frame='SAMEORIGIN'] Who may show the site inside a frame.
 * @property {boolean} [hsts=false]    Force HTTPS in browsers for 6 months. Only when the whole site works on HTTPS.
 * @property {object}  [csp]           Content-Security-Policy: { enforce, scripts, styles, images, fonts, connect, frames }.
 * @property {boolean} [pace=true]     Cloudflare only: pages a minute per address and network.
 * @property {string}  [today]         Date written in the header comment (tests pass a fixed one).
 */

const DEFAULTS = { probes: true, scanners: true, headers: true, frame: 'SAMEORIGIN', hsts: false, csp: null, pace: true };

const list = (value) => (Array.isArray(value) ? value : String(value ?? '').split(/[\s,]+/))
  .map((s) => s.trim()).filter((s) => /^(https?:\/\/)?[a-z0-9*.-]+(:\d+)?(\/[^\s;'"]*)?$/i.test(s) || s === "'unsafe-inline'" || s === 'data:' || s === 'https:');

/** The Content-Security-Policy, built from the origins each kind of resource may come from. */
export function cspValue(csp, frame = 'SAMEORIGIN') {
  const parts = [
    "default-src 'self'",
    `script-src 'self' ${list(csp.scripts).join(' ')}`,
    `style-src 'self' ${list(csp.styles).join(' ')}`,
    `img-src 'self' data: ${list(csp.images).join(' ')}`,
    `font-src 'self' data: ${list(csp.fonts).join(' ')}`,
    `connect-src 'self' ${list(csp.connect).join(' ')}`,
    `frame-src 'self' ${list(csp.frames).join(' ')}`,
    `frame-ancestors ${frame === 'DENY' ? "'none'" : "'self'"}`,
    "base-uri 'self'",
    "form-action 'self' " + list(csp.forms).join(' '),
    "object-src 'none'",
  ];
  return parts.map((p) => p.replace(/\s+/g, ' ').trim()).join('; ');
}

/** The response headers, in order. */
export function headers(options = {}) {
  const o = { ...DEFAULTS, ...options };
  const out = [];
  if (o.headers) {
    out.push(['X-Content-Type-Options', 'nosniff']);
    out.push(['X-Frame-Options', o.frame === 'DENY' ? 'DENY' : 'SAMEORIGIN']);
    out.push(['Referrer-Policy', 'strict-origin-when-cross-origin']);
    out.push(['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()']);
  }
  if (o.csp) {
    out.push([o.csp.enforce ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only', cspValue(o.csp, o.frame)]);
  }
  // Browsers ignore it over plain HTTP, so it can always be sent.
  if (o.hsts) out.push(['Strict-Transport-Security', 'max-age=15552000']);
  return out;
}

function header(o, platform) {
  const what = [o.probes && 'secret files refused', o.scanners && 'known scanners refused', o.headers && 'security headers',
    o.csp && (o.csp.enforce ? 'Content-Security-Policy' : 'Content-Security-Policy (report only)'), o.hsts && 'HSTS'].filter(Boolean).join(', ');
  return [
    `Draco Insomnis for static sites: ${PLATFORMS[platform].label}.`,
    `Generated${o.today ? ` on ${o.today}` : ''}: ${what || 'nothing switched on'}.`,
    'https://github.com/fermatacordis-create/draco-insomnis — GPL-2.0-or-later.',
  ];
}

// Only the quote is escaped: Apache and nginx keep other backslashes as they are, and the patterns need them.
const q = (s) => s.replace(/"/g, '\\"');

/** .htaccess for Apache 2.4 and LiteSpeed. */
export function apache(options = {}) {
  const o = { ...DEFAULTS, ...options };
  const lines = header(o, 'apache').map((l) => `# ${l}`);
  lines.push('', '# No folder listings.', 'Options -Indexes');
  if (o.probes || o.scanners) {
    lines.push('', '<IfModule mod_rewrite.c>', 'RewriteEngine On');
    if (o.scanners) lines.push('# Known scanners, by their User-Agent.', `RewriteCond %{HTTP_USER_AGENT} "${q(SCANNERS)}" [NC]`, 'RewriteRule ^ - [F]');
    if (o.probes) lines.push('# Files that must never be public: .git, .env, backups, logs, web shells.', `RewriteCond %{REQUEST_URI} "${q(PROBES)}" [NC]`, 'RewriteRule ^ - [F]');
    lines.push('</IfModule>');
  }
  const h = headers(o);
  if (h.length) {
    lines.push('', '<IfModule mod_headers.c>');
    for (const [k, v] of h) lines.push(`Header always set ${k} "${q(v)}"`);
    lines.push('</IfModule>');
  }
  return lines.join('\n') + '\n';
}

/** A file to include inside the server { } block, before any other location. */
export function nginx(options = {}) {
  const o = { ...DEFAULTS, ...options };
  const lines = header(o, 'nginx').map((l) => `# ${l}`);
  lines.push('# In the server { } block of the site:  include /etc/nginx/snippets/draco-insomnis.conf;', '', 'autoindex off;');
  if (o.scanners) lines.push('', '# Known scanners, by their User-Agent.', `if ($http_user_agent ~* "${q(SCANNERS)}") { return 403; }`);
  if (o.probes) lines.push('', '# Files that must never be public: .git, .env, backups, logs, web shells.', `if ($uri ~* "${q(PROBES)}") { return 403; }`);
  const h = headers(o);
  if (h.length) {
    lines.push('');
    for (const [k, v] of h) lines.push(`add_header ${k} "${q(v)}" always;`);
  }
  return lines.join('\n') + '\n';
}

/** Netlify's _headers (Netlify cannot refuse requests by pattern: headers only). */
export function netlify(options = {}) {
  const o = { ...DEFAULTS, ...options };
  const lines = header(o, 'netlify').map((l) => `# ${l}`);
  lines.push('# Netlify cannot refuse requests by pattern, so this file only sets headers.', '/*');
  for (const [k, v] of headers(o)) lines.push(`  ${k}: ${v}`);
  return lines.join('\n') + '\n';
}

/** vercel.json (Vercel cannot refuse requests by pattern: headers only). Merge it with yours if you have one. */
export function vercel(options = {}) {
  const o = { ...DEFAULTS, ...options };
  return JSON.stringify({
    $comment: header(o, 'vercel').join(' '),
    headers: [{ source: '/(.*)', headers: headers(o).map(([key, value]) => ({ key, value })) }],
  }, null, 2) + '\n';
}

/**
 * A Cloudflare Worker with static assets: the whole of Draco in front of the HTML (firewall, block
 * list, anti-copy pace, review requests, headers). Three files: worker.js, wrangler.toml, package.json.
 */
export function cloudflare(options = {}) {
  const o = { ...DEFAULTS, ...options };
  const extra = headers({ ...o, headers: false, hsts: false });
  const worker = [
    ...header(o, 'cloudflare').map((l) => `// ${l}`),
    "import { withDraco, KVStore } from 'draco-insomnis/worker';",
    '',
    'export default withDraco(',
    '  // The site itself: the files in ./public, served by Cloudflare.',
    '  { fetch: (request, env) => env.ASSETS.fetch(request) },',
    '  (env) => ({',
    "    waf: 'block',",
    `    pace: '${o.pace ? 'block' : 'off'}',`,
    `    headers: ${o.headers},`,
    `    hsts: ${o.hsts},`,
    '    store: new KVStore(env.DRACO),',
    "    review: env.DRACO_SECRET ? { secret: env.DRACO_SECRET } : undefined,",
    '  }),',
    ');',
  ];
  if (extra.length) {
    worker.push('', '// Headers Draco does not send itself (the Content-Security-Policy) go in ./public/_headers:');
    for (const [k, v] of extra) worker.push(`//   ${k}: ${v}`);
  }
  const toml = [
    'name = "my-static-site"',
    'main = "worker.js"',
    'compatibility_date = "2026-11-01"',
    '',
    '# The HTML, CSS and images of the site.',
    '[assets]',
    'directory = "./public"',
    'binding = "ASSETS"',
    'run_worker_first = true',
    '',
    '# Blocks and verified search engines: npx wrangler kv namespace create DRACO',
    '[[kv_namespaces]]',
    'binding = "DRACO"',
    'id = "PUT-THE-ID-HERE"',
  ];
  const pkg = { name: 'my-static-site', private: true, type: 'module', dependencies: { 'draco-insomnis': '^0.1.29' }, devDependencies: { wrangler: '^4' } };
  return {
    'worker.js': worker.join('\n') + '\n',
    'wrangler.toml': toml.join('\n') + '\n',
    'package.json': JSON.stringify(pkg, null, 2) + '\n',
    ...(extra.length ? { 'public/_headers': ['/*', ...extra.map(([k, v]) => `  ${k}: ${v}`)].join('\n') + '\n' } : {}),
  };
}

/** Every file for one platform: { name: content }. */
export function generate(platform, options = {}) {
  switch (platform) {
    case 'apache': return { '.htaccess': apache(options) };
    case 'nginx': return { 'draco-insomnis.conf': nginx(options) };
    case 'netlify': return { _headers: netlify(options) };
    case 'vercel': return { 'vercel.json': vercel(options) };
    case 'cloudflare': return cloudflare(options);
    default: throw new Error(`Unknown platform: ${platform}`);
  }
}
