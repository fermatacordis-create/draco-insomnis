/**
 * Attack signatures for one request — the same rules as src/Core/WafRules.php, kept in step by the
 * shared vectors in tests/vectors/waf.json (run by both the PHP and the JavaScript tests).
 *
 * Precise on purpose: words like "select" or "update" appear in ordinary messages, so only shapes
 * that real visitors never send are matched. Text bodies (forms) are only checked for SQL and code
 * injection shapes; HTML-looking input is only checked in the URL, where nobody types it by hand.
 */

export interface WafInput {
  /** URL path, decoded once. */
  path?: string;
  /** Query string, decoded once. */
  query?: string;
  /** Decoded GET and POST values (and keys). */
  params?: string[];
  userAgent?: string;
}

export type WafRule = 'scanner' | 'probe' | 'sqli' | 'traversal' | 'code' | 'xss';

const SCANNERS = /\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b/i;

const PROBES = /(^|\/)(\.env(\.[a-z0-9]+)?$|\.git(\/|$)|\.svn\/|\.hg\/|\.aws\/|\.ssh\/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor\/phpunit\/|[\w.-]+\.sql(\.gz|\.zip)?$|debug\.log$|server-status$|cgi-bin\/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)/i;

const SP = String.raw`(\s|\/\*.*?\*\/|\+)`;

const SQLI: RegExp[] = [
  // "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
  new RegExp(String.raw`\bunion\b${SP}+(all${SP}+|distinct${SP}+)?select${SP}*(\d|null\b|@@|\*|0x|['"(]|concat|char\s*\(|group_concat|[a-z_.\`]+\s*,)`, 'is'),
  // A single column right after a quote, a whole number value or a bracket.
  new RegExp(String.raw`(['")]|(^|[=&])-?\d+)${SP}*\bunion\b${SP}+(all${SP}+)?select${SP}+[a-z_.\`]+${SP}+from\b`, 'is'),
  /\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b/is,
  /\b(sleep|benchmark|pg_sleep)\s*\(\s*\d/i,
  /\bwaitfor\s+delay\s+'/i,
  /'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+/i,
  /\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|\/\*)/i,
  /;\s*(drop|truncate|alter)\s+table\b/i,
];

const TRAVERSAL: RegExp[] = [
  /(\.\.[/\\]){2,}/,
  /\b(etc\/passwd|etc\/shadow|proc\/self\/environ|boot\.ini|win\.ini)\b/i,
  /\b(php|expect|phar|zip|data):\/\//i,
];

const CODE: RegExp[] = [
  /\$\{\s*jndi\s*:/i,
  /\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(/i,
  /\b(wget|curl)\s+(-[a-z]+\s+)*https?:\/\//i,
  /<\?php/i,
];

const XSS_URL: RegExp[] = [
  /<\s*script\b/i,
  /\bjavascript\s*:/i,
  /<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=/i,
  /["'\s]on(error|load|mouseover|focus|toggle)\s*=/i,
];

/** Byte-wise %XX decoding like PHP's rawurldecode (never throws on malformed input). */
export function rawUrlDecode(value: string): string {
  return value.replace(/%([0-9a-f]{2})/gi, (_m, h: string) => String.fromCharCode(parseInt(h, 16)));
}

/** The value decoded once more when it still holds %XX sequences; '' when there is nothing more to decode. */
function decodedAgain(value: string): string {
  if (!/%[0-9a-f]{2}/i.test(value)) return '';
  const again = rawUrlDecode(value);
  return again === value ? '' : again;
}

const any = (patterns: RegExp[], value: string): boolean => patterns.some((p) => p.test(value));

/** The rule that matched, or null. */
export function inspect(r: WafInput): WafRule | null {
  const path = r.path ?? '';
  const query = r.query ?? '';
  const params = r.params ?? [];
  if (SCANNERS.test(r.userAgent ?? '')) return 'scanner';
  if (PROBES.test(path)) return 'probe';
  // Encoded twice (%2527 → %27 → '): look at the second decoding too. Nothing is changed, only inspected.
  const path2 = decodedAgain(path);
  const query2 = decodedAgain(query);
  const everything = [path, query, path2, query2, ...params.map(String), ...params.map((v) => decodedAgain(String(v)))];
  for (const [rule, patterns] of [['sqli', SQLI], ['traversal', TRAVERSAL], ['code', CODE]] as const) {
    for (const value of everything) {
      if (value !== '' && any(patterns, value)) return rule;
    }
  }
  for (const value of [path, query, path2, query2]) {
    if (value !== '' && any(XSS_URL, value)) return 'xss';
  }
  return null;
}

/** Flattens nested request values (query objects, JSON bodies) into strings, at most `limit` of them. */
export function flatten(values: unknown, limit = 200): string[] {
  const out: string[] = [];
  const walk = (value: unknown, depth: number): void => {
    if (out.length >= limit) return;
    if (value !== null && typeof value === 'object' && depth < 5) {
      for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
        if (!Array.isArray(value) && key !== '') out.push(key);
        walk(item, depth + 1);
      }
    } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
      out.push(typeof value === 'boolean' ? (value ? '1' : '') : String(value));
    }
  };
  walk(values, 0);
  return out.slice(0, limit);
}
