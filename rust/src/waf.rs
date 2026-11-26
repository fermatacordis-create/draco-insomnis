//! The attack signatures of src/Core/WafRules.php and every other edition, kept in step by the shared
//! cases in tests/vectors/waf.json. Matched on the request's bytes with ASCII classes ("(?-u)"), like
//! PHP's byte-wise PCRE.

use crate::json::Value;
use regex::bytes::Regex;
use std::sync::LazyLock;

/// PCRE's "$" (without the m flag) also matches before a final "\n"; Rust's matches only at the end.
fn pcre(pattern: &str) -> String {
    let mut o = String::new();
    let (mut in_class, mut esc) = (false, false);
    for c in pattern.chars() {
        if esc {
            o.push(c);
            esc = false;
            continue;
        }
        match c {
            '\\' => {
                esc = true;
                o.push(c);
            }
            '[' if !in_class => {
                in_class = true;
                o.push(c);
            }
            ']' if in_class => {
                in_class = false;
                o.push(c);
            }
            '$' if !in_class => o.push_str(r"(?:\n?\z)"),
            c => o.push(c),
        }
    }
    o
}

fn r(flags: &str, pattern: &str) -> Regex {
    Regex::new(&format!("(?{flags}-u){}", pcre(pattern))).expect("Draco pattern")
}

const I: &str = "i";
const IS: &str = "is";

static SCANNERS: LazyLock<Regex> = LazyLock::new(|| {
    r(
        I,
        r"\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b",
    )
});

static PROBES: LazyLock<Regex> = LazyLock::new(|| {
    r(
        I,
        r"(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|[\w.-]+\.log(\.\d+|\.gz)?$|error_log$|(storage|var)/logs?/|\.ht(access|passwd)$|core/install\.php$|wp-admin/(install|setup-config)\.php$|(phpmyadmin|phppgadmin)[\w.-]*(/|$)|pma(/|$)|[\w.-]+\.(bak|old|orig|save|swp)$|(backup|backups|dump|database)[\w.-]*\.(zip|tar|tgz|gz|bz2|7z|rar)$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)",
    )
});

const SP: &str = r"(\s|/\*.*?\*/|\+)";

static SQLI: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
        r(
            IS,
            &format!(
                r#"\bunion\b{SP}+(all{SP}+|distinct{SP}+)?select{SP}*(\d|null\b|@@|\*|0x|['"(]|concat|char\s*\(|group_concat|[a-z_.`]+\s*,)"#
            ),
        ),
        // A single column right after a quote, a whole number value or a bracket.
        r(IS, &format!(r#"(['")]|(^|[=&])-?\d+){SP}*\bunion\b{SP}+(all{SP}+)?select{SP}+[a-z_.`]+{SP}+from\b"#)),
        r(IS, r"\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b"),
        r(I, r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d"),
        r(I, r"\bwaitfor\s+delay\s+'"),
        r(I, r"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+"),
        r(I, r"\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)"),
        r(I, r";\s*(drop|truncate|alter)\s+table\b"),
    ]
});

static TRAVERSAL: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        r("", r"(\.\.[/\\]){2,}"),
        r(I, r"\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b"),
        r(I, r"\b(php|expect|phar|zip|data)://"),
    ]
});

static CODE: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        r(I, r"\$\{\s*jndi\s*:"),
        r(I, r"\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\("),
        r(I, r"\b(wget|curl)\s+(-[a-z]+\s+)*https?://"),
        r(I, r"<\?php"),
    ]
});

static XSS_URL: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        r(I, r"<\s*script\b"),
        r(I, r"\bjavascript\s*:"),
        r(I, r"<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*="),
        r(I, r#"["'\s]on(error|load|mouseover|focus|toggle)\s*="#),
    ]
});

fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|d| d as u8)
}

/// Byte-wise %XX decoding like PHP's rawurldecode.
pub fn raw_url_decode(v: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(v.len());
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%' && i + 2 < v.len() {
            if let (Some(h), Some(l)) = (hex(v[i + 1]), hex(v[i + 2])) {
                o.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        o.push(v[i]);
        i += 1;
    }
    o
}

fn has_pct(v: &[u8]) -> bool {
    v.windows(3).any(|w| w[0] == b'%' && hex(w[1]).is_some() && hex(w[2]).is_some())
}

fn decoded_again(v: &[u8]) -> Vec<u8> {
    if !has_pct(v) {
        return Vec::new();
    }
    let again = raw_url_decode(v);
    if again == v {
        Vec::new()
    } else {
        again
    }
}

fn any(patterns: &[Regex], v: &[u8]) -> bool {
    patterns.iter().any(|p| p.is_match(v))
}

/// The rule a request breaks ("scanner", "probe", "sqli", "traversal", "code", "xss"), or None.
pub fn inspect<S: AsRef<str>>(path: &str, query: &str, params: &[S], user_agent: &str) -> Option<&'static str> {
    let (path, query) = (path.as_bytes(), query.as_bytes());
    if SCANNERS.is_match(user_agent.as_bytes()) {
        return Some("scanner");
    }
    if PROBES.is_match(path) {
        return Some("probe");
    }
    // Encoded twice (%2527 -> %27 -> '): look at the second decoding too. Nothing is changed.
    let path2 = decoded_again(path);
    let query2 = decoded_again(query);
    let ps: Vec<&[u8]> = params.iter().map(|p| p.as_ref().as_bytes()).collect();
    let ps2: Vec<Vec<u8>> = ps.iter().map(|p| decoded_again(p)).collect();
    let mut everything: Vec<&[u8]> = vec![path, query, &path2, &query2];
    everything.extend(ps.iter().copied());
    everything.extend(ps2.iter().map(|p| p.as_slice()));
    for (rule, set) in [("sqli", &*SQLI), ("traversal", &*TRAVERSAL), ("code", &*CODE)] {
        if everything.iter().any(|v| !v.is_empty() && any(set, v)) {
            return Some(rule);
        }
    }
    if [path, query, &path2, &query2].iter().any(|v| !v.is_empty() && any(&XSS_URL, v)) {
        return Some("xss");
    }
    None
}

/// A parsed JSON body as strings, keys too, at most `limit`.
pub fn flatten_json(v: &Value, limit: usize) -> Vec<String> {
    fn walk(o: &mut Vec<String>, v: &Value, depth: usize, limit: usize) {
        if o.len() >= limit {
            return;
        }
        match v {
            Value::Null => {}
            Value::Str(s) => o.push(s.clone()),
            Value::Num(n) => o.push(n.clone()),
            Value::Bool(b) => o.push(if *b { "1".into() } else { String::new() }),
            _ if depth >= 5 => {}
            Value::Arr(a) => a.iter().for_each(|x| walk(o, x, depth + 1, limit)),
            Value::Obj(m) => {
                for (k, x) in m {
                    if !k.is_empty() {
                        o.push(k.clone());
                    }
                    walk(o, x, depth + 1, limit);
                }
            }
        }
    }
    let mut o = Vec::new();
    walk(&mut o, v, 0, limit);
    o.truncate(limit);
    o
}

/// Query or form fields (name and values) as strings, at most `limit`.
pub fn flatten_fields(fields: &[(String, Vec<String>)], limit: usize) -> Vec<String> {
    let mut o = Vec::new();
    for (k, vs) in fields {
        if !k.is_empty() {
            o.push(k.clone());
        }
        o.extend(vs.iter().cloned());
    }
    o.truncate(limit);
    o
}
