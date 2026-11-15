"""Attack signatures for one request: the same rules as src/Core/WafRules.php and js/src/core/waf.ts,
kept in step by the shared cases in tests/vectors/waf.json.

Precise on purpose: words like "select" or "update" appear in ordinary messages, so only shapes that
real visitors never send are matched. Form values are only checked for SQL and code injection;
HTML-looking input only in the URL, where nobody types it by hand. ASCII rules, like PHP's.
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

_F = re.I | re.A

SCANNERS = re.compile(r"\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b", _F)

PROBES = re.compile(
    r"(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|"
    r"wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|"
    r"vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|debug\.log$|server-status$|cgi-bin/|"
    r"(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)",
    _F,
)

_SP = r"(\s|/\*.*?\*/|\+)"

SQLI = [
    # "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
    re.compile(r"\bunion\b" + _SP + r"+(all" + _SP + r"+|distinct" + _SP + r"+)?select" + _SP
               + r"*(\d|null\b|@@|\*|0x|['\"(]|concat|char\s*\(|group_concat|[a-z_.`]+\s*,)", _F | re.S),
    # A single column right after a quote, a whole number value or a bracket.
    re.compile(r"(['\")]|(^|[=&])-?\d+)" + _SP + r"*\bunion\b" + _SP + r"+(all" + _SP + r"+)?select" + _SP
               + r"+[a-z_.`]+" + _SP + r"+from\b", _F | re.S),
    re.compile(r"\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b", _F | re.S),
    re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d", _F),
    re.compile(r"\bwaitfor\s+delay\s+'", _F),
    re.compile(r"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+", _F),
    re.compile(r"\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)", _F),
    re.compile(r";\s*(drop|truncate|alter)\s+table\b", _F),
]

TRAVERSAL = [
    re.compile(r"(\.\.[/\\]){2,}", re.A),
    re.compile(r"\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b", _F),
    re.compile(r"\b(php|expect|phar|zip|data)://", _F),
]

CODE = [
    re.compile(r"\$\{\s*jndi\s*:", _F),
    re.compile(r"\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(", _F),
    re.compile(r"\b(wget|curl)\s+(-[a-z]+\s+)*https?://", _F),
    re.compile(r"<\?php", _F),
]

XSS_URL = [
    re.compile(r"<\s*script\b", _F),
    re.compile(r"\bjavascript\s*:", _F),
    re.compile(r"<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=", _F),
    re.compile(r"[\"'\s]on(error|load|mouseover|focus|toggle)\s*=", _F),
]

_PCT = re.compile(r"%([0-9a-f]{2})", re.I)


def raw_url_decode(value: str) -> str:
    """Byte-wise %XX decoding like PHP's rawurldecode (never fails on malformed input)."""
    return _PCT.sub(lambda m: chr(int(m.group(1), 16)), value)


def _decoded_again(value: str) -> str:
    """The value decoded once more when it still holds %XX; '' when there is nothing more to decode."""
    if not _PCT.search(value):
        return ""
    again = raw_url_decode(value)
    return "" if again == value else again


def inspect(path: str = "", query: str = "", params: Iterable[str] = (), user_agent: str = "") -> Optional[str]:
    """The rule that matched ("scanner", "probe", "sqli", "traversal", "code", "xss"), or None."""
    params = [str(p) for p in params]
    if SCANNERS.search(user_agent or ""):
        return "scanner"
    if PROBES.search(path or ""):
        return "probe"
    # Encoded twice (%2527 → %27 → '): look at the second decoding too. Nothing is changed, only inspected.
    path2, query2 = _decoded_again(path), _decoded_again(query)
    everything = [path, query, path2, query2, *params, *(_decoded_again(v) for v in params)]
    for rule, patterns in (("sqli", SQLI), ("traversal", TRAVERSAL), ("code", CODE)):
        for value in everything:
            if value and any(p.search(value) for p in patterns):
                return rule
    for value in (path, query, path2, query2):
        if value and any(p.search(value) for p in XSS_URL):
            return "xss"
    return None


def flatten(values, limit: int = 200) -> list:
    """Nested request values (query dicts, JSON bodies) as strings: keys too, at most `limit`."""
    out: list = []

    def walk(value, depth: int) -> None:
        if len(out) >= limit:
            return
        if isinstance(value, (dict, list, tuple)) and depth < 5:
            items = value.items() if isinstance(value, dict) else enumerate(value)
            for key, item in items:
                if isinstance(value, dict) and key != "":
                    out.append(str(key))
                walk(item, depth + 1)
        elif isinstance(value, bool):
            out.append("1" if value else "")
        elif isinstance(value, (str, int, float)):
            out.append(_js_number(value) if isinstance(value, float) else str(value))

    walk(values, 0)
    return out[:limit]


def _js_number(x: float) -> str:
    """Floats written like JavaScript's String(): 2.0 → "2"."""
    return str(int(x)) if x.is_integer() else repr(x)
