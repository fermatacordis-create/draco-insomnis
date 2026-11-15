package draco

import (
	"regexp"
	"strconv"
)

// The attack signatures of src/Core/WafRules.php, js/src/core/waf.ts and the Python edition, kept in
// step by the shared cases in tests/vectors/waf.json. Precise on purpose: only shapes that real
// visitors never send are matched. Go's regexp is RE2 (ASCII \b and \w, like PHP's).

var scanners = regexp.MustCompile(`(?i)\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b`)

var probes = regexp.MustCompile(`(?i)(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|debug\.log$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)`)

const sp = `(\s|/\*.*?\*/|\+)`

var sqli = []*regexp.Regexp{
	// "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
	regexp.MustCompile(`(?is)\bunion\b` + sp + `+(all` + sp + `+|distinct` + sp + `+)?select` + sp + "*(\\d|null\\b|@@|\\*|0x|['\"(]|concat|char\\s*\\(|group_concat|[a-z_.`]+\\s*,)"),
	// A single column right after a quote, a whole number value or a bracket.
	regexp.MustCompile(`(?is)(['")]|(^|[=&])-?\d+)` + sp + `*\bunion\b` + sp + `+(all` + sp + `+)?select` + sp + "+[a-z_.`]+" + sp + `+from\b`),
	regexp.MustCompile(`(?is)\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b`),
	regexp.MustCompile(`(?i)\b(sleep|benchmark|pg_sleep)\s*\(\s*\d`),
	regexp.MustCompile(`(?i)\bwaitfor\s+delay\s+'`),
	regexp.MustCompile(`(?i)'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+`),
	regexp.MustCompile(`(?i)\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)`),
	regexp.MustCompile(`(?i);\s*(drop|truncate|alter)\s+table\b`),
}

var traversal = []*regexp.Regexp{
	regexp.MustCompile(`(\.\.[/\\]){2,}`),
	regexp.MustCompile(`(?i)\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b`),
	regexp.MustCompile(`(?i)\b(php|expect|phar|zip|data)://`),
}

var code = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\$\{\s*jndi\s*:`),
	regexp.MustCompile(`(?i)\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(`),
	regexp.MustCompile(`(?i)\b(wget|curl)\s+(-[a-z]+\s+)*https?://`),
	regexp.MustCompile(`(?i)<\?php`),
}

var xssURL = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*script\b`),
	regexp.MustCompile(`(?i)\bjavascript\s*:`),
	regexp.MustCompile(`(?i)<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=`),
	regexp.MustCompile(`(?i)["'\s]on(error|load|mouseover|focus|toggle)\s*=`),
}

var pct = regexp.MustCompile(`(?i)%([0-9a-f]{2})`)

// rawURLDecode is byte-wise %XX decoding like PHP's rawurldecode (never fails on malformed input).
func rawURLDecode(v string) string {
	return pct.ReplaceAllStringFunc(v, func(m string) string {
		n, _ := strconv.ParseUint(m[1:], 16, 8)
		return string([]byte{byte(n)})
	})
}

func decodedAgain(v string) string {
	if !pct.MatchString(v) {
		return ""
	}
	if again := rawURLDecode(v); again != v {
		return again
	}
	return ""
}

func anyMatch(patterns []*regexp.Regexp, v string) bool {
	for _, p := range patterns {
		if p.MatchString(v) {
			return true
		}
	}
	return false
}

// Inspect returns the rule a request breaks ("scanner", "probe", "sqli", "traversal", "code", "xss"),
// or "" when it breaks none. path and query are decoded once; params are the decoded values (and keys).
func Inspect(path, query string, params []string, userAgent string) string {
	if scanners.MatchString(userAgent) {
		return "scanner"
	}
	if probes.MatchString(path) {
		return "probe"
	}
	// Encoded twice (%2527 → %27 → '): look at the second decoding too. Nothing is changed, only inspected.
	path2, query2 := decodedAgain(path), decodedAgain(query)
	everything := []string{path, query, path2, query2}
	everything = append(everything, params...)
	for _, p := range params {
		everything = append(everything, decodedAgain(p))
	}
	for _, group := range []struct {
		rule     string
		patterns []*regexp.Regexp
	}{{"sqli", sqli}, {"traversal", traversal}, {"code", code}} {
		for _, v := range everything {
			if v != "" && anyMatch(group.patterns, v) {
				return group.rule
			}
		}
	}
	for _, v := range []string{path, query, path2, query2} {
		if v != "" && anyMatch(xssURL, v) {
			return "xss"
		}
	}
	return ""
}

// Flatten turns nested request values (form maps, decoded JSON) into strings, keys too, at most limit.
func Flatten(v interface{}, limit int) []string {
	var out []string
	var walk func(v interface{}, depth int)
	walk = func(v interface{}, depth int) {
		if len(out) >= limit {
			return
		}
		switch x := v.(type) {
		case map[string]interface{}:
			if depth >= 5 {
				return
			}
			for k, item := range x {
				if k != "" {
					out = append(out, k)
				}
				walk(item, depth+1)
			}
		case map[string][]string:
			for k, items := range x {
				if k != "" {
					out = append(out, k)
				}
				for _, item := range items {
					walk(item, depth+1)
				}
			}
		case []interface{}:
			if depth >= 5 {
				return
			}
			for _, item := range x {
				walk(item, depth+1)
			}
		case string:
			out = append(out, x)
		case float64:
			out = append(out, strconv.FormatFloat(x, 'f', -1, 64))
		case bool:
			if x {
				out = append(out, "1")
			} else {
				out = append(out, "")
			}
		}
	}
	walk(v, 0)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
