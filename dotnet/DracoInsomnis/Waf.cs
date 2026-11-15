using System.Collections;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>
/// The attack signatures of src/Core/WafRules.php and every other edition, kept in step by the shared
/// cases in tests/vectors/waf.json. .NET's \w, \s, \b and \d are Unicode; PHP's are ASCII, so the
/// patterns are rewritten to ASCII classes (<see cref="Ascii"/>) and matched on the request's bytes
/// read one char per byte (Latin-1), like PHP's byte-wise PCRE.
/// </summary>
public static class Waf
{
    private const RegexOptions I = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private const RegexOptions IS = I | RegexOptions.Singleline;

    /// <summary>Rewrites \w, \s, \d and \b to their ASCII meaning, inside and outside [classes].</summary>
    public static string Ascii(string pattern)
    {
        var o = new StringBuilder();
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                var n = pattern[++i];
                o.Append((n, inClass) switch
                {
                    ('w', false) => "[A-Za-z0-9_]",
                    ('w', true) => "A-Za-z0-9_",
                    ('s', false) => "[ \\t\\n\\r\\f\\v]",
                    ('s', true) => " \\t\\n\\r\\f\\v",
                    ('d', false) => "[0-9]",
                    ('d', true) => "0-9",
                    ('b', false) => "(?:(?<![A-Za-z0-9_])(?=[A-Za-z0-9_])|(?<=[A-Za-z0-9_])(?![A-Za-z0-9_]))",
                    _ => "\\" + n,
                });
                continue;
            }
            if (c == '[' && !inClass) inClass = true;
            else if (c == ']' && inClass) inClass = false;
            o.Append(c);
        }
        return o.ToString();
    }

    private static Regex R(string pattern, RegexOptions options) => new(Ascii(pattern), options | RegexOptions.Compiled);

    private static readonly Regex Scanners = R(@"\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\b", I);

    private static readonly Regex Probes = R(@"(^|/)(\.env(\.[a-z0-9]+)?$|\.git(/|$)|\.svn/|\.hg/|\.aws/|\.ssh/|\.ds_store$|wp-config\.php[^/]+$|wp-config\.(bak|old|txt|orig|save|swp)$|phpinfo\.php$|info\.php$|adminer[\w.-]*\.php$|eval-stdin\.php$|vendor/phpunit/|[\w.-]+\.sql(\.gz|\.zip)?$|debug\.log$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\w-]*|shell|webshell|b374k)\.php$)", I);

    private const string Sp = @"(\s|/\*.*?\*/|\+)";

    private static readonly Regex[] Sqli =
    {
        // "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
        R(@"\bunion\b" + Sp + "+(all" + Sp + "+|distinct" + Sp + "+)?select" + Sp + @"*(\d|null\b|@@|\*|0x|['""(]|concat|char\s*\(|group_concat|[a-z_.`]+\s*,)", IS),
        // A single column right after a quote, a whole number value or a bracket.
        R(@"(['"")]|(^|[=&])-?\d+)" + Sp + @"*\bunion\b" + Sp + "+(all" + Sp + "+)?select" + Sp + "+[a-z_.`]+" + Sp + @"+from\b", IS),
        R(@"\bselect\b.{1,120}\bfrom\b.{1,120}\b(information_schema|mysql\.user|pg_catalog)\b", IS),
        R(@"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d", I),
        R(@"\bwaitfor\s+delay\s+'", I),
        R(@"'\s*(or|and)\s+'?\d+'?\s*=\s*'?\d+", I),
        R(@"\b(or|and)\s+\d+\s*=\s*\d+\s*(--|#|/\*)", I),
        R(@";\s*(drop|truncate|alter)\s+table\b", I),
    };

    private static readonly Regex[] Traversal =
    {
        R(@"(\.\.[/\\]){2,}", RegexOptions.CultureInvariant),
        R(@"\b(etc/passwd|etc/shadow|proc/self/environ|boot\.ini|win\.ini)\b", I),
        R(@"\b(php|expect|phar|zip|data)://", I),
    };

    private static readonly Regex[] Code =
    {
        R(@"\$\{\s*jndi\s*:", I),
        R(@"\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(", I),
        R(@"\b(wget|curl)\s+(-[a-z]+\s+)*https?://", I),
        R(@"<\?php", I),
    };

    private static readonly Regex[] XssUrl =
    {
        R(@"<\s*script\b", I),
        R(@"\bjavascript\s*:", I),
        R(@"<\s*(svg|img|iframe|body|details)\b[^>]*\bon[a-z]+\s*=", I),
        R(@"[""'\s]on(error|load|mouseover|focus|toggle)\s*=", I),
    };

    private static readonly Regex Pct = new("%([0-9a-fA-F]{2})", RegexOptions.Compiled);

    /// <summary>The string's UTF-8 bytes, one char per byte (what PHP's byte-wise patterns see).</summary>
    public static string Bytes(string? s) => s is null ? "" : Encoding.Latin1.GetString(Encoding.UTF8.GetBytes(s));

    /// <summary>Byte-wise %XX decoding like PHP's rawurldecode, on a byte string.</summary>
    public static string RawUrlDecode(string v) => Pct.Replace(v, m => ((char)Convert.ToByte(m.Groups[1].Value, 16)).ToString());

    private static string DecodedAgain(string v)
    {
        if (!Pct.IsMatch(v)) return "";
        var again = RawUrlDecode(v);
        return again == v ? "" : again;
    }

    private static bool Any(Regex[] patterns, string v)
    {
        foreach (var p in patterns) if (p.IsMatch(v)) return true;
        return false;
    }

    /// <summary>The rule a request breaks ("scanner", "probe", "sqli", "traversal", "code", "xss"), or null.</summary>
    public static string? Inspect(string path, string query, IEnumerable<string> parameters, string userAgent)
    {
        path = Bytes(path);
        query = Bytes(query);
        var ps = parameters.Select(Bytes).ToList();
        if (Scanners.IsMatch(Bytes(userAgent))) return "scanner";
        if (Probes.IsMatch(path)) return "probe";
        // Encoded twice (%2527 -> %27 -> '): look at the second decoding too. Nothing is changed.
        var path2 = DecodedAgain(path);
        var query2 = DecodedAgain(query);
        var everything = new List<string> { path, query, path2, query2 };
        everything.AddRange(ps);
        everything.AddRange(ps.Select(DecodedAgain));
        foreach (var (rule, patterns) in new[] { ("sqli", Sqli), ("traversal", Traversal), ("code", Code) })
            foreach (var v in everything)
                if (v.Length > 0 && Any(patterns, v)) return rule;
        foreach (var v in new[] { path, query, path2, query2 })
            if (v.Length > 0 && Any(XssUrl, v)) return "xss";
        return null;
    }

    /// <summary>Nested values (form maps, parsed JSON) as strings, keys too, at most <paramref name="limit"/>.</summary>
    public static List<string> Flatten(object? value, int limit = 200)
    {
        var o = new List<string>();
        void Walk(object? v, int depth)
        {
            if (o.Count >= limit) return;
            switch (v)
            {
                case string s: o.Add(s); break;
                case bool b: o.Add(b ? "1" : ""); break;
                case JsonElement j: WalkJson(j, depth); break;
                case IDictionary d when depth < 5:
                    foreach (DictionaryEntry e in d)
                    {
                        var k = e.Key?.ToString() ?? "";
                        if (k.Length > 0) o.Add(k);
                        Walk(e.Value, depth + 1);
                    }
                    break;
                case IEnumerable<KeyValuePair<string, Microsoft.Extensions.Primitives.StringValues>> kv when depth < 5:
                    foreach (var e in kv)
                    {
                        if (e.Key.Length > 0) o.Add(e.Key);
                        foreach (var item in e.Value) Walk(item, depth + 1);
                    }
                    break;
                case IEnumerable e when depth < 5 && v is not string:
                    foreach (var item in e) Walk(item, depth + 1);
                    break;
                case int or long or double or decimal: o.Add(Convert.ToString(v, System.Globalization.CultureInfo.InvariantCulture)!); break;
            }
        }
        void WalkJson(JsonElement j, int depth)
        {
            if (o.Count >= limit) return;
            switch (j.ValueKind)
            {
                case JsonValueKind.Object when depth < 5:
                    foreach (var p in j.EnumerateObject())
                    {
                        if (p.Name.Length > 0) o.Add(p.Name);
                        WalkJson(p.Value, depth + 1);
                    }
                    break;
                case JsonValueKind.Array when depth < 5:
                    foreach (var item in j.EnumerateArray()) WalkJson(item, depth + 1);
                    break;
                case JsonValueKind.String: o.Add(j.GetString() ?? ""); break;
                case JsonValueKind.Number: o.Add(j.GetRawText()); break;
                case JsonValueKind.True: o.Add("1"); break;
                case JsonValueKind.False: o.Add(""); break;
            }
        }
        Walk(value, 0);
        return o.Count > limit ? o.GetRange(0, limit) : o;
    }
}
