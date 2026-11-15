package dracoinsomnis;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The attack signatures of src/Core/WafRules.php and every other edition, kept in step by the shared
 * cases in tests/vectors/waf.json. The patterns are rewritten to ASCII classes ({@link #ascii}) and
 * matched on the request's bytes read one char per byte (Latin-1), like PHP's byte-wise PCRE.
 */
public final class Waf {
    private Waf() {}

    // UNIX_LINES: only "\n" ends a line, as in PCRE ("." and "$" would otherwise also stop at \r and \x85).
    private static final int I = Pattern.CASE_INSENSITIVE | Pattern.UNIX_LINES;
    private static final int IS = I | Pattern.DOTALL;
    private static final String WORD = "[A-Za-z0-9_]";

    /** Rewrites \w, \s, \d and \b to their ASCII (PHP) meaning, inside and outside [classes]. */
    public static String ascii(String pattern) {
        StringBuilder o = new StringBuilder();
        boolean inClass = false;
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '\\' && i + 1 < pattern.length()) {
                char n = pattern.charAt(++i);
                if (n == 'w') o.append(inClass ? "A-Za-z0-9_" : WORD);
                else if (n == 's') o.append(inClass ? " \\t\\n\\r\\f\\x0B" : "[ \\t\\n\\r\\f\\x0B]");
                else if (n == 'd') o.append(inClass ? "0-9" : "[0-9]");
                else if (n == 'b' && !inClass) o.append("(?:(?<!" + WORD + ")(?=" + WORD + ")|(?<=" + WORD + ")(?!" + WORD + "))");
                else o.append('\\').append(n);
                continue;
            }
            if (c == '[' && !inClass) inClass = true;
            else if (c == ']' && inClass) inClass = false;
            o.append(c);
        }
        return o.toString();
    }

    private static Pattern r(String pattern, int flags) {
        return Pattern.compile(ascii(pattern), flags);
    }

    private static final Pattern SCANNERS = r("\\b(sqlmap|nikto|wpscan|nmap|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|ffuf|feroxbuster|wfuzz|whatweb|openvas|netsparker|jaeles|hydra)\\b", I);

    private static final Pattern PROBES = r("(^|/)(\\.env(\\.[a-z0-9]+)?$|\\.git(/|$)|\\.svn/|\\.hg/|\\.aws/|\\.ssh/|\\.ds_store$|wp-config\\.php[^/]+$|wp-config\\.(bak|old|txt|orig|save|swp)$|phpinfo\\.php$|info\\.php$|adminer[\\w.-]*\\.php$|eval-stdin\\.php$|vendor/phpunit/|[\\w.-]+\\.sql(\\.gz|\\.zip)?$|debug\\.log$|server-status$|cgi-bin/|(wso|c99|r57|alfa[\\w-]*|shell|webshell|b374k)\\.php$)", I);

    private static final String SP = "(\\s|/\\*.*?\\*/|\\+)";

    private static final Pattern[] SQLI = {
        // "union select" followed by a column list, not by a word: "European Union Select Committee" passes.
        r("\\bunion\\b" + SP + "+(all" + SP + "+|distinct" + SP + "+)?select" + SP + "*(\\d|null\\b|@@|\\*|0x|['\"(]|concat|char\\s*\\(|group_concat|[a-z_.`]+\\s*,)", IS),
        // A single column right after a quote, a whole number value or a bracket.
        r("(['\")]|(^|[=&])-?\\d+)" + SP + "*\\bunion\\b" + SP + "+(all" + SP + "+)?select" + SP + "+[a-z_.`]+" + SP + "+from\\b", IS),
        r("\\bselect\\b.{1,120}\\bfrom\\b.{1,120}\\b(information_schema|mysql\\.user|pg_catalog)\\b", IS),
        r("\\b(sleep|benchmark|pg_sleep)\\s*\\(\\s*\\d", I),
        r("\\bwaitfor\\s+delay\\s+'", I),
        r("'\\s*(or|and)\\s+'?\\d+'?\\s*=\\s*'?\\d+", I),
        r("\\b(or|and)\\s+\\d+\\s*=\\s*\\d+\\s*(--|#|/\\*)", I),
        r(";\\s*(drop|truncate|alter)\\s+table\\b", I),
    };

    private static final Pattern[] TRAVERSAL = {
        r("(\\.\\.[/\\\\]){2,}", Pattern.UNIX_LINES),
        r("\\b(etc/passwd|etc/shadow|proc/self/environ|boot\\.ini|win\\.ini)\\b", I),
        r("\\b(php|expect|phar|zip|data)://", I),
    };

    private static final Pattern[] CODE = {
        r("\\$\\{\\s*jndi\\s*:", I),
        r("\\b(base64_decode|eval|assert|system|shell_exec|passthru|proc_open|popen)\\s*\\(", I),
        r("\\b(wget|curl)\\s+(-[a-z]+\\s+)*https?://", I),
        r("<\\?php", I),
    };

    private static final Pattern[] XSS_URL = {
        r("<\\s*script\\b", I),
        r("\\bjavascript\\s*:", I),
        r("<\\s*(svg|img|iframe|body|details)\\b[^>]*\\bon[a-z]+\\s*=", I),
        r("[\"'\\s]on(error|load|mouseover|focus|toggle)\\s*=", I),
    };

    private static final Pattern PCT = Pattern.compile("%([0-9a-fA-F]{2})");

    /** The string's UTF-8 bytes, one char per byte (what PHP's byte-wise patterns see). */
    public static String bytes(String s) {
        return s == null ? "" : new String(s.getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1);
    }

    /** Byte-wise %XX decoding like PHP's rawurldecode, on a byte string. */
    public static String rawUrlDecode(String v) {
        Matcher m = PCT.matcher(v);
        StringBuilder o = new StringBuilder();
        while (m.find()) m.appendReplacement(o, Matcher.quoteReplacement(String.valueOf((char) Integer.parseInt(m.group(1), 16))));
        m.appendTail(o);
        return o.toString();
    }

    private static String decodedAgain(String v) {
        if (!PCT.matcher(v).find()) return "";
        String again = rawUrlDecode(v);
        return again.equals(v) ? "" : again;
    }

    private static boolean any(Pattern[] patterns, String v) {
        for (Pattern p : patterns) if (p.matcher(v).find()) return true;
        return false;
    }

    /** The rule a request breaks ("scanner", "probe", "sqli", "traversal", "code", "xss"), or null. */
    public static String inspect(String path, String query, Collection<String> parameters, String userAgent) {
        path = bytes(path);
        query = bytes(query);
        List<String> ps = new ArrayList<>();
        for (String p : parameters) ps.add(bytes(p));
        if (SCANNERS.matcher(bytes(userAgent)).find()) return "scanner";
        if (PROBES.matcher(path).find()) return "probe";
        // Encoded twice (%2527 -> %27 -> '): look at the second decoding too. Nothing is changed.
        String path2 = decodedAgain(path);
        String query2 = decodedAgain(query);
        List<String> everything = new ArrayList<>(List.of(path, query, path2, query2));
        everything.addAll(ps);
        for (String p : ps) everything.add(decodedAgain(p));
        String[] rules = {"sqli", "traversal", "code"};
        Pattern[][] sets = {SQLI, TRAVERSAL, CODE};
        for (int k = 0; k < rules.length; k++) {
            for (String v : everything) if (!v.isEmpty() && any(sets[k], v)) return rules[k];
        }
        for (String v : new String[] {path, query, path2, query2}) if (!v.isEmpty() && any(XSS_URL, v)) return "xss";
        return null;
    }

    /** Nested values (parameter maps, parsed JSON) as strings, keys too, at most 200. */
    public static List<String> flatten(Object value) {
        return flatten(value, 200);
    }

    /** Nested values (parameter maps, parsed JSON) as strings, keys too, at most {@code limit}. */
    public static List<String> flatten(Object value, int limit) {
        List<String> o = new ArrayList<>();
        walk(o, value, 0, limit);
        return o.size() > limit ? new ArrayList<>(o.subList(0, limit)) : o;
    }

    private static void walk(List<String> o, Object v, int depth, int limit) {
        if (o.size() >= limit || v == null) return;
        if (v instanceof String s) o.add(s);
        else if (v instanceof Boolean b) o.add(b ? "1" : "");
        else if (v instanceof Json.Num || v instanceof Number) o.add(v.toString());
        else if (depth >= 5) return;
        else if (v instanceof Map<?, ?> m) {
            for (Map.Entry<?, ?> e : m.entrySet()) {
                String k = e.getKey() == null ? "" : e.getKey().toString();
                if (!k.isEmpty()) o.add(k);
                walk(o, e.getValue(), depth + 1, limit);
            }
        } else if (v instanceof Iterable<?> it) {
            for (Object x : it) walk(o, x, depth + 1, limit);
        } else if (v instanceof Object[] a) {
            for (Object x : a) walk(o, x, depth + 1, limit);
        }
    }
}
