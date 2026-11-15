package dracoinsomnis;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Lenient URL decoding and query parsing that never throw, for the framework adapters. */
public final class Http {
    private Http() {}

    private static int hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    /**
     * %XX decoded once as UTF-8 (broken sequences become U+FFFD; a lone "%" stays). With {@code form},
     * "+" is a space, as in query strings and forms.
     */
    public static String decode(String s, boolean form) {
        if (s == null || s.isEmpty()) return "";
        if (s.indexOf('%') < 0 && (!form || s.indexOf('+') < 0)) return s;
        ByteArrayOutputStream o = new ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%' && i + 2 < s.length() && hex(s.charAt(i + 1)) >= 0 && hex(s.charAt(i + 2)) >= 0) {
                o.write(hex(s.charAt(i + 1)) * 16 + hex(s.charAt(i + 2)));
                i += 2;
            } else if (c == '+' && form) {
                o.write(' ');
            } else if (c < 0x80) {
                o.write(c);
            } else {
                int end = Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1)) ? i + 2 : i + 1;
                byte[] b = s.substring(i, end).getBytes(StandardCharsets.UTF_8);
                o.write(b, 0, b.length);
                i = end - 1;
            }
        }
        return o.toString(StandardCharsets.UTF_8);
    }

    /** A query string or form body: name to every value, in order. */
    public static Map<String, List<String>> parseQuery(String s) {
        Map<String, List<String>> o = new LinkedHashMap<>();
        if (s == null || s.isEmpty()) return o;
        for (String pair : s.split("&")) {
            if (pair.isEmpty()) continue;
            int eq = pair.indexOf('=');
            String k = decode(eq < 0 ? pair : pair.substring(0, eq), true);
            String v = eq < 0 ? "" : decode(pair.substring(eq + 1), true);
            o.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
        }
        return o;
    }

    /** The last value of every field, for the review form. */
    public static Map<String, String> lastValues(Map<String, ?> values) {
        Map<String, String> o = new LinkedHashMap<>();
        for (Map.Entry<String, ?> e : values.entrySet()) {
            Object v = e.getValue();
            if (v instanceof List<?> l && !l.isEmpty() && l.get(l.size() - 1) instanceof String s) o.put(e.getKey(), s);
            else if (v instanceof String[] a && a.length > 0) o.put(e.getKey(), a[a.length - 1] == null ? "" : a[a.length - 1]);
            else if (v instanceof String s) o.put(e.getKey(), s);
        }
        return o;
    }

    /** The text fields of a JSON object body, for the review form. */
    public static Map<String, String> jsonFields(Object json) {
        Map<String, String> o = new LinkedHashMap<>();
        if (json instanceof Map<?, ?> m) for (Map.Entry<?, ?> e : m.entrySet()) if (e.getValue() instanceof String s) o.put(String.valueOf(e.getKey()), s);
        return o;
    }
}
