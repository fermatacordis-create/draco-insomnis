package dracoinsomnis;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The little JSON Draco needs (block list, CrowdSec answers, request bodies, log lines), so the
 * library has no dependencies. Objects are {@link LinkedHashMap}, arrays {@link ArrayList}, numbers
 * {@link Num} (their text as written), plus String, Boolean and null.
 */
public final class Json {
    private Json() {}

    /** A number exactly as it was written. */
    public record Num(String raw) {
        @Override
        public String toString() {
            return raw;
        }
    }

    private static final int MAX_DEPTH = 64;

    /** Parses one JSON value; {@link IllegalArgumentException} when it is not JSON. */
    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.space();
        Object v = p.value(0);
        p.space();
        if (p.i != text.length()) throw p.error();
        return v;
    }

    /** The value as compact JSON. Maps keep their order; use a TreeMap for sorted keys. */
    public static String write(Object value) {
        StringBuilder o = new StringBuilder();
        write(o, value);
        return o.toString();
    }

    private static void write(StringBuilder o, Object v) {
        if (v == null) o.append("null");
        else if (v instanceof String s) string(o, s);
        else if (v instanceof Boolean b) o.append(b ? "true" : "false");
        else if (v instanceof Num n) o.append(n.raw());
        else if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) o.append(v);
        else if (v instanceof Number n) o.append(Double.isFinite(n.doubleValue()) ? n.toString() : "null");
        else if (v instanceof Map<?, ?> m) {
            o.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) o.append(',');
                first = false;
                string(o, String.valueOf(e.getKey()));
                o.append(':');
                write(o, e.getValue());
            }
            o.append('}');
        } else if (v instanceof Collection<?> c) {
            o.append('[');
            boolean first = true;
            for (Object x : c) {
                if (!first) o.append(',');
                first = false;
                write(o, x);
            }
            o.append(']');
        } else string(o, v.toString());
    }

    private static void string(StringBuilder o, String s) {
        o.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> o.append("\\\"");
                case '\\' -> o.append("\\\\");
                case '\n' -> o.append("\\n");
                case '\r' -> o.append("\\r");
                case '\t' -> o.append("\\t");
                case '\b' -> o.append("\\b");
                case '\f' -> o.append("\\f");
                default -> {
                    // Control characters, and <, >, & so a line can never close a <script> it lands in.
                    if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == ' ' || c == ' ') o.append(String.format("\\u%04x", (int) c));
                    else o.append(c);
                }
            }
        }
        o.append('"');
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) {
            this.s = s;
        }

        IllegalArgumentException error() {
            return new IllegalArgumentException("not JSON at " + i);
        }

        void space() {
            while (i < s.length() && " \t\r\n".indexOf(s.charAt(i)) >= 0) i++;
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH || i >= s.length()) throw error();
            char c = s.charAt(i);
            if (c == '{') return object(depth);
            if (c == '[') return array(depth);
            if (c == '"') return string();
            if (s.startsWith("true", i)) { i += 4; return Boolean.TRUE; }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            if (s.startsWith("null", i)) { i += 4; return null; }
            return number();
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> o = new LinkedHashMap<>();
            i++;
            space();
            if (i < s.length() && s.charAt(i) == '}') { i++; return o; }
            while (true) {
                space();
                if (i >= s.length() || s.charAt(i) != '"') throw error();
                String k = string();
                space();
                if (i >= s.length() || s.charAt(i) != ':') throw error();
                i++;
                space();
                o.put(k, value(depth + 1));
                space();
                if (i >= s.length()) throw error();
                char c = s.charAt(i++);
                if (c == '}') return o;
                if (c != ',') throw error();
            }
        }

        List<Object> array(int depth) {
            List<Object> o = new ArrayList<>();
            i++;
            space();
            if (i < s.length() && s.charAt(i) == ']') { i++; return o; }
            while (true) {
                space();
                o.add(value(depth + 1));
                space();
                if (i >= s.length()) throw error();
                char c = s.charAt(i++);
                if (c == ']') return o;
                if (c != ',') throw error();
            }
        }

        String string() {
            StringBuilder o = new StringBuilder();
            i++;
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return o.toString();
                if (c < 0x20) throw error();
                if (c != '\\') { o.append(c); continue; }
                if (i >= s.length()) throw error();
                char e = s.charAt(i++);
                switch (e) {
                    case '"', '\\', '/' -> o.append(e);
                    case 'b' -> o.append('\b');
                    case 'f' -> o.append('\f');
                    case 'n' -> o.append('\n');
                    case 'r' -> o.append('\r');
                    case 't' -> o.append('\t');
                    case 'u' -> {
                        if (i + 4 > s.length()) throw error();
                        try {
                            o.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        } catch (NumberFormatException x) {
                            throw error();
                        }
                        i += 4;
                    }
                    default -> throw error();
                }
            }
            throw error();
        }

        Num number() {
            int start = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            int digits = i;
            while (i < s.length() && Character.isDigit(s.charAt(i)) && s.charAt(i) < 128) i++;
            if (i == digits) throw error();
            if (i < s.length() && s.charAt(i) == '.') {
                i++;
                int f = i;
                while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
                if (i == f) throw error();
            }
            if (i < s.length() && (s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                i++;
                if (i < s.length() && (s.charAt(i) == '+' || s.charAt(i) == '-')) i++;
                int f = i;
                while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
                if (i == f) throw error();
            }
            return new Num(s.substring(start, i));
        }
    }
}
