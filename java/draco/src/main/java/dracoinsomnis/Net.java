package dracoinsomnis;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Pattern;

/** Addresses and networks, like src/Core/NetList.php: decimal IPv4 without leading zeros, no zones. */
public final class Net {
    private Net() {}

    /** Cloudflare's published ranges: its headers are believed only from these. */
    public static final List<String> CLOUDFLARE = List.of(
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32");

    /** Private and loopback networks: the proxies believed when none are configured. */
    public static final List<String> LOCAL_PROXIES = List.of(
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10");

    private static final Pattern V4_PART = Pattern.compile("^(0|[1-9][0-9]{0,2})$");
    private static final Pattern HEX = Pattern.compile("^[0-9a-fA-F]{1,4}$");
    private static final Pattern V6_CHARS = Pattern.compile("^[0-9a-fA-F:.]+$");
    private static final Pattern DIGITS = Pattern.compile("^[0-9]+$");
    private static final Pattern MAPPED = Pattern.compile("^::ffff:[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$", Pattern.CASE_INSENSITIVE);

    private static byte[] v4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return null;
        byte[] o = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (!V4_PART.matcher(parts[i]).matches()) return null;
            int n = Integer.parseInt(parts[i]);
            if (n > 255) return null;
            o[i] = (byte) n;
        }
        return o;
    }

    private static List<Integer> words(String s) {
        List<Integer> o = new ArrayList<>();
        if (s.isEmpty()) return o;
        String[] items = s.split(":", -1);
        for (int i = 0; i < items.length; i++) {
            if (i == items.length - 1 && items[i].contains(".")) {
                byte[] b = v4(items[i]);
                if (b == null) return null;
                o.add(((b[0] & 0xff) << 8) | (b[1] & 0xff));
                o.add(((b[2] & 0xff) << 8) | (b[3] & 0xff));
            } else {
                if (!HEX.matcher(items[i]).matches()) return null;
                o.add(Integer.parseInt(items[i], 16));
            }
        }
        return o;
    }

    private static byte[] v6(String value) {
        if (value.contains("%") || !V6_CHARS.matcher(value).matches()) return null;
        String[] halves = value.split("::", -1);
        if (halves.length > 2) return null;
        List<Integer> head = words(halves[0]);
        List<Integer> tail = halves.length == 2 ? words(halves[1]) : new ArrayList<>();
        if (head == null || tail == null) return null;
        int missing = 8 - head.size() - tail.size();
        if (halves.length == 2 ? missing < 1 : missing != 0) return null;
        List<Integer> all = new ArrayList<>(head);
        for (int i = 0; halves.length == 2 && i < missing; i++) all.add(0);
        all.addAll(tail);
        byte[] bytes = new byte[16];
        for (int i = 0; i < 8; i++) {
            bytes[2 * i] = (byte) (all.get(i) >> 8);
            bytes[2 * i + 1] = (byte) (all.get(i) & 0xff);
        }
        return bytes;
    }

    /** The address as 4 or 16 bytes, or null when it is not one. */
    public static byte[] toBytes(String ip) {
        String v = ip == null ? "" : ip.trim();
        return v.contains(":") ? v6(v) : v4(v);
    }

    public static boolean isIp(String ip) {
        return toBytes(ip) != null;
    }

    /** The shortest text form: dotted IPv4, or IPv6 with the longest run of zeros as "::". */
    public static String fromBytes(byte[] b) {
        if (b.length == 4) return (b[0] & 0xff) + "." + (b[1] & 0xff) + "." + (b[2] & 0xff) + "." + (b[3] & 0xff);
        int[] w = new int[8];
        for (int i = 0; i < 8; i++) w[i] = ((b[2 * i] & 0xff) << 8) | (b[2 * i + 1] & 0xff);
        int best = -1, bestLen = 0;
        for (int i = 0; i < 8;) {
            if (w[i] != 0) { i++; continue; }
            int j = i;
            while (j < 8 && w[j] == 0) j++;
            if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
            i = j;
        }
        if (best < 0) return hex(w, 0, 8);
        return hex(w, 0, best) + "::" + hex(w, best + bestLen, 8);
    }

    private static String hex(int[] w, int from, int to) {
        StringBuilder o = new StringBuilder();
        for (int i = from; i < to; i++) {
            if (i > from) o.append(':');
            o.append(Integer.toHexString(w[i]));
        }
        return o.toString();
    }

    public static boolean inNet(String cidr, String ip) {
        String[] parts = cidr.trim().split("/", 2);
        byte[] b = toBytes(parts[0]);
        byte[] a = toBytes(ip);
        if (b == null || a == null || b.length != a.length) return false;
        int max = b.length * 8;
        int bits = max;
        if (parts.length == 2 && DIGITS.matcher(parts[1]).matches()) {
            if (parts[1].length() > 4) return false;
            bits = Integer.parseInt(parts[1]);
        }
        if (bits > max) return false;
        int whole = bits / 8, rest = bits % 8;
        for (int i = 0; i < whole; i++) if (b[i] != a[i]) return false;
        if (rest == 0) return true;
        int mask = (0xff << (8 - rest)) & 0xff;
        return (b[whole] & mask) == (a[whole] & mask);
    }

    public static boolean contains(Iterable<String> nets, String ip) {
        for (String n : nets) if (inNet(n, ip)) return true;
        return false;
    }

    /** Networks and addresses: one per line or comma-separated; "#" starts a comment. */
    public static List<String> parse(Iterable<String> items) {
        LinkedHashSet<String> o = new LinkedHashSet<>();
        for (String t : items) {
            if (t == null) continue;
            for (String line : t.split("\r\n|\r|\n", -1)) {
                for (String item : line.replaceAll("#.*", "").split("[\\s,]+", -1)) {
                    if (!item.isEmpty() && isIp(item.split("/", 2)[0])) o.add(item);
                }
            }
        }
        return new ArrayList<>(o);
    }

    /** The /24 (IPv4) or /64 (IPv6) of an address; "" when it is not one. */
    public static String network(String ip) {
        byte[] b = toBytes(ip);
        if (b == null) return "";
        if (b.length == 4) return (b[0] & 0xff) + "." + (b[1] & 0xff) + "." + (b[2] & 0xff) + ".0/24";
        byte[] keep = new byte[16];
        System.arraycopy(b, 0, keep, 0, 8);
        return fromBytes(keep) + "/64";
    }

    /** "::ffff:1.2.3.4" (IPv4 on an IPv6 socket) as "1.2.3.4". */
    public static String unmap(String ip) {
        return MAPPED.matcher(ip).matches() ? ip.substring(7) : ip;
    }
}
