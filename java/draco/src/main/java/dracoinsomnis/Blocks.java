package dracoinsomnis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** The block list on any store: one key per address, one key holding the blocked networks. */
public final class Blocks {
    /** "For good": 9999-12-31 23:59:59 UTC, like the other editions. */
    public static final long FOREVER = 253402300799L;
    private static final Pattern CIDR = Pattern.compile("^([0-9a-fA-F.:]+)/([0-9]{1,4})$");

    /** One blocked address or network. The JSON fields are the same in every edition. */
    public record Entry(String value, long until, String reason, boolean automatic) {
        Map<String, Object> toMap() {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("value", value);
            o.put("until", until);
            o.put("reason", reason);
            o.put("automatic", automatic);
            return o;
        }

        static Entry from(Object o) {
            if (!(o instanceof Map<?, ?> m) || !(m.get("value") instanceof String v)) return null;
            long until;
            try {
                until = m.get("until") == null ? 0 : (long) Double.parseDouble(m.get("until").toString());
            } catch (NumberFormatException e) {
                return null;
            }
            String reason = m.get("reason") instanceof String r ? r : "";
            return new Entry(v, until, reason, Boolean.TRUE.equals(m.get("automatic")));
        }
    }

    private final Store store;

    public Blocks(Store store) {
        this.store = store;
    }

    /** A network may be blocked when it is no wider than /16 (IPv4) or /32 (IPv6). */
    public static boolean validNet(String cidr) {
        Matcher m = CIDR.matcher(cidr.trim());
        if (!m.matches()) return false;
        byte[] b = Net.toBytes(m.group(1));
        int bits = Integer.parseInt(m.group(2));
        if (b == null) return false;
        return b.length == 16 ? bits >= 32 && bits <= 128 : bits >= 16 && bits <= 32;
    }

    /** Blocks an address or network for some days (0 = for good). */
    public boolean add(String value, int days, String reason, boolean automatic, double now) {
        long until = days == 0 ? FOREVER : (long) now + days * 86400L;
        return write(new Entry(value, until, reason, automatic), now, days == 0 ? 0 : days * 86400);
    }

    /** Blocks an address or network until a Unix time. */
    public boolean addUntil(String value, long until, String reason, boolean automatic, double now) {
        long ttl = until - (long) now;
        return ttl > 0 && write(new Entry(value, until, reason, automatic), now, (int) Math.min(ttl, Integer.MAX_VALUE));
    }

    public void remove(String value, double now) {
        if (value.contains("/")) {
            List<Object> keep = new ArrayList<>();
            for (Entry n : nets(now)) if (!n.value().equals(value)) keep.add(n.toMap());
            store.set("draco:nets", Json.write(keep), 0);
        } else {
            store.delete("draco:block:" + value);
        }
    }

    /** The blocked networks still in force. */
    public List<Entry> nets(double now) {
        List<Entry> o = new ArrayList<>();
        String raw = store.get("draco:nets");
        if (raw == null) return o;
        try {
            if (!(Json.parse(raw) instanceof List<?> all)) return o;
            for (Object x : all) {
                Entry e = Entry.from(x);
                if (e != null && e.until() > now) o.add(e);
            }
        } catch (IllegalArgumentException e) {
            return new ArrayList<>();
        }
        return o;
    }

    /** The entry of one address or network, or null. */
    public Entry entry(String value, double now) {
        if (value.contains("/")) {
            for (Entry n : nets(now)) if (n.value().equals(value)) return n;
            return null;
        }
        String raw = store.get("draco:block:" + value);
        if (raw == null) return null;
        try {
            return Entry.from(Json.parse(raw));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public boolean isBlocked(String ip, double now) {
        if (store.get("draco:block:" + ip) != null) return true;
        for (Entry n : nets(now)) if (Net.inNet(n.value(), ip)) return true;
        return false;
    }

    private boolean write(Entry e, double now, int ttl) {
        if (e.value().contains("/")) {
            if (!validNet(e.value())) return false;
            List<Object> nets = new ArrayList<>();
            for (Entry n : nets(now)) if (!n.value().equals(e.value())) nets.add(n.toMap());
            nets.add(e.toMap());
            store.set("draco:nets", Json.write(nets), 0);
            return true;
        }
        store.set("draco:block:" + e.value(), Json.write(e.toMap()), ttl);
        return true;
    }
}
