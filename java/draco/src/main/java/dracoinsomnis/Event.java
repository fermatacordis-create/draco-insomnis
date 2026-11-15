package dracoinsomnis;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A line of evidence: the same fields as the PHP events table and the other editions. */
public record Event(long time, String ip, String remote, String endpoint, String verdict, List<String> reasons,
        String userAgent, String detail, String email) {

    /** The fields by name, for a JSON log line. */
    public Map<String, Object> toMap() {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("time", time);
        o.put("ip", ip);
        o.put("remote", remote);
        o.put("endpoint", endpoint);
        o.put("verdict", verdict);
        o.put("reasons", reasons);
        o.put("userAgent", userAgent);
        o.put("detail", detail);
        o.put("email", email);
        return o;
    }
}
