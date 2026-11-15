package dracoinsomnis;

import java.util.List;
import java.util.Map;

/**
 * One visitor request in plain values, whatever the framework. Every field has a harmless default;
 * the chained setters return the request: {@code new DracoRequest().method("POST").path("/login")}.
 */
public final class DracoRequest {
    private String method = "GET";
    private String path = "/";
    private String query = "";
    private List<String> params = List.of();
    private String userAgent = "";
    private String remoteAddr = "";
    private String cfConnectingIp = "";
    private String forwardedFor = "";
    private String country = "";
    private String accept = "";
    private boolean ajax;
    private Map<String, String> form = Map.of();

    private static String nn(String s) {
        return s == null ? "" : s;
    }

    public String method() { return method; }
    public DracoRequest method(String v) { method = nn(v); return this; }
    /** The decoded path. */
    public String path() { return path; }
    public DracoRequest path(String v) { path = v == null || v.isEmpty() ? "/" : v; return this; }
    /** The decoded query string. */
    public String query() { return query; }
    public DracoRequest query(String v) { query = nn(v); return this; }
    /** Decoded query and body values (and keys), for the firewall only. */
    public List<String> params() { return params; }
    public DracoRequest params(List<String> v) { params = v == null ? List.of() : v; return this; }
    public String userAgent() { return userAgent; }
    public DracoRequest userAgent(String v) { userAgent = nn(v); return this; }
    /** The connection's own address. */
    public String remoteAddr() { return remoteAddr; }
    public DracoRequest remoteAddr(String v) { remoteAddr = nn(v); return this; }
    public String cfConnectingIp() { return cfConnectingIp; }
    public DracoRequest cfConnectingIp(String v) { cfConnectingIp = nn(v); return this; }
    /** X-Forwarded-For, every header joined with ", ". */
    public String forwardedFor() { return forwardedFor; }
    public DracoRequest forwardedFor(String v) { forwardedFor = nn(v); return this; }
    /** Cloudflare's CF-IPCountry, only when the connection comes from Cloudflare. */
    public String country() { return country; }
    public DracoRequest country(String v) { country = nn(v); return this; }
    public String accept() { return accept; }
    public DracoRequest accept(String v) { accept = nn(v); return this; }
    /** X-Requested-With: XMLHttpRequest. */
    public boolean ajax() { return ajax; }
    public DracoRequest ajax(boolean v) { ajax = v; return this; }
    /** The text fields of a posted form, for the review form. */
    public Map<String, String> form() { return form; }
    public DracoRequest form(Map<String, String> v) { form = v == null ? Map.of() : v; return this; }
}
