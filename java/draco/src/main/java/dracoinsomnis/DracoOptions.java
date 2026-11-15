package dracoinsomnis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Every setting. A plain JavaBean: Spring Boot binds it from application.yml
 * ({@code @ConfigurationProperties("draco-insomnis")}), and {@link #fromMap} reads servlet init
 * parameters, system properties or the environment.
 */
public class DracoOptions {
    private String waf = "log";
    private String pace = "off";
    private int rateIp;
    private int rateNet;
    private String proxy = "";
    private List<String> trustedProxies = new ArrayList<>();
    private List<String> adminIps = new ArrayList<>();
    private List<String> sensitive = new ArrayList<>();
    private List<String> except = new ArrayList<>();
    private GeoOptions geo = new GeoOptions();
    private boolean headers;
    private boolean hsts;
    private ReviewOptions review = new ReviewOptions();
    private CrowdSecOptions crowdSec = new CrowdSecOptions();
    private boolean logEvents;
    private Map<String, String> texts = new LinkedHashMap<>();

    /** Country filter: mode "block" (refuse the countries) or "allow" (only those). */
    public static class GeoOptions {
        private String mode = "off";
        private List<String> countries = new ArrayList<>();
        private String action = "log";
        private String scope = "sensitive";
        private String file = "";

        /** "off" (default), "block" or "allow". */
        public String getMode() { return mode; }
        public void setMode(String mode) { this.mode = nn(mode); }
        /** Two-letter codes. */
        public List<String> getCountries() { return countries; }
        public void setCountries(List<String> countries) { this.countries = countries == null ? new ArrayList<>() : new ArrayList<>(countries); }
        /** "log" (default) or "block". */
        public String getAction() { return action; }
        public void setAction(String action) { this.action = nn(action); }
        /** "sensitive" (default: logins, sign-ups and any POST) or "site". */
        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = nn(scope); }
        /** Where the country list is kept; it is downloaded there and refreshed. */
        public String getFile() { return file; }
        public void setFile(String file) { this.file = nn(file); }
    }

    /** Review requests from the 403 page. */
    public static class ReviewOptions {
        private String secret = "";

        /** 16 characters or more turn the review form on. */
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = nn(secret); }
    }

    /** The owner's CrowdSec Local API and the key from "cscli bouncers add draco". */
    public static class CrowdSecOptions {
        private String url = "";
        private String apiKey = "";

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = nn(url); }
        public String getApiKey() { return apiKey; }
        public void setApiKey(String apiKey) { this.apiKey = nn(apiKey); }
    }

    private static String nn(String s) {
        return s == null ? "" : s;
    }

    private static List<String> list(List<String> l) {
        return l == null ? new ArrayList<>() : new ArrayList<>(l);
    }

    /** Firewall signatures: "off", "log" (default) or "block". */
    public String getWaf() { return waf; }
    public void setWaf(String waf) { this.waf = nn(waf); }
    /** Anti-copy pace: "off" (default), "log" or "block". */
    public String getPace() { return pace; }
    public void setPace(String pace) { this.pace = nn(pace); }
    /** Pages a minute per address (default 120; at least 10). */
    public int getRateIp() { return rateIp; }
    public void setRateIp(int rateIp) { this.rateIp = rateIp; }
    /** Pages a minute per network, /24 or /64 (default 600; at least 10). */
    public int getRateNet() { return rateNet; }
    public void setRateNet(int rateNet) { this.rateNet = rateNet; }
    /** "" (the connection), "cf" (CF-Connecting-IP) or "xff" (X-Forwarded-For), believed only from trusted proxies. */
    public String getProxy() { return proxy; }
    public void setProxy(String proxy) { this.proxy = nn(proxy); }
    public List<String> getTrustedProxies() { return trustedProxies; }
    public void setTrustedProxies(List<String> v) { this.trustedProxies = list(v); }
    /** Addresses never inspected. */
    public List<String> getAdminIps() { return adminIps; }
    public void setAdminIps(List<String> v) { this.adminIps = list(v); }
    /** Path endings that count as sensitive, instead of the built-in list. */
    public List<String> getSensitive() { return sensitive; }
    public void setSensitive(List<String> v) { this.sensitive = list(v); }
    /** Path prefixes never inspected (webhooks, health checks). */
    public List<String> getExcept() { return except; }
    public void setExcept(List<String> v) { this.except = list(v); }
    public GeoOptions getGeo() { return geo; }
    public void setGeo(GeoOptions geo) { this.geo = geo == null ? new GeoOptions() : geo; }
    /** nosniff, frames, referrer and permissions headers, unless the app sets its own. */
    public boolean isHeaders() { return headers; }
    public void setHeaders(boolean headers) { this.headers = headers; }
    /** Strict-Transport-Security over HTTPS. */
    public boolean isHsts() { return hsts; }
    public void setHsts(boolean hsts) { this.hsts = hsts; }
    public ReviewOptions getReview() { return review; }
    public void setReview(ReviewOptions review) { this.review = review == null ? new ReviewOptions() : review; }
    public CrowdSecOptions getCrowdSec() { return crowdSec; }
    public void setCrowdSec(CrowdSecOptions crowdSec) { this.crowdSec = crowdSec == null ? new CrowdSecOptions() : crowdSec; }
    /** Every line of evidence (and review request) as JSON to the "DracoInsomnis" logger. */
    public boolean isLogEvents() { return logEvents; }
    public void setLogEvents(boolean logEvents) { this.logEvents = logEvents; }
    /** The page texts, by key. */
    public Map<String, String> getTexts() { return texts; }
    public void setTexts(Map<String, String> texts) { this.texts = texts == null ? new LinkedHashMap<>() : new LinkedHashMap<>(texts); }

    private static List<String> split(String v) {
        List<String> o = new ArrayList<>();
        for (String s : v.split("[,\\s]+")) if (!s.isEmpty()) o.add(s);
        return o;
    }

    private static boolean yes(String v) {
        return switch (v.trim().toLowerCase(Locale.ROOT)) {
            case "1", "true", "yes", "on" -> true;
            default -> false;
        };
    }

    private static int number(String v) {
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** Settings from the process environment: DRACO_INSOMNIS_WAF, DRACO_INSOMNIS_GEO_COUNTRIES and so on. */
    public static DracoOptions fromEnvironment() {
        return fromEnvironment(System.getenv());
    }

    /** Settings from the variables that start with DRACO_INSOMNIS_; every other one is ignored. */
    public static DracoOptions fromEnvironment(Map<String, String> env) {
        Map<String, String> ours = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : env.entrySet())
            if (e.getKey() != null && e.getKey().toUpperCase(Locale.ROOT).startsWith("DRACO_INSOMNIS_")) ours.put(e.getKey(), e.getValue());
        return fromMap(ours);
    }

    /**
     * Settings from flat keys, as in a web.xml or the environment: waf, pace, rateIp, rateNet, proxy,
     * trustedProxies, adminIps, sensitive, except (comma-separated), headers, hsts, logEvents,
     * geo.mode, geo.countries, geo.action, geo.scope, geo.file, review.secret, crowdSec.url,
     * crowdSec.apiKey, texts.KEY. Keys are case-insensitive; "-" and "_" are ignored, and a
     * "draco-insomnis." or "draco." prefix is allowed (so DRACO_INSOMNIS_WAF works too).
     */
    public static DracoOptions fromMap(Map<String, String> values) {
        DracoOptions o = new DracoOptions();
        for (Map.Entry<String, String> e : values.entrySet()) {
            if (e.getKey() == null || e.getValue() == null) continue;
            String lower = e.getKey().trim().toLowerCase(Locale.ROOT);
            String v = e.getValue();
            String k = lower.replaceAll("[-_.]", "");
            if (k.startsWith("dracoinsomnis")) k = k.substring(13);
            else if (k.startsWith("draco")) k = k.substring(5);
            int t = Math.max(lower.indexOf("texts."), lower.indexOf("texts_"));
            if (k.startsWith("texts") && t >= 0 && t + 6 < lower.length()) {
                // texts.review_email, or DRACO_TEXTS_REVIEW_EMAIL from the environment.
                o.texts.put(lower.substring(t + 6), v);
                continue;
            }
            switch (k) {
                case "waf" -> o.setWaf(v.trim());
                case "pace" -> o.setPace(v.trim());
                case "rateip" -> o.setRateIp(number(v));
                case "ratenet" -> o.setRateNet(number(v));
                case "proxy" -> o.setProxy(v.trim());
                case "trustedproxies" -> o.setTrustedProxies(split(v));
                case "adminips" -> o.setAdminIps(split(v));
                case "sensitive" -> o.setSensitive(split(v));
                case "except" -> o.setExcept(split(v));
                case "headers" -> o.setHeaders(yes(v));
                case "hsts" -> o.setHsts(yes(v));
                case "logevents" -> o.setLogEvents(yes(v));
                case "geomode" -> o.geo.setMode(v.trim());
                case "geocountries" -> o.geo.setCountries(split(v));
                case "geoaction" -> o.geo.setAction(v.trim());
                case "geoscope" -> o.geo.setScope(v.trim());
                case "geofile" -> o.geo.setFile(v.trim());
                case "reviewsecret" -> o.review.setSecret(v.trim());
                case "crowdsecurl" -> o.crowdSec.setUrl(v.trim());
                case "crowdsecapikey" -> o.crowdSec.setApiKey(v.trim());
                default -> { /* not a Draco setting */ }
            }
        }
        return o;
    }
}
