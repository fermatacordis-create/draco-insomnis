package dracoinsomnis;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;
import java.util.regex.Pattern;

/** Decides, in the same order as every edition: block list, country, signatures, pace. */
public final class Gatekeeper {
    public static final String VERSION = "0.1.32";

    /** Sensitive path endings, besides any POST. */
    public static final List<String> SENSITIVE_PATHS = List.of(
        "/wp-login.php", "/login", "/register", "/signup", "/user/login", "/user/register", "/admin",
        "/auth/login", "/api/auth/local", "/api/auth/local/register", "/admin/login",
        "/accounts/login/", "/accounts/signup/", "/token", "/auth/token",
        "/Identity/Account/Login", "/Identity/Account/Register", "/Account/Login", "/Account/Register",
        // Spring Security, Keycloak and Jakarta EE form logins
        "/j_security_check", "/oauth2/token", "/protocol/openid-connect/token");

    public static final Map<String, String> DEFAULT_TEXTS;

    static {
        Map<String, String> t = new LinkedHashMap<>();
        t.put("title", "Request blocked");
        t.put("text", "This request was blocked by the site's security. If you think this is a mistake, contact the site owner.");
        t.put("too_many", "Too many pages in a short time. Please wait a moment and try again.");
        t.put("text_with_review", "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:");
        t.put("review_email", "Your e-mail");
        t.put("review_message", "What were you doing?");
        t.put("review_button", "Ask for a review");
        t.put("review_sent_title", "Request sent");
        t.put("review_sent_text", "Thank you. The owner of the site will look at it and, if it was a mistake, let you through.");
        DEFAULT_TEXTS = Collections.unmodifiableMap(t);
    }

    private static final Pattern TWO_LETTERS = Pattern.compile("^[A-Z]{2}$");
    private static final List<String> GOOGLE = List.of("googlebot.com", "google.com", "googleusercontent.com");
    private static final List<String> BING = List.of("search.msn.com");
    private static final String[][] CRAWLERS = {
        {"googlebot"}, {"google-inspectiontool"}, {"googleother"}, {"adsbot-google"}, {"mediapartners-google"},
        {"bingbot"}, {"msnbot"}, {"adidxbot"}, {"applebot"}, {"yandex"},
    };
    private static final SecureRandom RANDOM = new SecureRandom();

    /** A rendered answer. */
    public record Rendered(int status, List<Map.Entry<String, String>> headers, String body) {}

    private final DracoOptions options;
    private final Store store;
    private final Blocks blocks;
    private final Map<String, String> texts;
    private final List<String> trusted;
    private final List<String> admins;
    private final CrowdSec crowdSec;
    private volatile Resolver resolver = Resolver.system();
    private volatile GeoFile geo;
    private volatile Consumer<Event> onEvent;
    private volatile Consumer<Review.Request> onReview;
    private volatile DoubleSupplier now = Clock::now;

    public Gatekeeper(DracoOptions options) {
        this(options, null);
    }

    /**
     * @param options every setting
     * @param store shared counters and block list; null = this process only
     */
    public Gatekeeper(DracoOptions options, Store store) {
        this.options = options;
        this.store = store == null ? new MemoryStore(() -> now.getAsDouble()) : store;
        this.blocks = new Blocks(this.store);
        Map<String, String> t = new LinkedHashMap<>(DEFAULT_TEXTS);
        t.putAll(options.getTexts());
        this.texts = Collections.unmodifiableMap(t);
        this.trusted = Net.parse(options.getTrustedProxies());
        List<String> a = new ArrayList<>();
        for (String ip : options.getAdminIps()) if (ip != null && !ip.trim().isEmpty()) a.add(ip.trim());
        this.admins = List.copyOf(a);
        if (!options.getGeo().getFile().isEmpty()) this.geo = new GeoFile(options.getGeo().getFile(), true);
        this.crowdSec = !options.getCrowdSec().getUrl().isEmpty() && !options.getCrowdSec().getApiKey().isEmpty()
            ? new CrowdSec(options.getCrowdSec().getUrl(), options.getCrowdSec().getApiKey(), this.store, () -> admins, () -> now.getAsDouble())
            : null;
    }

    public DracoOptions options() { return options; }
    public Store store() { return store; }
    public Blocks blocks() { return blocks; }
    public Map<String, String> texts() { return texts; }
    /** The CrowdSec bridge, or null when it is not configured. */
    public CrowdSec crowdSec() { return crowdSec; }
    public Resolver resolver() { return resolver; }
    /** null turns the search-engine proof off (search engines are then paced like anyone). */
    public Gatekeeper resolver(Resolver r) { resolver = r; return this; }
    public GeoFile geo() { return geo; }
    public Gatekeeper geo(GeoFile g) { geo = g; return this; }
    public Gatekeeper onEvent(Consumer<Event> c) { onEvent = c; return this; }
    public Gatekeeper onReview(Consumer<Review.Request> c) { onReview = c; return this; }
    public double now() { return now.getAsDouble(); }
    /** The clock in Unix seconds (for tests). */
    public Gatekeeper now(DoubleSupplier n) { now = n; return this; }

    static String remote(String remoteAddr) {
        String ip = Net.unmap(remoteAddr.trim());
        return Net.isIp(ip) ? ip : "0.0.0.0";
    }

    private List<String> proxies() {
        return trusted.isEmpty() ? Net.LOCAL_PROXIES : trusted;
    }

    /**
     * The visitor's address: the connection's own, unless a proxy header is chosen AND the connection
     * comes from a trusted proxy. X-Forwarded-For is read from the right.
     */
    public String ip(DracoRequest r) {
        String addr = remote(r.remoteAddr());
        switch (options.getProxy()) {
            case "cf" -> {
                String cf = r.cfConnectingIp().trim();
                if (!cf.isEmpty() && (Net.contains(Net.CLOUDFLARE, addr) || Net.contains(trusted, addr)) && Net.isIp(cf)) return cf;
            }
            case "xff" -> {
                if (r.forwardedFor().trim().isEmpty() || !Net.contains(proxies(), addr)) return addr;
                String[] hops = r.forwardedFor().split(",", -1);
                for (int i = hops.length - 1; i >= 0; i--) {
                    String hop = hops[i].trim();
                    if (!Net.isIp(hop)) return addr;
                    if (!Net.contains(proxies(), hop)) return hop;
                    addr = hop;
                }
            }
            default -> { /* the connection */ }
        }
        return addr;
    }

    private boolean reviewing() {
        return options.getReview().getSecret().length() >= 16;
    }

    /** The answer that stops the request, or null to let it through. */
    public Answer decide(DracoRequest r) {
        Answer a = rules(r);
        if (a != null && a.status() == 403 && reviewing())
            a = a.withForm(Review.form(options.getReview().getSecret(), ip(r), a.why(), now(), texts));
        return a;
    }

    private Answer rules(DracoRequest r) {
        if (crowdSec != null) crowdSec.maybeSync();
        DracoOptions c = options;
        String ip = ip(r);
        for (String p : c.getExcept()) {
            String prefix = "/" + p.replaceAll("^/+", "");
            if (!prefix.equals("/") && r.path().startsWith(prefix)) return null;
        }
        if (reviewing() && r.method().equals("POST") && "1".equals(r.form().get(Review.FIELD))) {
            Review.Request req = Review.accept(store, c.getReview().getSecret(), ip, r.userAgent(), r.form(), now());
            if (req != null) {
                log(r, ip, "review", "pending", List.of("review_" + (req.rule().isEmpty() ? "blocked" : req.rule())), req.message(), req.email());
                Consumer<Review.Request> cb = onReview;
                if (cb != null) cb.accept(req);
            }
            // The same answer either way, so a script learns nothing.
            return new Answer(200, "review");
        }
        if (admins.contains(ip)) return null;
        String waf = c.getWaf().isEmpty() ? "log" : c.getWaf();
        if (!waf.equals("off")) {
            if (isSensitive(r) && blocks.isBlocked(ip, now())) return new Answer(403, "blocked");
            String country = refusedCountry(r, ip);
            if (!country.isEmpty()) {
                boolean blocking = c.getGeo().getAction().equals("block");
                log(r, ip, "waf:geo", blocking ? "bot" : "doubtful", List.of("waf_geo"), country + " " + r.path(), null);
                if (blocking) return new Answer(403, "geo");
            }
            String rule = Waf.inspect(r.path(), r.query(), r.params(), r.userAgent());
            if (rule != null) {
                record(r, ip, rule, waf.equals("block"));
                if (waf.equals("block")) return new Answer(403, rule);
            }
        }
        if (!c.getPace().isEmpty() && !c.getPace().equals("off") && wantsPage(r)) {
            double t = now();
            String minute = Long.toString((long) t / 60);
            long ipHits = store.bump("draco:rl:i:" + ip + ":" + minute, 120);
            long netHits = store.bump("draco:rl:n:" + Net.network(ip) + ":" + minute, 120);
            long ipLimit = limit(c.getRateIp(), 120), netLimit = limit(c.getRateNet(), 600);
            String over = ipHits > ipLimit ? "ip" : netHits > netLimit ? "net" : "";
            if (!over.isEmpty() && !verifiedCrawler(ip, r.userAgent())) {
                boolean block = c.getPace().equals("block");
                if (ipHits == ipLimit + 1 || netHits == netLimit + 1)
                    log(r, ip, "anticopy:" + over, "doubtful", List.of("anticopy_" + over + "_" + (block ? "block" : "log")), r.path(), null);
                if (block) return new Answer(429, "pace", Math.max(1, 60 - (int) ((long) t % 60)), "");
            }
        }
        return null;
    }

    private static int limit(int v, int fallback) {
        return v >= 10 ? v : fallback;
    }

    private static boolean wantsPage(DracoRequest r) {
        String accept = r.accept().toLowerCase(Locale.ROOT);
        return (r.method().equals("GET") || r.method().equals("HEAD")) && (accept.isEmpty() || accept.contains("text/html")) && !r.ajax();
    }

    private boolean isSensitive(DracoRequest r) {
        if (r.method().equals("POST")) return true;
        List<String> endings = options.getSensitive().isEmpty() ? SENSITIVE_PATHS : options.getSensitive();
        for (String e : endings) if (e != null && !e.isEmpty() && r.path().endsWith(e)) return true;
        return false;
    }

    private String refusedCountry(DracoRequest r, String ip) {
        DracoOptions.GeoOptions g = options.getGeo();
        List<String> list = new ArrayList<>();
        for (String x : g.getCountries()) {
            String cc = x == null ? "" : x.trim().toUpperCase(Locale.ROOT);
            if (TWO_LETTERS.matcher(cc).matches()) list.add(cc);
        }
        if (g.getMode().isEmpty() || g.getMode().equals("off") || list.isEmpty()) return "";
        if (!g.getScope().equals("site") && !isSensitive(r)) return "";
        String country = r.country().toUpperCase(Locale.ROOT);
        GeoFile file = geo;
        if (!TWO_LETTERS.matcher(country).matches() && file != null) {
            String found = file.country(ip);
            country = found == null ? "" : found;
        }
        // Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
        if (!TWO_LETTERS.matcher(country).matches() || country.equals("XX") || country.equals("T1")) return "";
        boolean listed = list.contains(country);
        if ((g.getMode().equals("block") && !listed) || (g.getMode().equals("allow") && listed)) return "";
        return verifiedCrawler(ip, r.userAgent()) ? "" : country;
    }

    private void record(DracoRequest r, String ip, String rule, boolean blocking) {
        String detail = r.path() + (r.query().isEmpty() ? "" : "?" + r.query());
        log(r, ip, "waf:" + rule, blocking ? "bot" : "doubtful", List.of("waf_" + rule), detail, null);
        if (!blocking) return;
        long hits = store.bump("draco:waf:" + ip, 600);
        // An address read from a header nobody vouches for is never blocked: it could be anybody's.
        boolean vouched = ip.equals(remote(r.remoteAddr())) || !options.getProxy().isEmpty();
        if (hits >= 5 && vouched && !blocks.isBlocked(ip, now()))
            blocks.add(ip, 7, "Firewall: " + hits + " attacks in 10 minutes", true, now());
    }

    /** A search engine proved by its reverse DNS and the forward lookup back; cached a day. */
    public boolean verifiedCrawler(String ip, String userAgent) {
        String ua = userAgent.toLowerCase(Locale.ROOT);
        String token = null;
        for (String[] c : CRAWLERS) if (ua.contains(c[0])) { token = c[0]; break; }
        Resolver res = resolver;
        if (token == null || res == null) return false;
        String key = "draco:crawler:" + ip + ":" + token;
        String cached = store.get(key);
        if ("y".equals(cached) || "n".equals(cached)) return cached.equals("y");
        boolean ok = resolvesBack(res, ip, domains(token));
        store.set(key, ok ? "y" : "n", 86400);
        return ok;
    }

    private static List<String> domains(String token) {
        return switch (token) {
            case "bingbot", "msnbot", "adidxbot" -> BING;
            case "applebot" -> List.of("applebot.apple.com");
            case "yandex" -> List.of("yandex.ru", "yandex.net", "yandex.com");
            default -> GOOGLE;
        };
    }

    private static boolean resolvesBack(Resolver res, String ip, List<String> domains) {
        byte[] want = Net.toBytes(ip);
        if (want == null) return false;
        List<String> names;
        try {
            names = res.reverse(ip);
        } catch (Exception e) {
            return false;
        }
        int n = 0;
        for (String name : names) {
            if (n++ >= 3) break;
            String h = name.trim().toLowerCase(Locale.ROOT).replaceAll("\\.+$", "");
            boolean ours = false;
            for (String d : domains) if (h.equals(d) || h.endsWith("." + d)) ours = true;
            if (!ours) continue;
            try {
                for (String a : res.forward(h)) {
                    byte[] b = Net.toBytes(a);
                    if (b != null && Arrays.equals(b, want)) return true;
                }
            } catch (Exception e) {
                // next name
            }
        }
        return false;
    }

    private void log(DracoRequest r, String ip, String endpoint, String verdict, List<String> reasons, String detail, String email) {
        Consumer<Event> cb = onEvent;
        if (cb == null) return;
        String ua = r.userAgent().length() > 255 ? r.userAgent().substring(0, 255) : r.userAgent();
        int max = endpoint.equals("review") ? 500 : 200;
        if (detail.codePointCount(0, detail.length()) > max) detail = detail.substring(0, detail.offsetByCodePoints(0, max));
        cb.accept(new Event((long) now(), ip, remote(r.remoteAddr()), endpoint, verdict, reasons, ua, detail, email));
    }

    /** Security headers to add, unless the application already set them. */
    public List<Map.Entry<String, String>> securityHeaders(boolean https) {
        List<Map.Entry<String, String>> o = new ArrayList<>();
        if (options.isHeaders()) {
            o.add(Map.entry("X-Content-Type-Options", "nosniff"));
            o.add(Map.entry("X-Frame-Options", "SAMEORIGIN"));
            o.add(Map.entry("Referrer-Policy", "strict-origin-when-cross-origin"));
            o.add(Map.entry("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"));
        }
        if (https && options.isHsts()) o.add(Map.entry("Strict-Transport-Security", "max-age=15552000"));
        return o;
    }

    /** The status, headers and body of an answer. */
    public Rendered render(Answer a) {
        Map<String, String> t = texts;
        if (a.status() == 429)
            return new Rendered(429, List.of(Map.entry("Retry-After", Integer.toString(a.retry())), Map.entry("Content-Type", "text/plain; charset=UTF-8"),
                Map.entry("Cache-Control", "no-store"), Map.entry("X-Robots-Tag", "noindex")), t.get("too_many"));
        List<Map.Entry<String, String>> h = List.of(Map.entry("Content-Type", "text/html; charset=UTF-8"), Map.entry("Cache-Control", "no-store"),
            Map.entry("X-Robots-Tag", "noindex, nofollow"));
        if (a.status() == 200) return new Rendered(200, h, page(t.get("review_sent_title"), t.get("review_sent_text"), ""));
        return !a.form().isEmpty()
            ? new Rendered(403, h, page(t.get("title"), t.get("text_with_review"), a.form()))
            : new Rendered(403, h, page(t.get("title"), t.get("text"), ""));
    }

    /** The 403 page: it never says which rule matched; the reference ties it to the evidence. */
    public static String page(String title, String text, String extra) {
        byte[] ref = new byte[5];
        RANDOM.nextBytes(ref);
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex,nofollow\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>403</title>"
            + "<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}form{text-align:left;margin-top:20px}label{display:block;font-size:14px;margin:10px 0 4px}input,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}button{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}.hp{position:absolute;left:-9999px}</style></head><body><main>"
            + "<h1 style=\"font-size:20px\">" + Review.html(title) + "</h1><p>" + Review.html(text) + "</p>" + extra
            + "<p style=\"color:#64748b;font-size:13px\">Ref. " + HexFormat.of().formatHex(ref) + "</p></main></body></html>";
    }

    /** Writes every line of evidence and review request as JSON to the "DracoInsomnis" logger. */
    public Gatekeeper logToSystemLogger() {
        System.Logger log = System.getLogger("DracoInsomnis");
        onEvent(e -> log.log(System.Logger.Level.INFO, Json.write(Map.of("draco", "event", "event", e.toMap()))));
        onReview(rv -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("time", rv.time());
            m.put("ip", rv.ip());
            m.put("rule", rv.rule());
            m.put("email", rv.email());
            m.put("message", rv.message());
            m.put("userAgent", rv.userAgent());
            log.log(System.Logger.Level.INFO, Json.write(Map.of("draco", "review", "review", m)));
        });
        return this;
    }
}
