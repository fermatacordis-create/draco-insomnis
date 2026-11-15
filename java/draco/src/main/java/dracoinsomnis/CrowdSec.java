package dracoinsomnis;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Semaphore;
import java.util.function.DoubleSupplier;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Draco as a bouncer of the owner's own CrowdSec Local API, like server/src/CrowdSec.php: bans join the
 * block list, synced in the background at most once a minute; admin addresses are never imported and
 * blocks the owner set are never lifted by it.
 */
public final class CrowdSec {
    /** What one sync did. */
    public record Result(int added, int removed, String error) {}

    private static final Pattern DURATION = Pattern.compile("([0-9]+(?:\\.[0-9]+)?)(h|ms|m|s)");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);
    private static final HttpClient HTTP = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    private final String url;
    private final String key;
    private final Store store;
    private final Blocks blocks;
    private final Supplier<Collection<String>> admins;
    private final DoubleSupplier now;
    private final Semaphore running = new Semaphore(1);
    private volatile Duration timeout = Duration.ofSeconds(2);

    public CrowdSec(String url, String apiKey, Store store, Supplier<Collection<String>> admins, DoubleSupplier now) {
        this.url = url.replaceAll("/+$", "");
        this.key = apiKey;
        this.store = store;
        this.blocks = new Blocks(store);
        this.admins = admins;
        this.now = now;
    }

    /** How long to wait for the Local API (2 seconds by default). */
    public CrowdSec timeout(Duration timeout) {
        this.timeout = timeout;
        return this;
    }

    /** A Go duration ("3h59m40.5s") in whole seconds, rounded up; 0 when negative or not one. */
    public static int seconds(String duration) {
        if (duration.trim().startsWith("-")) return 0;
        Matcher m = DURATION.matcher(duration);
        double total = 0;
        boolean any = false;
        while (m.find()) {
            any = true;
            double n = Double.parseDouble(m.group(1));
            total += n * switch (m.group(2)) {
                case "h" -> 3600;
                case "m" -> 60;
                case "s" -> 1;
                default -> 0.001;
            };
        }
        return any ? (int) Math.ceil(total) : 0;
    }

    /** One line for CrowdSec's own log reader (acquisition), sorted keys, like the other editions. */
    public static String line(Event e, String host) {
        Map<String, Object> o = new TreeMap<>();
        o.put("time", TIME.format(Instant.ofEpochSecond(e.time())));
        o.put("ip", e.ip());
        o.put("host", host);
        o.put("endpoint", e.endpoint());
        o.put("verdict", e.verdict());
        o.put("reasons", String.join(",", e.reasons()));
        o.put("user_agent", e.userAgent());
        return Json.write(o);
    }

    /** One sync a minute at most (shared through the store), in the background. */
    public void maybeSync() {
        if (running.availablePermits() == 0 || store.bump("draco:crowdsec:sync", 60) != 1) return;
        Thread t = new Thread(() -> {
            try {
                sync();
            } catch (RuntimeException e) {
                // CrowdSec never breaks the app.
            }
        }, "draco-crowdsec");
        t.setDaemon(true);
        t.start();
    }

    /** Pulls the decisions now. */
    public Result sync() {
        running.acquireUninterruptibly();
        try {
            return pull();
        } finally {
            running.release();
        }
    }

    private static String s(Object o, String k) {
        return o instanceof Map<?, ?> m && m.get(k) instanceof String v ? v : "";
    }

    private Result pull() {
        store.set("draco:crowdsec:sync", "1", 60);
        int added = 0, removed = 0;
        String error = "";
        boolean startup = store.get("draco:crowdsec:started") == null;
        Object data = null;
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url + "/v1/decisions/stream?startup=" + startup + "&scopes=ip,range"))
                .timeout(timeout).header("X-Api-Key", key).header("User-Agent", "Draco-Insomnis").GET().build();
            HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
            if (res.statusCode() != 200) error = "HTTP " + res.statusCode();
            else data = Json.parse(res.body());
        } catch (IllegalArgumentException e) {
            error = "not JSON";
        } catch (IOException e) {
            error = "no answer";
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            error = "no answer";
        }
        double t = now.getAsDouble();
        if (!error.isEmpty() || !(data instanceof Map<?, ?> answer)) {
            if (error.isEmpty()) error = "not JSON";
            store.set("draco:crowdsec:last", (long) t + "|" + error, 86400 * 30);
            return new Result(0, 0, error);
        }
        List<String> imported = new ArrayList<>();
        try {
            String raw = store.get("draco:crowdsec:imported");
            if (raw != null && Json.parse(raw) instanceof List<?> l) for (Object x : l) if (x instanceof String v) imported.add(v);
        } catch (IllegalArgumentException e) {
            imported.clear();
        }
        if (startup) {
            for (String v : imported) if (removeIfOurs(v, t)) removed++;
            imported.clear();
        }
        if (answer.get("deleted") instanceof List<?> deleted) {
            for (Object d : deleted) {
                String value = s(d, "value").toLowerCase(Locale.ROOT);
                if (!value.isEmpty() && imported.contains(value) && removeIfOurs(value, t)) {
                    removed++;
                    imported.remove(value);
                }
            }
        }
        Collection<String> admin = admins.get();
        if (answer.get("new") instanceof List<?> news) {
            for (Object d : news) {
                if (!s(d, "type").toLowerCase(Locale.ROOT).equals("ban")) continue;
                String value = s(d, "value").trim().toLowerCase(Locale.ROOT);
                int ttl = seconds(s(d, "duration"));
                boolean allowed = value.contains("/") ? Blocks.validNet(value) : Net.isIp(value);
                if (ttl <= 0 || !allowed || admin.contains(value)) continue;
                String scenario = s(d, "scenario");
                if (scenario.isEmpty()) scenario = s(d, "origin");
                if (scenario.length() > 150) scenario = scenario.substring(0, 150);
                if (!blocks.addUntil(value, (long) t + ttl, "CrowdSec: " + scenario, true, t)) continue;
                added++;
                if (!imported.contains(value)) imported.add(value);
            }
        }
        List<String> keep = imported.size() > 20000 ? imported.subList(imported.size() - 20000, imported.size()) : imported;
        store.set("draco:crowdsec:imported", Json.write(keep), 0);
        store.set("draco:crowdsec:started", "1", 86400 * 365);
        store.set("draco:crowdsec:last", (long) t + "|ok +" + added + " -" + removed, 86400 * 30);
        return new Result(added, removed, "");
    }

    private boolean removeIfOurs(String value, double t) {
        Blocks.Entry e = blocks.entry(value, t);
        if (e == null || !e.reason().startsWith("CrowdSec")) return false;
        blocks.remove(value, t);
        return true;
    }
}
