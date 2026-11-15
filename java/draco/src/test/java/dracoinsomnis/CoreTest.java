package dracoinsomnis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CoreTest {
    static final double NOW = 1_800_000_000;

    static final Resolver NO_DNS = new Resolver() {
        @Override
        public List<String> reverse(String ip) throws IOException {
            throw new IOException("no DNS");
        }

        @Override
        public List<String> forward(String host) throws IOException {
            throw new IOException("no DNS");
        }
    };

    static final Resolver FAKE_DNS = new Resolver() {
        @Override
        public List<String> reverse(String ip) {
            return ip.equals("66.249.66.1") ? List.of("crawl-66-249-66-1.googlebot.com.") : List.of("x.example");
        }

        @Override
        public List<String> forward(String host) {
            return host.equals("crawl-66-249-66-1.googlebot.com") ? List.of("66.249.66.1") : List.of();
        }
    };

    static Gatekeeper gate(DracoOptions o) {
        return new Gatekeeper(o, new MemoryStore(() -> NOW)).resolver(NO_DNS).now(() -> NOW);
    }

    static DracoRequest req() {
        return new DracoRequest().remoteAddr("198.51.100.20").userAgent("Mozilla/5.0 Chrome/131.0");
    }

    static DracoRequest attack(String remote) {
        return req().remoteAddr(remote).query("../../etc/passwd").params(List.of("../../etc/passwd"));
    }

    static Map<String, String> hidden(String page) {
        Map<String, String> o = new LinkedHashMap<>();
        Matcher m = Pattern.compile("type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"").matcher(page);
        while (m.find()) o.put(m.group(1), m.group(2).replace("&quot;", "\"").replace("&lt;", "<").replace("&gt;", ">").replace("&#39;", "'").replace("&amp;", "&"));
        return o;
    }

    /** A small HTTP server for the country list and the CrowdSec API. */
    static HttpServer serve(Function<String, byte[]> answer, List<String> asked) throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/", x -> {
            if (asked != null) asked.add(x.getRequestURI().getRawQuery() + " " + x.getRequestHeaders().getFirst("X-Api-Key"));
            byte[] b = answer.apply(x.getRequestURI().getPath());
            x.sendResponseHeaders(200, b.length);
            x.getResponseBody().write(b);
            x.close();
        });
        s.start();
        return s;
    }

    static String url(HttpServer s) {
        return "http://127.0.0.1:" + s.getAddress().getPort();
    }

    @Test
    void netLikePhp() {
        assertFalse(Net.isIp("01.2.3.4"));
        assertFalse(Net.isIp("fe80::1%eth0"));
        assertFalse(Net.isIp("1.2.3"));
        assertFalse(Net.isIp("1:2:3:4:5:6:7:8:9"));
        assertTrue(Net.isIp("2001:db8::1"));
        assertTrue(Net.isIp("::ffff:1.2.3.4"));
        assertEquals("2001:db8:1:2::/64", Net.network("2001:db8:1:2:3:4:5:6"));
        assertEquals("203.0.113.0/24", Net.network("203.0.113.9"));
        assertTrue(Blocks.validNet("203.0.113.0/24"));
        assertFalse(Blocks.validNet("10.0.0.0/8"));
        assertTrue(Net.inNet("2a06:98c0::/29", "2a06:98c7::1"));
        assertFalse(Net.inNet("2a06:98c0::/29", "2a06:98c8::1"));
        assertEquals(List.of("10.0.0.0/8", "192.0.2.1"), Net.parse(List.of("10.0.0.0/8, x # office\n192.0.2.1")));
        Gatekeeper g = gate(options(o -> o.setProxy("xff")));
        assertEquals("203.0.113.5", g.ip(req().remoteAddr("203.0.113.5").forwardedFor("1.2.3.4")));
        assertEquals("198.51.100.7", g.ip(req().remoteAddr("10.0.0.2").forwardedFor("1.2.3.4, 198.51.100.7, 10.0.0.9")));
        assertEquals("198.51.100.20", g.ip(req().remoteAddr("::ffff:198.51.100.20")));
    }

    static DracoOptions options(java.util.function.Consumer<DracoOptions> c) {
        DracoOptions o = new DracoOptions();
        c.accept(o);
        return o;
    }

    @Test
    void reviewVectorsLikePhp() throws IOException {
        Map<?, ?> v = WafTest.vectors("review.json");
        String secret = (String) v.get("secret");
        int n = 0;
        for (Object o : (List<?>) v.get("cases")) {
            Map<?, ?> c = (Map<?, ?>) o;
            String ts = c.get("ts").toString();
            assertEquals(c.get("sealed"), Review.seal(secret, (String) c.get("ip"), ts, (String) c.get("rule")));
            assertEquals(c.get("opened"), Review.openSealed(secret, (String) c.get("ip"), ts, (String) c.get("sealed")));
            assertEquals(c.get("sig"), Review.sign(secret, (String) c.get("ip"), (String) c.get("rule"), ts));
            n++;
        }
        assertTrue(n >= 4);
    }

    @Test
    void reviewFlow() {
        List<Review.Request> asked = new ArrayList<>();
        Gatekeeper g = gate(options(o -> { o.setWaf("block"); o.getReview().setSecret("owner-secret-0123456789"); })).onReview(asked::add);
        Gatekeeper.Rendered page = g.render(g.decide(attack("198.51.100.20")));
        assertEquals(403, page.status());
        assertTrue(page.body().contains("Ask for a review"));
        assertFalse(page.body().contains("traversal"));
        Map<String, String> form = hidden(page.body());
        form.put("draco_email", "Ana@Example.org");
        form.put("draco_message", "I was <b>reading</b>");
        form.put("draco_website", "");
        for (int i = 0; i < 5; i++) assertEquals(200, g.decide(req().method("POST").form(form)).status());
        assertEquals(3, asked.size());
        assertEquals("ana@example.org", asked.get(0).email());
        assertEquals("I was reading", asked.get(0).message());
        assertEquals("traversal", asked.get(0).rule());

        Map<String, String> bad = new LinkedHashMap<>(form);
        bad.put("draco_sig", "0".repeat(64));
        List<Review.Request> none = new ArrayList<>();
        Gatekeeper g2 = gate(options(o -> { o.setWaf("block"); o.getReview().setSecret("owner-secret-0123456789"); })).onReview(none::add);
        g2.decide(req().method("POST").form(bad));
        g2.decide(req().method("POST").form(form).remoteAddr("203.0.113.7"));
        assertTrue(none.isEmpty());
    }

    @Test
    void firewallPaceAndBlocks() {
        List<String> seen = new ArrayList<>();
        Gatekeeper g = gate(options(o -> o.setWaf("block"))).onEvent(e -> seen.add(e.endpoint()));
        assertNull(g.decide(req().query("q=european union select committee").params(List.of("european union select committee"))));
        assertEquals("traversal", g.decide(attack("198.51.100.20")).why());
        assertEquals("probe", g.decide(req().path("/.env")).why());
        for (int i = 0; i < 4; i++) g.decide(attack("198.51.100.20"));
        assertTrue(g.blocks().isBlocked("198.51.100.20", NOW));
        assertNull(g.decide(req()));
        assertEquals("blocked", g.decide(req().method("POST").path("/contact")).why());
        assertEquals(List.of("waf:traversal", "waf:probe"), seen.subList(0, 2));
        assertNull(gate(options(o -> { o.setWaf("block"); o.setAdminIps(List.of("198.51.100.20")); })).decide(attack("198.51.100.20")));
        Gatekeeper except = gate(options(o -> { o.setWaf("block"); o.setExcept(List.of("webhooks")); }));
        assertNull(except.decide(req().path("/webhooks/stripe").query("../../etc/passwd").params(List.of("../../etc/passwd"))));

        Gatekeeper p = gate(options(o -> { o.setWaf("off"); o.setPace("block"); o.setRateIp(10); }));
        List<Answer> got = new ArrayList<>();
        for (int i = 0; i < 12; i++) got.add(p.decide(req().accept("text/html")));
        assertNull(got.get(9));
        assertEquals(429, got.get(10).status());
        assertTrue(got.get(10).retry() >= 1);
        assertNull(p.decide(req().accept("application/json")));
        assertEquals("Too many pages in a short time. Please wait a moment and try again.", p.render(got.get(10)).body());

        // A proved search engine is not held back; a pretender is.
        Gatekeeper c = gate(options(o -> { o.setWaf("off"); o.setPace("block"); o.setRateIp(10); })).resolver(FAKE_DNS);
        String bot = "Mozilla/5.0 (compatible; Googlebot/2.1)";
        for (int i = 0; i < 15; i++) assertNull(c.decide(req().remoteAddr("66.249.66.1").userAgent(bot)));
        Answer last = null;
        for (int i = 0; i < 15; i++) last = c.decide(req().remoteAddr("203.0.113.50").userAgent(bot));
        assertEquals(429, last.status());
        assertEquals("y", c.store().get("draco:crawler:66.249.66.1:googlebot"));
    }

    @Test
    void blockListIsSharedJson() {
        MemoryStore s = new MemoryStore(() -> NOW);
        Blocks b = new Blocks(s);
        assertTrue(b.add("203.0.113.0/24", 1, "Manual", false, NOW));
        assertFalse(b.add("10.0.0.0/8", 1, "too wide", false, NOW));
        assertTrue(b.add("198.51.100.9", 0, "Manual", false, NOW));
        assertTrue(b.isBlocked("203.0.113.77", NOW));
        assertEquals(Blocks.FOREVER, b.entry("198.51.100.9", NOW).until());
        // Written by another edition: the same JSON fields.
        s.set("draco:block:192.0.2.5", "{\"value\":\"192.0.2.5\",\"until\":1800003600,\"reason\":\"Python\",\"automatic\":true}", 3600);
        assertEquals("Python", b.entry("192.0.2.5", NOW).reason());
        b.remove("203.0.113.0/24", NOW);
        assertFalse(b.isBlocked("203.0.113.77", NOW));
    }

    @Test
    void jsonAndDecoding() {
        assertEquals(List.of("a", "1", "x", "2.5", "1", ""), Waf.flatten(Json.parse("{\"a\":1,\"x\":[2.5,true,false,null]}")));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("a", "<b>");
        m.put("b", java.util.Arrays.asList(1, null));
        assertEquals("{\"a\":\"\\u003cb\\u003e\",\"b\":[1,null]}", Json.write(m));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("[".repeat(100) + "]".repeat(100)));
        assertThrows(IllegalArgumentException.class, () -> Json.parse("{\"a\":1,}"));
        assertEquals("a b'é%zz%", Http.decode("a+b%27%C3%A9%zz%", true));
        assertEquals("a+b", Http.decode("a+b", false));
        assertEquals(Map.of("q", List.of("1", "2"), "x", List.of("")), Http.parseQuery("q=1&q=2&x"));
        DracoOptions o = DracoOptions.fromMap(Map.of("waf", "block", "geo.countries", "CN, RU", "review-secret", "s3cret", "DRACO_INSOMNIS_HEADERS", "true",
            "texts.title", "Bloqueado", "PATH", "/usr/bin"));
        assertEquals("block", o.getWaf());
        assertEquals(List.of("CN", "RU"), o.getGeo().getCountries());
        assertEquals("s3cret", o.getReview().getSecret());
        assertTrue(o.isHeaders());
        assertEquals("Bloqueado", new Gatekeeper(o).texts().get("title"));
        DracoOptions env = DracoOptions.fromEnvironment(Map.of("DRACO_INSOMNIS_WAF", "block", "DRACO_INSOMNIS_TEXTS_REVIEW_EMAIL", "Correo", "PROXY", "xff", "HSTS", "1"));
        assertEquals("block", env.getWaf());
        assertEquals("Correo", env.getTexts().get("review_email"));
        assertEquals("", env.getProxy());
        assertFalse(env.isHsts());
    }

    static byte[] geoFixture(String built) {
        String[][] v4 = {{"0.0.0.0", "--"}, {"1.0.0.0", "AU"}, {"1.0.1.0", "CN"}, {"1.0.4.0", "--"}, {"203.0.113.0", "ES"}, {"203.0.114.0", "--"}};
        String[][] v6 = {{"::", "--"}, {"2a00::", "ES"}, {"2a01::", "--"}};
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(("DRGEO1" + built).getBytes(StandardCharsets.US_ASCII));
        for (int n : new int[] {v4.length, v6.length}) o.writeBytes(new byte[] {(byte) (n >> 24), (byte) (n >> 16), (byte) (n >> 8), (byte) n});
        for (String[][] list : new String[][][] {v4, v6}) {
            for (String[] e : list) {
                o.writeBytes(Net.toBytes(e[0]));
                o.writeBytes(e[1].getBytes(StandardCharsets.US_ASCII));
            }
        }
        return o.toByteArray();
    }

    @Test
    void geoLikeGeoPhp(@TempDir Path dir) throws Exception {
        Path path = dir.resolve("g.bin");
        Files.write(path, geoFixture("20261113"));
        try (GeoFile geo = new GeoFile(path.toString(), false)) {
            Map<String, String> want = new LinkedHashMap<>();
            want.put("1.0.0.200", "AU");
            want.put("1.0.3.255", "CN");
            want.put("1.0.4.0", null);
            want.put("::ffff:203.0.113.10", "ES");
            want.put("2a00:1450::1", "ES");
            want.put("2a01::1", null);
            want.put("x", null);
            for (Map.Entry<String, String> e : want.entrySet()) assertEquals(e.getValue(), geo.country(e.getKey()), e.getKey());
            assertEquals("20261113", geo.built());

            Gatekeeper g = gate(options(o -> {
                o.setWaf("block");
                o.getGeo().setMode("block");
                o.getGeo().setCountries(List.of("cn"));
                o.getGeo().setAction("block");
            })).geo(geo);
            assertEquals("geo", g.decide(req().path("/login").remoteAddr("1.0.2.3")).why());
            assertNull(g.decide(req().remoteAddr("1.0.2.3")));
        }

        // Download with the published checksum; a wrong one keeps the old file.
        byte[] body = geoFixture("20991231");
        String[] sum = {HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body))};
        HttpServer srv = serve(p -> p.endsWith(".sha256") ? (sum[0] + "  draco-geo.bin\n").getBytes(StandardCharsets.US_ASCII) : body, null);
        try (GeoFile dl = new GeoFile(dir.resolve("sub/g.bin").toString(), false).source(url(srv) + "/draco-geo.bin")) {
            assertEquals("", dl.refresh());
            assertEquals("20991231", dl.built());
            sum[0] = "0".repeat(64);
            assertEquals("download", dl.update());
            assertEquals("20991231", dl.built());
        } finally {
            srv.stop(0);
        }
    }

    @Test
    void crowdSecBridge() throws IOException {
        assertEquals(14381, CrowdSec.seconds("3h59m40.5s"));
        assertEquals(1, CrowdSec.seconds("250ms"));
        assertEquals(0, CrowdSec.seconds("-3s"));
        String[] answer = {"{\"new\":[{\"type\":\"ban\",\"value\":\"198.51.100.66\",\"duration\":\"4h\",\"scenario\":\"crowdsecurity/http-probing\"},"
            + "{\"type\":\"ban\",\"value\":\"203.0.113.0/24\",\"duration\":\"1h\"},{\"type\":\"ban\",\"value\":\"10.0.0.0/8\",\"duration\":\"1h\"},"
            + "{\"type\":\"ban\",\"value\":\"192.0.2.1\",\"duration\":\"4h\"},{\"type\":\"captcha\",\"value\":\"198.51.100.67\",\"duration\":\"4h\"}],\"deleted\":null}"};
        List<String> asked = new ArrayList<>();
        HttpServer srv = serve(p -> answer[0].getBytes(StandardCharsets.UTF_8), asked);
        try {
            Gatekeeper g = gate(options(o -> {
                o.setWaf("block");
                o.setAdminIps(List.of("192.0.2.1"));
                o.getCrowdSec().setUrl(url(srv));
                o.getCrowdSec().setApiKey("k3y");
            }));
            g.blocks().add("203.0.113.200", 7, "Manual", false, NOW);
            assertEquals(new CrowdSec.Result(2, 0, ""), g.crowdSec().sync());
            assertEquals("startup=true&scopes=ip,range k3y", asked.get(0));
            assertEquals("blocked", g.decide(req().path("/login").remoteAddr("198.51.100.66")).why());
            assertEquals("blocked", g.decide(req().method("POST").remoteAddr("203.0.113.9")).why());
            assertNull(g.decide(req().path("/login").remoteAddr("10.1.2.3")));
            answer[0] = "{\"new\":[],\"deleted\":[{\"value\":\"198.51.100.66\"},{\"value\":\"203.0.113.200\"}]}";
            assertEquals(1, g.crowdSec().sync().removed());
            assertTrue(g.blocks().isBlocked("203.0.113.200", NOW));
            assertFalse(g.blocks().isBlocked("198.51.100.66", NOW));
        } finally {
            srv.stop(0);
        }
        String line = CrowdSec.line(new Event(1_800_000_000L, "198.51.100.9", "", "waf:sqli", "bot", List.of("waf_sqli"), "curl/8", "", null), "shop.example");
        assertEquals("{\"endpoint\":\"waf:sqli\",\"host\":\"shop.example\",\"ip\":\"198.51.100.9\",\"reasons\":\"waf_sqli\",\"time\":\"2027-01-15T08:00:00Z\",\"user_agent\":\"curl/8\",\"verdict\":\"bot\"}", line);
        assertNotNull(Gatekeeper.VERSION);
    }
}
