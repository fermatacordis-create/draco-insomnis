package dracoinsomnis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The shared firewall cases (tests/vectors/waf.json): every edition must agree. */
class WafTest {
    static Path root() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("tests/vectors"))) p = p.getParent();
        return p;
    }

    static Map<?, ?> vectors(String name) throws IOException {
        return (Map<?, ?>) Json.parse(Files.readString(root().resolve("tests/vectors/" + name)));
    }

    private static String s(Map<?, ?> m, String k) {
        return m.get(k) instanceof String v ? v : "";
    }

    private static String run(Map<?, ?> r) {
        List<String> ps = new ArrayList<>();
        if (r.get("params") instanceof List<?> l) for (Object x : l) ps.add((String) x);
        return Waf.inspect(s(r, "path"), s(r, "query"), ps, s(r, "userAgent"));
    }

    @Test
    void attacksGetTheSameRule() throws IOException {
        int n = 0;
        for (Object o : (List<?>) vectors("waf.json").get("attacks")) {
            Map<?, ?> c = (Map<?, ?>) o;
            assertEquals(c.get("rule"), run((Map<?, ?>) c.get("request")), (String) c.get("name"));
            n++;
        }
        assertTrue(n >= 30);
    }

    @Test
    void ordinaryRequestsPass() throws IOException {
        int n = 0;
        for (Object o : (List<?>) vectors("waf.json").get("ordinary")) {
            Map<?, ?> c = (Map<?, ?>) o;
            assertNull(run((Map<?, ?>) c.get("request")), (String) c.get("name"));
            n++;
        }
        assertTrue(n >= 10);
    }

    @Test
    void classesAreAsciiLikePhp() {
        // Byte-wise like PHP, "ñ" is not a word character, so there is a word boundary next to it.
        assertEquals("sqli", Waf.inspect("/", "x=ñunion select 1", List.of(), ""));
        assertEquals("scanner", Waf.inspect("/", "", List.of(), "Mozilla/5.0 nucleiñ"));
        // Only "\n" ends a line in PCRE: "$" matches before a final "\n", never before a final "\r".
        assertEquals("probe", Waf.inspect("/.env", "", List.of(), ""));
        assertEquals("probe", Waf.inspect("/.env\n", "", List.of(), ""));
        assertNull(Waf.inspect("/.env\r", "", List.of(), ""));
    }
}
