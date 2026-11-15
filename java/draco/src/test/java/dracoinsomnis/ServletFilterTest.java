package dracoinsomnis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dracoinsomnis.servlet.DracoFilter;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.junit.jupiter.api.Test;

/** The filter in a real servlet container (Jetty 12, Servlet 6), over real HTTP. */
class ServletFilterTest {
    static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";
    static final String ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20";

    static class App extends HttpServlet {
        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse res) throws IOException {
            if (req.getRequestURI().equals("/own")) res.setHeader("X-Frame-Options", "DENY");
            res.setContentType("text/plain; charset=UTF-8");
            res.getWriter().write(req.getRequestURI().equals("/") ? "page" : "ok");
        }

        @Override
        protected void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException {
            res.setContentType("text/plain; charset=UTF-8");
            if (req.getContentType() != null && req.getContentType().contains("json")) res.getWriter().write("json=" + req.getReader().lines().collect(Collectors.joining()));
            else res.getWriter().write("name=" + req.getParameter("name"));
        }

        @Override
        protected void doPut(HttpServletRequest req, HttpServletResponse res) throws IOException {
            doPost(req, res);
        }
    }

    static Server start(FilterHolder filter) throws Exception {
        Server server = new Server(new InetSocketAddress("127.0.0.1", 0));
        ServletContextHandler ctx = new ServletContextHandler();
        ctx.addFilter(filter, "/*", EnumSet.of(DispatcherType.REQUEST));
        ctx.addServlet(new ServletHolder(new App()), "/*");
        server.setHandler(ctx);
        server.start();
        return server;
    }

    static String base(Server s) {
        return "http://127.0.0.1:" + ((ServerConnector) s.getConnectors()[0]).getLocalPort();
    }

    static final HttpClient HTTP = HttpClient.newHttpClient();

    static HttpResponse<String> send(String method, String url, String type, String body) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).header("User-Agent", UA);
        if (type != null) b.header("Content-Type", type);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return HTTP.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static String form(Map<String, String> fields) {
        return fields.entrySet().stream()
            .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));
    }

    static final String FORM = "application/x-www-form-urlencoded";

    @Test
    void inJetty() throws Exception {
        List<String> asked = new ArrayList<>();
        DracoOptions o = new DracoOptions();
        o.setWaf("block");
        o.setHeaders(true);
        o.getReview().setSecret("owner-secret-0123456789");
        Gatekeeper gate = new Gatekeeper(o).resolver(null).onReview(r -> asked.add(r.email()));
        Server server = start(new FilterHolder(new DracoFilter(gate)));
        String url = base(server);
        try {
            HttpResponse<String> res = send("GET", url + "/", null, null);
            assertEquals(200, res.statusCode());
            assertEquals("page", res.body());
            assertEquals("nosniff", res.headers().firstValue("X-Content-Type-Options").orElse(""));
            assertEquals(List.of("DENY"), send("GET", url + "/own", null, null).headers().allValues("X-Frame-Options"));

            // The app still reads every body, in UTF-8.
            assertEquals("name=Ñandú", send("POST", url + "/echo", FORM, form(Map.of("name", "Ñandú"))).body());
            assertEquals("name=Ana", send("PUT", url + "/echo", FORM, form(Map.of("name", "Ana"))).body());
            assertEquals("json={\"name\": \"Ana\"}", send("POST", url + "/echo", "application/json", "{\"name\": \"Ana\"}").body());

            HttpResponse<String> blocked = send("GET", url + ATTACK, null, null);
            assertEquals(403, blocked.statusCode());
            assertFalse(blocked.body().contains("sqli"));
            assertEquals(403, send("GET", url + "/.env", null, null).statusCode());
            assertEquals(403, send("GET", url + "/search?q=%2527%20OR%20%25271%2527%3D%25271", null, null).statusCode());
            assertEquals(403, send("POST", url + "/contact", FORM, form(Map.of("message", "x'; DROP TABLE users; --"))).statusCode());
            assertEquals(403, send("POST", url + "/api", "application/json", "{\"q\": \"' OR '1'='1\"}").statusCode());
            assertEquals(403, send("PUT", url + "/api", FORM, form(Map.of("q", "' OR '1'='1"))).statusCode());

            // Five attacks in ten minutes: the address is blocked from sensitive pages and posts, but may read.
            assertTrue(gate.blocks().isBlocked("127.0.0.1", gate.now()));
            assertEquals(403, send("POST", url + "/echo", FORM, form(Map.of("name", "Ana"))).statusCode());
            assertEquals(200, send("GET", url + "/", null, null).statusCode());

            // The review form still works for a blocked address.
            Map<String, String> fields = CoreTest.hidden(blocked.body());
            fields.put("draco_email", "ana@example.org");
            fields.put("draco_message", "I was searching");
            fields.put("draco_website", "");
            HttpResponse<String> thanks = send("POST", url + ATTACK, FORM, form(fields));
            assertEquals(200, thanks.statusCode());
            assertTrue(thanks.body().contains("Request sent"));
            assertEquals(List.of("ana@example.org"), asked);
        } finally {
            server.stop();
        }
    }

    @Test
    void fromInitParameters() throws Exception {
        FilterHolder holder = new FilterHolder(new DracoFilter());
        holder.setInitParameter("waf", "block");
        holder.setInitParameter("except", "/webhooks");
        Server server = start(holder);
        String url = base(server);
        try {
            assertEquals(403, send("GET", url + "/?f=../../etc/passwd", null, null).statusCode());
            assertEquals(200, send("GET", url + "/webhooks/x?f=../../etc/passwd", null, null).statusCode());
            assertTrue(send("GET", url + "/", null, null).headers().firstValue("X-Content-Type-Options").isEmpty());
        } finally {
            server.stop();
        }
    }
}
