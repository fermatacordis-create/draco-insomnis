package e2e;

import dracoinsomnis.DracoOptions;
import dracoinsomnis.Gatekeeper;
import dracoinsomnis.servlet.DracoFilter;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Draco in a real Spring Boot app: settings from application.properties, Spring MVC on Tomcat, real HTTP. */
@SpringBootApplication
public class SpringE2e {
    static final List<String> ASKED = new CopyOnWriteArrayList<>();
    static final String UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";
    static final String ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
    static final String FORM = "application/x-www-form-urlencoded";
    static int fails;

    // What a user writes: the options bound from "draco-insomnis.*", one gatekeeper, the filter first.
    @Bean
    @ConfigurationProperties("draco-insomnis")
    DracoOptions dracoOptions() {
        return new DracoOptions();
    }

    @Bean
    Gatekeeper dracoGatekeeper(DracoOptions options) {
        return new Gatekeeper(options).resolver(null).onReview(r -> ASKED.add(r.email()));
    }

    @Bean
    FilterRegistrationBean<DracoFilter> dracoFilter(Gatekeeper gate) {
        FilterRegistrationBean<DracoFilter> b = new FilterRegistrationBean<>(new DracoFilter(gate));
        b.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return b;
    }

    @RestController
    static class Pages {
        @GetMapping("/")
        String home() {
            return "page";
        }

        @GetMapping("/own")
        String own(HttpServletResponse res) {
            res.setHeader("X-Frame-Options", "DENY");
            return "own";
        }

        @GetMapping("/search")
        String search(@RequestParam String q) {
            return "results";
        }

        @PostMapping("/echo")
        String echo(@RequestParam String name) {
            return "name=" + name;
        }

        @PostMapping("/json")
        String json(@RequestBody String body) {
            return "json=" + body;
        }
    }

    static void check(String name, boolean ok) {
        System.out.println((ok ? "ok   - " : "FAIL - ") + name);
        if (!ok) fails++;
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

    public static void main(String[] args) throws Exception {
        ConfigurableApplicationContext ctx = SpringApplication.run(SpringE2e.class, args);
        String url = "http://127.0.0.1:" + ctx.getEnvironment().getProperty("local.server.port");
        String name = "spring boot (tomcat)";
        try {
            HttpResponse<String> res = send("GET", url + "/", null, null);
            check(name + ": an ordinary page passes", res.statusCode() == 200 && res.body().equals("page"));
            check(name + ": security headers", res.headers().firstValue("X-Content-Type-Options").orElse("").equals("nosniff"));
            check(name + ": the app's own header wins", send("GET", url + "/own", null, null).headers().allValues("X-Frame-Options").equals(List.of("DENY")));
            check(name + ": settings bound from application.properties", ctx.getBean(Gatekeeper.class).options().getWaf().equals("block"));
            HttpResponse<String> echo = send("POST", url + "/echo", FORM, form(Map.of("name", "Ñandú")));
            check(name + ": the app still reads the form, in UTF-8", echo.statusCode() == 200 && echo.body().equals("name=Ñandú"));
            HttpResponse<String> json = send("POST", url + "/json", "application/json", "{\"name\": \"Ana\"}");
            check(name + ": the app still reads the JSON body", json.body().equals("json={\"name\": \"Ana\"}"));
            HttpResponse<String> blocked = send("GET", url + ATTACK, null, null);
            check(name + ": SQL injection gets 403", blocked.statusCode() == 403);
            check(name + ": the page never names the rule", !blocked.body().contains("sqli"));
            check(name + ": .env probe gets 403", send("GET", url + "/.env", null, null).statusCode() == 403);
            check(name + ": a posted form is inspected", send("POST", url + "/contact", FORM, form(Map.of("message", "x'; DROP TABLE users; --"))).statusCode() == 403);
            check(name + ": a JSON body is inspected", send("POST", url + "/json", "application/json", "{\"q\": \"' OR '1'='1\"}").statusCode() == 403);
            Map<String, String> fields = new LinkedHashMap<>();
            Matcher m = Pattern.compile("<input type=\"hidden\" name=\"([a-z_]+)\" value=\"([^\"]*)\">").matcher(blocked.body());
            while (m.find()) fields.put(m.group(1), m.group(2));
            fields.put("draco_email", "ana@example.org");
            fields.put("draco_message", "I was searching");
            fields.put("draco_website", "");
            HttpResponse<String> thanks = send("POST", url + ATTACK, FORM, form(fields));
            check(name + ": the review request is thanked", thanks.statusCode() == 200 && thanks.body().contains("Request sent"));
            check(name + ": and reaches the owner", ASKED.equals(List.of("ana@example.org")));
        } finally {
            ctx.close();
        }
        System.out.println(fails == 0 ? "all passed (Draco Insomnis " + Gatekeeper.VERSION + ")" : fails + " failed");
        System.exit(fails == 0 ? 0 : 1);
    }
}
