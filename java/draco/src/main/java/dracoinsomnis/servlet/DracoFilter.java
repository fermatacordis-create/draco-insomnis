package dracoinsomnis.servlet;

import dracoinsomnis.Answer;
import dracoinsomnis.DracoOptions;
import dracoinsomnis.DracoRequest;
import dracoinsomnis.Gatekeeper;
import dracoinsomnis.Http;
import dracoinsomnis.Json;
import dracoinsomnis.Net;
import dracoinsomnis.Waf;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Draco as a Jakarta Servlet filter (Servlet 5 or newer): Spring Boot 3 and 4 (Spring MVC), Tomcat 10+,
 * Jetty 11+, Undertow, Payara, WildFly, Open Liberty. It answers first; the app only sees what it lets
 * through. Forms and JSON bodies up to 64 KB are inspected, and the app still reads them unchanged.
 *
 * <p>In Spring Boot, register it first: {@code new FilterRegistrationBean<>(new DracoFilter(gate))}
 * with {@code setOrder(Ordered.HIGHEST_PRECEDENCE)}. In a web.xml, the init parameters are the keys of
 * {@link DracoOptions#fromMap}.
 */
public class DracoFilter implements Filter {
    static final int MAX_BODY = 65536;
    private static final System.Logger LOG = System.getLogger("DracoInsomnis");
    private volatile Gatekeeper gate;

    /** Configured from the filter's init parameters (web.xml or @WebFilter). */
    public DracoFilter() {}

    public DracoFilter(Gatekeeper gate) {
        this.gate = gate;
    }

    public DracoFilter(DracoOptions options) {
        this(create(options));
    }

    private static Gatekeeper create(DracoOptions options) {
        Gatekeeper g = new Gatekeeper(options);
        if (options.isLogEvents()) g.logToSystemLogger();
        return g;
    }

    public Gatekeeper gatekeeper() {
        return gate;
    }

    @Override
    public void init(FilterConfig config) {
        if (gate != null) return;
        Map<String, String> values = new LinkedHashMap<>();
        for (String name : Collections.list(config.getInitParameterNames())) values.put(name, config.getInitParameter(name));
        gate = create(DracoOptions.fromMap(values));
    }

    private static boolean hasBody(String method) {
        return method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
    }

    /**
     * Reads a request the way Draco needs it. The returned request is the one to pass on: when a
     * JSON or form body had to be read, it carries the same bytes again.
     */
    record Read(DracoRequest request, HttpServletRequest pass) {}

    static Read read(HttpServletRequest r) throws IOException {
        String method = r.getMethod().toUpperCase(Locale.ROOT);
        // Without a charset, forms are UTF-8 (as Spring Boot does), never the servlet default Latin-1.
        if (r.getCharacterEncoding() == null) r.setCharacterEncoding("UTF-8");
        String path = Http.decode(r.getRequestURI(), false);
        String raw = r.getQueryString() == null ? "" : r.getQueryString();
        List<String> params = new ArrayList<>(Waf.flatten(Http.parseQuery(raw)));
        Map<String, String> form = Map.of();
        HttpServletRequest pass = r;
        String kind = r.getContentType() == null ? "" : r.getContentType().toLowerCase(Locale.ROOT);
        long length = r.getContentLengthLong();
        boolean small = length >= 0 && length <= MAX_BODY;
        boolean json = kind.contains("json");
        boolean urlencoded = kind.contains("x-www-form-urlencoded");
        if (hasBody(method) && small && method.equals("POST") && urlencoded) {
            // The container parses a posted form itself; the app reads the same parameters.
            Map<String, String[]> values = r.getParameterMap();
            params.addAll(Waf.flatten(values));
            form = Http.lastValues(values);
        } else if (hasBody(method) && small && (json || urlencoded)) {
            byte[] body = r.getInputStream().readNBytes((int) length);
            pass = new CachedBodyRequest(r, body);
            String text = new String(body, charset(r));
            if (json) {
                try {
                    Object parsed = Json.parse(text);
                    params.addAll(Waf.flatten(parsed));
                    form = Http.jsonFields(parsed);
                } catch (IllegalArgumentException e) {
                    params.add(text);
                }
            } else {
                Map<String, List<String>> values = Http.parseQuery(text);
                params.addAll(Waf.flatten(values));
                form = Http.lastValues(values);
            }
        }
        String remote = r.getRemoteAddr() == null ? "" : r.getRemoteAddr();
        String unmapped = Net.unmap(remote.trim());
        // Cloudflare's country header, only when the connection really comes from Cloudflare.
        String country = Net.isIp(unmapped) && Net.contains(Net.CLOUDFLARE, unmapped) ? header(r, "CF-IPCountry") : "";
        List<String> xff = Collections.list(r.getHeaders("X-Forwarded-For"));
        DracoRequest d = new DracoRequest().method(method).path(path).query(Http.decode(raw, true)).params(params)
            .userAgent(header(r, "User-Agent")).remoteAddr(remote).country(country).cfConnectingIp(header(r, "CF-Connecting-IP"))
            .forwardedFor(String.join(", ", xff)).accept(header(r, "Accept"))
            .ajax("XMLHttpRequest".equalsIgnoreCase(header(r, "X-Requested-With"))).form(form);
        return new Read(d, pass);
    }

    private static java.nio.charset.Charset charset(HttpServletRequest r) {
        try {
            return java.nio.charset.Charset.forName(r.getCharacterEncoding());
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }

    private static String header(HttpServletRequest r, String name) {
        String v = r.getHeader(name);
        return v == null ? "" : v;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest req) || !(response instanceof HttpServletResponse res) || gate == null) {
            chain.doFilter(request, response);
            return;
        }
        Gatekeeper g = gate;
        Answer answer = null;
        HttpServletRequest pass = req;
        try {
            Read read = read(req);
            pass = read.pass();
            answer = g.decide(read.request());
        } catch (IOException | RuntimeException e) {
            // If Draco itself fails, the request goes through.
            LOG.log(System.Logger.Level.WARNING, "Draco Insomnis could not inspect the request; it was let through", e);
        }
        if (answer != null) {
            Gatekeeper.Rendered out = g.render(answer);
            res.setStatus(out.status());
            for (Map.Entry<String, String> h : out.headers()) res.setHeader(h.getKey(), h.getValue());
            byte[] body = out.body().getBytes(StandardCharsets.UTF_8);
            res.setContentLength(body.length);
            res.getOutputStream().write(body);
            return;
        }
        List<Map.Entry<String, String>> extra = g.securityHeaders(req.isSecure());
        if (extra.isEmpty()) {
            chain.doFilter(pass, res);
            return;
        }
        // Added when the answer starts, after the app set its own, so the app's always win.
        HeadersOnCommit wrapped = new HeadersOnCommit(res, extra);
        try {
            chain.doFilter(pass, wrapped);
        } finally {
            if (!req.isAsyncStarted()) wrapped.apply();
        }
    }
}
