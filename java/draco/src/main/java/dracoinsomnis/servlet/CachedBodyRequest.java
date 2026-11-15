package dracoinsomnis.servlet;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The request again, with the body Draco already read, so the app reads the same bytes. */
final class CachedBodyRequest extends HttpServletRequestWrapper {
    private final byte[] body;
    private final boolean form;
    private Map<String, String[]> parameters;

    CachedBodyRequest(HttpServletRequest request, byte[] body) {
        super(request);
        this.body = body;
        String kind = request.getContentType() == null ? "" : request.getContentType().toLowerCase(java.util.Locale.ROOT);
        this.form = kind.contains("x-www-form-urlencoded");
    }

    @Override
    public ServletInputStream getInputStream() {
        ByteArrayInputStream in = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public int read() {
                return in.read();
            }

            @Override
            public int read(byte[] b, int off, int len) {
                return in.read(b, off, len);
            }

            @Override
            public boolean isFinished() {
                return in.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener listener) {
                try {
                    listener.onDataAvailable();
                    listener.onAllDataRead();
                } catch (IOException e) {
                    listener.onError(e);
                }
            }
        };
    }

    @Override
    public BufferedReader getReader() {
        Charset cs;
        try {
            cs = getCharacterEncoding() == null ? StandardCharsets.UTF_8 : Charset.forName(getCharacterEncoding());
        } catch (RuntimeException e) {
            cs = StandardCharsets.UTF_8;
        }
        return new BufferedReader(new InputStreamReader(new ByteArrayInputStream(body), cs));
    }

    // A form sent with PUT or PATCH: the container does not parse those, but some frameworks ask for
    // its fields as parameters, so they come from the bytes already read (after the query's).
    private synchronized Map<String, String[]> parameters() {
        if (parameters != null) return parameters;
        Map<String, List<String>> all = new LinkedHashMap<>();
        for (Map.Entry<String, String[]> e : super.getParameterMap().entrySet())
            all.computeIfAbsent(e.getKey(), k -> new java.util.ArrayList<>()).addAll(List.of(e.getValue()));
        if (form) {
            Charset cs;
            try {
                cs = getCharacterEncoding() == null ? StandardCharsets.UTF_8 : Charset.forName(getCharacterEncoding());
            } catch (RuntimeException e) {
                cs = StandardCharsets.UTF_8;
            }
            for (Map.Entry<String, List<String>> e : dracoinsomnis.Http.parseQuery(new String(body, cs)).entrySet())
                all.computeIfAbsent(e.getKey(), k -> new java.util.ArrayList<>()).addAll(e.getValue());
        }
        Map<String, String[]> o = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : all.entrySet()) o.put(e.getKey(), e.getValue().toArray(new String[0]));
        parameters = Collections.unmodifiableMap(o);
        return parameters;
    }

    @Override
    public String getParameter(String name) {
        String[] v = parameters().get(name);
        return v == null || v.length == 0 ? null : v[0];
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        return parameters();
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(parameters().keySet());
    }

    @Override
    public String[] getParameterValues(String name) {
        String[] v = parameters().get(name);
        return v == null ? null : v.clone();
    }
}
