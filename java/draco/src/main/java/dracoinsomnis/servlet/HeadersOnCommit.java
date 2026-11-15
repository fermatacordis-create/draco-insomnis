package dracoinsomnis.servlet;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

/**
 * Adds the security headers at the last moment before the answer starts (first byte, flush, error or
 * redirect), and only those the app did not set: the app's own headers always win.
 */
final class HeadersOnCommit extends HttpServletResponseWrapper {
    private final List<Map.Entry<String, String>> headers;
    private boolean done;
    private ServletOutputStream stream;
    private PrintWriter writer;

    HeadersOnCommit(HttpServletResponse response, List<Map.Entry<String, String>> headers) {
        super(response);
        this.headers = headers;
    }

    synchronized void apply() {
        if (done) return;
        done = true;
        HttpServletResponse r = (HttpServletResponse) getResponse();
        if (r.isCommitted()) return;
        for (Map.Entry<String, String> h : headers) if (!r.containsHeader(h.getKey())) r.setHeader(h.getKey(), h.getValue());
    }

    @Override
    public void sendError(int sc, String msg) throws IOException {
        apply();
        super.sendError(sc, msg);
    }

    @Override
    public void sendError(int sc) throws IOException {
        apply();
        super.sendError(sc);
    }

    @Override
    public void sendRedirect(String location) throws IOException {
        apply();
        super.sendRedirect(location);
    }

    @Override
    public void flushBuffer() throws IOException {
        apply();
        super.flushBuffer();
    }

    @Override
    public synchronized ServletOutputStream getOutputStream() throws IOException {
        if (stream != null) return stream;
        ServletOutputStream out = super.getOutputStream();
        stream = new ServletOutputStream() {
            @Override
            public void write(int b) throws IOException {
                apply();
                out.write(b);
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                apply();
                out.write(b, off, len);
            }

            @Override
            public void flush() throws IOException {
                apply();
                out.flush();
            }

            @Override
            public void close() throws IOException {
                apply();
                out.close();
            }

            @Override
            public boolean isReady() {
                return out.isReady();
            }

            @Override
            public void setWriteListener(WriteListener listener) {
                out.setWriteListener(listener);
            }
        };
        return stream;
    }

    @Override
    public synchronized PrintWriter getWriter() throws IOException {
        if (writer != null) return writer;
        PrintWriter out = super.getWriter();
        writer = new PrintWriter(out) {
            @Override
            public void write(int c) {
                apply();
                super.write(c);
            }

            @Override
            public void write(char[] buf, int off, int len) {
                apply();
                super.write(buf, off, len);
            }

            @Override
            public void write(String s, int off, int len) {
                apply();
                super.write(s, off, len);
            }

            @Override
            public void flush() {
                apply();
                super.flush();
            }

            @Override
            public void close() {
                apply();
                super.close();
            }
        };
        return writer;
    }
}
