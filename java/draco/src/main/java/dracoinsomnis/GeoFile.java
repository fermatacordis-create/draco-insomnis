package dracoinsomnis;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * The visitor's country without Cloudflare: the same file and binary search as src/Core/Geo.php
 * (DB-IP Lite, CC BY 4.0, built monthly by this project). Local: nothing is sent anywhere.
 */
public final class GeoFile implements AutoCloseable {
    public static final String DEFAULT_SOURCE = "https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin";
    private static final int HEADER = 22;

    private record Info(long v4, long v6, String built) {}

    private final Path path;
    private volatile String source = DEFAULT_SOURCE;
    private RandomAccessFile file;
    private Info info;
    private long tried;
    private final ScheduledExecutorService timer;

    /**
     * @param path where the list is kept
     * @param update download the list when missing or older than 35 days, now and then daily
     */
    public GeoFile(String path, boolean update) {
        this.path = Path.of(path);
        if (update) {
            timer = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "draco-geo");
                t.setDaemon(true);
                return t;
            });
            timer.scheduleAtFixedRate(() -> {
                try {
                    refresh();
                } catch (RuntimeException e) {
                    // The country list never breaks the app.
                }
            }, 0, 1, TimeUnit.DAYS);
        } else {
            timer = null;
        }
    }

    public Path path() {
        return path;
    }

    /** Where the list is downloaded from; its SHA-256 is read from the same address plus ".sha256". */
    public GeoFile source(String url) {
        this.source = url;
        return this;
    }

    static Info readHead(byte[] head, long size) {
        if (head.length < HEADER || !new String(head, 0, 6, StandardCharsets.US_ASCII).equals("DRGEO1")) return null;
        long v4 = u32(head, 14);
        long v6 = u32(head, 18);
        return size == HEADER + v4 * 6 + v6 * 18 ? new Info(v4, v6, new String(head, 6, 8, StandardCharsets.US_ASCII)) : null;
    }

    private static long u32(byte[] b, int at) {
        return ((long) (b[at] & 0xff) << 24) | ((b[at + 1] & 0xff) << 16) | ((b[at + 2] & 0xff) << 8) | (b[at + 3] & 0xff);
    }

    private boolean open() {
        if (file != null) return true;
        long now = System.currentTimeMillis();
        if (now - tried < 60_000) return false;
        tried = now;
        try {
            RandomAccessFile f = new RandomAccessFile(path.toFile(), "r");
            byte[] head = new byte[HEADER];
            Info i = null;
            if (f.read(head) == HEADER) i = readHead(head, f.length());
            if (i == null) {
                f.close();
                return false;
            }
            file = f;
            info = i;
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /** The two-letter country of an address, or null when unknown. */
    public synchronized String country(String ip) {
        byte[] addr = Net.toBytes(Net.unmap(ip.trim()));
        if (addr == null || !open()) return null;
        try {
            boolean is4 = addr.length == 4;
            long count = is4 ? info.v4 : info.v6, size = is4 ? 6 : 18, width = size - 2, base = HEADER + (is4 ? 0 : info.v4 * 6);
            byte[] buf = new byte[(int) width];
            long lo = 0, hi = count - 1, found = -1;
            while (lo <= hi) {
                long mid = (lo + hi) / 2;
                file.seek(base + mid * size);
                file.readFully(buf);
                if (Arrays.compareUnsigned(buf, addr) <= 0) {
                    found = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if (found < 0) return null;
            file.seek(base + found * size + width);
            byte[] cc = new byte[2];
            file.readFully(cc);
            return cc[0] >= 'A' && cc[0] <= 'Z' && cc[1] >= 'A' && cc[1] <= 'Z' ? new String(cc, StandardCharsets.US_ASCII) : null;
        } catch (IOException e) {
            return null;
        }
    }

    /** The day the list was built (yyyyMMdd), or "" when there is none. */
    public synchronized String built() {
        return open() ? info.built : "";
    }

    public boolean stale() {
        try {
            LocalDate t = LocalDate.parse(built(), DateTimeFormatter.BASIC_ISO_DATE);
            return t.plusDays(35).isBefore(LocalDate.now(ZoneOffset.UTC));
        } catch (DateTimeParseException e) {
            return true;
        }
    }

    /** Downloads the list when it is missing or stale; "" when nothing failed. */
    public String refresh() {
        return stale() ? update() : "";
    }

    /** Downloads the list, checks the published SHA-256, only then replaces the old file. "" = done. */
    public String update() {
        HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).connectTimeout(Duration.ofSeconds(20)).build();
        byte[] sum = get(http, source + ".sha256");
        String want = sum == null ? "" : new String(sum, StandardCharsets.US_ASCII).trim().toLowerCase(Locale.ROOT);
        if (want.length() < 64 || !want.substring(0, 64).matches("[0-9a-f]{64}")) return "checksum";
        byte[] body = get(http, source);
        if (body == null || !HexFormat.of().formatHex(sha256(body)).equals(want.substring(0, 64))) return "download";
        if (body.length < HEADER || readHead(Arrays.copyOf(body, HEADER), body.length) == null) return "format";
        Path part = Path.of(path + ".part");
        try {
            Path dir = path.toAbsolutePath().getParent();
            if (dir != null) Files.createDirectories(dir);
            Files.write(part, body);
            Files.move(part, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            try {
                Files.deleteIfExists(part);
            } catch (IOException ignored) {
                // nothing to remove
            }
            return "folder";
        }
        reopen();
        return "";
    }

    private static byte[] get(HttpClient http, String url) {
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(2)).header("User-Agent", "Draco-Insomnis").build();
            HttpResponse<byte[]> res = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
            return res.statusCode() == 200 ? res.body() : null;
        } catch (IOException | IllegalArgumentException e) {
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private synchronized void reopen() {
        if (file != null) {
            try {
                file.close();
            } catch (IOException ignored) {
                // already closed
            }
        }
        file = null;
        tried = 0;
    }

    @Override
    public void close() {
        if (timer != null) timer.shutdownNow();
        reopen();
    }
}
