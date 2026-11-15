package dracoinsomnis;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * "This is a mistake": the review form of the 403 page, with the same seals, signatures and limits as
 * src/Core/Review.php (tests/vectors/review.json).
 */
public final class Review {
    private Review() {}

    /** One accepted review request, for the owner. */
    public record Request(long time, String ip, String rule, String email, String message, String userAgent) {}

    public static final String FIELD = "draco_review";

    private static final Pattern EMAIL = Pattern.compile(
        "^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
        Pattern.CASE_INSENSITIVE);
    private static final Pattern TAGS = Pattern.compile("<(script|style)[^>]*?>.*?</\\1>|<[^>]*>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
    private static final Pattern CONTROL = Pattern.compile("[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]");
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-fA-F]{64}$");
    private static final Pattern RULE = Pattern.compile("^[a-z0-9_]*$");
    private static final Pattern DIGITS = Pattern.compile("^[0-9]{1,18}$");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);
    private static final HexFormat HEX = HexFormat.of();

    private static byte[] mac(String secret, String data) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return m.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String cleanRule(String rule) {
        return rule.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_]", "");
    }

    /** The rule, encrypted for this visitor and moment, so the page never shows it. */
    public static String seal(String secret, String ip, String ts, String rule) {
        byte[] plain = new byte[32];
        byte[] r = cleanRule(rule).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(r, 0, plain, 0, Math.min(32, r.length));
        byte[] key = mac(secret, "review-rule|" + ip + "|" + ts);
        for (int i = 0; i < 32; i++) plain[i] ^= key[i];
        return HEX.formatHex(plain);
    }

    /** The rule back from a seal; "" when it is not one. */
    public static String openSealed(String secret, String ip, String ts, String sealedRule) {
        if (sealedRule == null || !HEX64.matcher(sealedRule).matches()) return "";
        byte[] b = HEX.parseHex(sealedRule.toLowerCase(Locale.ROOT));
        byte[] key = mac(secret, "review-rule|" + ip + "|" + ts);
        for (int i = 0; i < 32; i++) b[i] ^= key[i];
        String rule = new String(b, StandardCharsets.ISO_8859_1).replaceAll("\0+$", "");
        return RULE.matcher(rule).matches() ? rule : "";
    }

    public static String sign(String secret, String ip, String rule, String ts) {
        return HEX.formatHex(mac(secret, "review|" + ip + "|" + rule + "|" + ts));
    }

    static String html(String s) {
        StringBuilder o = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '&' -> o.append("&amp;");
                case '<' -> o.append("&lt;");
                case '>' -> o.append("&gt;");
                case '"' -> o.append("&quot;");
                case '\'' -> o.append("&#39;");
                default -> o.append(c);
            }
        }
        return o.toString();
    }

    static String form(String secret, String ip, String why, double now, Map<String, String> t) {
        String ts = Long.toString((long) now);
        String rule = cleanRule(why);
        return "<form method=\"post\" action=\"\">"
            + "<input type=\"hidden\" name=\"" + FIELD + "\" value=\"1\">"
            + "<input type=\"hidden\" name=\"draco_rule\" value=\"" + html(seal(secret, ip, ts, rule)) + "\">"
            + "<input type=\"hidden\" name=\"draco_ts\" value=\"" + html(ts) + "\">"
            + "<input type=\"hidden\" name=\"draco_sig\" value=\"" + html(sign(secret, ip, rule, ts)) + "\">"
            + "<p class=\"hp\"><label>Website <input type=\"text\" name=\"draco_website\" tabindex=\"-1\" autocomplete=\"off\"></label></p>"
            + "<label for=\"draco-r-email\">" + html(t.get("review_email")) + "</label>"
            + "<input id=\"draco-r-email\" type=\"email\" name=\"draco_email\" required maxlength=\"190\">"
            + "<label for=\"draco-r-msg\">" + html(t.get("review_message")) + "</label>"
            + "<textarea id=\"draco-r-msg\" name=\"draco_message\" rows=\"3\" maxlength=\"500\" required></textarea>"
            + "<button type=\"submit\">" + html(t.get("review_button")) + "</button></form>";
    }

    static Request accept(Store store, String secret, String ip, String userAgent, Map<String, String> post, double now) {
        String ts = post.getOrDefault("draco_ts", "");
        String rule = openSealed(secret, ip, ts, post.getOrDefault("draco_rule", ""));
        String email = post.getOrDefault("draco_email", "").trim().toLowerCase(Locale.ROOT);
        String message = TAGS.matcher(post.getOrDefault("draco_message", "")).replaceAll("");
        message = CONTROL.matcher(message).replaceAll("").trim();
        if (message.length() > 500) message = message.substring(0, 500);
        boolean fresh = false;
        if (DIGITS.matcher(ts).matches()) {
            long t = Long.parseLong(ts);
            fresh = t <= now && now - t < 86400;
        }
        String sig = post.getOrDefault("draco_sig", "");
        boolean ok = fresh && sig.length() == 64
            && MessageDigest.isEqual(sign(secret, ip, rule, ts).getBytes(StandardCharsets.US_ASCII), sig.getBytes(StandardCharsets.US_ASCII))
            && post.getOrDefault("draco_website", "").isEmpty() && EMAIL.matcher(email).matches() && email.length() <= 190
            && !message.isEmpty();
        if (!ok) return null;
        String day = DAY.format(Instant.ofEpochSecond((long) now));
        if (store.bump("draco:review:ip:" + ip, 86400) > 3 || store.bump("draco:review:day:" + day, 86400) > 50) return null;
        return new Request((long) now, ip, rule, email, message, userAgent.length() > 255 ? userAgent.substring(0, 255) : userAgent);
    }
}
