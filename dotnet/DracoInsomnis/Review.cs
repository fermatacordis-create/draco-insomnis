using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>One accepted review request, for the owner.</summary>
public sealed record ReviewRequest(long Time, string Ip, string Rule, string Email, string Message, string UserAgent);

/// <summary>
/// "This is a mistake": the review form from the 403 page — the same seals, signatures and limits as
/// src/Core/Review.php (tests/vectors/review.json).
/// </summary>
public static class Review
{
    public const string Field = "draco_review";

    private static readonly Regex EmailRe = new(
        @"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static byte[] Mac(string secret, string data) => HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(data));

    private static string CleanRule(string rule) => Regex.Replace(rule.ToLowerInvariant(), "[^a-z0-9_]", "");

    public static string Seal(string secret, string ip, string ts, string rule)
    {
        var plain = new byte[32];
        var r = Encoding.ASCII.GetBytes(CleanRule(rule));
        Array.Copy(r, plain, Math.Min(32, r.Length));
        var key = Mac(secret, $"review-rule|{ip}|{ts}");
        for (var i = 0; i < 32; i++) plain[i] ^= key[i];
        return Convert.ToHexString(plain).ToLowerInvariant();
    }

    public static string OpenSealed(string secret, string ip, string ts, string sealedRule)
    {
        if (!Regex.IsMatch(sealedRule ?? "", "^[0-9a-fA-F]{64}$")) return "";
        var b = Convert.FromHexString(sealedRule!);
        var key = Mac(secret, $"review-rule|{ip}|{ts}");
        for (var i = 0; i < 32; i++) b[i] ^= key[i];
        var rule = Encoding.Latin1.GetString(b).TrimEnd('\0');
        return Regex.IsMatch(rule, "^[a-z0-9_]*$") ? rule : "";
    }

    public static string Sign(string secret, string ip, string rule, string ts) =>
        Convert.ToHexString(Mac(secret, $"review|{ip}|{rule}|{ts}")).ToLowerInvariant();

    internal static string Form(string secret, string ip, string why, double now, IReadOnlyDictionary<string, string> t)
    {
        static string H(string s) => WebUtility.HtmlEncode(s);
        var ts = ((long)now).ToString();
        var rule = CleanRule(why);
        return "<form method=\"post\" action=\"\">"
            + $"<input type=\"hidden\" name=\"{Field}\" value=\"1\">"
            + $"<input type=\"hidden\" name=\"draco_rule\" value=\"{H(Seal(secret, ip, ts, rule))}\">"
            + $"<input type=\"hidden\" name=\"draco_ts\" value=\"{H(ts)}\">"
            + $"<input type=\"hidden\" name=\"draco_sig\" value=\"{H(Sign(secret, ip, rule, ts))}\">"
            + "<p class=\"hp\"><label>Website <input type=\"text\" name=\"draco_website\" tabindex=\"-1\" autocomplete=\"off\"></label></p>"
            + $"<label for=\"draco-r-email\">{H(t["review_email"])}</label>"
            + "<input id=\"draco-r-email\" type=\"email\" name=\"draco_email\" required maxlength=\"190\">"
            + $"<label for=\"draco-r-msg\">{H(t["review_message"])}</label>"
            + "<textarea id=\"draco-r-msg\" name=\"draco_message\" rows=\"3\" maxlength=\"500\" required></textarea>"
            + $"<button type=\"submit\">{H(t["review_button"])}</button></form>";
    }

    internal static ReviewRequest? Accept(IStore store, string secret, string ip, string userAgent, IReadOnlyDictionary<string, string> post, double now)
    {
        string P(string k) => post.TryGetValue(k, out var v) ? v : "";
        var ts = P("draco_ts");
        var rule = OpenSealed(secret, ip, ts, P("draco_rule"));
        var email = P("draco_email").Trim().ToLowerInvariant();
        var message = Regex.Replace(P("draco_message"), "<(script|style)[^>]*?>.*?</\\1>|<[^>]*>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);
        message = Regex.Replace(message, "[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]", "").Trim();
        if (message.Length > 500) message = message[..500];
        var fresh = Regex.IsMatch(ts, "^[0-9]+$") && long.TryParse(ts, out var t) && t <= now && now - t < 86400;
        var sig = P("draco_sig");
        var ok = fresh && sig.Length == 64
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Sign(secret, ip, rule, ts)), Encoding.ASCII.GetBytes(sig))
            && P("draco_website").Length == 0 && EmailRe.IsMatch(email) && email.Length <= 190 && message.Length > 0;
        if (!ok) return null;
        var day = DateTimeOffset.FromUnixTimeSeconds((long)now).UtcDateTime.ToString("yyyyMMdd");
        if (store.Bump("draco:review:ip:" + ip, 86400) > 3 || store.Bump("draco:review:day:" + day, 86400) > 50) return null;
        return new ReviewRequest((long)now, ip, rule, email, message, userAgent.Length > 255 ? userAgent[..255] : userAgent);
    }
}
