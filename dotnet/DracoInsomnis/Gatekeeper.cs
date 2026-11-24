using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>
/// Every setting. It binds from configuration (appsettings.json "DracoInsomnis" section) or code.
/// </summary>
public sealed class DracoOptions
{
    /// <summary>"off", "log" (default) or "block".</summary>
    public string Waf { get; set; } = "log";
    /// <summary>Anti-copy pace: "off" (default), "log" or "block".</summary>
    public string Pace { get; set; } = "off";
    public int RateIp { get; set; }
    public int RateNet { get; set; }
    /// <summary>"" (the connection), "cf" (CF-Connecting-IP) or "xff" (X-Forwarded-For), believed only from TrustedProxies.</summary>
    public string Proxy { get; set; } = "";
    public List<string> TrustedProxies { get; set; } = new();
    public List<string> AdminIps { get; set; } = new();
    public List<string> Sensitive { get; set; } = new();
    public List<string> Except { get; set; } = new();
    public GeoOptions Geo { get; set; } = new();
    public bool Headers { get; set; }
    public bool Hsts { get; set; }
    public ReviewOptions Review { get; set; } = new();
    public CrowdSecOptions CrowdSec { get; set; } = new();
    /// <summary>Writes every line of evidence (and every review request) as JSON to the log.</summary>
    public bool LogEvents { get; set; }
    public Dictionary<string, string> Texts { get; set; } = new();
}

/// <summary>Country filter: Mode "block" (refuse Countries) or "allow" (only those); Action "log" or "block"; Scope "sensitive" (default) or "site".</summary>
public sealed class GeoOptions
{
    public string Mode { get; set; } = "off";
    public List<string> Countries { get; set; } = new();
    public string Action { get; set; } = "log";
    public string Scope { get; set; } = "sensitive";
    /// <summary>Where the country list is kept; it is downloaded there and refreshed.</summary>
    public string File { get; set; } = "";
}

/// <summary>Review requests from the 403 page (Secret: 16+ characters).</summary>
public sealed class ReviewOptions
{
    public string Secret { get; set; } = "";
}

/// <summary>The owner's CrowdSec Local API and the key from "cscli bouncers add draco".</summary>
public sealed class CrowdSecOptions
{
    public string Url { get; set; } = "";
    public string ApiKey { get; set; } = "";
}

/// <summary>One visitor request in plain values.</summary>
public sealed class DracoRequest
{
    public string Method { get; init; } = "GET";
    public string Path { get; init; } = "/";
    public string Query { get; init; } = "";
    /// <summary>Decoded query and body values (and keys), for the firewall only.</summary>
    public IReadOnlyList<string> Params { get; init; } = Array.Empty<string>();
    public string UserAgent { get; init; } = "";
    public string RemoteAddr { get; init; } = "";
    public string CfConnectingIp { get; init; } = "";
    public string ForwardedFor { get; init; } = "";
    public string Country { get; init; } = "";
    public string Accept { get; init; } = "";
    public bool Ajax { get; init; }
    /// <summary>The text fields of a posted form, for the review form.</summary>
    public IReadOnlyDictionary<string, string> Form { get; init; } = new Dictionary<string, string>();
}

/// <summary>What stops a request: 403 (rule), 429 (pace) or 200 (the review thanks page).</summary>
public sealed record Answer(int Status, string Why, int Retry = 0, string Form = "");

/// <summary>Proves search engines through the reverse DNS.</summary>
public interface IResolver
{
    IReadOnlyList<string> Reverse(string ip);
    IReadOnlyList<string> Forward(string host);
}

internal sealed class SystemResolver : IResolver
{
    public IReadOnlyList<string> Reverse(string ip)
    {
        var e = Dns.GetHostEntry(IPAddress.Parse(ip));
        return new[] { e.HostName }.Concat(e.Aliases).ToList();
    }

    public IReadOnlyList<string> Forward(string host) => Dns.GetHostAddresses(host).Select(a => a.ToString()).ToList();
}

/// <summary>Decides, in the same order as every edition: block list → country → signatures → pace.</summary>
public sealed class Gatekeeper
{
    public const string Version = "0.1.37";

    /// <summary>Sensitive path endings, besides any POST.</summary>
    public static readonly string[] SensitivePaths =
    {
        "/wp-login.php", "/login", "/register", "/signup", "/user/login", "/user/register", "/admin",
        "/auth/login", "/api/auth/local", "/api/auth/local/register", "/admin/login",
        "/accounts/login/", "/accounts/signup/", "/token", "/auth/token",
        // ASP.NET Core Identity
        "/Identity/Account/Login", "/Identity/Account/Register", "/Account/Login", "/Account/Register",
    };

    public static readonly IReadOnlyDictionary<string, string> DefaultTexts = new Dictionary<string, string>
    {
        ["title"] = "Request blocked",
        ["text"] = "This request was blocked by the site's security. If you think this is a mistake, contact the site owner.",
        ["too_many"] = "Too many pages in a short time. Please wait a moment and try again.",
        ["text_with_review"] = "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:",
        ["review_email"] = "Your e-mail",
        ["review_message"] = "What were you doing?",
        ["review_button"] = "Ask for a review",
        ["review_sent_title"] = "Request sent",
        ["review_sent_text"] = "Thank you. The owner of the site will look at it and, if it was a mistake, let you through.",
    };

    private static readonly Regex TwoLetters = new("^[A-Z]{2}$");

    private static readonly (string Token, string[] Domains)[] Crawlers =
    {
        ("googlebot", new[] { "googlebot.com", "google.com", "googleusercontent.com" }),
        ("google-inspectiontool", new[] { "googlebot.com", "google.com", "googleusercontent.com" }),
        ("googleother", new[] { "googlebot.com", "google.com", "googleusercontent.com" }),
        ("adsbot-google", new[] { "googlebot.com", "google.com", "googleusercontent.com" }),
        ("mediapartners-google", new[] { "googlebot.com", "google.com", "googleusercontent.com" }),
        ("bingbot", new[] { "search.msn.com" }),
        ("msnbot", new[] { "search.msn.com" }),
        ("adidxbot", new[] { "search.msn.com" }),
        ("applebot", new[] { "applebot.apple.com" }),
        ("yandex", new[] { "yandex.ru", "yandex.net", "yandex.com" }),
    };

    private readonly Dictionary<string, string> _texts;
    private readonly List<string> _trusted;
    private readonly List<string> _admins;

    public DracoOptions Options { get; }
    public IStore Store { get; }
    public Blocks Blocks { get; }
    public IResolver? Resolver { get; set; } = new SystemResolver();
    public GeoFile? Geo { get; set; }
    public CrowdSec? CrowdSec { get; }
    public Action<Event>? OnEvent { get; set; }
    public Action<ReviewRequest>? OnReview { get; set; }
    public Func<double> Now { get; set; } = Clock.Now;

    /// <param name="options">Every setting.</param>
    /// <param name="store">Shared counters and block list; null = this process only.</param>
    public Gatekeeper(DracoOptions options, IStore? store = null)
    {
        Options = options;
        Store = store ?? new MemoryStore();
        Blocks = new Blocks(Store);
        _texts = new Dictionary<string, string>(DefaultTexts);
        foreach (var (k, v) in options.Texts) _texts[k] = v;
        _trusted = Net.Parse(options.TrustedProxies);
        _admins = options.AdminIps.Select(i => i.Trim()).Where(i => i.Length > 0).ToList();
        if (options.Geo.File.Length > 0) Geo = new GeoFile(options.Geo.File);
        if (options.CrowdSec.Url.Length > 0 && options.CrowdSec.ApiKey.Length > 0)
            CrowdSec = new CrowdSec(options.CrowdSec.Url, options.CrowdSec.ApiKey, Store, () => _admins, () => Now());
    }

    public IReadOnlyDictionary<string, string> Texts => _texts;

    internal static string Remote(DracoRequest r) => Remote(r.RemoteAddr);

    internal static string Remote(string remoteAddr)
    {
        var ip = Net.Unmap(remoteAddr.Trim());
        return Net.IsIp(ip) ? ip : "0.0.0.0";
    }

    private IReadOnlyList<string> Proxies => _trusted.Count > 0 ? _trusted : Net.LocalProxies;

    /// <summary>
    /// The visitor's address: the connection's own, unless a proxy header is chosen AND the connection
    /// comes from a trusted proxy. X-Forwarded-For is read from the right.
    /// </summary>
    public string Ip(DracoRequest r)
    {
        var addr = Remote(r);
        switch (Options.Proxy)
        {
            case "cf":
                var cf = r.CfConnectingIp.Trim();
                if (cf.Length > 0 && (Net.Contains(Net.Cloudflare, addr) || Net.Contains(_trusted, addr)) && Net.IsIp(cf)) return cf;
                break;
            case "xff":
                if (r.ForwardedFor.Trim().Length == 0 || !Net.Contains(Proxies, addr)) return addr;
                var hops = r.ForwardedFor.Split(',');
                for (var i = hops.Length - 1; i >= 0; i--)
                {
                    var hop = hops[i].Trim();
                    if (!Net.IsIp(hop)) return addr;
                    if (!Net.Contains(Proxies, hop)) return hop;
                    addr = hop;
                }
                break;
        }
        return addr;
    }

    private bool Reviewing => Options.Review.Secret.Length >= 16;

    /// <summary>The answer that stops the request, or null to let it through.</summary>
    public Answer? Decide(DracoRequest r)
    {
        var a = Rules(r);
        if (a is { Status: 403 } && Reviewing)
            a = a with { Form = Review.Form(Options.Review.Secret, Ip(r), a.Why, Now(), _texts) };
        return a;
    }

    private Answer? Rules(DracoRequest r)
    {
        CrowdSec?.MaybeSync();
        var c = Options;
        var ip = Ip(r);
        foreach (var p in c.Except)
        {
            var prefix = "/" + p.TrimStart('/');
            if (prefix != "/" && r.Path.StartsWith(prefix, StringComparison.Ordinal)) return null;
        }
        if (Reviewing && r.Method == "POST" && r.Form.TryGetValue(Review.Field, out var flag) && flag == "1")
        {
            var req = Review.Accept(Store, c.Review.Secret, ip, r.UserAgent, r.Form, Now());
            if (req is not null)
            {
                Log(r, ip, "review", "pending", new[] { "review_" + (req.Rule.Length > 0 ? req.Rule : "blocked") }, req.Message, req.Email);
                OnReview?.Invoke(req);
            }
            // The same answer either way, so a script learns nothing.
            return new Answer(200, "review");
        }
        if (_admins.Contains(ip)) return null;
        var waf = c.Waf.Length > 0 ? c.Waf : "log";
        if (waf != "off")
        {
            if (IsSensitive(r) && Blocks.IsBlocked(ip, Now())) return new Answer(403, "blocked");
            var country = RefusedCountry(r, ip);
            if (country.Length > 0)
            {
                var blocking = c.Geo.Action == "block";
                Log(r, ip, "waf:geo", blocking ? "bot" : "doubtful", new[] { "waf_geo" }, country + " " + r.Path);
                if (blocking) return new Answer(403, "geo");
            }
            var rule = Waf.Inspect(r.Path, r.Query, r.Params, r.UserAgent);
            if (rule is not null)
            {
                Record(r, ip, rule, waf == "block");
                if (waf == "block") return new Answer(403, rule);
            }
        }
        if (c.Pace.Length > 0 && c.Pace != "off" && WantsPage(r))
        {
            var now = Now();
            var minute = ((long)now / 60).ToString();
            var ipHits = Store.Bump($"draco:rl:i:{ip}:{minute}", 120);
            var netHits = Store.Bump($"draco:rl:n:{Net.Network(ip)}:{minute}", 120);
            long ipLimit = Limit(c.RateIp, 120), netLimit = Limit(c.RateNet, 600);
            var over = ipHits > ipLimit ? "ip" : netHits > netLimit ? "net" : "";
            if (over.Length > 0 && !VerifiedCrawler(ip, r.UserAgent))
            {
                var block = c.Pace == "block";
                if (ipHits == ipLimit + 1 || netHits == netLimit + 1)
                    Log(r, ip, "anticopy:" + over, "doubtful", new[] { $"anticopy_{over}_{(block ? "block" : "log")}" }, r.Path);
                if (block) return new Answer(429, "pace", Math.Max(1, 60 - (int)((long)now % 60)));
            }
        }
        return null;
    }

    private static int Limit(int v, int fallback) => v >= 10 ? v : fallback;

    private static bool WantsPage(DracoRequest r)
    {
        var accept = r.Accept.ToLowerInvariant();
        return r.Method is "GET" or "HEAD" && (accept.Length == 0 || accept.Contains("text/html")) && !r.Ajax;
    }

    private bool IsSensitive(DracoRequest r)
    {
        if (r.Method == "POST") return true;
        var endings = Options.Sensitive.Count > 0 ? (IEnumerable<string>)Options.Sensitive : SensitivePaths;
        return endings.Any(e => e.Length > 0 && r.Path.EndsWith(e, StringComparison.Ordinal));
    }

    private string RefusedCountry(DracoRequest r, string ip)
    {
        var geo = Options.Geo;
        var list = geo.Countries.Select(x => x.Trim().ToUpperInvariant()).Where(x => TwoLetters.IsMatch(x)).ToList();
        if (geo.Mode is "" or "off" || list.Count == 0) return "";
        if (geo.Scope != "site" && !IsSensitive(r)) return "";
        var country = r.Country.ToUpperInvariant();
        if (!TwoLetters.IsMatch(country) && Geo is not null) country = Geo.Country(ip) ?? "";
        // Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
        if (!TwoLetters.IsMatch(country) || country is "XX" or "T1") return "";
        var listed = list.Contains(country);
        if ((geo.Mode == "block" && !listed) || (geo.Mode == "allow" && listed)) return "";
        return VerifiedCrawler(ip, r.UserAgent) ? "" : country;
    }

    private void Record(DracoRequest r, string ip, string rule, bool blocking)
    {
        var detail = r.Path + (r.Query.Length > 0 ? "?" + r.Query : "");
        Log(r, ip, "waf:" + rule, blocking ? "bot" : "doubtful", new[] { "waf_" + rule }, detail);
        if (!blocking) return;
        var hits = Store.Bump("draco:waf:" + ip, 600);
        // An address read from a header nobody vouches for is never blocked: it could be anybody's.
        var trusted = ip == Remote(r) || Options.Proxy.Length > 0;
        if (hits >= 5 && trusted && !Blocks.IsBlocked(ip, Now()))
            Blocks.Add(ip, 7, $"Firewall: {hits} attacks in 10 minutes", true, Now());
    }

    /// <summary>A search engine proved by its reverse DNS and the forward lookup back; cached a day.</summary>
    public bool VerifiedCrawler(string ip, string userAgent)
    {
        var ua = userAgent.ToLowerInvariant();
        var hit = Crawlers.FirstOrDefault(c => ua.Contains(c.Token));
        if (hit.Token is null || Resolver is null) return false;
        var key = $"draco:crawler:{ip}:{hit.Token}";
        var cached = Store.Get(key);
        if (cached is "y" or "n") return cached == "y";
        var ok = ResolvesBack(ip, hit.Domains);
        Store.Set(key, ok ? "y" : "n", 86400);
        return ok;
    }

    private bool ResolvesBack(string ip, string[] domains)
    {
        var want = Net.ToBytes(ip);
        if (want is null) return false;
        IReadOnlyList<string> names;
        try { names = Resolver!.Reverse(ip); }
        catch (Exception) { return false; }
        foreach (var name in names.Take(3))
        {
            var h = name.Trim().ToLowerInvariant().TrimEnd('.');
            if (!domains.Any(d => h == d || h.EndsWith("." + d, StringComparison.Ordinal))) continue;
            try
            {
                if (Resolver!.Forward(h).Any(a => Net.ToBytes(a) is { } b && b.AsSpan().SequenceEqual(want))) return true;
            }
            catch (Exception) { /* next name */ }
        }
        return false;
    }

    private void Log(DracoRequest r, string ip, string endpoint, string verdict, IReadOnlyList<string> reasons, string detail, string? email = null)
    {
        if (OnEvent is null) return;
        var ua = r.UserAgent.Length > 255 ? r.UserAgent[..255] : r.UserAgent;
        var max = endpoint == "review" ? 500 : 200;
        var runes = detail.EnumerateRunes().ToList();
        if (runes.Count > max) detail = string.Concat(runes.Take(max).Select(x => x.ToString()));
        OnEvent(new Event((long)Now(), ip, Remote(r), endpoint, verdict, reasons, ua, detail, email));
    }

    /// <summary>Security headers to add, unless the application already set them.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> SecurityHeaders(bool https)
    {
        var o = new List<KeyValuePair<string, string>>();
        if (Options.Headers)
        {
            o.Add(new("X-Content-Type-Options", "nosniff"));
            o.Add(new("X-Frame-Options", "SAMEORIGIN"));
            o.Add(new("Referrer-Policy", "strict-origin-when-cross-origin"));
            o.Add(new("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()"));
        }
        if (https && Options.Hsts) o.Add(new("Strict-Transport-Security", "max-age=15552000"));
        return o;
    }

    /// <summary>The status, headers and body of an answer.</summary>
    public (int Status, IReadOnlyList<KeyValuePair<string, string>> Headers, string Body) Render(Answer a)
    {
        var t = _texts;
        if (a.Status == 429)
            return (429, new KeyValuePair<string, string>[]
            {
                new("Retry-After", a.Retry.ToString()), new("Content-Type", "text/plain; charset=UTF-8"),
                new("Cache-Control", "no-store"), new("X-Robots-Tag", "noindex"),
            }, t["too_many"]);
        var h = new KeyValuePair<string, string>[]
        {
            new("Content-Type", "text/html; charset=UTF-8"), new("Cache-Control", "no-store"), new("X-Robots-Tag", "noindex, nofollow"),
        };
        if (a.Status == 200) return (200, h, Page(t["review_sent_title"], t["review_sent_text"]));
        return a.Form.Length > 0 ? (403, h, Page(t["title"], t["text_with_review"], a.Form)) : (403, h, Page(t["title"], t["text"]));
    }

    /// <summary>The 403 page: it never says which rule matched; the reference ties it to the evidence.</summary>
    public static string Page(string title, string text, string extra = "")
    {
        static string H(string s) => WebUtility.HtmlEncode(s);
        var reference = Convert.ToHexString(RandomNumberGenerator.GetBytes(5)).ToLowerInvariant();
        return "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"robots\" content=\"noindex,nofollow\">"
            + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>403</title>"
            + "<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}form{text-align:left;margin-top:20px}label{display:block;font-size:14px;margin:10px 0 4px}input,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}button{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}.hp{position:absolute;left:-9999px}</style></head><body><main>"
            + $"<h1 style=\"font-size:20px\">{H(title)}</h1><p>{H(text)}</p>{extra}"
            + $"<p style=\"color:#64748b;font-size:13px\">Ref. {reference}</p></main></body></html>";
    }
}
