using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace DracoInsomnis.Tests;

internal sealed class NoDns : IResolver
{
    public IReadOnlyList<string> Reverse(string ip) => throw new IOException("no DNS");
    public IReadOnlyList<string> Forward(string host) => throw new IOException("no DNS");
}

internal sealed class FakeDns : IResolver
{
    public IReadOnlyList<string> Reverse(string ip) => ip == "66.249.66.1" ? new[] { "crawl-66-249-66-1.googlebot.com." } : new[] { "x.example" };
    public IReadOnlyList<string> Forward(string host) => host == "crawl-66-249-66-1.googlebot.com" ? new[] { "66.249.66.1" } : Array.Empty<string>();
}

/// <summary>A small HTTP server for the country list and the CrowdSec API.</summary>
internal sealed class Serve : IDisposable
{
    private readonly HttpListener _l = new();
    public string Url { get; }

    public Serve(Func<HttpListenerRequest, byte[]> answer)
    {
        var port = 20000 + Random.Shared.Next(20000);
        Url = $"http://127.0.0.1:{port}";
        _l.Prefixes.Add(Url + "/");
        _l.Start();
        Task.Run(async () =>
        {
            while (_l.IsListening)
            {
                HttpListenerContext c;
                try { c = await _l.GetContextAsync(); } catch { return; }
                var b = answer(c.Request);
                c.Response.OutputStream.Write(b);
                c.Response.Close();
            }
        });
    }

    public void Dispose() => _l.Close();
}

public class CoreTests
{
    private const double Now0 = 1_800_000_000;

    private static Gatekeeper Gate(DracoOptions o) =>
        new(o, new MemoryStore(() => Now0)) { Resolver = new NoDns(), Now = () => Now0 };

    private static DracoRequest Req(string method = "GET", string path = "/", string query = "", IReadOnlyList<string>? ps = null,
        string remote = "198.51.100.20", string accept = "", string xff = "", IReadOnlyDictionary<string, string>? form = null,
        string ua = "Mozilla/5.0 Chrome/131.0") =>
        new()
        {
            Method = method, Path = path, Query = query, Params = ps ?? Array.Empty<string>(), RemoteAddr = remote,
            Accept = accept, ForwardedFor = xff, Form = form ?? new Dictionary<string, string>(), UserAgent = ua,
        };

    private static DracoRequest Attack(string remote = "198.51.100.20") =>
        Req(query: "../../etc/passwd", ps: new[] { "../../etc/passwd" }, remote: remote);

    internal static Dictionary<string, string> Hidden(string page) =>
        Regex.Matches(page, "type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\"")
            .ToDictionary(m => m.Groups[1].Value, m => WebUtility.HtmlDecode(m.Groups[2].Value));

    [Fact]
    public void NetLikePhp()
    {
        Assert.False(Net.IsIp("01.2.3.4"));
        Assert.False(Net.IsIp("fe80::1%eth0"));
        Assert.True(Net.IsIp("2001:db8::1"));
        Assert.Equal("2001:db8:1:2::/64", Net.Network("2001:db8:1:2:3:4:5:6"));
        Assert.Equal("203.0.113.0/24", Net.Network("203.0.113.9"));
        Assert.True(Blocks.ValidNet("203.0.113.0/24"));
        Assert.False(Blocks.ValidNet("10.0.0.0/8"));
        Assert.True(Net.InNet("2a06:98c0::/29", "2a06:98c7::1"));
        var g = Gate(new DracoOptions { Proxy = "xff" });
        Assert.Equal("203.0.113.5", g.Ip(Req(remote: "203.0.113.5", xff: "1.2.3.4")));
        Assert.Equal("198.51.100.7", g.Ip(Req(remote: "10.0.0.2", xff: "1.2.3.4, 198.51.100.7, 10.0.0.9")));
        Assert.Equal("198.51.100.20", g.Ip(Req(remote: "::ffff:198.51.100.20")));
    }

    [Fact]
    public void ReviewVectorsLikePhp()
    {
        var v = JsonDocument.Parse(File.ReadAllText(Path.Combine(WafTests.Root, "tests/vectors/review.json"))).RootElement;
        var secret = v.GetProperty("secret").GetString()!;
        var n = 0;
        foreach (var c in v.GetProperty("cases").EnumerateArray())
        {
            string S(string k) => c.GetProperty(k).GetString()!;
            var ts = c.GetProperty("ts").GetRawText();
            Assert.Equal(S("sealed"), Review.Seal(secret, S("ip"), ts, S("rule")));
            Assert.Equal(S("opened"), Review.OpenSealed(secret, S("ip"), ts, S("sealed")));
            Assert.Equal(S("sig"), Review.Sign(secret, S("ip"), S("rule"), ts));
            n++;
        }
        Assert.True(n >= 4);
    }

    [Fact]
    public void ReviewFlow()
    {
        var asked = new List<ReviewRequest>();
        var g = Gate(new DracoOptions { Waf = "block", Review = new() { Secret = "owner-secret-0123456789" } });
        g.OnReview = asked.Add;
        var (status, _, body) = g.Render(g.Decide(Attack())!);
        Assert.Equal(403, status);
        Assert.Contains("Ask for a review", body);
        Assert.DoesNotContain("traversal", body);
        var form = Hidden(body);
        form["draco_email"] = "Ana@Example.org";
        form["draco_message"] = "I was <b>reading</b>";
        form["draco_website"] = "";
        for (var i = 0; i < 5; i++) Assert.Equal(200, g.Decide(Req("POST", form: form))?.Status);
        Assert.Equal(3, asked.Count);
        Assert.Equal("ana@example.org", asked[0].Email);
        Assert.Equal("I was reading", asked[0].Message);
        Assert.Equal("traversal", asked[0].Rule);

        var bad = new Dictionary<string, string>(form) { ["draco_sig"] = new string('0', 64) };
        var none = new List<ReviewRequest>();
        var g2 = Gate(new DracoOptions { Waf = "block", Review = new() { Secret = "owner-secret-0123456789" } });
        g2.OnReview = none.Add;
        g2.Decide(Req("POST", form: bad));
        g2.Decide(Req("POST", form: form, remote: "203.0.113.7"));
        Assert.Empty(none);
    }

    [Fact]
    public void FirewallPaceAndBlocks()
    {
        var seen = new List<string>();
        var g = Gate(new DracoOptions { Waf = "block" });
        g.OnEvent = e => seen.Add(e.Endpoint);
        Assert.Null(g.Decide(Req(query: "q=european union select committee", ps: new[] { "european union select committee" })));
        Assert.Equal("traversal", g.Decide(Attack())?.Why);
        Assert.Equal("probe", g.Decide(Req(path: "/.env"))?.Why);
        for (var i = 0; i < 4; i++) g.Decide(Attack());
        Assert.True(g.Blocks.IsBlocked("198.51.100.20", Now0));
        Assert.Null(g.Decide(Req()));
        Assert.Equal("blocked", g.Decide(Req("POST", "/contact"))?.Why);
        Assert.Equal(new[] { "waf:traversal", "waf:probe" }, seen.Take(2));
        Assert.Null(Gate(new DracoOptions { Waf = "block", AdminIps = { "198.51.100.20" } }).Decide(Attack()));
        var except = Gate(new DracoOptions { Waf = "block", Except = { "webhooks" } });
        Assert.Null(except.Decide(Req(path: "/webhooks/stripe", query: "../../etc/passwd", ps: new[] { "../../etc/passwd" })));

        var p = Gate(new DracoOptions { Waf = "off", Pace = "block", RateIp = 10 });
        var got = Enumerable.Range(0, 12).Select(_ => p.Decide(Req(accept: "text/html"))).ToList();
        Assert.Null(got[9]);
        Assert.Equal(429, got[10]?.Status);
        Assert.True(got[10]!.Retry >= 1);
        Assert.Null(p.Decide(Req(accept: "application/json")));

        // A proved search engine is not held back; a pretender is.
        var c = Gate(new DracoOptions { Waf = "off", Pace = "block", RateIp = 10 });
        c.Resolver = new FakeDns();
        var bot = "Mozilla/5.0 (compatible; Googlebot/2.1)";
        Assert.All(Enumerable.Range(0, 15), _ => Assert.Null(c.Decide(Req(remote: "66.249.66.1", ua: bot))));
        Assert.Equal(429, Enumerable.Range(0, 15).Select(_ => c.Decide(Req(remote: "203.0.113.50", ua: bot))).ToList().Last()?.Status);
        Assert.Equal("y", c.Store.Get("draco:crawler:66.249.66.1:googlebot"));
    }

    private static byte[] GeoFixture(string built)
    {
        var v4 = new[] { ("0.0.0.0", "--"), ("1.0.0.0", "AU"), ("1.0.1.0", "CN"), ("1.0.4.0", "--"), ("203.0.113.0", "ES"), ("203.0.114.0", "--") };
        var v6 = new[] { ("::", "--"), ("2a00::", "ES"), ("2a01::", "--") };
        var o = new List<byte>(Encoding.ASCII.GetBytes("DRGEO1" + built));
        void U32(int x) => o.AddRange(new[] { (byte)(x >> 24), (byte)(x >> 16), (byte)(x >> 8), (byte)x });
        U32(v4.Length);
        U32(v6.Length);
        foreach (var (ip, cc) in v4.Concat(v6))
        {
            o.AddRange(Net.ToBytes(ip)!);
            o.AddRange(Encoding.ASCII.GetBytes(cc));
        }
        return o.ToArray();
    }

    [Fact]
    public void GeoLikeGeoPhp()
    {
        var dir = Directory.CreateTempSubdirectory("draco").FullName;
        var path = Path.Combine(dir, "g.bin");
        File.WriteAllBytes(path, GeoFixture("20261113"));
        using var geo = new GeoFile(path, update: false);
        var want = new Dictionary<string, string?>
        {
            ["1.0.0.200"] = "AU", ["1.0.3.255"] = "CN", ["1.0.4.0"] = null, ["::ffff:203.0.113.10"] = "ES",
            ["2a00:1450::1"] = "ES", ["2a01::1"] = null, ["x"] = null,
        };
        foreach (var (ip, cc) in want) Assert.True(cc == geo.Country(ip), ip);
        Assert.Equal("20261113", geo.Built());

        var g = Gate(new DracoOptions { Waf = "block", Geo = new() { Mode = "block", Countries = { "cn" }, Action = "block" } });
        g.Geo = geo;
        Assert.Equal("geo", g.Decide(Req(path: "/login", remote: "1.0.2.3"))?.Why);
        Assert.Null(g.Decide(Req(remote: "1.0.2.3")));

        // Download with the published checksum; a wrong one keeps the old file.
        var body = GeoFixture("20991231");
        var sum = Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant();
        using var srv = new Serve(r => r.Url!.AbsolutePath.EndsWith(".sha256") ? Encoding.ASCII.GetBytes(sum + "  draco-geo.bin\n") : body);
        using var dl = new GeoFile(Path.Combine(dir, "sub", "g.bin"), update: false) { Source = srv.Url + "/draco-geo.bin" };
        Assert.Equal("", dl.Refresh());
        Assert.Equal("20991231", dl.Built());
        sum = new string('0', 64);
        Assert.Equal("download", dl.Update());
        Assert.Equal("20991231", dl.Built());
    }

    [Fact]
    public void CrowdSecBridge()
    {
        Assert.Equal(14381, CrowdSec.Seconds("3h59m40.5s"));
        Assert.Equal(1, CrowdSec.Seconds("250ms"));
        Assert.Equal(0, CrowdSec.Seconds("-3s"));
        var answer = """
            {"new":[{"type":"ban","value":"198.51.100.66","duration":"4h","scenario":"crowdsecurity/http-probing"},
            {"type":"ban","value":"203.0.113.0/24","duration":"1h"},{"type":"ban","value":"10.0.0.0/8","duration":"1h"},
            {"type":"ban","value":"192.0.2.1","duration":"4h"},{"type":"captcha","value":"198.51.100.67","duration":"4h"}],"deleted":null}
            """;
        var asked = new List<string>();
        using var srv = new Serve(r =>
        {
            asked.Add(r.Url!.Query.TrimStart('?') + " " + r.Headers["X-Api-Key"]);
            return Encoding.UTF8.GetBytes(answer);
        });
        var g = Gate(new DracoOptions { Waf = "block", AdminIps = { "192.0.2.1" }, CrowdSec = new() { Url = srv.Url, ApiKey = "k3y" } });
        g.Blocks.Add("203.0.113.200", 7, "Manual", false, Now0);
        Assert.Equal((2, 0, ""), g.CrowdSec!.Sync());
        Assert.Equal("startup=true&scopes=ip,range k3y", asked[0]);
        Assert.Equal("blocked", g.Decide(Req(path: "/login", remote: "198.51.100.66"))?.Why);
        Assert.Equal("blocked", g.Decide(Req("POST", remote: "203.0.113.9"))?.Why);
        Assert.Null(g.Decide(Req(path: "/login", remote: "10.1.2.3")));
        answer = """{"new":[],"deleted":[{"value":"198.51.100.66"},{"value":"203.0.113.200"}]}""";
        Assert.Equal(1, g.CrowdSec.Sync().Removed);
        Assert.True(g.Blocks.IsBlocked("203.0.113.200", Now0));
        Assert.False(g.Blocks.IsBlocked("198.51.100.66", Now0));
        var line = CrowdSec.Line(new Event(1_800_000_000, "198.51.100.9", "", "waf:sqli", "bot", new[] { "waf_sqli" }, "curl/8", ""), "shop.example");
        Assert.Equal("""{"endpoint":"waf:sqli","host":"shop.example","ip":"198.51.100.9","reasons":"waf_sqli","time":"2027-01-15T08:00:00Z","user_agent":"curl/8","verdict":"bot"}""", line);
    }

    [Fact]
    public async Task AspNetCoreMiddleware()
    {
        var asked = new List<string>();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDracoInsomnis(o =>
        {
            o.Waf = "block";
            o.Headers = true;
            o.Review.Secret = "owner-secret-0123456789";
        });
        await using var app = builder.Build();
        var gate = app.Services.GetRequiredService<Gatekeeper>();
        gate.Resolver = new NoDns();
        gate.OnReview = r => asked.Add(r.Email);
        app.UseDracoInsomnis();
        app.MapGet("/", () => "page");
        app.MapGet("/own", (HttpContext c) => { c.Response.Headers.XFrameOptions = "DENY"; return "own"; });
        app.MapGet("/search", () => "results");
        app.MapPost("/search", () => "results");
        app.MapPost("/echo", async (HttpRequest r) => "name=" + (await r.ReadFormAsync())["name"]);
        await app.StartAsync();
        var http = app.GetTestClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 Chrome/131.0");

        var res = await http.GetAsync("/");
        Assert.Equal(200, (int)res.StatusCode);
        Assert.Equal("nosniff", res.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", (await http.GetAsync("/own")).Headers.GetValues("X-Frame-Options").Single());

        const string sqli = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
        res = await http.GetAsync(sqli);
        var page = await res.Content.ReadAsStringAsync();
        Assert.Equal(403, (int)res.StatusCode);
        Assert.DoesNotContain("sqli", page);

        var form = (Dictionary<string, string> d) => new FormUrlEncodedContent(d);
        Assert.Equal(403, (int)(await http.PostAsync("/echo", form(new() { ["message"] = "x'; DROP TABLE users; --" }))).StatusCode);
        Assert.Equal(403, (int)(await http.PostAsync("/echo", new StringContent("{\"q\": \"' OR '1'='1\"}", Encoding.UTF8, "application/json"))).StatusCode);
        var ok = await http.PostAsync("/echo", form(new() { ["name"] = "Ana" }));
        Assert.Equal("name=Ana", await ok.Content.ReadAsStringAsync());

        var review = Hidden(page);
        review["draco_email"] = "ana@example.org";
        review["draco_message"] = "I was searching";
        var thanks = await http.PostAsync(sqli, form(review));
        Assert.Equal(200, (int)thanks.StatusCode);
        Assert.Equal(new[] { "ana@example.org" }, asked);
        await app.StopAsync();
    }
}
