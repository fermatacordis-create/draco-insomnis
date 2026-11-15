// The middleware in real ASP.NET Core apps on Kestrel: a minimal API configured from appsettings, and
// MVC controllers configured in code. Real sockets, real HTTP.
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using DracoInsomnis;
using Microsoft.AspNetCore.Mvc;

const string Secret = "owner-secret-0123456789";
const string Ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36";
const string Attack = "/search?q=1%27%20union%20select%20password%20from%20users--%20";
var fails = 0;
void Check(string name, bool ok)
{
    Console.WriteLine($"{(ok ? "ok  " : "FAIL")} - {name}");
    if (!ok) fails++;
}

async Task<(WebApplication App, string Url, List<string> Asked)> Minimal()
{
    var builder = WebApplication.CreateBuilder();
    builder.Logging.ClearProviders();
    builder.WebHost.UseUrls("http://127.0.0.1:0");
    // As a user writes it in appsettings.json: "DracoInsomnis": { "Waf": "block", ... }
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["DracoInsomnis:Waf"] = "block", ["DracoInsomnis:Headers"] = "true", ["DracoInsomnis:Review:Secret"] = Secret,
    });
    builder.Services.AddDracoInsomnis(o => builder.Configuration.GetSection("DracoInsomnis").Bind(o));
    var app = builder.Build();
    var asked = new List<string>();
    var gate = app.Services.GetRequiredService<Gatekeeper>();
    gate.Resolver = null;
    gate.OnReview = r => asked.Add(r.Email);
    app.UseDracoInsomnis();
    app.MapGet("/", () => "page");
    app.MapGet("/own", (HttpContext c) => { c.Response.Headers.XFrameOptions = "DENY"; return "own"; });
    app.MapPost("/echo", async (HttpRequest r) => "name=" + (await r.ReadFormAsync())["name"]);
    await app.StartAsync();
    return (app, app.Urls.First(), asked);
}

async Task<(WebApplication App, string Url, List<string> Asked)> Mvc()
{
    var builder = WebApplication.CreateBuilder();
    builder.Logging.ClearProviders();
    builder.WebHost.UseUrls("http://127.0.0.1:0");
    builder.Services.AddControllers();
    var app = builder.Build();
    var asked = new List<string>();
    // A gatekeeper made in code (shared store, own callbacks).
    var gate = new Gatekeeper(new DracoOptions { Waf = "block", Headers = true, Review = new() { Secret = Secret } }, new MemoryStore())
    {
        Resolver = null,
        OnReview = r => asked.Add(r.Email),
    };
    app.UseDracoInsomnis(gate);
    app.MapControllers();
    await app.StartAsync();
    return (app, app.Urls.First(), asked);
}

using var http = new HttpClient();
http.DefaultRequestHeaders.UserAgent.ParseAdd(Ua);
foreach (var (name, start) in new (string, Func<Task<(WebApplication, string, List<string>)>>)[] { ("minimal api", Minimal), ("mvc", Mvc) })
{
    var (app, url, asked) = await start();
    async Task<HttpResponseMessage> Post(string path, HttpContent body) => await http.PostAsync(url + path, body);
    var res = await http.GetAsync(url + "/");
    Check($"{name}: an ordinary page passes", res.StatusCode == HttpStatusCode.OK);
    Check($"{name}: security headers", res.Headers.TryGetValues("X-Content-Type-Options", out var v) && v.Single() == "nosniff");
    var own = await http.GetAsync(url + "/own");
    Check($"{name}: the app's own header wins", own.Headers.TryGetValues("X-Frame-Options", out var f) && f.Single() == "DENY");
    var blocked = await http.GetAsync(url + Attack);
    var page = await blocked.Content.ReadAsStringAsync();
    Check($"{name}: SQL injection gets 403", blocked.StatusCode == HttpStatusCode.Forbidden);
    Check($"{name}: the page never names the rule", !page.Contains("sqli"));
    Check($"{name}: .env probe gets 403", (await http.GetAsync(url + "/.env")).StatusCode == HttpStatusCode.Forbidden);
    Check($"{name}: a posted form is inspected", (await Post("/contact",
        new FormUrlEncodedContent(new Dictionary<string, string> { ["message"] = "x'; DROP TABLE users; --" }))).StatusCode == HttpStatusCode.Forbidden);
    Check($"{name}: a JSON body is inspected", (await Post("/api",
        new StringContent("{\"q\": \"' OR '1'='1\"}", Encoding.UTF8, "application/json"))).StatusCode == HttpStatusCode.Forbidden);
    var echo = await Post("/echo", new FormUrlEncodedContent(new Dictionary<string, string> { ["name"] = "Ana" }));
    Check($"{name}: the app still reads the body", echo.StatusCode == HttpStatusCode.OK && await echo.Content.ReadAsStringAsync() == "name=Ana");
    var fields = Regex.Matches(page, "<input type=\"hidden\" name=\"([a-z_]+)\" value=\"([^\"]*)\">")
        .ToDictionary(m => m.Groups[1].Value, m => WebUtility.HtmlDecode(m.Groups[2].Value));
    fields["draco_email"] = "ana@example.org";
    fields["draco_message"] = "I was searching";
    fields["draco_website"] = "";
    var thanks = await Post(Attack, new FormUrlEncodedContent(fields));
    Check($"{name}: the review request is thanked", thanks.StatusCode == HttpStatusCode.OK && (await thanks.Content.ReadAsStringAsync()).Contains("Request sent"));
    Check($"{name}: and reaches the owner", asked.SequenceEqual(new[] { "ana@example.org" }));
    await app.StopAsync();
}
Console.WriteLine(fails == 0 ? $"all passed (Draco Insomnis {Gatekeeper.Version})" : $"{fails} failed");
return fails == 0 ? 0 : 1;

public class PagesController : Controller
{

    [HttpGet("/")] public string Home() => "page";

    [HttpGet("/own")]
    public string Own()
    {
        Response.Headers.XFrameOptions = "DENY";
        return "own";
    }

    [HttpPost("/echo"), IgnoreAntiforgeryToken]
    public string Echo([FromForm] string name) => "name=" + name;
}
