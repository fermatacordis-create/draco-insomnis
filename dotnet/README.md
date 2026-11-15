# Draco Insomnis for .NET

The Draco Insomnis firewall as **ASP.NET Core middleware**, with **no dependencies** beyond ASP.NET
Core itself: minimal APIs, MVC, Razor Pages, Blazor Server and any Kestrel app. Same signatures and
limits as the WordPress, CMS, server, JavaScript, Python, Go and Ruby editions; the .NET engine runs the
same shared test cases (`tests/vectors`).

```csharp
// Program.cs
builder.Services.AddDracoInsomnis(o => builder.Configuration.GetSection("DracoInsomnis").Bind(o));
var app = builder.Build();
app.UseDracoInsomnis(); // first, before routing, static files and authentication
```

```json
// appsettings.json
"DracoInsomnis": { "Waf": "block", "Pace": "block", "Headers": true, "LogEvents": true }
```

Or in code: `app.UseDracoInsomnis(o => { o.Waf = "block"; o.Headers = true; });`

.NET 8 or newer. `dotnet add package DracoInsomnis --source ./folder-with-the-nupkg` (from the release).

What it does, in this order: blocked addresses may read but not post or open sensitive pages
(ASP.NET Core Identity's `/Identity/Account/Login` and `/Identity/Account/Register` included); the
country filter (behind Cloudflare from its header, otherwise `Geo.File`, a local list that downloads
itself and is checked against its published SHA-256); the firewall signatures (log or block; 5 attacks
in 10 minutes block the address for 7 days); the anti-copy pace limit (HTML pages only; Google, Bing,
Apple and Yandex once the reverse DNS proves them). Forms and JSON bodies up to 64 KB are read once and
rewound, so the app reads them unchanged. Security headers never replace the app's own. If Draco itself
fails, the request goes through.

| Option | Default | |
| --- | --- | --- |
| `Waf` | `"log"` | `"off"`, `"log"` or `"block"` |
| `Pace` | `"off"` | `"off"`, `"log"` or `"block"`; `RateIp`, `RateNet` (at least 10) |
| `Proxy`, `TrustedProxies` | connection | `"cf"` or `"xff"`, and who may set them |
| `AdminIps`, `Except`, `Sensitive` | | never inspected; path prefixes never inspected; extra sensitive endings |
| `Headers`, `Hsts` | off | nosniff, frames, referrer, permissions; HSTS over HTTPS |
| `Geo` | off | `{ Mode: "block" or "allow", Countries: [...], Action: "log" or "block", Scope: "sensitive" or "site", File: "path" }` |
| `Review` | off | `{ Secret: "16+ characters" }`; requests reach `OnReview` (and the log) |
| `CrowdSec` | off | `{ Url: "http://127.0.0.1:8080", ApiKey: "..." }` |
| `LogEvents` | off | every line of evidence as JSON to the `DracoInsomnis` logger |
| `Texts` | English | the page texts, by key |

The counters and the block list live in memory (one process). For several servers, implement
`IStore` (`Bump`, `Get`, `Set`, `Delete`) on Redis and pass it to `AddDracoInsomnis(configure, store)`:
the keys are the same as in the other editions, so one Redis can serve apps in several languages.

`Gatekeeper` (from the services, or `new Gatekeeper(options, store)` for `app.UseDracoInsomnis(gate)`)
has `OnEvent`, `OnReview`, `Blocks` (add, remove, list) and `CrowdSec.Sync()`.

Tests: `dotnet test` in `DracoInsomnis.Tests` (the engine, the shared vectors and the middleware in a
test host), and `e2e/` (real Kestrel apps, minimal API and MVC, from the built package).
