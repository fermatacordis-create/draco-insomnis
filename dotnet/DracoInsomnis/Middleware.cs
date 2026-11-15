using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace DracoInsomnis;

/// <summary>Draco as ASP.NET Core middleware: it answers first; the app only sees what it lets through.</summary>
public sealed class DracoMiddleware
{
    private const int MaxBody = 65536;
    private readonly RequestDelegate _next;
    private readonly Gatekeeper _gate;
    private readonly ILogger? _log;

    public DracoMiddleware(RequestDelegate next, Gatekeeper gate, ILoggerFactory? logs = null)
    {
        _next = next;
        _gate = gate;
        _log = logs?.CreateLogger("DracoInsomnis");
    }

    /// <summary>
    /// Reads a request the way Draco needs it. Forms and JSON bodies up to 64 KB are read once and
    /// rewound, so the app reads them unchanged.
    /// </summary>
    public static async Task<DracoRequest> ReadAsync(HttpRequest r)
    {
        var path = (r.PathBase + r.Path).Value ?? "/";
        if (path.Length == 0) path = "/";
        var raw = r.QueryString.HasValue ? r.QueryString.Value![1..] : "";
        var query = WebUtility.UrlDecode(raw);
        var parameters = Waf.Flatten(r.Query);
        Dictionary<string, string>? form = null;
        var kind = (r.ContentType ?? "").ToLowerInvariant();
        if (r.Method is "POST" or "PUT" or "PATCH" && r.ContentLength is >= 0 and <= MaxBody
            && (kind.Contains("json") || kind.Contains("x-www-form-urlencoded")))
        {
            r.EnableBuffering(MaxBody + 1);
            var buffer = new byte[(int)r.ContentLength.Value];
            var read = 0;
            while (read < buffer.Length)
            {
                var n = await r.Body.ReadAsync(buffer.AsMemory(read));
                if (n == 0) break;
                read += n;
            }
            r.Body.Position = 0;
            var body = System.Text.Encoding.UTF8.GetString(buffer, 0, read);
            if (kind.Contains("json"))
            {
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    parameters.AddRange(Waf.Flatten(doc.RootElement));
                    if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    {
                        form = new();
                        foreach (var p in doc.RootElement.EnumerateObject())
                            if (p.Value.ValueKind == JsonValueKind.String) form[p.Name] = p.Value.GetString()!;
                    }
                }
                catch (JsonException) { parameters.Add(body); }
            }
            else
            {
                var values = QueryHelpers.ParseQuery(body);
                parameters.AddRange(Waf.Flatten(values));
                form = values.Where(v => v.Value.Count > 0).ToDictionary(v => v.Key, v => v.Value[^1] ?? "");
            }
        }
        var h = r.Headers;
        var remote = r.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
        // Cloudflare's country header, only when the connection really comes from Cloudflare.
        var country = Net.Contains(Net.Cloudflare, Gatekeeper.Remote(remote)) ? h["CF-IPCountry"].ToString() : "";
        return new DracoRequest
        {
            Method = r.Method.ToUpperInvariant(), Path = path, Query = query, Params = parameters,
            UserAgent = h.UserAgent.ToString(), RemoteAddr = remote, Country = country,
            CfConnectingIp = h["CF-Connecting-IP"].ToString(), ForwardedFor = string.Join(", ", h["X-Forwarded-For"].ToArray()),
            Accept = h.Accept.ToString(), Ajax = string.Equals(h.XRequestedWith, "XMLHttpRequest", StringComparison.OrdinalIgnoreCase),
            Form = form ?? new Dictionary<string, string>(),
        };
    }

    public async Task InvokeAsync(HttpContext context)
    {
        Answer? answer = null;
        try { answer = _gate.Decide(await ReadAsync(context.Request)); }
        catch (Exception e)
        {
            // If Draco itself fails, the request goes through.
            _log?.LogWarning(e, "Draco Insomnis could not inspect the request; it was let through");
        }
        if (answer is not null)
        {
            var (status, headers, body) = _gate.Render(answer);
            context.Response.StatusCode = status;
            foreach (var (k, v) in headers) context.Response.Headers[k] = v;
            await context.Response.WriteAsync(body);
            return;
        }
        var extra = _gate.SecurityHeaders(context.Request.IsHttps);
        if (extra.Count > 0)
            // Added when the answer starts, after the app set its own, so the app's always win.
            context.Response.OnStarting(() =>
            {
                foreach (var (k, v) in extra)
                    if (!context.Response.Headers.ContainsKey(k)) context.Response.Headers[k] = v;
                return Task.CompletedTask;
            });
        await _next(context);
    }
}

public static class DracoExtensions
{
    /// <summary>Registers one shared gatekeeper; options bind like any other (e.g. from the "DracoInsomnis" section).</summary>
    public static IServiceCollection AddDracoInsomnis(this IServiceCollection services, Action<DracoOptions>? configure = null, IStore? store = null)
    {
        var options = new DracoOptions();
        configure?.Invoke(options);
        return services.AddSingleton(sp => Create(options, store, sp.GetService<ILoggerFactory>()));
    }

    /// <summary>Puts Draco first in the pipeline: app.UseDracoInsomnis() after AddDracoInsomnis, or with options here.</summary>
    public static IApplicationBuilder UseDracoInsomnis(this IApplicationBuilder app, Action<DracoOptions>? configure = null, IStore? store = null)
    {
        var gate = configure is null ? app.ApplicationServices.GetService<Gatekeeper>() : null;
        if (gate is null)
        {
            var options = new DracoOptions();
            configure?.Invoke(options);
            gate = Create(options, store, app.ApplicationServices.GetService<ILoggerFactory>());
        }
        return app.UseDracoInsomnis(gate);
    }

    public static IApplicationBuilder UseDracoInsomnis(this IApplicationBuilder app, Gatekeeper gate) =>
        app.UseMiddleware<DracoMiddleware>(gate);

    private static Gatekeeper Create(DracoOptions options, IStore? store, ILoggerFactory? logs)
    {
        var gate = new Gatekeeper(options, store);
        if (options.LogEvents && logs is not null) gate.LogTo(logs.CreateLogger("DracoInsomnis"));
        return gate;
    }

    /// <summary>Writes every line of evidence and review request as JSON to the log.</summary>
    public static void LogTo(this Gatekeeper gate, ILogger log)
    {
        gate.OnEvent = e => log.LogInformation("{Line}", JsonSerializer.Serialize(new { draco = "event", @event = e }));
        gate.OnReview = r => log.LogInformation("{Line}", JsonSerializer.Serialize(new { draco = "review", review = r }));
    }
}
