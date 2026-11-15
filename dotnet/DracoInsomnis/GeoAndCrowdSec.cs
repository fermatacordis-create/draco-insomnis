using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>
/// The visitor's country without Cloudflare: the same file and binary search as src/Core/Geo.php
/// (DB-IP Lite, CC BY 4.0, built monthly by this project). Local: nothing is sent anywhere.
/// </summary>
public sealed class GeoFile : IDisposable
{
    public const string DefaultSource = "https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin";
    private const int Header = 22;
    private readonly object _lock = new();
    private FileStream? _file;
    private (long V4, long V6, string Built) _info;
    private DateTime _tried = DateTime.MinValue;
    private readonly Timer? _timer;

    public string Path { get; }
    public string Source { get; init; } = DefaultSource;

    /// <param name="path">Where the list is kept.</param>
    /// <param name="update">Download the list when missing or older than 35 days, now and then daily.</param>
    public GeoFile(string path, bool update = true)
    {
        Path = path;
        if (update) _timer = new Timer(_ => { try { Refresh(); } catch { /* the country list never breaks the app */ } }, null, TimeSpan.Zero, TimeSpan.FromDays(1));
    }

    internal static (long, long, string)? ReadHead(byte[] head, long size)
    {
        if (head.Length < Header || System.Text.Encoding.ASCII.GetString(head, 0, 6) != "DRGEO1") return null;
        long v4 = (uint)(head[14] << 24 | head[15] << 16 | head[16] << 8 | head[17]);
        long v6 = (uint)(head[18] << 24 | head[19] << 16 | head[20] << 8 | head[21]);
        return size == Header + v4 * 6 + v6 * 18 ? (v4, v6, System.Text.Encoding.ASCII.GetString(head, 6, 8)) : null;
    }

    private bool Open()
    {
        if (_file is not null) return true;
        if (DateTime.UtcNow - _tried < TimeSpan.FromMinutes(1)) return false;
        _tried = DateTime.UtcNow;
        try
        {
            var f = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            var head = new byte[Header];
            if (f.Read(head, 0, Header) != Header || ReadHead(head, f.Length) is not { } info) { f.Dispose(); return false; }
            _file = f;
            _info = info;
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    public string? Country(string ip)
    {
        var addr = Net.ToBytes(Net.Unmap(ip.Trim()));
        if (addr is null) return null;
        lock (_lock)
        {
            if (!Open()) return null;
            var is4 = addr.Length == 4;
            long count = is4 ? _info.V4 : _info.V6, size = is4 ? 6 : 18, width = size - 2, @base = Header + (is4 ? 0 : _info.V4 * 6);
            var buf = new byte[width];
            long lo = 0, hi = count - 1, found = -1;
            while (lo <= hi)
            {
                var mid = (lo + hi) / 2;
                _file!.Seek(@base + mid * size, SeekOrigin.Begin);
                _file.ReadExactly(buf);
                var cmp = buf.AsSpan().SequenceCompareTo(addr);
                if (cmp <= 0) { found = mid; lo = mid + 1; } else hi = mid - 1;
            }
            if (found < 0) return null;
            _file!.Seek(@base + found * size + width, SeekOrigin.Begin);
            var cc = new byte[2];
            _file.ReadExactly(cc);
            return cc[0] is >= (byte)'A' and <= (byte)'Z' && cc[1] is >= (byte)'A' and <= (byte)'Z' ? System.Text.Encoding.ASCII.GetString(cc) : null;
        }
    }

    public string Built() { lock (_lock) return Open() ? _info.Built : ""; }

    public bool Stale() => !DateTime.TryParseExact(Built(), "yyyyMMdd", null, System.Globalization.DateTimeStyles.AssumeUniversal, out var t)
        || DateTime.UtcNow - t.ToUniversalTime() > TimeSpan.FromDays(35);

    public string Refresh() => Stale() ? Update() : "";

    /// <summary>Downloads the list, checks the published SHA-256, only then replaces the old file.</summary>
    public string Update()
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromMinutes(2) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Draco-Insomnis");
        byte[]? Get(string url) { try { return http.GetByteArrayAsync(url).GetAwaiter().GetResult(); } catch { return null; } }
        var sum = Get(Source + ".sha256");
        var want = sum is null ? "" : System.Text.Encoding.ASCII.GetString(sum).Trim().ToLowerInvariant();
        if (want.Length < 64 || !Regex.IsMatch(want[..64], "^[0-9a-f]{64}$")) return "checksum";
        var body = Get(Source);
        if (body is null || Convert.ToHexString(SHA256.HashData(body)).ToLowerInvariant() != want[..64]) return "download";
        if (body.Length < Header || ReadHead(body[..Header], body.Length) is null) return "format";
        var part = Path + ".part";
        try
        {
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(Path))!);
            File.WriteAllBytes(part, body);
            File.Move(part, Path, true);
        }
        catch (Exception)
        {
            try { File.Delete(part); } catch { /* nothing to remove */ }
            return "folder";
        }
        Close();
        return "";
    }

    public void Close() { lock (_lock) { _file?.Dispose(); _file = null; _tried = DateTime.MinValue; } }

    public void Dispose() { _timer?.Dispose(); Close(); }
}

/// <summary>
/// Draco as a bouncer of the owner's own CrowdSec Local API, like server/src/CrowdSec.php: bans join the
/// block list, synced in the background at most once a minute; admin addresses are never imported and
/// blocks the owner set are never lifted by it.
/// </summary>
public sealed class CrowdSec
{
    private readonly string _url, _key;
    private readonly IStore _store;
    private readonly Blocks _blocks;
    private readonly Func<IReadOnlyCollection<string>> _admins;
    private readonly Func<double> _now;
    private readonly SemaphoreSlim _running = new(1, 1);
    private static readonly HttpClient Http = new();

    public CrowdSec(string url, string apiKey, IStore store, Func<IReadOnlyCollection<string>> admins, Func<double> now)
    {
        _url = url.TrimEnd('/');
        _key = apiKey;
        _store = store;
        _blocks = new Blocks(store);
        _admins = admins;
        _now = now;
    }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(2);

    public static int Seconds(string duration)
    {
        if (duration.Trim().StartsWith('-')) return 0;
        var m = Regex.Matches(duration, @"([0-9]+(?:\.[0-9]+)?)(h|ms|m|s)");
        if (m.Count == 0) return 0;
        double total = 0;
        foreach (Match x in m)
            total += double.Parse(x.Groups[1].Value, System.Globalization.CultureInfo.InvariantCulture)
                * x.Groups[2].Value switch { "h" => 3600, "m" => 60, "s" => 1, _ => 0.001 };
        return (int)Math.Ceiling(total);
    }

    public static string Line(Event e, string host = "") => JsonSerializer.Serialize(new SortedDictionary<string, string>(StringComparer.Ordinal)
    {
        ["time"] = DateTimeOffset.FromUnixTimeSeconds(e.Time).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        ["ip"] = e.Ip, ["host"] = host, ["endpoint"] = e.Endpoint, ["verdict"] = e.Verdict,
        ["reasons"] = string.Join(',', e.Reasons), ["user_agent"] = e.UserAgent,
    });

    /// <summary>One sync a minute at most (shared through the store), in the background.</summary>
    public void MaybeSync()
    {
        if (_running.CurrentCount == 0 || _store.Bump("draco:crowdsec:sync", 60) != 1) return;
        _ = Task.Run(Sync);
    }

    public (int Added, int Removed, string Error) Sync()
    {
        _running.Wait();
        try { return Pull(); }
        finally { _running.Release(); }
    }

    private (int, int, string) Pull()
    {
        _store.Set("draco:crowdsec:sync", "1", 60);
        int added = 0, removed = 0;
        var error = "";
        var startup = _store.Get("draco:crowdsec:started") is null;
        JsonElement data = default;
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, $"{_url}/v1/decisions/stream?startup={(startup ? "true" : "false")}&scopes=ip,range");
            req.Headers.Add("X-Api-Key", _key);
            req.Headers.UserAgent.ParseAdd("Draco-Insomnis");
            using var cts = new CancellationTokenSource(Timeout);
            using var res = Http.Send(req, cts.Token);
            if ((int)res.StatusCode != 200) error = $"HTTP {(int)res.StatusCode}";
            else data = JsonDocument.Parse(res.Content.ReadAsStream()).RootElement;
        }
        catch (JsonException) { error = "not JSON"; }
        catch (Exception) { error = "no answer"; }
        var now = _now();
        if (error.Length > 0 || data.ValueKind != JsonValueKind.Object)
        {
            if (error.Length == 0) error = "not JSON";
            _store.Set("draco:crowdsec:last", $"{(long)now}|{error}", 86400 * 30);
            return (0, 0, error);
        }
        List<string> imported;
        try { imported = JsonSerializer.Deserialize<List<string>>(_store.Get("draco:crowdsec:imported") ?? "[]") ?? new(); }
        catch (JsonException) { imported = new(); }
        if (startup)
        {
            removed += imported.Count(v => RemoveIfOurs(v, now));
            imported.Clear();
        }
        static string S(JsonElement e, string k) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(k, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
        if (data.TryGetProperty("deleted", out var deleted) && deleted.ValueKind == JsonValueKind.Array)
            foreach (var d in deleted.EnumerateArray())
            {
                var value = S(d, "value").ToLowerInvariant();
                if (value.Length > 0 && imported.Contains(value) && RemoveIfOurs(value, now)) { removed++; imported.Remove(value); }
            }
        var admins = _admins();
        if (data.TryGetProperty("new", out var news) && news.ValueKind == JsonValueKind.Array)
            foreach (var d in news.EnumerateArray())
            {
                if (S(d, "type").ToLowerInvariant() != "ban") continue;
                var value = S(d, "value").Trim().ToLowerInvariant();
                var ttl = Seconds(S(d, "duration"));
                var allowed = value.Contains('/') ? Blocks.ValidNet(value) : Net.IsIp(value);
                if (ttl <= 0 || !allowed || admins.Contains(value)) continue;
                var scenario = S(d, "scenario");
                if (scenario.Length == 0) scenario = S(d, "origin");
                if (scenario.Length > 150) scenario = scenario[..150];
                if (!_blocks.AddUntil(value, (long)now + ttl, "CrowdSec: " + scenario, true, now)) continue;
                added++;
                if (!imported.Contains(value)) imported.Add(value);
            }
        _store.Set("draco:crowdsec:imported", JsonSerializer.Serialize(imported.TakeLast(20000)), 0);
        _store.Set("draco:crowdsec:started", "1", 86400 * 365);
        _store.Set("draco:crowdsec:last", $"{(long)now}|ok +{added} -{removed}", 86400 * 30);
        return (added, removed, "");
    }

    private bool RemoveIfOurs(string value, double now)
    {
        var e = _blocks.Entry(value, now);
        if (e is null || !e.Reason.StartsWith("CrowdSec")) return false;
        _blocks.Remove(value, now);
        return true;
    }
}
