using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>
/// Counters, the block list and verified crawlers. The keys are the same as in the JavaScript, Python,
/// Go and Ruby editions, so one Redis can serve apps in several languages.
/// </summary>
public interface IStore
{
    /// <summary>Adds one and returns the new value; the counter disappears after ttl seconds.</summary>
    long Bump(string key, int ttl);
    string? Get(string key);
    /// <summary>Keeps a value for ttl seconds; 0 = for good.</summary>
    void Set(string key, string value, int ttl);
    void Delete(string key);
}

/// <summary>One process; thread-safe; lost on restart.</summary>
public sealed class MemoryStore : IStore
{
    private readonly Dictionary<string, (string Value, double Until)> _items = new();
    private readonly object _lock = new();
    private readonly Func<double> _now;

    public MemoryStore(Func<double>? now = null) => _now = now ?? Clock.Now;

    private (string Value, double Until)? Live(string key)
    {
        if (!_items.TryGetValue(key, out var it)) return null;
        if (it.Until != 0 && it.Until <= _now()) { _items.Remove(key); return null; }
        return it;
    }

    private void Sweep()
    {
        if (_items.Count < 50_000) return;
        foreach (var k in _items.Keys.ToList()) Live(k);
    }

    public long Bump(string key, int ttl)
    {
        lock (_lock)
        {
            var it = Live(key);
            var n = it is null ? 1 : long.Parse(it.Value.Value) + 1;
            _items[key] = (n.ToString(), it is null ? _now() + ttl : it.Value.Until);
            Sweep();
            return n;
        }
    }

    public string? Get(string key) { lock (_lock) return Live(key)?.Value; }

    public void Set(string key, string value, int ttl)
    {
        lock (_lock)
        {
            _items[key] = (value, ttl == 0 ? 0 : _now() + ttl);
            Sweep();
        }
    }

    public void Delete(string key) { lock (_lock) _items.Remove(key); }
}

internal static class Clock
{
    public static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;
}

/// <summary>A line of evidence: the same fields as the PHP events table and the other editions.</summary>
public sealed record Event(long Time, string Ip, string Remote, string Endpoint, string Verdict, IReadOnlyList<string> Reasons,
    string UserAgent, string Detail, string? Email = null);

/// <summary>One blocked address or network.</summary>
public sealed record BlockEntry(
    [property: JsonPropertyName("value")] string Value,
    [property: JsonPropertyName("until")] long Until,
    [property: JsonPropertyName("reason")] string Reason,
    [property: JsonPropertyName("automatic")] bool Automatic);

/// <summary>The block list on any store: one key per address, one key holding the blocked networks.</summary>
public sealed class Blocks
{
    public const long Forever = 253402300799;
    private readonly IStore _store;

    public Blocks(IStore store) => _store = store;

    /// <summary>A network may be blocked when it is no wider than /16 (IPv4) or /32 (IPv6).</summary>
    public static bool ValidNet(string cidr)
    {
        var m = Regex.Match(cidr.Trim(), "^([0-9a-fA-F.:]+)/([0-9]+)$");
        if (!m.Success) return false;
        var b = Net.ToBytes(m.Groups[1].Value);
        var bits = int.Parse(m.Groups[2].Value);
        if (b is null) return false;
        return b.Length == 16 ? bits is >= 32 and <= 128 : bits is >= 16 and <= 32;
    }

    public bool Add(string value, int days, string reason, bool automatic, double now) =>
        Write(new BlockEntry(value, days == 0 ? Forever : (long)now + days * 86400L, reason, automatic), now, days == 0 ? 0 : days * 86400);

    public bool AddUntil(string value, long until, string reason, bool automatic, double now)
    {
        var ttl = (int)(until - (long)now);
        return ttl > 0 && Write(new BlockEntry(value, until, reason, automatic), now, ttl);
    }

    public void Remove(string value, double now)
    {
        if (value.Contains('/'))
            _store.Set("draco:nets", JsonSerializer.Serialize(Nets(now).Where(n => n.Value != value).ToList()), 0);
        else
            _store.Delete("draco:block:" + value);
    }

    public List<BlockEntry> Nets(double now)
    {
        try
        {
            var all = JsonSerializer.Deserialize<List<BlockEntry>>(_store.Get("draco:nets") ?? "[]") ?? new();
            return all.Where(n => n.Until > now).ToList();
        }
        catch (JsonException) { return new(); }
    }

    public BlockEntry? Entry(string value, double now)
    {
        if (value.Contains('/')) return Nets(now).FirstOrDefault(n => n.Value == value);
        var raw = _store.Get("draco:block:" + value);
        try { return raw is null ? null : JsonSerializer.Deserialize<BlockEntry>(raw); }
        catch (JsonException) { return null; }
    }

    public bool IsBlocked(string ip, double now) =>
        _store.Get("draco:block:" + ip) is not null || Nets(now).Any(n => Net.InNet(n.Value, ip));

    private bool Write(BlockEntry e, double now, int ttl)
    {
        if (e.Value.Contains('/'))
        {
            if (!ValidNet(e.Value)) return false;
            var nets = Nets(now).Where(n => n.Value != e.Value).Append(e).ToList();
            _store.Set("draco:nets", JsonSerializer.Serialize(nets), 0);
            return true;
        }
        _store.Set("draco:block:" + e.Value, JsonSerializer.Serialize(e), ttl);
        return true;
    }
}
