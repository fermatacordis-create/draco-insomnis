using System.Text.Json;
using Xunit;

namespace DracoInsomnis.Tests;

/// <summary>The shared firewall cases (tests/vectors/waf.json): every edition must agree.</summary>
public class WafTests
{
    internal static string Root => Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../.."));

    private static JsonElement Vectors() => JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "tests/vectors/waf.json"))).RootElement;

    private static string? Run(JsonElement r) => Waf.Inspect(
        r.TryGetProperty("path", out var p) ? p.GetString()! : "",
        r.TryGetProperty("query", out var q) ? q.GetString()! : "",
        r.TryGetProperty("params", out var ps) ? ps.EnumerateArray().Select(x => x.GetString()!).ToList() : new List<string>(),
        r.TryGetProperty("userAgent", out var ua) ? ua.GetString()! : "");

    [Fact]
    public void AttacksGetTheSameRule()
    {
        var n = 0;
        foreach (var c in Vectors().GetProperty("attacks").EnumerateArray())
        {
            Assert.True(c.GetProperty("rule").GetString() == Run(c.GetProperty("request")), c.GetProperty("name").GetString());
            n++;
        }
        Assert.True(n >= 30);
    }

    [Fact]
    public void OrdinaryRequestsPass()
    {
        foreach (var c in Vectors().GetProperty("ordinary").EnumerateArray())
            Assert.True(Run(c.GetProperty("request")) is null, c.GetProperty("name").GetString());
    }

    [Fact]
    public void ClassesAreAsciiLikePhp()
    {
        // Byte-wise like PHP, "ñ" is not a word character, so there is a word boundary next to it.
        // With .NET's Unicode classes neither of these would match.
        Assert.Equal("sqli", Waf.Inspect("/", "x=ñunion select 1", new List<string>(), ""));
        Assert.Equal("scanner", Waf.Inspect("/", "", new List<string>(), "Mozilla/5.0 nucleiñ"));
    }
}
