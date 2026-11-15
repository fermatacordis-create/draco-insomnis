using System.Text.RegularExpressions;

namespace DracoInsomnis;

/// <summary>Addresses and networks, like src/Core/NetList.php: decimal IPv4 without leading zeros, no zones.</summary>
public static class Net
{
    public static readonly string[] Cloudflare =
    {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    };

    public static readonly string[] LocalProxies =
    {
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
    };

    private static readonly Regex V4Part = new("^(0|[1-9][0-9]{0,2})$", RegexOptions.Compiled);
    private static readonly Regex Hex = new("^[0-9a-fA-F]{1,4}$", RegexOptions.Compiled);

    private static byte[]? V4(string value)
    {
        var parts = value.Split('.');
        if (parts.Length != 4) return null;
        var o = new byte[4];
        for (var i = 0; i < 4; i++)
        {
            if (!V4Part.IsMatch(parts[i]) || int.Parse(parts[i]) > 255) return null;
            o[i] = (byte)int.Parse(parts[i]);
        }
        return o;
    }

    private static byte[]? V6(string value)
    {
        if (value.Contains('%') || !Regex.IsMatch(value, "^[0-9a-fA-F:.]+$")) return null;
        var halves = value.Split("::");
        if (halves.Length > 2) return null;
        List<int>? Words(string s)
        {
            var o = new List<int>();
            if (s.Length == 0) return o;
            var items = s.Split(':');
            for (var i = 0; i < items.Length; i++)
            {
                if (i == items.Length - 1 && items[i].Contains('.'))
                {
                    var b = V4(items[i]);
                    if (b is null) return null;
                    o.Add((b[0] << 8) | b[1]);
                    o.Add((b[2] << 8) | b[3]);
                }
                else
                {
                    if (!Hex.IsMatch(items[i])) return null;
                    o.Add(Convert.ToInt32(items[i], 16));
                }
            }
            return o;
        }
        var head = Words(halves[0]);
        var tail = halves.Length == 2 ? Words(halves[1]) : new List<int>();
        if (head is null || tail is null) return null;
        var missing = 8 - head.Count - tail.Count;
        if (halves.Length == 2 ? missing < 1 : missing != 0) return null;
        var all = head.Concat(Enumerable.Repeat(0, halves.Length == 2 ? missing : 0)).Concat(tail).ToList();
        var bytes = new byte[16];
        for (var i = 0; i < 8; i++)
        {
            bytes[2 * i] = (byte)(all[i] >> 8);
            bytes[2 * i + 1] = (byte)(all[i] & 0xff);
        }
        return bytes;
    }

    /// <summary>The address as 4 or 16 bytes, or null when it is not one.</summary>
    public static byte[]? ToBytes(string? ip)
    {
        var v = (ip ?? "").Trim();
        return v.Contains(':') ? V6(v) : V4(v);
    }

    public static bool IsIp(string? ip) => ToBytes(ip) is not null;

    public static string FromBytes(byte[] b)
    {
        if (b.Length == 4) return string.Join('.', b);
        var w = new int[8];
        for (var i = 0; i < 8; i++) w[i] = (b[2 * i] << 8) | b[2 * i + 1];
        int best = -1, bestLen = 0;
        for (var i = 0; i < 8;)
        {
            if (w[i] != 0) { i++; continue; }
            var j = i;
            while (j < 8 && w[j] == 0) j++;
            if (j - i > bestLen && j - i >= 2) { best = i; bestLen = j - i; }
            i = j;
        }
        string Hx(IEnumerable<int> xs) => string.Join(':', xs.Select(x => x.ToString("x")));
        return best < 0 ? Hx(w) : Hx(w.Take(best)) + "::" + Hx(w.Skip(best + bestLen));
    }

    public static bool InNet(string cidr, string ip)
    {
        var parts = cidr.Trim().Split('/', 2);
        var b = ToBytes(parts[0]);
        var a = ToBytes(ip);
        if (b is null || a is null || b.Length != a.Length) return false;
        var max = b.Length * 8;
        var bits = parts.Length == 2 && Regex.IsMatch(parts[1], "^[0-9]+$") ? int.Parse(parts[1]) : max;
        if (bits > max) return false;
        int whole = bits / 8, rest = bits % 8;
        for (var i = 0; i < whole; i++) if (b[i] != a[i]) return false;
        if (rest == 0) return true;
        var mask = (byte)((0xff << (8 - rest)) & 0xff);
        return (b[whole] & mask) == (a[whole] & mask);
    }

    public static bool Contains(IEnumerable<string> nets, string ip) => nets.Any(n => InNet(n, ip));

    /// <summary>Networks and addresses: one per line or comma-separated; "#" starts a comment.</summary>
    public static List<string> Parse(IEnumerable<string> items) => items
        .SelectMany(t => Regex.Split(t, "\r\n|\r|\n"))
        .SelectMany(l => Regex.Split(Regex.Replace(l, "#.*", ""), @"[\s,]+"))
        .Where(i => i.Length > 0 && IsIp(i.Split('/', 2)[0])).Distinct().ToList();

    /// <summary>The /24 (IPv4) or /64 (IPv6) of an address; "" when it is not one.</summary>
    public static string Network(string ip)
    {
        var b = ToBytes(ip);
        if (b is null) return "";
        if (b.Length == 4) return $"{b[0]}.{b[1]}.{b[2]}.0/24";
        var keep = new byte[16];
        Array.Copy(b, keep, 8);
        return FromBytes(keep) + "/64";
    }

    public static string Unmap(string ip) => Regex.IsMatch(ip, @"^::ffff:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", RegexOptions.IgnoreCase) ? ip[7..] : ip;
}
