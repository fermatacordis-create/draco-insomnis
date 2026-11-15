//! Addresses and networks, like src/Core/NetList.php: decimal IPv4 without leading zeros, no zones.

/// Cloudflare's published ranges: its headers are believed only from these.
pub const CLOUDFLARE: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

/// Private and loopback networks: the proxies believed when none are configured.
pub const LOCAL_PROXIES: &[&str] = &[
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

fn v4(value: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut o = Vec::with_capacity(4);
    for p in parts {
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
            return None;
        }
        let n: u32 = p.parse().ok()?;
        if n > 255 {
            return None;
        }
        o.push(n as u8);
    }
    Some(o)
}

fn words(s: &str) -> Option<Vec<u16>> {
    let mut o = Vec::new();
    if s.is_empty() {
        return Some(o);
    }
    let items: Vec<&str> = s.split(':').collect();
    for (i, item) in items.iter().enumerate() {
        if i == items.len() - 1 && item.contains('.') {
            let b = v4(item)?;
            o.push(((b[0] as u16) << 8) | b[1] as u16);
            o.push(((b[2] as u16) << 8) | b[3] as u16);
        } else {
            if item.is_empty() || item.len() > 4 || !item.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            o.push(u16::from_str_radix(item, 16).ok()?);
        }
    }
    Some(o)
}

fn v6(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.') {
        return None;
    }
    let halves: Vec<&str> = value.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let head = words(halves[0])?;
    let tail = if halves.len() == 2 { words(halves[1])? } else { Vec::new() };
    let missing = 8i32 - head.len() as i32 - tail.len() as i32;
    if (halves.len() == 2 && missing < 1) || (halves.len() == 1 && missing != 0) {
        return None;
    }
    let mut all = head;
    if halves.len() == 2 {
        all.extend(std::iter::repeat_n(0, missing as usize));
    }
    all.extend(tail);
    let mut bytes = Vec::with_capacity(16);
    for w in all {
        bytes.push((w >> 8) as u8);
        bytes.push((w & 0xff) as u8);
    }
    Some(bytes)
}

/// The address as 4 or 16 bytes, or None when it is not one.
pub fn to_bytes(ip: &str) -> Option<Vec<u8>> {
    let v = ip.trim();
    if v.contains(':') {
        v6(v)
    } else {
        v4(v)
    }
}

pub fn is_ip(ip: &str) -> bool {
    to_bytes(ip).is_some()
}

/// The shortest text form: dotted IPv4, or IPv6 with the longest run of zeros as "::".
pub fn from_bytes(b: &[u8]) -> String {
    if b.len() == 4 {
        return format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]);
    }
    let w: Vec<u16> = (0..8).map(|i| ((b[2 * i] as u16) << 8) | b[2 * i + 1] as u16).collect();
    let (mut best, mut best_len) = (usize::MAX, 0);
    let mut i = 0;
    while i < 8 {
        if w[i] != 0 {
            i += 1;
            continue;
        }
        let mut j = i;
        while j < 8 && w[j] == 0 {
            j += 1;
        }
        if j - i > best_len && j - i >= 2 {
            best = i;
            best_len = j - i;
        }
        i = j;
    }
    let hx = |xs: &[u16]| xs.iter().map(|x| format!("{:x}", x)).collect::<Vec<_>>().join(":");
    if best == usize::MAX {
        hx(&w)
    } else {
        format!("{}::{}", hx(&w[..best]), hx(&w[best + best_len..]))
    }
}

pub fn in_net(cidr: &str, ip: &str) -> bool {
    let mut parts = cidr.trim().splitn(2, '/');
    let (Some(b), Some(a)) = (to_bytes(parts.next().unwrap_or("")), to_bytes(ip)) else {
        return false;
    };
    if b.len() != a.len() {
        return false;
    }
    let max = b.len() * 8;
    let bits = match parts.next() {
        Some(p) if !p.is_empty() && p.len() <= 4 && p.bytes().all(|c| c.is_ascii_digit()) => p.parse().unwrap_or(usize::MAX),
        Some(p) if !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit()) => return false,
        _ => max,
    };
    if bits > max {
        return false;
    }
    let (whole, rest) = (bits / 8, bits % 8);
    if b[..whole] != a[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = (0xffu16 << (8 - rest)) as u8;
    (b[whole] & mask) == (a[whole] & mask)
}

pub fn contains<S: AsRef<str>>(nets: &[S], ip: &str) -> bool {
    nets.iter().any(|n| in_net(n.as_ref(), ip))
}

/// Networks and addresses: one per line or comma-separated; "#" starts a comment.
pub fn parse<S: AsRef<str>>(items: &[S]) -> Vec<String> {
    let mut o: Vec<String> = Vec::new();
    for t in items {
        for line in t.as_ref().lines() {
            let line = line.split('#').next().unwrap_or("");
            for item in line.split(|c: char| c == ',' || c.is_whitespace()) {
                if !item.is_empty() && is_ip(item.split('/').next().unwrap_or("")) && !o.iter().any(|x| x == item) {
                    o.push(item.to_string());
                }
            }
        }
    }
    o
}

/// The /24 (IPv4) or /64 (IPv6) of an address; "" when it is not one.
pub fn network(ip: &str) -> String {
    match to_bytes(ip) {
        None => String::new(),
        Some(b) if b.len() == 4 => format!("{}.{}.{}.0/24", b[0], b[1], b[2]),
        Some(b) => {
            let mut keep = [0u8; 16];
            keep[..8].copy_from_slice(&b[..8]);
            from_bytes(&keep) + "/64"
        }
    }
}

/// "::ffff:1.2.3.4" (IPv4 on an IPv6 socket) as "1.2.3.4".
pub fn unmap(ip: &str) -> &str {
    if ip.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("::ffff:")) {
        let rest = &ip[7..];
        let parts: Vec<&str> = rest.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())) {
            return rest;
        }
    }
    ip
}
