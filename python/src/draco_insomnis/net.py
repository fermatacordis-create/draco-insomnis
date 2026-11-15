"""Addresses and networks: the same behaviour as src/Core/NetList.php and js/src/core/net.ts."""
from __future__ import annotations

import re
from typing import Iterable, Optional

_V4_PART = re.compile(r"^(0|[1-9]\d{0,2})$")
_HEX = re.compile(r"^[0-9a-f]{1,4}$", re.I)


def _v4(value: str) -> Optional[bytes]:
    parts = value.split(".")
    if len(parts) != 4:
        return None
    out = bytearray()
    for p in parts:
        # Like PHP's filter_var: decimal only, no leading zeros.
        if not _V4_PART.match(p) or int(p) > 255:
            return None
        out.append(int(p))
    return bytes(out)


def _v6(value: str) -> Optional[bytes]:
    if "%" in value or not re.match(r"^[0-9a-f:.]+$", value, re.I):
        return None
    halves = value.split("::")
    if len(halves) > 2:
        return None

    def words(s: str) -> Optional[list]:
        if s == "":
            return []
        out = []
        items = s.split(":")
        for i, item in enumerate(items):
            if i == len(items) - 1 and "." in item:
                b = _v4(item)
                if b is None:
                    return None
                out += [(b[0] << 8) | b[1], (b[2] << 8) | b[3]]
            else:
                if not _HEX.match(item):
                    return None
                out.append(int(item, 16))
        return out

    head = words(halves[0])
    tail = words(halves[1]) if len(halves) == 2 else []
    if head is None or tail is None:
        return None
    missing = 8 - len(head) - len(tail)
    if (missing < 1) if len(halves) == 2 else (missing != 0):
        return None
    allw = head + [0] * (missing if len(halves) == 2 else 0) + tail
    return b"".join(w.to_bytes(2, "big") for w in allw)


def to_bytes(ip: str) -> Optional[bytes]:
    """The address as 4 or 16 bytes, or None when it is not a valid IPv4 or IPv6 address."""
    value = (ip or "").strip()
    return _v6(value) if ":" in value else _v4(value)


def is_ip(ip: str) -> bool:
    return to_bytes(ip) is not None


def from_bytes(b: bytes) -> str:
    """Dotted IPv4, or compressed lower-case IPv6 (like inet_ntop)."""
    if len(b) == 4:
        return ".".join(str(x) for x in b)
    w = [(b[i] << 8) | b[i + 1] for i in range(0, 16, 2)]
    best, best_len, i = -1, 0, 0
    while i < 8:
        if w[i] != 0:
            i += 1
            continue
        j = i
        while j < 8 and w[j] == 0:
            j += 1
        if j - i > best_len and j - i >= 2:
            best, best_len = i, j - i
        i = j
    hexs = lambda xs: ":".join(format(x, "x") for x in xs)  # noqa: E731
    if best < 0:
        return hexs(w)
    return f"{hexs(w[:best])}::{hexs(w[best + best_len:])}"


def in_net(cidr: str, ip: str) -> bool:
    """Whether the address is inside the network ("10.0.0.0/8", "2001:db8::/32" or one address)."""
    base_text, _, bits_text = cidr.strip().partition("/")
    base, addr = to_bytes(base_text), to_bytes(ip)
    if base is None or addr is None or len(base) != len(addr):
        return False
    top = len(base) * 8
    bits = int(bits_text) if bits_text.isdigit() else top
    if bits > top:
        return False
    whole, rest = divmod(bits, 8)
    if base[:whole] != addr[:whole]:
        return False
    if rest == 0:
        return True
    mask = (0xFF << (8 - rest)) & 0xFF
    return (base[whole] & mask) == (addr[whole] & mask)


def contains(nets: Iterable[str], ip: str) -> bool:
    return any(in_net(n, ip) for n in nets)


def parse(text) -> list:
    """Networks and addresses from text or a list: one per line or comma-separated; "#" starts a comment."""
    lines = re.split(r"\r\n|\r|\n", text) if isinstance(text, str) else list(text)
    out: list = []
    for line in lines:
        for item in re.split(r"[\s,]+", re.sub(r"#.*", "", str(line))):
            if item and is_ip(item.split("/", 1)[0]) and item not in out:
                out.append(item)
    return out


def network(ip: str) -> str:
    """The /24 (IPv4) or /64 (IPv6) the address belongs to; '' when it is not an address."""
    b = to_bytes(ip)
    if b is None:
        return ""
    if len(b) == 4:
        return f"{b[0]}.{b[1]}.{b[2]}.0/24"
    return f"{from_bytes(b[:8] + bytes(8))}/64"


def unmap(ip: str) -> str:
    """'::ffff:1.2.3.4' (IPv4 on a dual-stack socket) → '1.2.3.4'."""
    return ip[7:] if re.match(r"^::ffff:\d+\.\d+\.\d+\.\d+$", ip, re.I) else ip


# Cloudflare's published ranges (https://www.cloudflare.com/ips/), as in Request::CLOUDFLARE.
CLOUDFLARE = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)

# Proxies trusted when none are listed: this machine and networks unreachable from the internet.
LOCAL_PROXIES = (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)
