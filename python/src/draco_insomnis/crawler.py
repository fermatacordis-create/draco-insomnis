"""Search engines that may go past the pace limit, but only when the reverse DNS proves who they are
(the same list and rules as src/Core/Crawler.php and js/src/core/crawler.ts)."""
from __future__ import annotations

import re
import socket
from typing import Callable, List, Optional, Protocol

from .net import from_bytes, to_bytes

_GOOGLE = ("googlebot.com", "google.com", "googleusercontent.com")

KNOWN = {
    "googlebot": _GOOGLE,
    "google-inspectiontool": _GOOGLE,
    "googleother": _GOOGLE,
    "adsbot-google": _GOOGLE,
    "mediapartners-google": _GOOGLE,
    "bingbot": ("search.msn.com",),
    "msnbot": ("search.msn.com",),
    "adidxbot": ("search.msn.com",),
    "applebot": ("applebot.apple.com",),
    "yandex": ("yandex.ru", "yandex.net", "yandex.com"),
}


class Resolver(Protocol):
    def reverse(self, ip: str) -> List[str]: ...

    def lookup(self, host: str) -> List[str]: ...


class SystemResolver:
    """The system's DNS (blocking: the ASGI adapter runs the engine in a worker thread)."""

    def reverse(self, ip: str) -> List[str]:
        name, aliases, _ = socket.gethostbyaddr(ip)
        return [name, *aliases]

    def lookup(self, host: str) -> List[str]:
        return list({a[4][0] for a in socket.getaddrinfo(host, None)})


def _same(ip: str) -> str:
    b = to_bytes(ip)
    return f"?{ip}" if b is None else from_bytes(b)


def claimed(user_agent: str) -> str:
    ua = (user_agent or "").lower()
    return next((token for token in KNOWN if token in ua), "")


def host_matches(token: str, host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    domains = KNOWN.get(token)
    if not h or domains is None or re.match(r"^[\d.]+$", h) or ":" in h:
        return False
    return any(h == d or h.endswith("." + d) for d in domains)


def resolves_back(resolver: Resolver, ip: str, token: str) -> bool:
    """The name the address points back to must belong to the engine, and point back to the address."""
    try:
        for name in resolver.reverse(ip)[:3]:
            if not host_matches(token, name):
                continue
            want = _same(ip)
            if any(_same(a) == want for a in resolver.lookup(name)):
                return True
    except (OSError, ValueError):
        pass  # No answer: not proven.
    return False
