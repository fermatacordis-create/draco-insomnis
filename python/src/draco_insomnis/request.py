"""One visitor request in plain values, as an adapter (ASGI, WSGI) read it: the same fields as
src/Core/Request.php and js/src/core/request.ts, so the engine can be tested without a server."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import unquote, unquote_plus

from .net import CLOUDFLARE, LOCAL_PROXIES, contains, is_ip, parse, unmap


@dataclass
class DracoRequest:
    method: str = "GET"
    #: URL path, decoded once.
    path: str = "/"
    #: Query string without "?", decoded once.
    query: str = ""
    #: Decoded query and body values (and keys), for the firewall only.
    params: List[str] = field(default_factory=list)
    user_agent: str = ""
    #: The address of the connection itself.
    remote_addr: str = ""
    cf_connecting_ip: str = ""
    forwarded_for: str = ""
    #: Two-letter country the platform already knows (Cloudflare), if any.
    country: str = ""
    #: The Accept header: only pages count for the anti-copy pace.
    accept: str = ""
    #: Sent with "X-Requested-With: XMLHttpRequest".
    ajax: bool = False
    #: The text fields of a posted form (urlencoded or JSON), for the review form.
    form: Optional[Dict[str, str]] = None


def url_decode(value: str, plus_is_space: bool = False) -> str:
    """Like PHP's urldecode: malformed "%" sequences are left as they are; bytes read as UTF-8."""
    return unquote_plus(value, errors="replace") if plus_is_space else unquote(value, errors="replace")


def remote(r: DracoRequest) -> str:
    ip = unmap((r.remote_addr or "").strip())
    return ip if is_ip(ip) else "0.0.0.0"


def _proxies(trusted) -> list:
    listed = parse(trusted or [])
    return listed if listed else list(LOCAL_PROXIES)


def from_trusted_proxy(r: DracoRequest, mode: str, trusted=()) -> bool:
    """Whether the chosen proxy header may be read at all: the connection comes from a trusted proxy."""
    addr = remote(r)
    if mode == "cf":
        return bool(r.cf_connecting_ip) and (contains(CLOUDFLARE, addr) or contains(parse(trusted or []), addr))
    if mode == "xff":
        return bool((r.forwarded_for or "").strip()) and contains(_proxies(trusted), addr)
    return False


def client_ip(r: DracoRequest, mode: str = "", trusted=()) -> str:
    """The visitor's address: the connection's own, unless a proxy header is chosen AND the connection
    comes from a trusted proxy. X-Forwarded-For is read from the right: the first address that is not
    a trusted proxy is the visitor; whatever is on its left was written by the visitor."""
    addr = remote(r)
    if not from_trusted_proxy(r, mode, trusted):
        return addr
    if mode == "cf":
        ip = (r.cf_connecting_ip or "").strip()
        return ip if is_ip(ip) else addr
    proxies = _proxies(trusted)
    for hop in reversed([h.strip() for h in (r.forwarded_for or "").split(",")]):
        if not is_ip(hop):
            return addr
        if not contains(proxies, hop):
            return hop
        addr = hop
    return addr


def wants_page(r: DracoRequest) -> bool:
    """A page (HTML) rather than an API call, an image or a script: only pages count for the pace."""
    accept = (r.accept or "").lower()
    return r.method in ("GET", "HEAD") and (accept == "" or "text/html" in accept) and not r.ajax


_CLEAN = re.compile(r"[\x00-\x1f\x7f]+")


def clean(value: str) -> str:
    """One line of plain text."""
    return _CLEAN.sub(" ", value or "").strip()
