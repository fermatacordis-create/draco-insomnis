"""The decision for one request — the same order and limits as src/Core/Gatekeeper.php and
js/src/core/gatekeeper.ts:
  1. blocked addresses may read, but not post or open sensitive pages;
  2. countries (where the platform says it, Cloudflare, or a GeoFile lookup);
  3. firewall signatures (log or block; 5 hits in 10 minutes block the address for 7 days);
  4. anti-copy pace (pages a minute per address and per /24 or /64).
"""
from __future__ import annotations

import html
import math
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Optional

from .crawler import SystemResolver, claimed, resolves_back
from .crowdsec import CrowdSec
from .net import network, parse
from .request import DracoRequest, client_ip, remote, wants_page
from .review import accept as accept_review, form as review_form, is_request as is_review
from .store import Blocks, DracoEvent, MemoryStore
from .waf import inspect

SENSITIVE = (
    "/wp-login.php", "/login", "/register", "/signup", "/user/login", "/user/register", "/admin",
    "/auth/login", "/api/auth/local", "/api/auth/local/register", "/admin/login",
    "/accounts/login/", "/accounts/signup/", "/token", "/auth/token",
)

TEXTS = {
    "title": "Request blocked",
    "text": "This request was blocked by the site's security. If you think this is a mistake, contact the site owner.",
    "too_many": "Too many pages in a short time. Please wait a moment and try again.",
    "text_with_review": "This request was blocked by the site's security. If you think this is a mistake, tell the site owner what you were doing:",
    "review_email": "Your e-mail",
    "review_message": "What were you doing?",
    "review_button": "Ask for a review",
    "review_sent_title": "Request sent",
    "review_sent_text": "Thank you. The owner of the site will look at it and, if it was a mistake, let you through.",
}

_HITS_TO_BLOCK = 5
_HIT_WINDOW = 600
_BLOCK_DAYS = 7
_WINDOW = 60
_VERIFIED_FOR = 86400


@dataclass
class Answer:
    #: 200 only answers a review request (the thanks page).
    status: int
    #: The rule, "blocked", "geo", "pace" or "review": for the evidence, never shown to the visitor.
    why: str
    retry: int = 0
    #: The review form for the 403 page, when reviews are on.
    form: Optional[str] = None


def _limit(value, fallback: int) -> int:
    return int(value) if value is not None and value >= 10 else fallback


class Gatekeeper:
    def __init__(
        self,
        waf: str = "log",
        pace: str = "off",
        rate_ip: Optional[int] = None,
        rate_net: Optional[int] = None,
        proxy: str = "",
        trusted_proxies: Iterable[str] = (),
        admin_ips: Iterable[str] = (),
        sensitive: Optional[Iterable[str]] = None,
        except_paths: Iterable[str] = (),
        geo: Optional[dict] = None,
        headers: bool = False,
        hsts: bool = False,
        store=None,
        resolver=None,
        on_event: Optional[Callable[[DracoEvent], None]] = None,
        review: Optional[dict] = None,
        crowdsec: Optional[dict] = None,
        texts: Optional[Dict[str, str]] = None,
        now: Callable[[], float] = time.time,
    ):
        """
        waf/pace: "off", "log" or "block". proxy: "" (the connection), "cf" or "xff", believed only
        from trusted proxies. geo: {"mode": "off|block|allow", "countries": [...], "action": "log|block",
        "scope": "sensitive|site", "lookup": GeoFile(...)}. review: {"secret": "16+ characters",
        "on_request": callable}. crowdsec: {"url": ..., "api_key": ..., "timeout": 2}.
        """
        self.waf, self.pace = waf, pace
        self.rate_ip, self.rate_net = rate_ip, rate_net
        self.proxy = proxy
        self.trusted_proxies = parse(list(trusted_proxies))
        self.admin_ips = [ip.strip() for ip in admin_ips if ip.strip()]
        self.sensitive_endings = tuple(SENSITIVE if sensitive is None else sensitive)
        self.except_paths = tuple(except_paths)
        self.geo = geo or {}
        self.send_headers, self.hsts = headers, hsts
        self.store = store if store is not None else MemoryStore(now)
        self.blocks = Blocks(self.store)
        self.resolver = resolver if resolver is not None else SystemResolver()
        self.on_event = on_event
        self.review = review or {}
        self.texts = {**TEXTS, **(texts or {})}
        self.now = now
        self._recent: deque = deque(maxlen=200)
        cs = crowdsec or {}
        self.crowdsec = CrowdSec(cs["url"], cs["api_key"], self.store, lambda: self.admin_ips, cs.get("timeout", 2), now) \
            if cs.get("url") and cs.get("api_key") else None

    # The decision

    def ip(self, r: DracoRequest) -> str:
        return client_ip(r, self.proxy, self.trusted_proxies)

    def events(self) -> list:
        """The last 200 lines of evidence of this process (newest last)."""
        return list(self._recent)

    def decide(self, r: DracoRequest) -> Optional[Answer]:
        answer = self._rules(r)
        if answer is not None and answer.status == 403 and self._reviewing():
            t = self.texts
            answer.form = review_form(self.review["secret"], self.ip(r), answer.why, self.now(),
                                      {"email": t["review_email"], "message": t["review_message"], "button": t["review_button"]})
        return answer

    def _reviewing(self) -> bool:
        return len(self.review.get("secret") or "") >= 16

    def _rules(self, r: DracoRequest) -> Optional[Answer]:
        if self.crowdsec is not None:
            # In a background thread: no request waits for CrowdSec.
            self.crowdsec.maybe_sync()
        ip = self.ip(r)
        if self._excepted(r.path):
            return None
        if self._reviewing() and is_review(r.method, r.form):
            request = accept_review(self.store, self.review["secret"], ip, r.user_agent, r.form or {}, self.now())
            if request is not None:
                self._log(r, ip, "review", "pending", [f"review_{request.rule or 'blocked'}"], request.message, request.email)
                callback = self.review.get("on_request")
                if callback is not None:
                    try:
                        callback(request)
                    except Exception:  # noqa: BLE001 - the visitor gets the thanks page whatever happens
                        pass
            # The same answer either way, so a script learns nothing.
            return Answer(200, "review")
        if ip in self.admin_ips:
            return None
        if self.waf != "off":
            if self._sensitive(r) and self.blocks.is_blocked(ip, self.now()):
                return Answer(403, "blocked")
            country = self._refused_country(r, ip)
            if country:
                blocking = self.geo.get("action") == "block"
                self._log(r, ip, "waf:geo", "bot" if blocking else "doubtful", ["waf_geo"], f"{country} {r.path}")
                if blocking:
                    return Answer(403, "geo")
            rule = inspect(r.path, r.query, r.params, r.user_agent)
            if rule is not None:
                self._record(r, ip, rule, self.waf == "block")
                if self.waf == "block":
                    return Answer(403, rule)
        if self.pace != "off" and wants_page(r):
            now = self.now()
            minute = math.floor(now / _WINDOW)
            ip_hits = self.store.bump(f"draco:rl:i:{ip}:{minute}", _WINDOW * 2)
            net_hits = self.store.bump(f"draco:rl:n:{network(ip)}:{minute}", _WINDOW * 2)
            ip_limit, net_limit = _limit(self.rate_ip, 120), _limit(self.rate_net, 600)
            over = "ip" if ip_hits > ip_limit else "net" if net_hits > net_limit else ""
            if over and not self.verified_crawler(ip, r.user_agent):
                block = self.pace == "block"
                # One line per address and minute is enough evidence; the rest only counts.
                if ip_hits == ip_limit + 1 or net_hits == net_limit + 1:
                    self._log(r, ip, f"anticopy:{over}", "doubtful", [f"anticopy_{over}_{'block' if block else 'log'}"], r.path)
                if block:
                    return Answer(429, "pace", max(1, _WINDOW - (int(now) % _WINDOW)))
        return None

    def _excepted(self, path: str) -> bool:
        for p in self.except_paths:
            prefix = "/" + p.lstrip("/")
            if prefix != "/" and path.startswith(prefix):
                return True
        return False

    def _sensitive(self, r: DracoRequest) -> bool:
        return r.method == "POST" or any(end and r.path.endswith(end) for end in self.sensitive_endings)

    def _refused_country(self, r: DracoRequest, ip: str) -> str:
        geo = self.geo
        mode = geo.get("mode", "off")
        wanted = [c.strip().upper() for c in geo.get("countries", []) if re.fullmatch(r"[A-Za-z]{2}", c.strip())]
        if mode == "off" or not wanted:
            return ""
        if geo.get("scope") != "site" and not self._sensitive(r):
            return ""
        country = (r.country or "").upper()
        lookup = geo.get("lookup")
        if not re.fullmatch(r"[A-Z]{2}", country) and lookup is not None:
            try:
                country = (lookup.country(ip) or "").upper()
            except Exception:  # noqa: BLE001
                country = ""
        # Unknown, Tor ("T1") or anonymous ("XX"): not refused for its country.
        if not re.fullmatch(r"[A-Z]{2}", country) or country in ("XX", "T1"):
            return ""
        listed = country in wanted
        if (mode == "block" and not listed) or (mode == "allow" and listed):
            return ""
        # Last: it may ask the DNS, and only matters for a request that would be refused.
        if self.verified_crawler(ip, r.user_agent):
            return ""
        return country

    def _record(self, r: DracoRequest, ip: str, rule: str, blocking: bool) -> None:
        self._log(r, ip, f"waf:{rule}", "bot" if blocking else "doubtful", [f"waf_{rule}"], r.path + (f"?{r.query}" if r.query else ""))
        if not blocking:
            return
        hits = self.store.bump(f"draco:waf:{ip}", _HIT_WINDOW)
        # An address read from a header nobody vouches for is never blocked: it could be anybody's.
        trusted = ip == remote(r) or self.proxy != ""
        if hits >= _HITS_TO_BLOCK and trusted and not self.blocks.is_blocked(ip, self.now()):
            self.blocks.add(ip, _BLOCK_DAYS, f"Firewall: {hits} attacks in 10 minutes", True, self.now())

    def verified_crawler(self, ip: str, user_agent: str) -> bool:
        token = claimed(user_agent)
        if not token or self.resolver is None:
            return False
        key = f"draco:crawler:{ip}:{token}"
        cached = self.store.get(key)
        if cached in ("y", "n"):
            return cached == "y"
        ok = resolves_back(self.resolver, ip, token)
        self.store.set(key, "y" if ok else "n", _VERIFIED_FOR)
        return ok

    def _log(self, r: DracoRequest, ip: str, endpoint: str, verdict: str, reasons: list, detail: str, email: str = "") -> None:
        event = DracoEvent(int(self.now()), ip, remote(r), endpoint, verdict, reasons, r.user_agent[:255],
                           detail[: 500 if endpoint == "review" else 200], email)
        self._recent.append(event)
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:  # noqa: BLE001 - a broken log sink must never break the site
                pass

    # The answer

    def security_headers(self, https: bool) -> Dict[str, str]:
        """Security headers to add, unless the application already set them."""
        out: Dict[str, str] = {}
        if self.send_headers:
            out.update({
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
            })
        if https and self.hsts:
            out["Strict-Transport-Security"] = "max-age=15552000"
        return out

    def render(self, answer: Answer):
        """(status, headers, body) of an answer, for any framework."""
        t = self.texts
        if answer.status == 429:
            return 429, {"Retry-After": str(answer.retry), "Content-Type": "text/plain; charset=UTF-8",
                         "Cache-Control": "no-store", "X-Robots-Tag": "noindex"}, t["too_many"]
        h = {"Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}
        if answer.status == 200:
            return 200, h, page(t["review_sent_title"], t["review_sent_text"])
        if answer.form is not None:
            return 403, h, page(t["title"], t["text_with_review"], answer.form)
        return 403, h, page(t["title"], t["text"])


def page(title: str, text: str, extra_html: str = "") -> str:
    """The 403 page: says nothing about which rule matched; the reference ties it to the evidence."""
    h = lambda s: html.escape(s, quote=True)  # noqa: E731
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow">'
        '<meta name="viewport" content="width=device-width,initial-scale=1"><title>403</title>'
        "<style>body{font:16px/1.5 system-ui,sans-serif;background:#f4f5f7;color:#1d2327;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box}main{background:#fff;border-radius:12px;padding:32px;max-width:440px;width:100%;box-shadow:0 2px 12px rgba(0,0,0,.08);text-align:center}form{text-align:left;margin-top:20px}label{display:block;font-size:14px;margin:10px 0 4px}input,textarea{width:100%;box-sizing:border-box;padding:8px;border:1px solid #c3c4c7;border-radius:6px;font:inherit}button{margin-top:12px;padding:9px 16px;border:0;border-radius:6px;background:#2271b1;color:#fff;font:inherit;cursor:pointer}.hp{position:absolute;left:-9999px}</style></head><body><main>"
        f'<h1 style="font-size:20px">{h(title)}</h1><p>{h(text)}</p>{extra_html}'
        f'<p style="color:#64748b;font-size:13px">Ref. {secrets.token_hex(5)}</p></main></body></html>'
    )
