"""Where Draco keeps counters, the block list and recent evidence: the same keys and rules as
js/src/core/store.ts, so a Redis shared by a Node and a Python app reads the same blocks."""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import List, Optional, Protocol

from .net import in_net

FOREVER = 253402300799
_MIN_PREFIX = {4: 16, 6: 32}


class Store(Protocol):
    def bump(self, key: str, ttl: int) -> int:
        """Adds one and returns the new value; the counter disappears after ttl seconds."""

    def get(self, key: str) -> Optional[str]: ...

    def set(self, key: str, value: str, ttl: int) -> None:
        """ttl 0 = keep for good."""

    def delete(self, key: str) -> None: ...


class MemoryStore:
    """One process, nothing to install; thread-safe. Lost on restart: fine for one server."""

    def __init__(self, now=time.time):
        self._items: dict = {}
        self._lock = threading.Lock()
        self._now = now

    def _live(self, key: str) -> Optional[str]:
        item = self._items.get(key)
        if item is None:
            return None
        value, until = item
        if until != 0 and until <= self._now():
            del self._items[key]
            return None
        return value

    def _sweep(self) -> None:
        if len(self._items) >= 50_000:
            for key in list(self._items):
                self._live(key)

    def bump(self, key: str, ttl: int) -> int:
        with self._lock:
            current = self._live(key)
            n = (0 if current is None else int(current)) + 1
            until = self._now() + ttl if current is None else self._items[key][1]
            self._items[key] = (str(n), until)
            self._sweep()
            return n

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._live(key)

    def set(self, key: str, value: str, ttl: int) -> None:
        with self._lock:
            self._items[key] = (value, 0 if ttl == 0 else self._now() + ttl)
            self._sweep()

    def delete(self, key: str) -> None:
        with self._lock:
            self._items.pop(key, None)


@dataclass
class DracoEvent:
    """A line of evidence, the same fields as the PHP events table and the JavaScript DracoEvent."""

    time: int
    ip: str
    remote: str
    #: "waf:sqli", "waf:geo", "anticopy:ip", "review"…
    endpoint: str
    #: "bot", "doubtful" or "pending" (a review request).
    verdict: str
    reasons: List[str] = field(default_factory=list)
    user_agent: str = ""
    #: Path and query, country and path, or the review request's message.
    detail: str = ""
    #: Review requests: the e-mail the visitor left.
    email: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def valid_net(cidr: str) -> bool:
    """A network may be blocked when it is no wider than /16 (IPv4) or /32 (IPv6), as in Blocklist.php."""
    m = re.match(r"^([0-9a-f.:]+)/(\d+)$", cidr.strip(), re.I)
    if not m:
        return False
    v6 = ":" in m.group(1)
    bits = int(m.group(2))
    return in_net(m.group(1) + "/0", m.group(1)) and _MIN_PREFIX[6 if v6 else 4] <= bits <= (128 if v6 else 32)


class Blocks:
    """The block list on any Store: one key per address, one key holding the blocked networks."""

    def __init__(self, store: Store):
        self.store = store

    def _write(self, value: str, until: int, reason: str, automatic: bool, now: float, ttl: int) -> bool:
        entry = {"value": value, "until": until, "reason": reason, "automatic": automatic}
        if "/" in value:
            if not valid_net(value):
                return False
            nets = [n for n in self.nets(now) if n["value"] != value] + [entry]
            self.store.set("draco:nets", json.dumps(nets), 0)
            return True
        self.store.set(f"draco:block:{value}", json.dumps(entry), ttl)
        return True

    def add(self, value: str, days: int, reason: str, automatic: bool = False, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        until = FOREVER if days == 0 else int(now) + days * 86400
        return self._write(value, until, reason, automatic, now, 0 if days == 0 else days * 86400)

    def add_until(self, value: str, until: float, reason: str, automatic: bool = True, now: Optional[float] = None) -> bool:
        """A block until a given moment, for lists that bring their own duration (CrowdSec)."""
        now = time.time() if now is None else now
        ttl = int(until - now)
        return ttl > 0 and self._write(value, int(until), reason, automatic, now, ttl)

    def remove(self, value: str) -> None:
        if "/" in value:
            self.store.set("draco:nets", json.dumps([n for n in self.nets() if n["value"] != value]), 0)
        else:
            self.store.delete(f"draco:block:{value}")

    def nets(self, now: Optional[float] = None) -> list:
        now = time.time() if now is None else now
        raw = self.store.get("draco:nets")
        try:
            return [n for n in json.loads(raw or "[]") if n["until"] > now]
        except (ValueError, KeyError, TypeError):
            return []

    def entry(self, value: str, now: Optional[float] = None) -> Optional[dict]:
        if "/" in value:
            return next((n for n in self.nets(now) if n["value"] == value), None)
        raw = self.store.get(f"draco:block:{value}")
        try:
            return json.loads(raw) if raw is not None else None
        except ValueError:
            return None

    def is_blocked(self, ip: str, now: Optional[float] = None) -> bool:
        if self.store.get(f"draco:block:{ip}") is not None:
            return True
        return any(in_net(n["value"], ip) for n in self.nets(now))
