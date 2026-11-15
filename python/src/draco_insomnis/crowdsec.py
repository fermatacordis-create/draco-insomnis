"""CrowdSec, both ways — like server/src/CrowdSec.php and js/src/core/crowdsec.ts.

In: Draco is a bouncer of your own CrowdSec Local API (url + the key from "cscli bouncers add draco").
The decisions stream is copied into Draco's block list at most once a minute, in a background
thread: no request ever waits for CrowdSec. Bans on an address or a range (no wider than /16 or /32)
become Draco blocks. The owner's addresses (admin_ips) are never imported.

Out: crowdsec_line(event) is one JSON line in the format the parser and scenario in server/crowdsec
read: append it to a file the CrowdSec agent watches, from on_event.
"""
from __future__ import annotations

import json
import math
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Iterable

from .net import is_ip
from .store import Blocks, DracoEvent, valid_net

REASON = "CrowdSec"
_EVERY = 60
_IMPORTED = "draco:crowdsec:imported"


def seconds(duration: str) -> int:
    """Go durations as CrowdSec sends them: "3h59m40.5s", "45m", "1.5s"…"""
    if duration.strip().startswith("-"):
        return 0
    found = re.findall(r"(\d+(?:\.\d+)?)(h|ms|m|s)", duration)
    total = sum(float(n) * {"h": 3600, "m": 60, "s": 1, "ms": 0.001}[u] for n, u in found)
    return math.ceil(total) if found else 0


class CrowdSec:
    def __init__(self, url: str, api_key: str, store, admins: Callable[[], Iterable[str]] = lambda: (), timeout: float = 2, now=time.time):
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.store = store
        self.blocks = Blocks(store)
        self.admins = admins
        self.timeout = timeout
        self.now = now
        self._running = threading.Lock()

    def maybe_sync(self) -> None:
        """One sync a minute at most (across processes sharing the store), in a background thread."""
        if self._running.locked() or self.store.bump("draco:crowdsec:sync", _EVERY) != 1:
            return
        threading.Thread(target=self.sync, name="draco-crowdsec", daemon=True).start()

    def sync(self) -> dict:
        with self._running:
            # Any sync, also one called by hand, counts as this minute's.
            self.store.set("draco:crowdsec:sync", "1", _EVERY)
            return self._pull()

    def _pull(self) -> dict:
        out = {"added": 0, "removed": 0, "error": ""}
        startup = self.store.get("draco:crowdsec:started") is None
        url = f"{self.url}/v1/decisions/stream?startup={'true' if startup else 'false'}&scopes=ip,range"
        data = None
        try:
            req = urllib.request.Request(url, headers={"X-Api-Key": self.api_key, "User-Agent": "Draco-Insomnis"})
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                data = json.loads(res.read() or b"null")
        except urllib.error.HTTPError as e:
            out["error"] = f"HTTP {e.code}"
        except ValueError:
            out["error"] = "not JSON"
        except Exception:  # noqa: BLE001
            out["error"] = "no answer"
        if out["error"] or not isinstance(data, dict):
            out["error"] = out["error"] or "not JSON"
            self.store.set("draco:crowdsec:last", f"{int(self.now())}|{out['error']}", 86400 * 30)
            return out
        imported = self._imported()
        if startup:
            out["removed"] += sum(1 for v in imported if self._remove_if_ours(v))
            imported = []
        for d in data.get("deleted") or []:
            value = str((d or {}).get("value", "")).lower()
            if value and value in imported and self._remove_if_ours(value):
                out["removed"] += 1
                imported.remove(value)
        admins = set(self.admins())
        for d in data.get("new") or []:
            d = d or {}
            if str(d.get("type", "")).lower() != "ban":
                continue
            value = str(d.get("value", "")).strip().lower()
            ttl = seconds(str(d.get("duration", "")))
            allowed = valid_net(value) if "/" in value else is_ip(value)
            if ttl <= 0 or not allowed or value in admins:
                continue
            reason = f"{REASON}: {str(d.get('scenario') or d.get('origin') or '')[:150]}"
            if self.blocks.add_until(value, int(self.now()) + ttl, reason, True, self.now()):
                out["added"] += 1
                if value not in imported:
                    imported.append(value)
        self.store.set(_IMPORTED, json.dumps(imported[-20000:]), 0)
        self.store.set("draco:crowdsec:started", "1", 86400 * 365)
        self.store.set("draco:crowdsec:last", f"{int(self.now())}|ok +{out['added']} -{out['removed']}", 86400 * 30)
        return out

    def _imported(self) -> list:
        try:
            return [v for v in json.loads(self.store.get(_IMPORTED) or "[]") if isinstance(v, str)]
        except ValueError:
            return []

    def _remove_if_ours(self, value: str) -> bool:
        """Only blocks that came from CrowdSec are lifted: a block the owner set stays."""
        entry = self.blocks.entry(value, self.now())
        if not entry or not str(entry.get("reason", "")).startswith(REASON):
            return False
        self.blocks.remove(value)
        return True


def crowdsec_line(event: DracoEvent, host: str = "") -> str:
    """One line for the CrowdSec agent (server/crowdsec: parser draco-insomnis-logs)."""
    return json.dumps({
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.time)),
        "ip": event.ip,
        "host": host,
        "endpoint": event.endpoint,
        "verdict": event.verdict,
        "reasons": ",".join(event.reasons),
        "user_agent": event.user_agent,
    }, separators=(",", ":"), ensure_ascii=False)
