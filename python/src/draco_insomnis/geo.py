"""The visitor's country without Cloudflare: the same file and lookup as src/Core/Geo.php and
js/src/geo.ts (DB-IP "IP to Country Lite", CC BY 4.0, built monthly by this project). A binary search
over fixed-size records, about 20 small reads, nothing sent anywhere. Private, reserved and unknown
addresses have no country, so they are never filtered by country.

    geo = GeoFile("/var/lib/myapp/draco-geo.bin")   # downloaded now and kept fresh
    app.add_middleware(DracoASGI, waf="block", geo={"mode": "block", "countries": ["XX"], "lookup": geo})
"""
from __future__ import annotations

import calendar
import hashlib
import os
import struct
import threading
import time
import urllib.request
from typing import Optional

from .net import to_bytes, unmap

SOURCE = "https://github.com/fermatacordis-create/draco-insomnis/releases/download/geo/draco-geo.bin"
MAX_AGE_DAYS = 35
_HEADER = 22
_DAY = 86400


def _read_head(head: bytes, size: int):
    if len(head) < _HEADER or head[:6] != b"DRGEO1":
        return None
    v4, v6 = struct.unpack(">II", head[14:22])
    if size != _HEADER + v4 * 6 + v6 * 18:
        return None
    return v4, v6, head[6:14].decode("ascii", "replace")


class GeoFile:
    def __init__(self, path: str, update: bool = True, source: str = SOURCE):
        """update: download the list when missing or older than 35 days, now and then once a day
        (a daemon thread). False if you refresh the file yourself."""
        self.path = path
        self.source = source
        self.last_error = ""
        self._fh = None
        self._info = None
        self._tried = 0.0
        self._lock = threading.Lock()
        if update:
            def loop():
                while True:
                    try:
                        self.refresh()
                    except Exception:  # noqa: BLE001 - never kill the app over the country list
                        pass
                    time.sleep(_DAY)
            threading.Thread(target=loop, name="draco-geo", daemon=True).start()

    def _open(self):
        if self._info is not None:
            return self._info
        # A missing file is looked for again at most once a minute.
        if time.time() - self._tried < 60:
            return None
        self._tried = time.time()
        try:
            fh = open(self.path, "rb")
        except OSError:
            return None
        info = _read_head(fh.read(_HEADER), os.fstat(fh.fileno()).st_size)
        if info is None:
            fh.close()
            return None
        self._fh, self._info = fh, info
        return info

    def country(self, ip: str) -> Optional[str]:
        """Two-letter country, or None (no file yet, private or unknown address)."""
        addr = to_bytes(unmap((ip or "").strip()))
        if addr is None:
            return None
        with self._lock:
            info = self._open()
            if info is None:
                return None
            v4c, v6c, _ = info
            is4 = len(addr) == 4
            count, size = (v4c, 6) if is4 else (v6c, 18)
            width = size - 2
            base = _HEADER + (0 if is4 else v4c * 6)
            lo, hi, found = 0, count - 1, -1
            fh = self._fh
            while lo <= hi:
                mid = (lo + hi) // 2
                fh.seek(base + mid * size)
                if fh.read(width) <= addr:
                    found, lo = mid, mid + 1
                else:
                    hi = mid - 1
            if found < 0:
                return None
            fh.seek(base + found * size + width)
            cc = fh.read(2).decode("ascii", "replace")
        return cc if len(cc) == 2 and cc.isalpha() and cc.isupper() else None

    def built(self) -> str:
        """The date the file was built (YYYYMMDD), or '' when it is missing or not a Draco file."""
        with self._lock:
            info = self._open()
        return info[2] if info else ""

    def stale(self, now: Optional[float] = None) -> bool:
        b = self.built()
        if not b:
            return True
        built = calendar.timegm((int(b[:4]), int(b[4:6]), int(b[6:8]), 0, 0, 0))
        return (time.time() if now is None else now) - built > MAX_AGE_DAYS * _DAY

    def refresh(self) -> str:
        """Downloads the list when it is missing or stale. '' when done or not needed, otherwise why not."""
        self.last_error = "" if not self.stale() else self.update()
        return self.last_error

    def update(self) -> str:
        """Downloads, checks the published SHA-256, and only then replaces the old file.
        '' when done; otherwise "checksum", "download", "format" or "folder"."""
        def get(url: str) -> Optional[bytes]:
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Draco-Insomnis"}), timeout=120) as res:
                    return res.read() if res.status == 200 else None
            except Exception:  # noqa: BLE001
                return None

        sum_ = get(self.source + ".sha256")
        want = sum_.decode("ascii", "replace").strip()[:64].lower() if sum_ else ""
        if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
            return "checksum"
        body = get(self.source)
        if body is None or hashlib.sha256(body).hexdigest() != want:
            return "download"
        if _read_head(body[:_HEADER], len(body)) is None:
            return "format"
        part = self.path + ".part"
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(part, "wb") as f:
                f.write(body)
            os.replace(part, self.path)
        except OSError:
            try:
                os.unlink(part)
            except OSError:
                pass
            return "folder"
        self.close()
        return ""

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
            self._fh, self._info, self._tried = None, None, 0.0
