""""This is a mistake": a person the firewall stopped asks the owner to look again, from the 403 page —
the same form, signatures and limits as src/Core/Review.php and js/src/core/review.ts
(tests/vectors/review.json).

The form is signed for the address and the moment it was shown, carries the rule sealed (the page
never says what matched), has a trap field and is limited per address (3 a day) and per site (50 a
day). Draco never writes to the person who asks: that would let anyone make the site send mail.
"""
from __future__ import annotations

import hashlib
import hmac
import html
import re
import time
from dataclasses import dataclass
from typing import Dict, Optional

FIELD = "draco_review"
ENDPOINT = "review"
_MAX_PER_IP_DAY = 3
_MAX_PER_DAY = 50
_VALID_FOR = 86400


@dataclass
class ReviewRequest:
    time: int
    ip: str
    #: The rule that stopped the visitor ("sqli", "blocked", "geo"…); '' when it could not be read.
    rule: str
    email: str
    message: str
    user_agent: str


def _hmac(secret: str, data: str) -> bytes:
    return hmac.new(secret.encode(), data.encode(), hashlib.sha256).digest()


def _clean_rule(rule: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", rule.lower())


def seal(secret: str, ip: str, ts: str, rule: str) -> str:
    """The rule hidden from the visitor: XOR with a key from the secret, the address and the moment."""
    plain = _clean_rule(rule)[:32].encode().ljust(32, b"\0")
    key = _hmac(secret, f"review-rule|{ip}|{ts}")
    return bytes(a ^ b for a, b in zip(plain, key)).hex()


def open_sealed(secret: str, ip: str, ts: str, sealed: str) -> str:
    """The rule from seal(), or '' when the value is not one."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sealed or ""):
        return ""
    key = _hmac(secret, f"review-rule|{ip}|{ts}")
    rule = bytes(a ^ b for a, b in zip(bytes.fromhex(sealed), key)).rstrip(b"\0")
    try:
        text = rule.decode()
    except UnicodeDecodeError:
        return ""
    return text if re.fullmatch(r"[a-z0-9_]*", text) else ""


def sign(secret: str, ip: str, rule: str, ts: str) -> str:
    return _hmac(secret, f"review|{ip}|{rule}|{ts}").hex()


def form(secret: str, ip: str, why: str, now: float, labels: Dict[str, str]) -> str:
    """The form under the 403 text, already escaped."""
    h = lambda s: html.escape(s, quote=True)  # noqa: E731
    ts = str(int(now))
    rule = _clean_rule(why)
    return (
        '<form method="post" action="">'
        f'<input type="hidden" name="{FIELD}" value="1">'
        f'<input type="hidden" name="draco_rule" value="{h(seal(secret, ip, ts, rule))}">'
        f'<input type="hidden" name="draco_ts" value="{h(ts)}">'
        f'<input type="hidden" name="draco_sig" value="{h(sign(secret, ip, rule, ts))}">'
        '<p class="hp"><label>Website <input type="text" name="draco_website" tabindex="-1" autocomplete="off"></label></p>'
        f'<label for="draco-r-email">{h(labels["email"])}</label>'
        '<input id="draco-r-email" type="email" name="draco_email" required maxlength="190">'
        f'<label for="draco-r-msg">{h(labels["message"])}</label>'
        '<textarea id="draco-r-msg" name="draco_message" rows="3" maxlength="500" required></textarea>'
        f'<button type="submit">{h(labels["button"])}</button>'
        "</form>"
    )


def is_request(method: str, fields: Optional[Dict[str, str]]) -> bool:
    return method == "POST" and (fields or {}).get(FIELD, "") == "1"


_EMAIL = re.compile(r"^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", re.I | re.A)


def accept(store, secret: str, ip: str, user_agent: str, post: Dict[str, str], now: float) -> Optional[ReviewRequest]:
    """Checks a request and returns it when it passes; the visitor gets the same thanks either way."""
    ts = post.get("draco_ts", "")
    rule = open_sealed(secret, ip, ts, post.get("draco_rule", ""))
    email = post.get("draco_email", "").strip().lower()
    message = re.sub(r"<(script|style)[^>]*?>.*?</\1>|<[^>]*>", "", post.get("draco_message", ""), flags=re.I | re.S)
    message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", message).strip()[:500]
    fresh = ts.isdigit() and int(ts) <= now and now - int(ts) < _VALID_FOR
    ok = (fresh and hmac.compare_digest(sign(secret, ip, rule, ts), post.get("draco_sig", ""))
          and post.get("draco_website", "") == "" and bool(_EMAIL.match(email)) and len(email) <= 190 and message != "")
    if not ok:
        return None
    day = time.strftime("%Y%m%d", time.gmtime(now))
    if store.bump(f"draco:review:ip:{ip}", _VALID_FOR) > _MAX_PER_IP_DAY:
        return None
    if store.bump(f"draco:review:day:{day}", _VALID_FOR) > _MAX_PER_DAY:
        return None
    return ReviewRequest(int(now), ip, rule, email, message, user_agent[:255])
