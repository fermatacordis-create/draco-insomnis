"""WSGI: Flask, Django, Bottle, Pyramid… A plain WSGI middleware, no dependency.

    # Flask
    from draco_insomnis.wsgi import DracoWSGI
    app.wsgi_app = DracoWSGI(app.wsgi_app, waf="block")

    # Django (wsgi.py)
    application = DracoWSGI(get_wsgi_application(), waf="block")

If Draco itself fails, the request goes through.
"""
from __future__ import annotations

import io
from typing import Optional

from .asgi import MAX_BODY, read_scope
from .gatekeeper import Gatekeeper


def _scope(environ: dict) -> dict:
    """The WSGI environ in the shape read_scope() reads."""
    headers = []
    for key, value in environ.items():
        if key.startswith("HTTP_"):
            headers.append((key[5:].replace("_", "-").lower().encode("latin-1"), str(value).encode("latin-1")))
    for key in ("CONTENT_TYPE", "CONTENT_LENGTH"):
        if environ.get(key):
            headers.append((key.replace("_", "-").lower().encode(), str(environ[key]).encode("latin-1")))
    # PEP 3333: PATH_INFO is the raw bytes read as latin-1; the script name comes first.
    path = (environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")) or "/"
    return {
        "method": environ.get("REQUEST_METHOD", "GET"),
        "raw_path": path.encode("latin-1", "replace"),
        "query_string": environ.get("QUERY_STRING", "").encode("latin-1", "replace"),
        "headers": headers,
        "client": (environ.get("REMOTE_ADDR", ""), 0),
        "scheme": environ.get("wsgi.url_scheme", "http"),
    }


class DracoWSGI:
    def __init__(self, app, gate: Optional[Gatekeeper] = None, **options):
        self.app = app
        self.gate = gate if gate is not None else Gatekeeper(**options)

    def __call__(self, environ, start_response):
        answer = None
        try:
            body = None
            kind = environ.get("CONTENT_TYPE", "").lower()
            length = str(environ.get("CONTENT_LENGTH", "") or "")
            if environ.get("REQUEST_METHOD") in ("POST", "PUT", "PATCH") and ("json" in kind or "x-www-form-urlencoded" in kind) \
                    and length.isdigit() and int(length) <= MAX_BODY:
                body = environ["wsgi.input"].read(int(length))
                # Handed on unchanged.
                environ["wsgi.input"] = io.BytesIO(body)
            answer = self.gate.decide(read_scope(_scope(environ), body))
        except Exception:  # noqa: BLE001 - Draco failing never takes the site with it
            answer = None
        if answer is not None:
            status, headers, text = self.gate.render(answer)
            reason = {200: "OK", 403: "Forbidden", 429: "Too Many Requests"}[status]
            start_response(f"{status} {reason}", list(headers.items()))
            return [text.encode("utf-8")]
        extra = self.gate.security_headers(environ.get("wsgi.url_scheme") == "https")
        if not extra:
            return self.app(environ, start_response)

        def start_with_headers(status, headers, exc_info=None):
            have = {k.lower() for k, _ in headers}
            return start_response(status, [*headers, *[(k, v) for k, v in extra.items() if k.lower() not in have]], exc_info)

        return self.app(environ, start_with_headers)
