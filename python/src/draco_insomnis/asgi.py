"""ASGI: FastAPI, Starlette, Django (ASGI), Quart, Litestar… A plain ASGI middleware, no dependency.

    from fastapi import FastAPI
    from draco_insomnis.asgi import DracoASGI

    app = FastAPI()
    app.add_middleware(DracoASGI, waf="block", headers=True)

The engine runs in a worker thread (it may ask the DNS to prove a search engine), so the event loop
never waits on it. If Draco itself fails, the request goes through.
"""
from __future__ import annotations

import asyncio
import json
from typing import Optional
from urllib.parse import parse_qsl

from .gatekeeper import Gatekeeper
from .net import CLOUDFLARE, contains
from .request import DracoRequest, remote, url_decode
from .waf import flatten

MAX_BODY = 65536


def read_scope(scope: dict, body: Optional[bytes] = None) -> DracoRequest:
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
    raw_path = scope.get("raw_path")
    path = raw_path.decode("latin-1").split("?", 1)[0] if raw_path else scope.get("path", "/")
    raw_query = scope.get("query_string", b"").decode("latin-1")
    params = flatten(dict(parse_qsl(raw_query, keep_blank_values=True)))
    form = None
    if body:
        kind = headers.get("content-type", "").lower()
        try:
            text = body.decode("utf-8", "replace")
            if "json" in kind:
                data = json.loads(text)
                params += flatten(data, 200 - min(len(params), 200))
                if isinstance(data, dict):
                    form = {k: v for k, v in data.items() if isinstance(v, str)}
            else:
                pairs = dict(parse_qsl(text, keep_blank_values=True))
                params += flatten(pairs, 200 - min(len(params), 200))
                form = pairs
        except ValueError:
            params.append(body[:MAX_BODY].decode("utf-8", "replace"))
    client = scope.get("client") or ("", 0)
    r = DracoRequest(
        method=scope.get("method", "GET").upper(),
        path=url_decode(path.encode("latin-1").decode("utf-8", "replace") if raw_path else path),
        query=url_decode(raw_query, True),
        params=params,
        user_agent=headers.get("user-agent", ""),
        remote_addr=str(client[0] or ""),
        cf_connecting_ip=headers.get("cf-connecting-ip", ""),
        forwarded_for=headers.get("x-forwarded-for", ""),
        accept=headers.get("accept", ""),
        ajax=headers.get("x-requested-with", "").lower() == "xmlhttprequest",
        form=form,
    )
    # Cloudflare's country header, only when the connection really comes from Cloudflare.
    if contains(CLOUDFLARE, remote(r)):
        r.country = headers.get("cf-ipcountry", "")
    return r


class DracoASGI:
    def __init__(self, app, gate: Optional[Gatekeeper] = None, **options):
        self.app = app
        self.gate = gate if gate is not None else Gatekeeper(**options)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        kind = headers.get(b"content-type", b"").lower()
        length = headers.get(b"content-length", b"")
        body = b""
        replay = receive
        # Forms and JSON up to 64 KB are read once and handed on unchanged.
        if scope.get("method") in ("POST", "PUT", "PATCH") and (b"json" in kind or b"x-www-form-urlencoded" in kind) \
                and length.isdigit() and int(length) <= MAX_BODY:
            messages = []
            while True:
                message = await receive()
                messages.append(message)
                if message.get("type") != "http.request":
                    break
                body += message.get("body", b"")
                if not message.get("more_body", False):
                    break

            async def replay():
                return messages.pop(0) if messages else await receive()

        answer = None
        try:
            r = read_scope(scope, body or None)
            answer = await asyncio.to_thread(self.gate.decide, r)
        except Exception:  # noqa: BLE001 - Draco failing never takes the site with it
            answer = None
        if answer is not None:
            status, out_headers, text = self.gate.render(answer)
            await send({"type": "http.response.start", "status": status,
                        "headers": [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in out_headers.items()]})
            await send({"type": "http.response.body", "body": text.encode("utf-8")})
            return
        extra = self.gate.security_headers(scope.get("scheme") == "https")

        async def send_with_headers(message):
            if extra and message.get("type") == "http.response.start":
                have = {k.lower() for k, _ in message.get("headers", [])}
                message = {**message, "headers": [*message.get("headers", []),
                                                  *[(k.lower().encode(), v.encode()) for k, v in extra.items() if k.lower().encode() not in have]]}
            await send(message)

        await self.app(scope, replay, send_with_headers)
