"""The adapters inside real frameworks: FastAPI (ASGI, served by uvicorn), Flask and Django (WSGI).
Needs: pip install fastapi uvicorn flask django. Run: python tests/e2e_frameworks.py"""
import http.client
import re
import socket
import sys
import threading
import time
import urllib.parse

from draco_insomnis.asgi import DracoASGI
from draco_insomnis.wsgi import DracoWSGI

ATTACK = "/search?q=1%27%20union%20select%20password%20from%20users--%20"
UA = {"User-Agent": "Mozilla/5.0 Chrome/131.0"}
fails = 0


def check(name, ok):
    global fails
    print(("ok   - " if ok else "FAIL - ") + name)
    fails += 0 if ok else 1


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def call(port, path, method="GET", body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {**UA, **(headers or {})}
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    out = (r.status, {k.lower(): v for k, v in r.getheaders()}, data)
    c.close()
    return out


def hidden(html):
    return dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)">', html))


def suite(name, port, asked):
    status, headers, _ = call(port, "/")
    check(f"{name}: an ordinary page passes", status == 200)
    check(f"{name}: security headers are added", headers.get("x-content-type-options") == "nosniff")
    check(f"{name}: the app's own header wins", call(port, "/own")[1].get("x-frame-options") == "DENY")
    status, _, body = call(port, ATTACK)
    check(f"{name}: SQL injection gets 403", status == 403)
    check(f"{name}: the page never names the rule", "sqli" not in body)
    check(f"{name}: .env probe gets 403", call(port, "/.env")[0] == 403)
    form = urllib.parse.urlencode({"message": "x'; DROP TABLE users; --"})
    check(f"{name}: a posted form is inspected", call(port, "/contact", "POST", form, {"Content-Type": "application/x-www-form-urlencoded"})[0] == 403)
    js = '{"q": "\' OR \'1\'=\'1"}'
    check(f"{name}: a JSON body is inspected", call(port, "/api", "POST", js, {"Content-Type": "application/json"})[0] == 403)
    ok = call(port, "/echo", "POST", urllib.parse.urlencode({"name": "Ana"}), {"Content-Type": "application/x-www-form-urlencoded"})
    check(f"{name}: the app still reads the body Draco read", ok[0] == 200 and "Ana" in ok[2])
    fields = {**hidden(body), "draco_email": "ana@example.org", "draco_message": "I was searching", "draco_website": ""}
    status, _, thanks = call(port, ATTACK, "POST", urllib.parse.urlencode(fields), {"Content-Type": "application/x-www-form-urlencoded"})
    check(f"{name}: the review request is thanked", status == 200 and "Request sent" in thanks)
    check(f"{name}: and reaches the owner", [a.email for a in asked] == ["ana@example.org"])


def options(asked):
    return dict(waf="block", headers=True, review={"secret": "owner-secret-0123456789", "on_request": asked.append})


def fastapi_app(asked):
    from fastapi import FastAPI, Request
    from fastapi.responses import PlainTextResponse

    app = FastAPI()

    @app.get("/")
    def home():
        return PlainTextResponse("home")

    @app.get("/own")
    def own():
        return PlainTextResponse("own", headers={"X-Frame-Options": "DENY"})

    @app.post("/echo")
    async def echo(request: Request):
        return PlainTextResponse((await request.form()).get("name", ""))

    app.add_middleware(DracoASGI, **options(asked))
    return app


def flask_app(asked):
    from flask import Flask, request

    app = Flask("draco")

    @app.get("/")
    def home():
        return "home"

    @app.get("/own")
    def own():
        return "own", 200, {"X-Frame-Options": "DENY"}

    @app.post("/echo")
    def echo():
        return request.form.get("name", "")

    app.wsgi_app = DracoWSGI(app.wsgi_app, **options(asked))
    return app


def django_app(asked):
    from django.conf import settings
    from django.http import HttpResponse
    from django.urls import path

    def home(request):
        return HttpResponse("home")

    def own(request):
        r = HttpResponse("own")
        r["X-Frame-Options"] = "DENY"
        return r

    def echo(request):
        return HttpResponse(request.POST.get("name", ""))

    settings.configure(DEBUG=False, ALLOWED_HOSTS=["*"], ROOT_URLCONF=__name__, SECRET_KEY="test", MIDDLEWARE=[])
    globals()["urlpatterns"] = [path("", home), path("own", own), path("echo", echo)]
    import django
    from django.core.wsgi import get_wsgi_application

    django.setup()
    return DracoWSGI(get_wsgi_application(), **options(asked))


def serve_wsgi(app):
    from wsgiref.simple_server import WSGIRequestHandler, make_server

    class Quiet(WSGIRequestHandler):
        def log_message(self, *a):
            pass

    srv = make_server("127.0.0.1", 0, app, handler_class=Quiet)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_port


def serve_asgi(app):
    import uvicorn

    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return port


for name, make, serve in (("fastapi", fastapi_app, serve_asgi), ("flask", flask_app, serve_wsgi), ("django", django_app, serve_wsgi)):
    asked = []
    suite(name, serve(make(asked)), asked)

print()
print(f"{fails} check(s) failed" if fails else "all framework checks passed")
sys.exit(1 if fails else 0)
