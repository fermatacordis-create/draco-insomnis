"""The engine without a server: the same behaviour the PHP and JavaScript tests check."""
import hashlib
import http.server
import json
import os
import pathlib
import re
import struct
import tempfile
import threading
import unittest

from draco_insomnis import Gatekeeper, GeoFile, MemoryStore, crowdsec_line, open_sealed, seal, sign
from draco_insomnis.crowdsec import seconds
from draco_insomnis.net import network, to_bytes
from draco_insomnis.request import DracoRequest, client_ip
from draco_insomnis.store import DracoEvent, valid_net

ROOT = pathlib.Path(__file__).resolve().parents[2]
NOW = 1_800_000_000
UA = "Mozilla/5.0 Chrome/131.0"


def req(**kw):
    base = dict(method="GET", path="/", query="", params=[], user_agent=UA, remote_addr="198.51.100.20")
    base.update(kw)
    return DracoRequest(**base)


def attack(**kw):
    return req(query="../../etc/passwd", params=["../../etc/passwd"], **kw)


def hidden(html):
    return dict(re.findall(r'<input type="hidden" name="([a-z_]+)" value="([^"]*)">', html))


class NoDNS:
    def reverse(self, ip):
        raise OSError

    def lookup(self, host):
        raise OSError


class Net(unittest.TestCase):
    def test_addresses_like_php(self):
        self.assertIsNone(to_bytes("01.2.3.4"))
        self.assertIsNone(to_bytes("fe80::1%eth0"))
        self.assertEqual(network("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64")
        self.assertEqual(network("203.0.113.9"), "203.0.113.0/24")
        self.assertTrue(valid_net("203.0.113.0/24"))
        self.assertFalse(valid_net("10.0.0.0/8"))

    def test_a_forged_forwarded_for_never_counts(self):
        r = req(remote_addr="203.0.113.5", forwarded_for="1.2.3.4")
        self.assertEqual(client_ip(r, "xff"), "203.0.113.5", "not from a trusted proxy")
        r = req(remote_addr="10.0.0.2", forwarded_for="1.2.3.4, 198.51.100.7, 10.0.0.9")
        self.assertEqual(client_ip(r, "xff"), "198.51.100.7", "read from the right")


class Review(unittest.TestCase):
    def test_the_same_signatures_as_php(self):
        v = json.loads((ROOT / "tests" / "vectors" / "review.json").read_text())
        for c in v["cases"]:
            with self.subTest(c["ip"]):
                self.assertEqual(seal(v["secret"], c["ip"], str(c["ts"]), c["rule"]), c["sealed"])
                self.assertEqual(open_sealed(v["secret"], c["ip"], str(c["ts"]), c["sealed"]), c["opened"])
                self.assertEqual(sign(v["secret"], c["ip"], c["rule"], str(c["ts"])), c["sig"])

    def gate(self, now=NOW):
        asked = []
        g = Gatekeeper(waf="block", resolver=NoDNS(), review={"secret": "owner-secret-0123456789", "on_request": asked.append}, now=lambda: now)
        return g, asked

    def test_form_then_request_then_thanks(self):
        g, asked = self.gate()
        blocked = g.decide(attack())
        status, _, body = g.render(blocked)
        self.assertEqual(status, 403)
        self.assertIn("Ask for a review", body)
        self.assertNotIn("traversal", body)
        fields = {**hidden(body), "draco_email": "Ana@Example.org", "draco_message": "I was <b>reading</b>", "draco_website": ""}
        answer = g.decide(req(method="POST", form=fields))
        self.assertEqual(g.render(answer)[0], 200)
        self.assertEqual([(a.email, a.message, a.rule) for a in asked], [("ana@example.org", "I was reading", "traversal")])
        self.assertEqual(g.events()[-1].verdict, "pending")
        for _ in range(4):
            g.decide(req(method="POST", form=fields))
        self.assertEqual(len(asked), 3, "3 a day from one address")

    def test_forged_requests_reach_nobody(self):
        g, asked = self.gate()
        fields = {**hidden(g.render(g.decide(attack()))[2]), "draco_email": "a@example.org", "draco_message": "x", "draco_website": ""}
        for bad in ({"draco_sig": "0" * 64}, {"draco_website": "http://spam"}, {"draco_email": "nope"}):
            self.assertEqual(g.decide(req(method="POST", form={**fields, **bad})).status, 200)
        g.decide(req(method="POST", form=fields, remote_addr="203.0.113.7"))
        later, late_asked = self.gate(NOW + 86400)
        later.decide(req(method="POST", form=fields))
        self.assertEqual(asked + late_asked, [])


class Firewall(unittest.TestCase):
    def test_log_block_and_the_automatic_block(self):
        seen = []
        g = Gatekeeper(waf="block", resolver=NoDNS(), on_event=lambda e: seen.append(e.endpoint), now=lambda: NOW)
        self.assertIsNone(g.decide(req(query="q=european union select committee", params=["european union select committee"])))
        self.assertEqual(g.decide(attack()).why, "traversal")
        self.assertEqual(g.decide(req(path="/.env")).why, "probe")
        for _ in range(4):
            g.decide(attack())
        self.assertTrue(g.blocks.is_blocked("198.51.100.20", NOW))
        self.assertIsNone(g.decide(req()), "a blocked address may still read")
        self.assertEqual(g.decide(req(method="POST", path="/contact")).why, "blocked")
        self.assertEqual(seen[:2], ["waf:traversal", "waf:probe"])
        logging = Gatekeeper(waf="log", resolver=NoDNS())
        self.assertIsNone(logging.decide(attack()))
        self.assertEqual(logging.events()[-1].endpoint, "waf:traversal")

    def test_admins_and_excepted_paths_are_never_inspected(self):
        g = Gatekeeper(waf="block", admin_ips=["198.51.100.20"], except_paths=["webhooks"], resolver=NoDNS())
        self.assertIsNone(g.decide(attack()))
        self.assertIsNone(Gatekeeper(waf="block", except_paths=["webhooks"]).decide(attack(path="/webhooks/stripe")))

    def test_pace_counts_pages_only(self):
        g = Gatekeeper(waf="off", pace="block", rate_ip=10, resolver=NoDNS(), now=lambda: NOW)
        answers = [g.decide(req(accept="text/html")) for _ in range(12)]
        self.assertEqual(answers[:10], [None] * 10)
        self.assertEqual(answers[10].status, 429)
        self.assertGreater(answers[10].retry, 0)
        self.assertIsNone(g.decide(req(accept="application/json")), "API calls are not pages")

    def test_headers(self):
        g = Gatekeeper(headers=True, hsts=True)
        self.assertEqual(g.security_headers(True)["X-Content-Type-Options"], "nosniff")
        self.assertNotIn("Strict-Transport-Security", g.security_headers(False))


def geo_fixture(built=b"20261113"):
    v4 = [("0.0.0.0", b"--"), ("1.0.0.0", b"AU"), ("1.0.1.0", b"CN"), ("1.0.4.0", b"--"), ("203.0.113.0", b"ES"), ("203.0.114.0", b"--")]
    v6 = [("::", b"--"), ("2a00::", b"ES"), ("2a01::", b"--")]
    return b"DRGEO1" + built + struct.pack(">II", len(v4), len(v6)) + b"".join(to_bytes(ip) + cc for ip, cc in v4 + v6)


class Geo(unittest.TestCase):
    def test_lookup_like_geo_php(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "g.bin")
            pathlib.Path(path).write_bytes(geo_fixture())
            geo = GeoFile(path, update=False)
            self.assertEqual(geo.country("1.0.0.200"), "AU")
            self.assertEqual(geo.country("1.0.3.255"), "CN")
            self.assertIsNone(geo.country("1.0.4.0"))
            self.assertEqual(geo.country("::ffff:203.0.113.10"), "ES")
            self.assertEqual(geo.country("2a00:1450::1"), "ES")
            self.assertIsNone(geo.country("not an ip"))
            self.assertEqual(geo.built(), "20261113")
            g = Gatekeeper(waf="block", resolver=NoDNS(), geo={"mode": "block", "countries": ["CN"], "action": "block", "lookup": geo})
            self.assertEqual(g.decide(req(path="/login", remote_addr="1.0.2.3")).why, "geo")
            self.assertIsNone(g.decide(req(path="/", remote_addr="1.0.2.3")))
            self.assertIsNone(g.decide(req(path="/login", remote_addr="1.0.2.3", country="ES")))
            geo.close()

    def test_download_with_checksum(self):
        body = geo_fixture(b"20991231")
        state = {"sum": hashlib.sha256(body).hexdigest()}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                data = (state["sum"] + "  draco-geo.bin\n").encode() if self.path.endswith(".sha256") else body
                self.send_response(200)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as d:
                path = os.path.join(d, "sub", "g.bin")
                geo = GeoFile(path, update=False, source=f"http://127.0.0.1:{srv.server_port}/draco-geo.bin")
                self.assertEqual(geo.refresh(), "")
                self.assertEqual(geo.built(), "20991231")
                state["sum"] = "0" * 64
                self.assertEqual(geo.update(), "download")
                self.assertEqual(pathlib.Path(path).read_bytes()[6:14], b"20991231", "the old file stays")
                geo.close()
        finally:
            srv.shutdown()


class CrowdSecBridge(unittest.TestCase):
    def test_durations(self):
        self.assertEqual(seconds("3h59m40.5s"), 14381)
        self.assertEqual(seconds("250ms"), 1)
        self.assertEqual(seconds("-3s"), 0)

    def test_bans_join_and_leave_the_block_list(self):
        state = {"answer": {"new": [
            {"type": "ban", "value": "198.51.100.66", "duration": "4h", "scenario": "crowdsecurity/http-probing"},
            {"type": "ban", "value": "203.0.113.0/24", "duration": "1h", "scenario": "x"},
            {"type": "ban", "value": "10.0.0.0/8", "duration": "1h"},
            {"type": "ban", "value": "192.0.2.1", "duration": "4h"},
            {"type": "captcha", "value": "198.51.100.67", "duration": "4h"},
        ], "deleted": None}, "asked": []}

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                state["asked"].append((self.path, self.headers.get("X-Api-Key")))
                data = json.dumps(state["answer"]).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            g = Gatekeeper(waf="block", resolver=NoDNS(), admin_ips=["192.0.2.1"],
                           crowdsec={"url": f"http://127.0.0.1:{srv.server_port}", "api_key": "k3y"})
            g.blocks.add("203.0.113.200", 7, "Manual")
            self.assertEqual(g.crowdsec.sync(), {"added": 2, "removed": 0, "error": ""})
            self.assertTrue(state["asked"][0][0].endswith("startup=true&scopes=ip,range"))
            self.assertEqual(state["asked"][0][1], "k3y")
            self.assertEqual(g.decide(req(path="/login", remote_addr="198.51.100.66")).why, "blocked")
            self.assertEqual(g.decide(req(method="POST", remote_addr="203.0.113.9")).why, "blocked")
            self.assertIsNone(g.decide(req(path="/login", remote_addr="10.1.2.3")))
            state["answer"] = {"new": [], "deleted": [{"value": "198.51.100.66"}, {"value": "203.0.113.200"}]}
            self.assertEqual(g.crowdsec.sync(), {"added": 0, "removed": 1, "error": ""})
            self.assertIsNone(g.decide(req(path="/login", remote_addr="198.51.100.66")))
            self.assertTrue(g.blocks.is_blocked("203.0.113.200"), "the owner's block stays")
        finally:
            srv.shutdown()

    def test_a_dead_local_api_never_breaks_a_request(self):
        g = Gatekeeper(waf="block", resolver=NoDNS(), crowdsec={"url": "http://127.0.0.1:9", "api_key": "x", "timeout": 1})
        self.assertEqual(g.crowdsec.sync()["error"], "no answer")
        self.assertIsNone(g.decide(req()))

    def test_evidence_line(self):
        line = json.loads(crowdsec_line(DracoEvent(1_800_000_000, "198.51.100.9", "198.51.100.9", "waf:sqli", "bot", ["waf_sqli"], "curl/8", "/?q=1"), "shop.example"))
        self.assertEqual(line, {"time": "2027-01-15T08:00:00Z", "ip": "198.51.100.9", "host": "shop.example", "endpoint": "waf:sqli",
                                "verdict": "bot", "reasons": "waf_sqli", "user_agent": "curl/8"})


if __name__ == "__main__":
    unittest.main()
