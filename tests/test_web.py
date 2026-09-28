"""The web backend, tested through a real HTTP server on a free port."""

import base64
import json
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from backend.server import make_server

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"


class TestWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = make_server("127.0.0.1", 0, verbose=False)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def call(self, path, body=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def api(self, path, body=None):
        status, data = self.call(path, body)
        return status, json.loads(data)

    @staticmethod
    def b64(data):
        return base64.b64encode(data).decode()

    # ----- pages -----
    def test_pages_served(self):  # WEB-01
        for path, marker in (("/", b"Digital Signature Verifier"), ("/static/app.js", b"fetch"),
                             ("/static/style.css", b":root"), ("/samples/invoice.txt", b"")):
            with self.subTest(path=path):
                status, data = self.call(path)
                self.assertEqual(status, 200)
                self.assertIn(marker, data)

    def test_path_traversal_blocked(self):  # WEB-02
        for path in ("/static/..%2f..%2fbackend/api.py", "/samples/%2e%2e/pki/ca/root/key.json",
                     "/samples/../pki/ca/root/key.json", "/nope"):
            with self.subTest(path=path):
                self.assertEqual(self.call(path)[0], 404)

    # ----- verify -----
    def test_verify_samples(self):  # WEB-03
        status, listing = self.api("/api/samples")
        self.assertEqual(status, 200)
        for s in listing["samples"]:
            with self.subTest(sample=s["id"]):
                body = {"document_b64": self.b64((SAMPLES / s["file"]).read_bytes()), "filename": s["file"]}
                if s["signature"]:
                    body["signature_b64"] = self.b64((SAMPLES / s["signature"]).read_bytes())
                status, report = self.api("/api/verify", body)
                self.assertEqual(status, 200)
                self.assertEqual(report["overall"], s["expected"])

    def test_verify_bad_input(self):  # WEB-04
        for body in ({}, {"document_b64": "%%%"}, {"document_b64": 5}):
            with self.subTest(body=body):
                status, data = self.api("/api/verify", body)
                self.assertEqual(status, 400)
                self.assertFalse(data["ok"])

    def test_bad_json_and_unknown_route(self):  # WEB-05
        self.assertEqual(self.call("/api/verify", raw=b"{not json")[0], 400)
        self.assertEqual(self.call("/api/verify", raw=b"[1, 2]")[0], 400)
        self.assertEqual(self.call("/api/nothing", {})[0], 404)

    # ----- sign -----
    def test_sign_pdf_then_verify(self):  # WEB-06
        status, ids = self.api("/api/identities")
        self.assertIn("alice", [i["id"] for i in ids["identities"]])
        status, out = self.api("/api/sign/pdf", {"signer": "alice", "title": "Test", "text": "Hello",
                                                 "reason": "Testing", "location": "Delhi"})
        self.assertEqual(status, 200)
        self.assertTrue(out["filename"].endswith(".pdf"))
        status, report = self.api("/api/verify", {"document_b64": out["file_b64"], "filename": out["filename"]})
        self.assertEqual(report["overall"], "VALID")
        self.assertEqual(report["signatures"][0]["reason"], "Testing")

    def test_sign_file_then_verify(self):  # WEB-07
        data = self.b64(b"any bytes \x00\xff")
        status, out = self.api("/api/sign/file", {"signer": "bob", "file_b64": data, "filename": "a.bin"})
        self.assertEqual((status, out["filename"]), (200, "a.bin.p7s"))
        status, report = self.api("/api/verify", {"document_b64": data, "signature_b64": out["file_b64"]})
        self.assertEqual(report["overall"], "VALID")

    def test_sign_bad_input(self):  # WEB-08
        for path, body in (("/api/sign/pdf", {"signer": "../ca/root", "title": "t", "text": "x"}),
                           ("/api/sign/pdf", {"signer": "alice", "title": "", "text": "x"}),
                           ("/api/sign/file", {"signer": "alice"}),
                           ("/api/identities", {"name": ""}),
                           ("/api/identities", {"name": "A", "email": "bad"})):
            with self.subTest(path=path, body=body):
                self.assertEqual(self.api(path, body)[0], 400)

    def test_trust_list(self):  # WEB-09
        status, data = self.api("/api/trust")
        self.assertEqual([r["name"] for r in data["roots"]], ["DSV Demo Root CA"])

    # ----- maths -----
    def test_math_endpoints(self):  # WEB-10
        cases = (("/api/math/gcd", {"a": "3120", "b": "17"}, "gcd", "1"),
                 ("/api/math/inverse", {"a": "17", "n": "3120"}, "inverse", "2753"),
                 ("/api/math/modpow", {"base": "2678", "exponent": "17", "modulus": "3233"}, "result", "1128"),
                 ("/api/math/prime", {"n": "561"}, "miller_rabin", False),
                 ("/api/math/crt", {"r1": "2", "m1": "3", "r2": "3", "m2": "5"}, "x", "8"),
                 ("/api/math/rsa", {"p": "61", "q": "53", "e": "17", "m": "65"}, "d", "2753"))
        for path, body, key, want in cases:
            with self.subTest(path=path):
                status, data = self.api(path, body)
                self.assertEqual((status, data[key]), (200, want))

    def test_math_bad_input(self):  # WEB-11
        for path, body in (("/api/math/gcd", {"a": "x", "b": "1"}),                            ("/api/math/modpow", {"base": "2", "exponent": "3", "modulus": "0"}),
                           ("/api/math/rsa", {"p": "61", "q": "53", "e": "17", "m": "5000"}),
                           ("/api/math/prime", {"n": "1" + "0" * 2000})):
            with self.subTest(path=path, body=body):
                self.assertEqual(self.api(path, body)[0], 400)

    def test_no_inverse_explained(self):  # WEB-13
        status, data = self.api("/api/math/inverse", {"a": "2", "n": "4"})
        self.assertEqual((status, data["inverse"], data["gcd"]), (200, None, "2"))

    def test_attacks(self):  # WEB-12
        status, data = self.api("/api/attacks/factor", {"n": "600313907681", "e": "65537"})
        self.assertTrue(data["found"])
        self.assertEqual(int(data["p"]) * int(data["q"]), 600313907681)
        self.assertEqual(self.api("/api/attacks/factor", {"n": "97"})[0], 400)
        status, data = self.api("/api/attacks/forgery", {"m1": "5", "m2": "7"})
        self.assertTrue(data["multiplicative"]["textbook_accepts"])
        self.assertFalse(data["multiplicative"]["hashed_accepts"])


if __name__ == "__main__":
    unittest.main()
