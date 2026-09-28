"""End-to-end verification: shipped samples, files made by OpenSSL and pyHanko, and the demo PKI."""

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dsv import pki, verifier
from dsv.x509 import TrustStore, load_certificates

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
AT = datetime(2026, 10, 1, tzinfo=timezone.utc)  # inside the fixture certificates' validity
FIX_TRUST = TrustStore(load_certificates((FIX / "ca.pem").read_bytes()))
EMPTY = TrustStore([])


def run(doc, name="doc", sig=None, trust=FIX_TRUST, at=AT):
    return verifier.verify_upload(doc, name, sig, trust, at)


def statuses(report, i=0):
    return {c["id"]: c["status"] for c in report["signatures"][i]["checks"]}


class TestShippedSamples(unittest.TestCase):
    def test_every_sample_gives_expected_verdict(self):  # VER-01
        folder = ROOT / "samples"
        samples = json.loads((folder / "samples.json").read_text())["samples"]
        self.assertEqual(len(samples), 22)
        trust = TrustStore.from_folder(ROOT / "trust")
        for s in samples:
            with self.subTest(sample=s["id"]):
                doc = (folder / s["file"]).read_bytes()
                sig = (folder / s["signature"]).read_bytes() if s["signature"] else None
                report = verifier.verify_upload(doc, s["file"], sig, trust)
                self.assertEqual(report["overall"], s["expected"], s["title"])


class TestOpenSSLFiles(unittest.TestCase):
    doc = (FIX / "doc.txt").read_bytes()

    def test_rsa_detached_valid(self):  # VER-02
        r = run(self.doc, sig=(FIX / "rsa.p7s").read_bytes())
        self.assertEqual(r["overall"], "VALID")
        self.assertEqual(r["signatures"][0]["signer"]["name"], "Rsa Signer")

    def test_ecdsa_p256_valid(self):  # VER-03
        r = run(self.doc, sig=(FIX / "ec.p7s").read_bytes())
        self.assertEqual(r["overall"], "VALID")
        self.assertIn("P-256", r["signatures"][0]["algorithm"])

    def test_ecdsa_p384_self_signed_is_unknown(self):  # VER-04
        r = run(self.doc, sig=(FIX / "ec384.p7s").read_bytes())
        self.assertEqual(r["overall"], "UNKNOWN")
        self.assertEqual(statuses(r)["signature"], "pass")
        self.assertEqual(statuses(r)["chain"], "warn")

    def test_enveloping_p7m(self):  # VER-05
        r = run((FIX / "rsa.p7m").read_bytes(), "doc.p7m")
        self.assertEqual(r["overall"], "VALID")

    def test_sha1_without_attributes_is_weak(self):  # VER-06
        r = run(self.doc, sig=(FIX / "rsa-noattr-sha1.p7s").read_bytes())
        self.assertEqual(r["overall"], "UNKNOWN")
        self.assertEqual(statuses(r)["signature"], "pass")
        self.assertEqual(statuses(r)["algorithm"], "warn")

    def test_changed_document_invalid(self):  # VER-07
        for sig in ("rsa.p7s", "ec.p7s"):
            with self.subTest(sig=sig):
                r = run(self.doc + b"!", sig=(FIX / sig).read_bytes())
                self.assertEqual(r["overall"], "INVALID")
                self.assertEqual(statuses(r)["integrity"], "fail")

    def test_untrusted_when_ca_not_in_store(self):  # VER-08
        r = run(self.doc, sig=(FIX / "rsa.p7s").read_bytes(), trust=EMPTY)
        self.assertEqual(r["overall"], "UNKNOWN")

    def test_certificate_validity_uses_signing_time(self):  # VER-09
        later = datetime(2030, 1, 1, tzinfo=timezone.utc)
        # signed while the certificate was valid: still passes, with a note that it has expired since
        r = run(self.doc, sig=(FIX / "rsa.p7s").read_bytes(), at=later)
        check = [c for c in r["signatures"][0]["checks"] if c["id"] == "validity"][0]
        self.assertEqual(check["status"], "pass")
        self.assertIn("expired since", check["message"])
        # no signing time inside the signature: checked against "now", so it warns
        r = run(self.doc, sig=(FIX / "rsa-noattr-sha1.p7s").read_bytes(), at=later)
        self.assertEqual(statuses(r)["validity"], "warn")

    def test_flipped_signature_byte_invalid(self):  # VER-10
        sig = bytearray((FIX / "rsa.p7s").read_bytes())
        sig[-10] ^= 0x01  # inside the RSA signature value, which ends the SignerInfo
        r = run(self.doc, sig=bytes(sig))
        self.assertIn(r["overall"], ("INVALID", "ERROR"))

    def test_unsupported_algorithms_need_attention(self):  # VER-19
        for sig in ("rsa-pss.p7s", "ec521.p7s"):
            with self.subTest(sig=sig):
                r = run(self.doc, sig=(FIX / sig).read_bytes())
                self.assertEqual(r["overall"], "UNKNOWN")
                self.assertEqual(statuses(r)["signature"], "warn")
                self.assertIn("not supported", r["signatures"][0]["checks"][1]["message"])


class TestPyHankoPDFs(unittest.TestCase):
    def test_two_signatures_each(self):  # VER-11
        for name in ("ph-rsa.pdf", "ph-ec.pdf"):
            with self.subTest(pdf=name):
                r = run((FIX / name).read_bytes(), name)
                self.assertEqual(len(r["signatures"]), 2)
                self.assertEqual(r["overall"], "VALID")

    def test_untrusted_ca(self):  # VER-12
        r = run((FIX / "ph-ec.pdf").read_bytes(), "ph-ec.pdf", trust=EMPTY)
        self.assertEqual(r["overall"], "UNKNOWN")

    def test_edit_inside_signed_range(self):  # VER-13
        data = bytearray((FIX / "ph-rsa.pdf").read_bytes())
        i = data.index(b"endobj")
        data[i - 2] ^= 0x20
        r = run(bytes(data), "x.pdf")
        self.assertEqual(r["overall"], "INVALID")

    def test_bytes_appended_after_signing(self):  # VER-14
        data = (FIX / "ph-rsa.pdf").read_bytes() + b"\n% appended\n"
        r = run(data, "x.pdf")
        self.assertEqual(r["overall"], "UNKNOWN")
        self.assertEqual(statuses(r, 1)["coverage"], "warn")


class TestInputs(unittest.TestCase):
    def test_no_signature(self):  # VER-15
        self.assertEqual(run(b"just text")["overall"], "NO_SIGNATURE")

    def test_garbage_signature_file(self):  # VER-16
        self.assertEqual(run(b"text", sig=b"not a signature")["overall"], "ERROR")

    def test_empty_document_with_signature(self):  # VER-17
        r = run(b"", sig=(FIX / "rsa.p7s").read_bytes())
        self.assertEqual(r["overall"], "INVALID")

    def test_report_has_file_hash(self):  # VER-18
        import hashlib
        r = run(b"abc")
        self.assertEqual(r["file"]["sha256"], hashlib.sha256(b"abc").hexdigest())


class TestDemoPKI(unittest.TestCase):
    """Uses a copy of the shipped PKI so nothing is written into the project."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        shutil.copytree(ROOT / "pki", cls.tmp / "pki")
        cls.trust = TrustStore.from_folder(ROOT / "trust")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp)

    def test_create_identity_and_sign_pdf(self):  # PKI-01
        ident = pki.create_identity("Test Student", "t@example.org", "College", self.tmp / "pki")
        self.assertEqual(pki.get_identity(ident.id, self.tmp / "pki").cert.common_name, "Test Student")
        data = pki.sign_new_pdf("Title", "Body", ident, location="Delhi")
        r = verifier.verify_upload(data, "x.pdf", None, self.trust)
        self.assertEqual(r["overall"], "VALID")
        self.assertEqual(len(r["signatures"][0]["chain"]), 3)

    def test_sign_detached_and_attached(self):  # PKI-02
        ident = pki.get_identity("bob", self.tmp / "pki")
        data = b"\x00\x01binary\xff" * 100
        self.assertEqual(verifier.verify_upload(data, "f", pki.sign_detached(data, ident), self.trust)["overall"], "VALID")
        p7m = pki.sign_detached(data, ident, attach=True)
        self.assertEqual(verifier.verify_upload(p7m, "f.p7m", None, self.trust)["overall"], "VALID")

    def test_identity_validation(self):  # PKI-03
        for name, email, org in (("", "", ""), ("x" * 65, "", ""), ("A", "not-an-email", ""), ("A", "", "o" * 65)):
            with self.subTest(name=name, email=email):
                with self.assertRaises(ValueError):
                    pki.create_identity(name, email, org, self.tmp / "pki")

    def test_bad_identity_ids(self):  # PKI-04
        for bad in ("", "../ca/root", "ALICE", "nobody", "a" * 41):
            with self.subTest(id=bad):
                with self.assertRaises(ValueError):
                    pki.get_identity(bad, self.tmp / "pki")


if __name__ == "__main__":
    unittest.main()
