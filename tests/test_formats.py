"""ASN.1, elliptic curves, X.509, CMS and PDF building blocks."""

import hashlib
import unittest
from datetime import datetime, timedelta, timezone

from dsv import asn1, cms, ecc, pdf
from dsv.rsa import generate_keypair
from dsv.x509 import TrustStore, build_certificate, build_chain, load_certificates, parse_certificate, to_pem

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
ROOT_KEY = generate_keypair(1024)
LEAF_KEY = generate_keypair(1024)
ROOT = parse_certificate(build_certificate([("CN", "Test Root")], ROOT_KEY, None, ROOT_KEY, 1,
                                           T0, T0 + timedelta(days=3650), True))
LEAF = parse_certificate(build_certificate([("CN", "Test Signer"), ("E", "s@example.org")], LEAF_KEY, ROOT,
                                           ROOT_KEY, 2, T0, T0 + timedelta(days=365), False))


class TestASN1(unittest.TestCase):
    def test_integer_round_trip(self):  # ASN-01
        for n in (0, 1, 127, 128, 255, 256, 2 ** 64, 2 ** 2048 - 1):
            self.assertEqual(asn1.decode_all(asn1.integer(n)).as_int(), n)

    def test_oid_round_trip(self):  # ASN-02
        for o in ("1.2.840.113549.1.1.11", "2.5.4.3", "1.3.132.0.34", "2.16.840.1.101.3.4.2.1"):
            self.assertEqual(asn1.decode_all(asn1.oid(o)).as_oid(), o)

    def test_long_length_and_nesting(self):  # ASN-03
        blob = asn1.seq(asn1.octets(b"x" * 300), asn1.utf8("héllo"), asn1.null())
        node = asn1.decode_all(blob)
        self.assertEqual(len(node), 3)
        self.assertEqual(node[0].as_octets(), b"x" * 300)
        self.assertEqual(node[1].as_string(), "héllo")

    def test_time_round_trip(self):  # ASN-04
        for dt in (datetime(2024, 5, 6, 7, 8, 9, tzinfo=timezone.utc), datetime(2051, 1, 1, tzinfo=timezone.utc)):
            self.assertEqual(asn1.decode_all(asn1.time(dt)).as_time(), dt)

    def test_truncated_input_rejected(self):  # ASN-05
        blob = asn1.seq(asn1.integer(12345))
        for cut in (1, 2, len(blob) - 1):
            with self.assertRaises(asn1.ASN1Error):
                asn1.decode_all(blob[:cut])

    def test_garbage_rejected(self):  # ASN-06
        for junk in (b"", b"\x30\x84\xff\xff\xff\xff", b"hello world"):
            with self.assertRaises(asn1.ASN1Error):
                asn1.decode_all(junk)


class TestEllipticCurves(unittest.TestCase):
    def test_generators_on_curve(self):  # ECC-01
        for c in (ecc.P256, ecc.P384):
            self.assertTrue(c.on_curve(c.g))

    def test_order_times_g_is_infinity(self):  # ECC-02
        for c in (ecc.P256, ecc.P384):
            self.assertIsNone(c.multiply(c.n, c.g))

    def test_group_law(self):  # ECC-03
        c = ecc.P256
        a, b = 1234567, 7654321
        self.assertEqual(c.add(c.multiply(a, c.g), c.multiply(b, c.g)), c.multiply(a + b, c.g))
        self.assertEqual(c.add(c.g, c.g), c.multiply(2, c.g))
        self.assertTrue(c.on_curve(c.multiply(a, c.g)))

    def test_own_ecdsa_sign_then_verify(self):  # ECC-04
        from dsv.number_theory import mod_inverse
        c = ecc.P256
        d, k = 0xC0FFEE123456789, 0xBADC0DE987654321
        Q = c.multiply(d, c.g)
        digest = hashlib.sha256(b"discrete maths").digest()
        z = ecc.hash_to_z(c, digest)
        r = c.multiply(k, c.g)[0] % c.n
        s = mod_inverse(k, c.n) * (z + r * d) % c.n
        self.assertTrue(ecc.verify(c, Q, digest, r, s)["valid"])
        self.assertFalse(ecc.verify(c, Q, hashlib.sha256(b"other").digest(), r, s)["valid"])
        self.assertFalse(ecc.verify(c, Q, digest, 0, s)["valid"])

    def test_point_decoding_rejects_off_curve(self):  # ECC-05
        c = ecc.P256
        x, y = c.g
        good = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
        self.assertEqual(ecc.decode_point(c, good), c.g)
        with self.assertRaises(ValueError):
            ecc.decode_point(c, b"\x04" + x.to_bytes(32, "big") + (y + 1).to_bytes(32, "big"))


class TestX509(unittest.TestCase):
    def test_parse_fields(self):  # X509-01
        self.assertEqual(LEAF.common_name, "Test Signer")
        self.assertEqual(LEAF.issuer, ROOT.subject)
        self.assertEqual(LEAF.serial, 2)
        self.assertTrue(ROOT.is_ca)
        self.assertFalse(LEAF.is_ca)
        self.assertTrue(ROOT.self_issued)
        self.assertEqual(LEAF.public_key.n, LEAF_KEY.n)

    def test_pem_round_trip(self):  # X509-02
        pem = (to_pem(ROOT.der) + to_pem(LEAF.der)).encode()
        certs = load_certificates(pem)
        self.assertEqual([c.der for c in certs], [ROOT.der, LEAF.der])

    def test_chain_to_trusted_root(self):  # X509-03
        result = build_chain(LEAF, [], TrustStore([ROOT]))
        self.assertTrue(result.trusted)
        self.assertTrue(all(l.signature_ok is not False for l in result.links))

    def test_chain_without_trusted_root(self):  # X509-04
        self.assertFalse(build_chain(LEAF, [ROOT], TrustStore([])).trusted)

    def test_tampered_certificate_fails_link(self):  # X509-05
        other_key = generate_keypair(1024)
        fake_root = parse_certificate(build_certificate([("CN", "Test Root")], other_key, None, other_key, 1,
                                                        T0, T0 + timedelta(days=10), True))
        result = build_chain(LEAF, [], TrustStore([fake_root]))
        self.assertFalse(result.trusted)

    def test_garbage_certificate(self):  # X509-06
        from dsv.x509 import CertificateError
        with self.assertRaises((CertificateError, asn1.ASN1Error)):
            parse_certificate(b"\x30\x03\x02\x01\x01")


class TestCMS(unittest.TestCase):
    def test_build_and_parse_detached(self):  # CMS-01
        data = b"hello"
        blob = cms.build_signed_data(cms.content_digest(data), LEAF, LEAF_KEY, [ROOT], T0)
        sd = cms.parse_signed_data(blob)
        self.assertEqual(len(sd.signers), 1)
        si = sd.signers[0]
        self.assertEqual(sd.find_signer_cert(si).der, LEAF.der)
        self.assertEqual(si.hash_name, "sha256")
        self.assertIsNone(sd.content)

    def test_attached_content(self):  # CMS-02
        blob = cms.build_signed_data(cms.content_digest(b"abc"), LEAF, LEAF_KEY, [], T0, attached=b"abc")
        self.assertEqual(cms.parse_signed_data(blob).content, b"abc")

    def test_pem_wrapped_accepted(self):  # CMS-03
        import base64
        der = cms.build_signed_data(cms.content_digest(b"x"), LEAF, LEAF_KEY, [], T0)
        pem = b"-----BEGIN PKCS7-----\n" + base64.encodebytes(der) + b"-----END PKCS7-----\n"
        self.assertEqual(len(cms.parse_signed_data(pem).signers), 1)

    def test_not_cms(self):  # CMS-04
        for junk in (b"", b"plain text", asn1.seq(asn1.integer(1))):
            with self.assertRaises(cms.CMSError):
                cms.parse_signed_data(junk)


class TestPDF(unittest.TestCase):
    def make(self):
        return pdf.make_pdf_with_signature(
            "Title", "Line one\nLine two", "Test Signer", T0, "Approve", "Delhi",
            lambda signed: cms.build_signed_data(cms.content_digest(signed), LEAF, LEAF_KEY, [ROOT], T0))

    def test_signature_found(self):  # PDF-01
        data = self.make()
        self.assertTrue(pdf.is_pdf(data))
        sigs = pdf.find_signatures(data)
        self.assertEqual(len(sigs), 1)
        s = sigs[0]
        self.assertTrue(s.covers_whole_file(data))
        self.assertEqual((s.reason, s.location), ("Approve", "Delhi"))
        self.assertEqual(s.pdf_time, T0)

    def test_byte_range_excludes_only_hole(self):  # PDF-02
        data = self.make()
        a, b, c, d = pdf.find_signatures(data)[0].byte_range
        self.assertEqual(a, 0)
        self.assertEqual(data[b:b + 1], b"<")
        self.assertEqual(data[c - 1:c], b">")

    def test_unsigned_pdf(self):  # PDF-03
        self.assertEqual(pdf.find_signatures(b"%PDF-1.4\n1 0 obj << >> endobj\n%%EOF"), [])

    def test_pdf_dates(self):  # PDF-04
        self.assertEqual(pdf.parse_pdf_date("D:20240102030405Z"), datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
        self.assertEqual(pdf.parse_pdf_date("D:20240102030405+05'30'"),
                         datetime(2024, 1, 1, 21, 34, 5, tzinfo=timezone.utc))
        self.assertIsNone(pdf.parse_pdf_date("garbage"))


if __name__ == "__main__":
    unittest.main()
