"""Signature pictures (JPEG/PNG reading) and signing existing PDFs."""

import struct
import unittest
import zlib
from pathlib import Path

from dsv import images, pdfedit, pki, verifier
from dsv.images import ImageError
from dsv.pdfedit import PdfError, PdfReader
from dsv.x509 import TrustStore

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).resolve().parent / "fixtures"
ASSETS = ROOT / "samples" / "assets"


def pixels(width_bytes, height, seed=7):
    return bytes((seed * (i + 1) * 31) & 0xFF for i in range(width_bytes * height))


class TestImages(unittest.TestCase):
    def test_detect(self):  # IMG-01
        self.assertEqual(images.detect(b"\xff\xd8\xff\xe0...."), "JPEG")
        self.assertEqual(images.detect(b"\x89PNG\r\n\x1a\n...."), "PNG")
        self.assertEqual(images.detect(b"%PDF-1.7"), "")
        with self.assertRaises(ImageError):
            images.load(b"GIF89a....")

    def test_png_rgba_splits_alpha(self):  # IMG-02
        rows = bytes([10, 20, 30, 0, 40, 50, 60, 255])  # 2x1 RGBA
        img = images.load(images.write_png(2, 1, rows, color=6))
        self.assertEqual((img.width, img.height, img.color_space, img.filter), (2, 1, "DeviceRGB", "FlateDecode"))
        self.assertEqual(zlib.decompress(img.data), bytes([10, 20, 30, 40, 50, 60]))
        self.assertEqual(zlib.decompress(img.alpha), bytes([0, 255]))

    def test_png_opaque_has_no_mask(self):  # IMG-03
        img = images.load(images.write_png(3, 2, pixels(9, 2), color=2))
        self.assertIsNone(img.alpha)
        self.assertEqual(zlib.decompress(img.data), pixels(9, 2))

    def test_png_gray_and_gray_alpha(self):  # IMG-04
        g = images.load(images.write_png(4, 1, bytes([0, 85, 170, 255]), color=0))
        self.assertEqual(g.color_space, "DeviceGray")
        ga = images.load(images.write_png(2, 1, bytes([100, 0, 200, 128]), color=4))
        self.assertEqual(zlib.decompress(ga.data), bytes([100, 200]))
        self.assertEqual(zlib.decompress(ga.alpha), bytes([0, 128]))

    def test_png_low_bit_depth_gray(self):  # IMG-05
        # 2-bit gray: values 0,1,2,3 packed in one byte, scaled to 0,85,170,255
        img = images.load(images.write_png(4, 1, bytes([0b00011011]), color=0, depth=2))
        self.assertEqual(zlib.decompress(img.data), bytes([0, 85, 170, 255]))

    def test_png_palette_with_transparency(self):  # IMG-06
        def chunk(kind, body):
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 2, 1, 8, 3, 0, 0, 0))
               + chunk(b"PLTE", bytes([255, 0, 0, 0, 0, 255])) + chunk(b"tRNS", bytes([0]))
               + chunk(b"IDAT", zlib.compress(b"\x00\x00\x01")) + chunk(b"IEND", b""))
        img = images.load(png)
        self.assertEqual(zlib.decompress(img.data), bytes([255, 0, 0, 0, 0, 255]))
        self.assertEqual(zlib.decompress(img.alpha), bytes([0, 255]))

    def test_png_row_filters(self):  # IMG-07
        # Sub, Up, Average and Paeth rows must all decode back to the same pixels.
        width_bytes, bpp, height = 6, 3, 4
        plain = pixels(width_bytes, height)
        raw = bytearray()
        prev = bytes(width_bytes)
        for y, ftype in enumerate([1, 2, 3, 4]):
            row = plain[y * width_bytes:(y + 1) * width_bytes]
            enc = bytearray()
            for x in range(width_bytes):
                a = row[x - bpp] if x >= bpp else 0
                b = prev[x]
                c = prev[x - bpp] if x >= bpp else 0
                pred = {1: a, 2: b, 3: (a + b) >> 1, 4: images._paeth(a, b, c)}[ftype]
                enc.append((row[x] - pred) & 0xFF)
            raw += bytes([ftype]) + enc
            prev = row
        self.assertEqual(bytes(images.unfilter(bytes(raw), width_bytes, bpp, height)), plain)

    def test_png_errors(self):  # IMG-08
        with self.assertRaises(ImageError):
            images.load(b"\x89PNG\r\n\x1a\n")  # no IHDR
        good = images.write_png(1, 1, b"\x00\x00\x00\x00")
        interlaced = bytearray(good)
        interlaced[28] = 1  # interlace byte of IHDR
        with self.assertRaises(ImageError):
            images.load(bytes(interlaced))

    def test_jpeg_size_and_passthrough(self):  # IMG-09
        data = (ASSETS / "signature-bob.jpg").read_bytes()
        img = images.load(data)
        self.assertEqual((img.kind, img.filter, img.color_space), ("JPEG", "DCTDecode", "DeviceRGB"))
        self.assertGreater(img.width, 0)
        self.assertIs(img.data, data)
        with self.assertRaises(ImageError):
            images.load(b"\xff\xd8\xff\xd9")  # no frame header

    def test_sample_assets_load(self):  # IMG-10
        for name in ("signature-alice.png", "signature-alice.jpg", "photo.png", "photo.jpg"):
            img = images.load((ASSETS / name).read_bytes())
            self.assertGreater(img.width * img.height, 0, name)
        self.assertIsNotNone(images.load((ASSETS / "signature-alice.png").read_bytes()).alpha)


class TestSignExistingPdf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.trust = TrustStore.from_folder(ROOT / "trust")
        cls.alice = pki.get_identity("alice")

    def sign(self, data, image=None, **kw):
        return pki.sign_uploaded_pdf(data, self.alice, "I approve this document", "New Delhi", image, **kw)

    def verdict(self, data):
        return verifier.verify_upload(data, "doc.pdf", None, self.trust)

    def test_sign_unsigned_pdf(self):  # EDIT-01
        original = (ROOT / "samples" / "unsigned.pdf").read_bytes()
        out = self.sign(original)
        self.assertTrue(out.startswith(original), "incremental update keeps the original bytes")
        r = self.verdict(out)
        self.assertEqual(r["overall"], "VALID")
        self.assertEqual(r["signatures"][0]["signer"]["name"], "Alice Sharma")

    def test_sign_with_png_and_jpeg(self):  # EDIT-02
        base = (ASSETS / "certificate-unsigned.pdf").read_bytes()
        for name in ("signature-alice.png", "signature-alice.jpg"):
            out = self.sign(base, (ASSETS / name).read_bytes())
            self.assertEqual(self.verdict(out)["overall"], "VALID", name)
            self.assertIn(b"/Subtype /Image", out)

    def test_edit_after_signing_is_invalid(self):  # EDIT-03
        out = self.sign((ASSETS / "certificate-unsigned.pdf").read_bytes(), (ASSETS / "signature-alice.png").read_bytes())
        edited = out.replace(b"(New Delhi)", b"(New Dehli)")
        self.assertNotEqual(edited, out)
        self.assertEqual(self.verdict(edited)["overall"], "INVALID")

    def test_second_signature_keeps_first(self):  # EDIT-04
        original = (FIX / "ph-rsa.pdf").read_bytes()  # signed by pyHanko, uses an xref stream
        before = self.verdict(original)["signatures"]
        out = self.sign(original)
        after = self.verdict(out)["signatures"]
        self.assertTrue(PdfReader(original).uses_xref_stream)
        self.assertEqual(len(after), len(before) + 1)
        self.assertEqual(after[-1]["signer"]["name"], "Alice Sharma")
        self.assertTrue(all(c["status"] == "pass" for s in after for c in s["checks"] if c["id"] in ("integrity", "signature")))

    def test_object_stream_pdf(self):  # EDIT-05
        out = self.sign((FIX / "objstm.pdf").read_bytes())
        self.assertEqual(self.verdict(out)["overall"], "VALID")

    def test_rejects_encrypted_and_non_pdf(self):  # EDIT-06
        plain = (ROOT / "samples" / "unsigned.pdf").read_bytes()
        encrypted = plain.replace(b"trailer\n<<", b"trailer\n<< /Encrypt 99 0 R", 1)
        self.assertNotEqual(encrypted, plain)
        with self.assertRaises(PdfError):
            self.sign(encrypted)
        with self.assertRaises(PdfError):
            self.sign(b"hello, not a pdf")


if __name__ == "__main__":
    unittest.main()
