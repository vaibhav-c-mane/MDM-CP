"""Create the sample files shown on the Verify page (samples/ + samples.json).

Each sample records the verdict the verifier must give; the tests check them all.
Run from the project folder:   python scripts/make_samples.py
"""

from __future__ import annotations

import json
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "samples" / "assets"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dsv import pki  # noqa: E402

CONTRACT_TITLE = "Service Agreement"
CONTRACT = """This agreement is made between Alice Sharma ("Client") and Bob Verma ("Provider").

1. The Provider will deliver Discrete Mathematics tutoring for 6 months.
2. The Client will pay Rs. 5,000 on completion.
3. Either party may end this agreement with 30 days notice.

By signing digitally, both parties accept these terms."""

INVOICE = """INVOICE #2026-042
Bill to: Alice Sharma
Item: Discrete Mathematics tutoring (6 months)
Amount due: Rs. 5,000
"""


def tiny_bmp(width: int = 24, height: int = 24) -> bytes:
    row_size = (width * 3 + 3) & ~3
    pixels = bytearray()
    for y in range(height):
        row = bytearray()
        for x in range(width):
            row += bytes((x * 10 % 256, y * 10 % 256, 180))
        pixels += row + b"\x00" * (row_size - len(row))
    header = b"BM" + struct.pack("<IHHI", 54 + len(pixels), 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    return header + info + bytes(pixels)


def unsigned_pdf(text: str) -> bytes:
    stream = b"BT /F1 14 Tf 60 780 Td (" + text.encode("latin-1") + b") Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.7\n")
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    x = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, x)
    return bytes(out)


def flip_signature_byte(pdf_bytes: bytes) -> bytes:
    """Change one hex digit near the end of the signature value (inside the RSA number)."""
    start = pdf_bytes.index(b"/Contents <") + len(b"/Contents <")
    end = pdf_bytes.index(b">", start)
    hexsig = pdf_bytes[start:end].rstrip(b"0")
    pos = start + len(hexsig) - 20   # well inside the last field (the signature value)
    digit = pdf_bytes[pos:pos + 1]
    new = b"0" if digit != b"0" else b"1"
    return pdf_bytes[:pos] + new + pdf_bytes[pos + 1:]


def main(out_dir: Optional[Path] = None, pki_dir: Path = pki.PKI_DIR, trust_dir: Path = pki.TRUST_DIR) -> Path:
    out = Path(out_dir) if out_dir else ROOT / "samples"
    out.mkdir(parents=True, exist_ok=True)
    pki.ensure_demo_pki(pki_dir, trust_dir)
    alice = pki.get_identity("alice", pki_dir)
    bob = pki.get_identity("bob", pki_dir)
    signing_ca = pki.load_identity(pki_dir / "ca" / "signing")

    # Extra identities that are NOT properly trusted, to show the other verdicts.
    mallory = pki.issue([("C", "IN"), ("CN", "Mallory (self-signed)")], None, False, days=365)
    unknown_root = pki.issue([("O", "Unknown Certificates Ltd"), ("CN", "Unknown Root CA")], None, True, days=3650)
    charlie = pki.issue([("C", "IN"), ("CN", "Charlie Khan")], unknown_root, False, days=365)
    expired = pki.issue([("C", "IN"), ("O", "Sharma & Co. Legal"), ("CN", "Alice Sharma (old certificate)")],
                        signing_ca, False, days=365,
                        not_before=datetime(2023, 1, 1, tzinfo=timezone.utc))

    samples = []

    def write(name: str, data: bytes) -> None:
        (out / name).write_bytes(data)

    def add(sid, title, file, expected, explanation, signature=None, group="PDF documents"):
        sid = f"S{len(samples) + 1:02d}"  # numbered in list order
        samples.append({"id": sid, "group": group, "title": title, "file": file, "signature": signature,
                        "expected": expected, "explanation": explanation})

    contract = pki.sign_new_pdf(CONTRACT_TITLE, CONTRACT, alice, location="New Delhi")
    write("contract-signed.pdf", contract)
    add("S01", "Signed contract", "contract-signed.pdf", "VALID",
        "Alice signed it with a certificate from the trusted demo CA. Nothing changed afterwards.")

    tampered = contract.replace(b"Rs. 5,000", b"Rs. 9,000")
    assert tampered != contract
    write("contract-amount-changed.pdf", tampered)
    add("S02", "Amount changed after signing", "contract-amount-changed.pdf", "INVALID",
        "Someone edited Rs. 5,000 to Rs. 9,000 inside the PDF, so the hash no longer matches.")

    write("contract-bad-signature.pdf", flip_signature_byte(contract))
    add("S03", "Corrupted signature value", "contract-bad-signature.pdf", "INVALID",
        "One digit of the signature number s was changed, so s^e mod n no longer gives the hash.")

    write("contract-changed-later.pdf", contract + b"% A note was appended after signing.\n%%EOF\n")
    add("S04", "Content added after signing", "contract-changed-later.pdf", "UNKNOWN",
        "The signed part is intact, but extra bytes were appended afterwards, outside the signature.")

    write("letter-self-signed.pdf", pki.sign_new_pdf("Letter", "Please transfer the money today.", mallory))
    add("S05", "Self-signed certificate", "letter-self-signed.pdf", "UNKNOWN",
        "The maths is correct, but Mallory issued their own certificate, so nobody vouches for the name.")

    write("letter-unknown-ca.pdf", pki.sign_new_pdf("Letter", "Meeting moved to Friday.", charlie))
    add("S06", "Certificate from an untrusted CA", "letter-unknown-ca.pdf", "UNKNOWN",
        "Charlie's certificate chains to 'Unknown Root CA', which is not in our trust store.")

    write("contract-expired-cert.pdf", pki.sign_new_pdf(CONTRACT_TITLE, CONTRACT, expired, location="New Delhi"))
    add("S07", "Expired certificate", "contract-expired-cert.pdf", "UNKNOWN",
        "The certificate was valid only during 2023; it had expired when this was signed.")

    write("contract-sha1.pdf", pki.sign_new_pdf(CONTRACT_TITLE, CONTRACT, alice, hash_name="sha1"))
    add("S08", "Weak hash (SHA-1)", "contract-sha1.pdf", "UNKNOWN",
        "The signature is correct, but SHA-1 collisions have been found, so it is no longer trusted.")

    write("unsigned.pdf", unsigned_pdf("This PDF has no digital signature."))
    add("S09", "Unsigned PDF", "unsigned.pdf", "NO_SIGNATURE", "A normal PDF without any signature.")

    # ---- existing PDF signed with a picture of a handwritten signature ----
    g_pic = "PDF + signature picture (JPEG / PNG)"
    cert_pdf = (ASSETS / "certificate-unsigned.pdf").read_bytes()
    write("certificate-unsigned.pdf", cert_pdf)
    reason = "Project approved"
    with_png = pki.sign_uploaded_pdf(cert_pdf, alice, reason, "New Delhi", (ASSETS / "signature-alice.png").read_bytes())
    write("certificate-signed-png.pdf", with_png)
    add("S15", "PDF + PNG signature picture", "certificate-signed-png.pdf", "VALID",
        "An existing PDF signed by Alice. Her PNG signature picture is shown in the box on the page; "
        "the real proof is the digital signature inside the PDF.", group=g_pic)

    with_jpg = pki.sign_uploaded_pdf(cert_pdf, bob, reason, "Mumbai", (ASSETS / "signature-bob.jpg").read_bytes())
    write("certificate-signed-jpeg.pdf", with_jpg)
    add("S16", "PDF + JPEG signature picture", "certificate-signed-jpeg.pdf", "VALID",
        "The same PDF signed by Bob, with his JPEG signature picture.", group=g_pic)

    edited = with_png.replace(b"(Project approved)", b"(Project rejected)")
    assert edited != with_png
    write("certificate-signed-png-edited.pdf", edited)
    add("S17", "PDF + PNG, edited after signing", "certificate-signed-png-edited.pdf", "INVALID",
        "The reason was changed from 'Project approved' to 'Project rejected' after signing. The picture still "
        "looks the same, but the hash no longer matches: a picture alone proves nothing.", group=g_pic)

    write("certificate-signed.pdf", pki.sign_uploaded_pdf(cert_pdf, alice, reason, "New Delhi"))
    add("S18", "Existing PDF signed (no picture)", "certificate-signed.pdf", "VALID",
        "An existing PDF signed without a picture; the box shows the signer's name and date.", group=g_pic)

    # ---- JPEG and PNG images with a .p7s signature ----
    g_img = "JPEG and PNG images + .p7s signature"
    for ext, kind, first in (("jpg", "JPEG", "S19"), ("png", "PNG", "S21")):
        photo = (ASSETS / f"photo.{ext}").read_bytes()
        write(f"photo.{ext}", photo)
        write(f"photo.{ext}.p7s", pki.sign_detached(photo, alice))
        write(f"photo-edited.{ext}", (ASSETS / f"photo-edited.{ext}").read_bytes())
        second = f"S{int(first[1:]) + 1}"
        add(first, f"{kind} photo + .p7s", f"photo.{ext}", "VALID",
            f"Alice signed the {kind} image; the signature is in photo.{ext}.p7s.", f"photo.{ext}.p7s", g_img)
        add(second, f"{kind} photo edited after signing", f"photo-edited.{ext}", "INVALID",
            f"The year in the caption was changed from 2026 to 2027, so the {kind} bytes and their hash changed.",
            f"photo.{ext}.p7s", g_img)

    g2 = "Other files + .p7s signature"
    write("invoice.txt", INVOICE.encode())
    write("invoice.txt.p7s", pki.sign_detached(INVOICE.encode(), bob))
    add("S23", "Text file with detached signature", "invoice.txt", "VALID",
        "Bob signed the invoice; the signature is in a separate .p7s file.", "invoice.txt.p7s", g2)

    write("invoice-edited.txt", INVOICE.replace("5,000", "50,000").encode())
    add("S24", "Edited text file", "invoice-edited.txt", "INVALID",
        "The amount was changed after Bob signed, so the hash is different.", "invoice.txt.p7s", g2)

    image = tiny_bmp()
    write("photo.bmp", image)
    write("photo.bmp.p7s", pki.sign_detached(image, alice))
    add("S25", "Image with detached signature", "photo.bmp", "VALID",
        "Any file is just bytes, so images can be signed too.", "photo.bmp.p7s", g2)

    add("S26", "Signature for a different file", "invoice.txt", "INVALID",
        "The photo's signature does not match the invoice.", "photo.bmp.p7s", g2)

    write("message.p7m", pki.sign_detached(b"Exam results will be announced on Monday.\n", alice, attach=True))
    add("S27", "Signed message (.p7m)", "message.p7m", "VALID",
        "The text is stored inside the signature file itself (an 'enveloping' signature).", None, g2)

    (out / "samples.json").write_text(json.dumps({"samples": samples}, indent=2))
    print(f"Wrote {len(samples)} samples to {out}")
    return out


if __name__ == "__main__":
    main()
