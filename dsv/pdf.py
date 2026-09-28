"""Find signatures inside PDF files, and create simple signed PDFs.

How a PDF signature works:
    %PDF ... /ByteRange [0 a b c] /Contents <3082...hex...> ... %%EOF
             |---- range 1 ----|   (the hole: the signature) |-- range 2 --|
The hash covers every byte of the file except the hole that holds the
signature itself. If anything outside the hole changes, the hash changes.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


def is_pdf(data: bytes) -> bool:
    return b"%PDF-" in data[:1024]


@dataclass
class PdfSignature:
    byte_range: Tuple[int, int, int, int]
    contents: bytes            # the DER signature from the hole
    sub_filter: str
    name: str = ""
    reason: str = ""
    location: str = ""
    pdf_time: Optional[datetime] = None
    error: str = ""

    def signed_bytes(self, data: bytes) -> bytes:
        a, b, c, d = self.byte_range
        return data[a:a + b] + data[c:c + d]

    def covers_whole_file(self, data: bytes) -> bool:
        a, b, c, d = self.byte_range
        return a == 0 and c + d == len(data)


def _pdf_string(window: bytes, key: bytes) -> str:
    m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", window, re.S)
    if not m:
        return ""
    raw = m.group(1)
    raw = re.sub(rb"\\([nrtbf()\\])", lambda x: {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"", b"f": b""}
                 .get(x.group(1), x.group(1)), raw)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", "replace")
    return raw.decode("latin-1")


def parse_pdf_date(text: str) -> Optional[datetime]:
    m = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Z+\-])?(\d{2})?'?(\d{2})?", text)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(g) if g else dflt for g, dflt in zip(m.groups()[:6], (0, 1, 1, 0, 0, 0)))
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    sign, oh, om = m.group(7), m.group(8), m.group(9)
    if sign in ("+", "-") and oh:
        from datetime import timedelta
        offset = timedelta(hours=int(oh), minutes=int(om or 0))
        dt = dt - offset if sign == "+" else dt + offset
    return dt


def find_signatures(data: bytes) -> List[PdfSignature]:
    """Locate every /ByteRange in the file and read the signature in its hole."""
    found: List[PdfSignature] = []
    seen = set()
    for m in BYTE_RANGE.finditer(data):
        br = tuple(int(x) for x in m.groups())
        if br in seen:
            continue
        seen.add(br)
        a, b, c, d = br
        sig = PdfSignature(br, b"", "")  # type: ignore[arg-type]
        if a != 0 or b <= 0 or c <= b or d < 0 or c + d > len(data):
            sig.error = f"the /ByteRange {list(br)} is not valid for a file of {len(data)} bytes"
            found.append(sig)
            continue
        hole = data[b:c].strip()
        if not (hole.startswith(b"<") and hole.endswith(b">")):
            sig.error = "the signature hole does not contain a hex string"
            found.append(sig)
            continue
        try:
            sig.contents = bytes.fromhex(hole[1:-1].decode("ascii"))
        except ValueError:
            sig.error = "the signature hole contains invalid hex"
        # The signature dictionary surrounds the hole; look around it for its other keys.
        window = data[max(0, b - 4000):b] + data[c:c + 4000]
        sf = re.findall(rb"/SubFilter\s*/([A-Za-z0-9.#_\-]+)", window)
        sig.sub_filter = sf[-1].decode() if sf else "adbe.pkcs7.detached"
        sig.name = _pdf_string(window, b"Name")
        sig.reason = _pdf_string(window, b"Reason")
        sig.location = _pdf_string(window, b"Location")
        sig.pdf_time = parse_pdf_date(_pdf_string(window, b"M"))
        found.append(sig)
    found.sort(key=lambda s: s.byte_range[2] + s.byte_range[3])
    return found


# ---------------- creating a signed PDF ----------------

def _esc(text: str) -> bytes:
    raw = text.encode("cp1252", "replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def _pdf_date(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("D:%Y%m%d%H%M%SZ")


CONTENTS_SPACE = 16384  # bytes reserved for the DER signature (hex doubles it)


def make_pdf_with_signature(title: str, body: str, signer_name: str, signing_time: datetime,
                            reason: str, location: str, sign_callback) -> bytes:
    """Build a PDF, then fill the signature hole.

    sign_callback(signed_bytes) -> DER CMS signature over the two byte ranges.
    """
    lines: List[str] = []
    for para in body.replace("\r\n", "\n").split("\n"):
        lines.extend(textwrap.wrap(para, 88) or [""])
    per_page = 40
    pages = [lines[i:i + per_page] for i in range(0, max(len(lines), 1), per_page)] or [[]]

    objects: List[bytes] = []   # object i+1

    def add(obj: bytes) -> int:
        objects.append(obj)
        return len(objects)

    catalog = add(b"")          # 1, filled later
    pages_obj = add(b"")        # 2
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
    font_b = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
    sig_obj = add(b"")
    widget = add(b"")
    page_ids = []
    stamp = signing_time.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    for pi, page_lines in enumerate(pages):
        ops = [b"BT /F2 18 Tf 60 780 Td (" + _esc(title) + b") Tj ET"] if pi == 0 else []
        y = 745 if pi == 0 else 790
        for line in page_lines:
            ops.append(b"BT /F1 11 Tf 60 %d Td (" % y + _esc(line) + b") Tj ET")
            y -= 16
        if pi == len(pages) - 1:
            ops += [
                b"0.18 0.36 0.83 RG 1.2 w 60 70 300 72 re S",
                b"BT /F2 10 Tf 72 124 Td (Digitally signed by " + _esc(signer_name) + b") Tj ET",
                b"BT /F1 9 Tf 72 110 Td (Date: " + _esc(stamp) + b") Tj ET",
                b"BT /F1 9 Tf 72 97 Td (Reason: " + _esc(reason) + b") Tj ET",
                b"BT /F1 9 Tf 72 84 Td (Verify with the Digital Signature Verifier) Tj ET",
            ]
        stream = b"\n".join(ops)
        content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        annots = b" /Annots [%d 0 R]" % widget if pi == len(pages) - 1 else b""
        page_ids.append(add(
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 %d 0 R /F2 %d 0 R >> >>"
            b" /Contents %d 0 R%s >>" % (pages_obj, font, font_b, content, annots)))

    objects[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R /AcroForm << /Fields [%d 0 R] /SigFlags 3 >> >>" % (pages_obj, widget)
    objects[pages_obj - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(b"%d 0 R" % p for p in page_ids), len(page_ids))
    objects[widget - 1] = (b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature1) /F 132 /Rect [0 0 0 0]"
                           b" /P %d 0 R /V %d 0 R >>" % (page_ids[-1], sig_obj))
    placeholder_br = b"/ByteRange [0 0000000000 0000000000 0000000000]"
    objects[sig_obj - 1] = (
        b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached "
        + placeholder_br
        + b" /Contents <" + b"0" * (2 * CONTENTS_SPACE) + b">"
        + b" /Name (" + _esc(signer_name) + b") /Reason (" + _esc(reason) + b") /Location (" + _esc(location)
        + b") /M (" + _pdf_date(signing_time).encode() + b") >>")

    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, catalog, xref)

    # Fill in the byte range around the /Contents hole.
    hole_start = out.index(b"/Contents <") + len(b"/Contents ")
    hole_end = out.index(b">", hole_start) + 1
    br = b"/ByteRange [0 %010d %010d %010d]" % (hole_start, hole_end, len(out) - hole_end)
    pos = out.index(placeholder_br)
    out[pos:pos + len(br)] = br
    signed = bytes(out[:hole_start]) + bytes(out[hole_end:])
    der = sign_callback(signed)
    hexsig = der.hex().encode()
    if len(hexsig) > 2 * CONTENTS_SPACE:
        raise ValueError("signature is too large for the reserved space")
    out[hole_start + 1:hole_start + 1 + len(hexsig)] = hexsig
    return bytes(out)
