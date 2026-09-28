"""Sign an existing PDF by appending an "incremental update".

A PDF can be extended without touching its original bytes: new and changed
objects are written after the old %%EOF, followed by a new cross-reference
section that points back to the old one (/Prev). Signing works like this:

    original PDF bytes | new objects: signature, widget, appearance,
                       |   changed page (/Annots), changed catalog (/AcroForm)
                       | new xref + trailer (/Prev -> old xref) | %%EOF

Earlier signatures stay valid, because their bytes are unchanged.
Optionally a JPEG or PNG image (e.g. a handwritten signature) is drawn
inside the visible signature box.

The small PDF reader below understands classic xref tables, xref streams and
object streams, which covers PDFs made by Word, browsers and most tools.
"""

from __future__ import annotations

import re
import zlib
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from .images import PdfImage
from .pdf import CONTENTS_SPACE, _esc, _pdf_date


class PdfError(ValueError):
    """The PDF cannot be read or signed; the message is shown to the user."""


# ---------------- object model ----------------

class Name(str):
    pass


class Ref:
    __slots__ = ("num", "gen")

    def __init__(self, num: int, gen: int = 0):
        self.num, self.gen = num, gen

    def __eq__(self, other):
        return isinstance(other, Ref) and (self.num, self.gen) == (other.num, other.gen)

    def __hash__(self):
        return hash((self.num, self.gen))

    def __repr__(self):
        return f"Ref({self.num}, {self.gen})"


class Stream:
    def __init__(self, info: Dict[str, Any], raw: bytes):
        self.info, self.raw = info, raw


class PdfBytes(bytes):
    """A PDF string (kept as raw bytes)."""


# ---------------- tokenizer / parser ----------------

WS = b" \t\r\n\f\x00"
DELIM = b"()<>[]{}/%"


class Parser:
    def __init__(self, data: bytes, pos: int = 0):
        self.data, self.pos = data, pos

    def skip(self) -> None:
        d, n = self.data, len(self.data)
        while self.pos < n:
            c = d[self.pos]
            if c in WS:
                self.pos += 1
            elif c == 0x25:  # % comment
                while self.pos < n and d[self.pos] not in b"\r\n":
                    self.pos += 1
            else:
                break

    def token(self) -> bytes:
        self.skip()
        d, start = self.data, self.pos
        if start >= len(d):
            raise PdfError("unexpected end of PDF data")
        c = d[start:start + 1]
        if c in (b"[", b"]", b"{", b"}"):
            self.pos += 1
            return c
        if c == b"<" and d[start:start + 2] == b"<<":
            self.pos += 2
            return b"<<"
        if c == b">" and d[start:start + 2] == b">>":
            self.pos += 2
            return b">>"
        end = start + 1 if c == b"/" else start
        while end < len(d) and d[end] not in WS and d[end] not in DELIM:
            end += 1
        self.pos = end
        return d[start:end]

    def parse(self) -> Any:
        self.skip()
        d = self.data
        if self.pos >= len(d):
            raise PdfError("unexpected end of PDF data")
        c = d[self.pos]
        if c == 0x2F:  # /Name
            tok = self.token()
            return Name(re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), tok[1:]).decode("latin-1"))
        if c == 0x28:  # (string)
            return self._literal()
        if d[self.pos:self.pos + 2] == b"<<":
            self.pos += 2
            out: Dict[str, Any] = {}
            while True:
                self.skip()
                if d[self.pos:self.pos + 2] == b">>":
                    self.pos += 2
                    break
                key = self.parse()
                if not isinstance(key, Name):
                    raise PdfError("PDF dictionary key is not a name")
                out[key] = self.parse()
            return out
        if c == 0x3C:  # <hex>
            end = d.index(b">", self.pos)
            hexs = re.sub(rb"\s", b"", d[self.pos + 1:end])
            self.pos = end + 1
            if len(hexs) % 2:
                hexs += b"0"
            return PdfBytes(bytes.fromhex(hexs.decode("ascii")))
        if c == 0x5B:  # [array]
            self.pos += 1
            arr = []
            while True:
                self.skip()
                if d[self.pos:self.pos + 1] == b"]":
                    self.pos += 1
                    return arr
                arr.append(self.parse())
        tok = self.token()
        if tok == b"true":
            return True
        if tok == b"false":
            return False
        if tok == b"null":
            return None
        if re.fullmatch(rb"[+-]?\d+", tok):
            # maybe "n g R"
            save = self.pos
            try:
                t2 = self.token()
                if re.fullmatch(rb"\d+", t2):
                    t3 = self.token()
                    if t3 == b"R":
                        return Ref(int(tok), int(t2))
            except PdfError:
                pass
            self.pos = save
            return int(tok)
        if re.fullmatch(rb"[+-]?(\d+\.\d*|\.\d+|\d+\.)", tok):
            return float(tok)
        raise PdfError(f"unexpected PDF token {tok[:20]!r}")

    def _literal(self) -> PdfBytes:
        d, i, depth, out = self.data, self.pos + 1, 1, bytearray()
        esc = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
        while i < len(d):
            c = d[i]
            if c == 0x5C:  # backslash
                i += 1
                c = d[i]
                if c in esc:
                    out.append(esc[c])
                elif 0x30 <= c <= 0x37:
                    j = i
                    while j < i + 3 and j < len(d) and 0x30 <= d[j] <= 0x37:
                        j += 1
                    out.append(int(d[i:j], 8) & 0xFF)
                    i = j - 1
                elif c == 0x0D:
                    if d[i + 1:i + 2] == b"\n":
                        i += 1
                elif c != 0x0A:
                    out.append(c)
            elif c == 0x28:
                depth += 1
                out.append(c)
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    self.pos = i + 1
                    return PdfBytes(bytes(out))
                out.append(c)
            else:
                out.append(c)
            i += 1
        raise PdfError("unterminated PDF string")


# ---------------- serializer ----------------

def serialize(obj: Any) -> bytes:
    if obj is None:
        return b"null"
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if isinstance(obj, Name):
        return b"/" + re.sub(rb"[^!-~]|[#()<>\[\]{}/%]", lambda m: b"#%02X" % m.group(0)[0], obj.encode("latin-1"))
    if isinstance(obj, Ref):
        return b"%d %d R" % (obj.num, obj.gen)
    if isinstance(obj, bool):
        return b"true" if obj else b"false"
    if isinstance(obj, int):
        return b"%d" % obj
    if isinstance(obj, float):
        return (b"%.6f" % obj).rstrip(b"0").rstrip(b".") or b"0"
    if isinstance(obj, PdfBytes):
        return b"<" + obj.hex().encode() + b">"
    if isinstance(obj, (bytes, bytearray)):  # already-encoded fragment
        return bytes(obj)
    if isinstance(obj, list):
        return b"[" + b" ".join(serialize(x) for x in obj) + b"]"
    if isinstance(obj, dict):
        return b"<<" + b"".join(serialize(Name(k)) + b" " + serialize(v) + b" " for k, v in obj.items()) + b">>"
    if isinstance(obj, Stream):
        info = dict(obj.info)
        info["Length"] = len(obj.raw)
        return serialize(info) + b"\nstream\n" + obj.raw + b"\nendstream"
    raise PdfError(f"cannot write {type(obj).__name__} into a PDF")


# ---------------- reader ----------------

def _decode_stream(stream: Stream) -> bytes:
    filters = stream.info.get("Filter")
    parms = stream.info.get("DecodeParms")
    if filters is None:
        return stream.raw
    if not isinstance(filters, list):
        filters, parms = [filters], [parms]
    parms = parms if isinstance(parms, list) else [parms] * len(filters)
    data = stream.raw
    for f, p in zip(filters, parms):
        if f != "FlateDecode":
            raise PdfError(f"PDF uses the {f} filter for its structure, which is not supported")
        try:
            data = zlib.decompress(data)
        except zlib.error:
            data = zlib.decompressobj().decompress(data)
        if isinstance(p, dict) and int(p.get("Predictor", 1)) >= 10:
            cols = int(p.get("Columns", 1)) * int(p.get("Colors", 1)) * int(p.get("BitsPerComponent", 8)) // 8
            from .images import unfilter
            rows = len(data) // (cols + 1)
            data = bytes(unfilter(data[:rows * (cols + 1)], cols, 1, rows))
    return data


class PdfReader:
    def __init__(self, data: bytes):
        if b"%PDF-" not in data[:1024]:
            raise PdfError("this file is not a PDF")
        self.data = data
        self.xref: Dict[int, Tuple] = {}     # num -> ("n", offset, gen) | ("c", objstm, index)
        self.trailer: Dict[str, Any] = {}
        self.uses_xref_stream = False
        self._cache: Dict[int, Any] = {}
        self._objstm: Dict[int, Tuple[bytes, List[Tuple[int, int]], int]] = {}
        self.startxref = self._find_startxref()
        self._read_xref_chain(self.startxref)
        if "Encrypt" in self.trailer:
            raise PdfError("this PDF is password-protected (encrypted); remove the password first")
        if "Root" not in self.trailer:
            raise PdfError("the PDF has no document catalog")

    def _find_startxref(self) -> int:
        tail = self.data[-4096:]
        i = tail.rfind(b"startxref")
        if i < 0:
            raise PdfError("the PDF is damaged: no 'startxref' at the end")
        m = re.match(rb"startxref\s+(\d+)", tail[i:])
        if not m:
            raise PdfError("the PDF is damaged: bad 'startxref'")
        return int(m.group(1))

    def _read_xref_chain(self, offset: int) -> None:
        seen = set()
        first = True
        while offset is not None and offset not in seen:
            seen.add(offset)
            if not 0 <= offset < len(self.data):
                raise PdfError("the PDF is damaged: xref offset outside the file")
            p = Parser(self.data, offset)
            p.skip()
            if self.data.startswith(b"xref", p.pos):
                trailer = self._read_classic(p)
            else:
                trailer = self._read_xref_stream(p)
                if first:
                    self.uses_xref_stream = True
            if first:
                self.trailer = trailer
                first = False
            if "XRefStm" in trailer:  # hybrid file
                self._read_xref_stream(Parser(self.data, int(trailer["XRefStm"])))
            prev = trailer.get("Prev")
            offset = int(prev) if prev is not None else None

    def _read_classic(self, p: Parser) -> Dict[str, Any]:
        p.pos += 4
        while True:
            p.skip()
            if self.data.startswith(b"trailer", p.pos):
                p.pos += 7
                return p.parse()
            start, count = int(p.token()), int(p.token())
            for k in range(count):
                p.skip()
                line = self.data[p.pos:p.pos + 20]
                m = re.match(rb"(\d{10}) (\d{5}) ([nf])", line)
                if not m:
                    raise PdfError("the PDF cross-reference table is damaged")
                num = start + k
                if m.group(3) == b"n" and num not in self.xref:
                    self.xref[num] = ("n", int(m.group(1)), int(m.group(2)))
                elif num not in self.xref:
                    self.xref[num] = ("f",)
                p.pos += 18

    def _read_xref_stream(self, p: Parser) -> Dict[str, Any]:
        _num, _gen, obj = self._parse_indirect(p)
        if not isinstance(obj, Stream) or obj.info.get("Type") != "XRef":
            raise PdfError("the PDF cross-reference data is damaged")
        data = _decode_stream(obj)
        w = [int(x) for x in obj.info["W"]]
        size = int(obj.info["Size"])
        index = [int(x) for x in obj.info.get("Index", [0, size])]
        pos, rec = 0, sum(w)
        for s, c in zip(index[0::2], index[1::2]):
            for num in range(s, s + c):
                row = data[pos:pos + rec]
                pos += rec
                if len(row) < rec:
                    break
                vals, j = [], 0
                for width in w:
                    vals.append(int.from_bytes(row[j:j + width], "big") if width else None)
                    j += width
                t = vals[0] if w[0] else 1
                if num in self.xref:
                    continue
                if t == 1:
                    self.xref[num] = ("n", vals[1], vals[2] or 0)
                elif t == 2:
                    self.xref[num] = ("c", vals[1], vals[2] or 0)
                else:
                    self.xref[num] = ("f",)
        return obj.info

    def _parse_indirect(self, p: Parser):
        num, gen, kw = p.token(), p.token(), p.token()
        if kw != b"obj" or not num.isdigit():
            raise PdfError("the PDF points to an object that is not there")
        obj = p.parse()
        p.skip()
        if isinstance(obj, dict) and self.data.startswith(b"stream", p.pos):
            p.pos += 6
            if self.data[p.pos:p.pos + 2] == b"\r\n":
                p.pos += 2
            elif self.data[p.pos:p.pos + 1] in (b"\n", b"\r"):
                p.pos += 1
            length = obj.get("Length")
            if isinstance(length, Ref):
                length = self.resolve(length)
            start = p.pos
            if not isinstance(length, int) or not self.data.startswith(b"endstream", self._skip_ws(start + length)):
                end = self.data.index(b"endstream", start)  # fall back to searching
                length = len(self.data[start:end].rstrip(b"\r\n"))
            obj = Stream(obj, self.data[start:start + length])
        return int(num), int(gen), obj

    def _skip_ws(self, i: int) -> int:
        while i < len(self.data) and self.data[i] in WS:
            i += 1
        return i

    def get(self, num: int) -> Any:
        if num in self._cache:
            return self._cache[num]
        entry = self.xref.get(num)
        if not entry or entry[0] == "f":
            return None
        if entry[0] == "n":
            _n, _g, obj = self._parse_indirect(Parser(self.data, entry[1]))
        else:
            obj = self._from_objstm(entry[1], entry[2])
        self._cache[num] = obj
        return obj

    def _from_objstm(self, stm_num: int, index: int) -> Any:
        if stm_num not in self._objstm:
            stm = self.get(stm_num)
            if not isinstance(stm, Stream):
                raise PdfError("the PDF object stream is damaged")
            data = _decode_stream(stm)
            n, first = int(stm.info["N"]), int(stm.info["First"])
            head = Parser(data[:first])
            pairs = [(int(head.token()), int(head.token())) for _ in range(n)]
            self._objstm[stm_num] = (data, pairs, first)
        data, pairs, first = self._objstm[stm_num]
        if index >= len(pairs):
            raise PdfError("the PDF object stream is damaged")
        return Parser(data, first + pairs[index][1]).parse()

    def resolve(self, obj: Any) -> Any:
        seen = 0
        while isinstance(obj, Ref):
            obj = self.get(obj.num)
            seen += 1
            if seen > 50:
                raise PdfError("the PDF has a reference loop")
        return obj

    # --- document structure ---
    def pages(self) -> List[Tuple[Ref, Dict[str, Any]]]:
        root = self.resolve(self.trailer["Root"])
        out: List[Tuple[Ref, Dict[str, Any]]] = []

        def walk(ref: Any, depth: int = 0) -> None:
            node = self.resolve(ref)
            if depth > 50 or not isinstance(node, dict):
                return
            if node.get("Type") == "Pages" or "Kids" in node:
                for kid in self.resolve(node.get("Kids", [])):
                    walk(kid, depth + 1)
            elif isinstance(ref, Ref):
                out.append((ref, node))

        walk(root.get("Pages"))
        if not out:
            raise PdfError("the PDF has no pages")
        return out

    def inherited(self, page: Dict[str, Any], key: str) -> Any:
        node, depth = page, 0
        while isinstance(node, dict) and depth < 50:
            if key in node:
                return self.resolve(node[key])
            node = self.resolve(node.get("Parent"))
            depth += 1
        return None


# ---------------- signing ----------------

def _fit(img_w: int, img_h: int, box_w: float, box_h: float) -> Tuple[float, float]:
    scale = min(box_w / img_w, box_h / img_h)
    return img_w * scale, img_h * scale


def sign_existing_pdf(data: bytes, signer_name: str, signing_time: datetime, reason: str, location: str,
                      sign_callback: Callable[[bytes], bytes], image: Optional[PdfImage] = None) -> bytes:
    """Append a signature (visible box on the last page) to an existing PDF."""
    reader = PdfReader(data)
    pages = reader.pages()
    page_ref, page = pages[-1]
    root_ref = reader.trailer["Root"]
    if not isinstance(root_ref, Ref):
        raise PdfError("the PDF catalog is not an indirect object")
    catalog = dict(reader.resolve(root_ref))

    # page size (MediaBox may be inherited from the page tree; CropBox wins if present)
    box = reader.inherited(page, "CropBox") or reader.inherited(page, "MediaBox") or [0, 0, 595, 842]
    x0, y0, x1, y1 = (float(reader.resolve(v)) for v in box)
    x0, x1 = min(x0, x1), max(x0, x1)
    y0, y1 = min(y0, y1), max(y0, y1)

    next_num = int(reader.trailer.get("Size", max(reader.xref) + 1 if reader.xref else 1))
    new: Dict[int, Any] = {}

    def alloc(obj: Any = None) -> Ref:
        nonlocal next_num
        ref = Ref(next_num)
        next_num += 1
        new[ref.num] = obj
        return ref

    # count existing signature fields for a unique name
    existing_fields = 0
    acro = reader.resolve(catalog.get("AcroForm"))
    if isinstance(acro, dict):
        existing_fields = len(reader.resolve(acro.get("Fields", [])) or [])
    field_name = f"Signature{existing_fields + 1}"

    # --- visible appearance ---
    w, h = 240.0, 84.0 if image else 64.0
    margin = 36.0
    stamp = signing_time.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M UTC")
    resources: Dict[str, Any] = {"Font": {"F1": {"Type": Name("Font"), "Subtype": Name("Type1"),
                                                 "BaseFont": Name("Helvetica"), "Encoding": Name("WinAnsiEncoding")},
                                          "F2": {"Type": Name("Font"), "Subtype": Name("Type1"),
                                                 "BaseFont": Name("Helvetica-Bold"), "Encoding": Name("WinAnsiEncoding")}}}
    ops = [b"1 1 1 rg 0 0 %.1f %.1f re f" % (w, h), b"0.79 0.39 0.26 RG 1 w 0.5 0.5 %.1f %.1f re S" % (w - 1, h - 1)]
    text_x = 8.0
    if image:
        img_info: Dict[str, Any] = {"Type": Name("XObject"), "Subtype": Name("Image"), "Width": image.width,
                                    "Height": image.height, "ColorSpace": Name(image.color_space),
                                    "BitsPerComponent": 8, "Filter": Name(image.filter)}
        if image.invert_cmyk:
            img_info["Decode"] = [1, 0, 1, 0, 1, 0, 1, 0]
        if image.alpha is not None:
            img_info["SMask"] = alloc(Stream({"Type": Name("XObject"), "Subtype": Name("Image"),
                                              "Width": image.width, "Height": image.height,
                                              "ColorSpace": Name("DeviceGray"), "BitsPerComponent": 8,
                                              "Filter": Name("FlateDecode")}, image.alpha))
        img_ref = alloc(Stream(img_info, image.data))
        resources["XObject"] = {"Im1": img_ref}
        iw, ih = _fit(image.width, image.height, 96, h - 12)
        ops.append(b"q %.3f 0 0 %.3f %.3f %.3f cm /Im1 Do Q" % (iw, ih, 6 + (96 - iw) / 2, (h - ih) / 2))
        text_x = 108.0
    lines = [(b"F2", 8.5, "Digitally signed by"), (b"F2", 8.5, signer_name[:40]),
             (b"F1", 7.5, "Date: " + stamp), (b"F1", 7.5, ("Reason: " + reason)[:48])]
    if location:
        lines.append((b"F1", 7.5, ("Location: " + location)[:48]))
    ty = h - 14
    for font, size, text in lines:
        ops.append(b"BT 0.12 0.12 0.11 rg /%s %.1f Tf %.1f %.1f Td (%s) Tj ET" % (font, size, text_x, ty, _esc(text)))
        ty -= size + 3.5
    ap_ref = alloc(Stream({"Type": Name("XObject"), "Subtype": Name("Form"), "BBox": [0, 0, w, h],
                           "Resources": resources}, b"\n".join(ops)))

    # place the box at the bottom-right of the last page
    margin = min(margin, (x1 - x0 - w) / 2, (y1 - y0 - h) / 2) if x1 - x0 > w and y1 - y0 > h else 0
    rect = [round(v, 2) for v in (x1 - margin - w, y0 + margin, x1 - margin, y0 + margin + h)]

    # --- signature dictionary (with placeholders) and widget ---
    placeholder_br = b"/ByteRange [0 0000000000 0000000000 0000000000]"
    sig_raw = (b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached " + placeholder_br
               + b" /Contents <" + b"0" * (2 * CONTENTS_SPACE) + b">"
               + b" /Name (" + _esc(signer_name) + b") /Reason (" + _esc(reason) + b") /Location (" + _esc(location)
               + b") /M (" + _pdf_date(signing_time).encode() + b") >>")
    sig_ref = alloc(sig_raw)  # raw bytes are written as they are
    widget = {"Type": Name("Annot"), "Subtype": Name("Widget"), "FT": Name("Sig"),
              "T": PdfBytes(field_name.encode()), "V": sig_ref, "F": 4, "Rect": rect, "P": page_ref,
              "AP": {"N": ap_ref}}
    widget_ref = alloc(widget)

    # --- changed page: add the widget to /Annots ---
    new_page = dict(page)
    annots = reader.resolve(page.get("Annots")) or []
    new_page["Annots"] = list(annots) + [widget_ref]
    new[page_ref.num] = new_page

    # --- changed form: add the field to /AcroForm ---
    acro_src = catalog.get("AcroForm")
    acro_dict = dict(reader.resolve(acro_src)) if acro_src is not None else {}
    fields = reader.resolve(acro_dict.get("Fields")) or []
    acro_dict["Fields"] = list(fields) + [widget_ref]
    acro_dict["SigFlags"] = 3
    if isinstance(acro_src, Ref):
        new[acro_src.num] = acro_dict
    else:
        catalog["AcroForm"] = acro_dict
        new[root_ref.num] = catalog

    # --- write the update ---
    out = bytearray(data)
    if not out.endswith(b"\n"):
        out += b"\n"
    offsets: Dict[int, int] = {}
    for num in sorted(new):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + serialize(new[num]) + b"\nendobj\n"

    trailer: Dict[str, Any] = {"Size": next_num, "Root": root_ref, "Prev": reader.startxref}
    for key in ("Info", "ID"):
        if key in reader.trailer:
            trailer[key] = reader.trailer[key]
    xref_pos = len(out)
    if reader.uses_xref_stream:
        xref_num = next_num
        trailer["Size"] = next_num + 1
        offsets[xref_num] = xref_pos
        nums = sorted(offsets)
        index, rows = [], bytearray()
        for num in nums:
            if index and index[-2] + index[-1] == num:
                index[-1] += 1
            else:
                index += [num, 1]
            rows += b"\x01" + offsets[num].to_bytes(4, "big") + b"\x00\x00"
        info = dict(trailer)
        info.update({"Type": Name("XRef"), "W": [1, 4, 2], "Index": index})
        out += b"%d 0 obj\n" % xref_num + serialize(Stream(info, bytes(rows))) + b"\nendobj\n"
    else:
        out += b"xref\n"
        nums = sorted(offsets)
        runs: List[List[int]] = []
        for num in nums:
            if runs and runs[-1][-1] + 1 == num:
                runs[-1].append(num)
            else:
                runs.append([num])
        for run in runs:
            out += b"%d %d\n" % (run[0], len(run))
            for num in run:
                out += b"%010d 00000 n \n" % offsets[num]
        out += b"trailer\n" + serialize(trailer) + b"\n"
    out += b"startxref\n%d\n%%%%EOF\n" % xref_pos

    # --- fill the byte range and the signature ---
    start = len(data)
    pos = out.index(placeholder_br, start)
    hole_start = out.index(b"/Contents <", pos) + len(b"/Contents ")
    hole_end = out.index(b">", hole_start) + 1
    br = b"/ByteRange [0 %010d %010d %010d]" % (hole_start, hole_end, len(out) - hole_end)
    out[pos:pos + len(br)] = br
    der = sign_callback(bytes(out[:hole_start]) + bytes(out[hole_end:]))
    hexsig = der.hex().encode()
    if len(hexsig) > 2 * CONTENTS_SPACE:
        raise PdfError("signature is too large for the reserved space")
    out[hole_start + 1:hole_start + 1 + len(hexsig)] = hexsig
    return bytes(out)
