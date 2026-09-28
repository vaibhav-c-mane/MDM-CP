"""Read JPEG and PNG images so they can be placed inside a PDF.

JPEG: PDF can show JPEG data as it is (DCTDecode), so we only read the size.
PNG:  we decompress it (zlib), undo the row filters, and split off the alpha
      channel, because a PDF image keeps transparency in a separate mask.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from typing import Optional

MAX_PIXELS = 4_000_000  # about 2000 x 2000


class ImageError(ValueError):
    """The file is not a JPEG/PNG we can use."""


@dataclass
class PdfImage:
    width: int
    height: int
    color_space: str          # "DeviceRGB", "DeviceGray" or "DeviceCMYK"
    data: bytes               # the stream bytes
    filter: str               # "DCTDecode" (JPEG) or "FlateDecode" (PNG)
    alpha: Optional[bytes] = None   # FlateDecode'd 8-bit mask, or None
    kind: str = ""            # "JPEG" or "PNG"
    invert_cmyk: bool = False  # Adobe CMYK JPEGs are stored inverted


def detect(data: bytes) -> str:
    if data[:3] == b"\xff\xd8\xff":
        return "JPEG"
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "PNG"
    return ""


def load(data: bytes) -> PdfImage:
    kind = detect(data)
    if kind == "JPEG":
        return load_jpeg(data)
    if kind == "PNG":
        return load_png(data)
    raise ImageError("the signature image must be a JPEG (.jpg) or PNG (.png) file")


# ---------------- JPEG ----------------

SOF_MARKERS = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}


def load_jpeg(data: bytes) -> PdfImage:
    """Walk the JPEG markers until the frame header (SOF) gives width, height and colours."""
    i, adobe = 2, False
    while i + 4 <= len(data):
        if data[i] != 0xFF:
            raise ImageError("JPEG file is damaged")
        marker = data[i + 1]
        if marker == 0xFF:          # padding
            i += 1
            continue
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = struct.unpack(">H", data[i + 2:i + 4])[0]
        if marker == 0xEE and data[i + 4:i + 9] == b"Adobe":
            adobe = True
        if marker in SOF_MARKERS:
            if i + 10 > len(data):
                break
            height, width = struct.unpack(">HH", data[i + 5:i + 9])
            comps = data[i + 9]
            space = {1: "DeviceGray", 3: "DeviceRGB", 4: "DeviceCMYK"}.get(comps)
            if not space or not width or not height:
                raise ImageError("unsupported JPEG colour format")
            if width * height > MAX_PIXELS:
                raise ImageError("image is too large (limit about 2000 x 2000 pixels)")
            return PdfImage(width, height, space, data, "DCTDecode", kind="JPEG",
                            invert_cmyk=adobe and comps == 4)
        i += 2 + length
    raise ImageError("JPEG file has no image header")


# ---------------- PNG ----------------

def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def unfilter(raw: bytes, width_bytes: int, bpp: int, height: int) -> bytearray:
    """Undo the PNG filter on each row (None, Sub, Up, Average, Paeth)."""
    out = bytearray(width_bytes * height)
    prev = bytearray(width_bytes)
    pos = 0
    for y in range(height):
        if pos >= len(raw):
            raise ImageError("PNG image data is too short")
        ftype = raw[pos]
        line = bytearray(raw[pos + 1:pos + 1 + width_bytes])
        if len(line) != width_bytes:
            raise ImageError("PNG image data is too short")
        pos += 1 + width_bytes
        if ftype == 1:
            for x in range(bpp, width_bytes):
                line[x] = (line[x] + line[x - bpp]) & 0xFF
        elif ftype == 2:
            for x in range(width_bytes):
                line[x] = (line[x] + prev[x]) & 0xFF
        elif ftype == 3:
            for x in range(width_bytes):
                left = line[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + ((left + prev[x]) >> 1)) & 0xFF
        elif ftype == 4:
            for x in range(width_bytes):
                left = line[x - bpp] if x >= bpp else 0
                up_left = prev[x - bpp] if x >= bpp else 0
                line[x] = (line[x] + _paeth(left, prev[x], up_left)) & 0xFF
        elif ftype != 0:
            raise ImageError(f"PNG uses an unknown row filter ({ftype})")
        out[y * width_bytes:(y + 1) * width_bytes] = line
        prev = line
    return out


def _unpack_bits(row: bytes, depth: int, count: int) -> list:
    """Split a row of 1/2/4-bit samples into integers."""
    vals, mask = [], (1 << depth) - 1
    for byte in row:
        for shift in range(8 - depth, -1, -depth):
            vals.append((byte >> shift) & mask)
    return vals[:count]


def load_png(data: bytes) -> PdfImage:
    pos, ihdr, idat, palette, trns = 8, None, bytearray(), b"", b""
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = data[pos + 4:pos + 8]
        body = data[pos + 8:pos + 8 + length]
        if len(body) != length:
            raise ImageError("PNG file is damaged")
        if ctype == b"IHDR":
            ihdr = body
        elif ctype == b"PLTE":
            palette = body
        elif ctype == b"tRNS":
            trns = body
        elif ctype == b"IDAT":
            idat += body
        elif ctype == b"IEND":
            break
        pos += 12 + length
    if not ihdr or len(ihdr) != 13:
        raise ImageError("PNG file has no image header")
    width, height, depth, color, _comp, _filt, interlace = struct.unpack(">IIBBBBB", ihdr)
    if not width or not height:
        raise ImageError("PNG image is empty")
    if width * height > MAX_PIXELS:
        raise ImageError("image is too large (limit about 2000 x 2000 pixels)")
    if interlace:
        raise ImageError("interlaced PNGs are not supported; save the image again without interlacing")
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color)
    if channels is None or depth not in (1, 2, 4, 8, 16):
        raise ImageError("unsupported PNG colour format")
    try:
        raw = zlib.decompress(bytes(idat))
    except zlib.error:
        raise ImageError("PNG image data is damaged") from None

    bits_per_pixel = channels * depth
    width_bytes = (width * bits_per_pixel + 7) // 8
    pixels = unfilter(raw, width_bytes, max(1, bits_per_pixel // 8), height)

    gray = color in (0, 4)
    rgb = bytearray()
    alpha = bytearray() if color in (4, 6) or trns else None
    step = 2 if depth == 16 else 1  # keep the high byte of 16-bit samples
    for y in range(height):
        row = pixels[y * width_bytes:(y + 1) * width_bytes]
        if depth < 8:
            vals = _unpack_bits(row, depth, width)
            if color == 3:
                for v in vals:
                    if 3 * v + 3 > len(palette):
                        raise ImageError("PNG palette is missing a colour")
                    rgb += palette[3 * v:3 * v + 3]
                    if alpha is not None:
                        alpha.append(trns[v] if v < len(trns) else 255)
            else:  # grayscale, scale up to 0..255
                scale = 255 // ((1 << depth) - 1)
                for v in vals:
                    rgb.append(v * scale)
                    if alpha is not None:
                        alpha.append(0 if trns and v == struct.unpack(">H", trns[:2])[0] else 255)
            continue
        samples = row[::step]
        if color == 3:
            for v in samples:
                if 3 * v + 3 > len(palette):
                    raise ImageError("PNG palette is missing a colour")
                rgb += palette[3 * v:3 * v + 3]
                if alpha is not None:
                    alpha.append(trns[v] if v < len(trns) else 255)
        elif color == 0:
            rgb += samples
            if alpha is not None:
                key = struct.unpack(">H", trns[:2])[0] >> (8 if depth == 16 else 0)
                alpha += bytes(0 if v == key else 255 for v in samples)
        elif color == 2:
            rgb += samples
            if alpha is not None:
                alpha += b"\xff" * width
        elif color == 4:
            rgb += samples[0::2]
            alpha += samples[1::2]
        else:  # color == 6, RGBA
            part = bytearray(width * 3)
            part[0::3], part[1::3], part[2::3] = samples[0::4], samples[1::4], samples[2::4]
            rgb += part
            alpha += samples[3::4]

    if alpha is not None and all(a == 255 for a in alpha):
        alpha = None  # fully opaque: no mask needed
    return PdfImage(width, height, "DeviceGray" if gray else "DeviceRGB", zlib.compress(bytes(rgb)),
                    "FlateDecode", zlib.compress(bytes(alpha)) if alpha is not None else None, kind="PNG")


# ---------------- tiny PNG writer (for tests and sample files) ----------------

def write_png(width: int, height: int, rows: bytes, color: int = 6, depth: int = 8) -> bytes:
    """Encode raw rows (already packed, no filter byte) as a PNG."""
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    width_bytes = (width * channels * depth + 7) // 8
    raw = b"".join(b"\x00" + rows[y * width_bytes:(y + 1) * width_bytes] for y in range(height))

    def chunk(kind: bytes, body: bytes) -> bytes:
        return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, depth, color, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))
