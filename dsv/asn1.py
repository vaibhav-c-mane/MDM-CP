"""A small ASN.1 DER reader and writer.

Certificates, CMS signatures and RSA keys are all stored in DER: a tree of
Tag-Length-Value (TLV) records. Reading DER is a recursive descent over a
byte string; writing it is the reverse.

Only what this project needs is implemented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

# Universal tag numbers
BOOLEAN, INTEGER, BIT_STRING, OCTET_STRING, NULL, OID = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
UTF8_STRING, PRINTABLE_STRING, IA5_STRING, UTC_TIME, GENERALIZED_TIME = 0x0C, 0x13, 0x16, 0x17, 0x18
T61_STRING, BMP_STRING, UNIVERSAL_STRING = 0x14, 0x1E, 0x1C
SEQUENCE, SET = 0x30, 0x31

MAX_DEPTH = 64


class ASN1Error(ValueError):
    """The bytes are not valid DER."""


@dataclass
class Node:
    tag: int            # full first tag byte, e.g. 0x30 for SEQUENCE, 0xA0 for [0]
    start: int          # offset of the tag byte in the original data
    header_len: int
    length: int
    data: bytes = field(repr=False)  # the whole input (shared, not copied)
    children: Optional[List["Node"]] = None

    @property
    def end(self) -> int:
        return self.start + self.header_len + self.length

    @property
    def raw(self) -> bytes:
        """The full TLV bytes, exactly as they appear in the input."""
        return self.data[self.start:self.end]

    @property
    def value(self) -> bytes:
        return self.data[self.start + self.header_len:self.end]

    @property
    def constructed(self) -> bool:
        return bool(self.tag & 0x20)

    @property
    def tag_class(self) -> int:
        return self.tag >> 6  # 0 universal, 2 context-specific

    @property
    def tag_number(self) -> int:
        return self.tag & 0x1F

    def is_context(self, number: int) -> bool:
        return self.tag_class == 2 and self.tag_number == number

    def __getitem__(self, i: int) -> "Node":
        if self.children is None:
            raise ASN1Error("not a constructed value")
        try:
            return self.children[i]
        except IndexError:
            raise ASN1Error("ASN.1 structure is shorter than expected") from None

    def __len__(self) -> int:
        return len(self.children or [])

    # ----- typed readers -----
    def expect(self, tag: int) -> "Node":
        if self.tag != tag:
            raise ASN1Error(f"expected tag 0x{tag:02x}, found 0x{self.tag:02x}")
        return self

    def as_int(self) -> int:
        self.expect(INTEGER)
        if self.length == 0:
            raise ASN1Error("empty INTEGER")
        return int.from_bytes(self.value, "big", signed=True)

    def as_oid(self) -> str:
        self.expect(OID)
        return decode_oid(self.value)

    def as_octets(self) -> bytes:
        self.expect(OCTET_STRING)
        return self.value

    def as_bits(self) -> bytes:
        self.expect(BIT_STRING)
        if self.length == 0:
            raise ASN1Error("empty BIT STRING")
        return self.value[1:]  # first byte = number of unused bits

    def as_string(self) -> str:
        v = self.value
        if self.tag == BMP_STRING:
            return v.decode("utf-16-be", "replace")
        if self.tag == UNIVERSAL_STRING:
            return v.decode("utf-32-be", "replace")
        if self.tag in (UTF8_STRING,):
            return v.decode("utf-8", "replace")
        return v.decode("latin-1")

    def as_time(self) -> datetime:
        text = self.value.decode("ascii", "replace")
        try:
            if self.tag == UTC_TIME:  # YYMMDDHHMMSSZ, years 1950-2049
                dt = datetime.strptime(text, "%y%m%d%H%M%SZ")
            elif self.tag == GENERALIZED_TIME:
                dt = datetime.strptime(text.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")
            else:
                raise ASN1Error("not a time value")
        except ValueError:
            raise ASN1Error(f"bad time value {text!r}") from None
        return dt.replace(tzinfo=timezone.utc)


def decode(data: bytes, offset: int = 0, depth: int = 0) -> Node:
    """Parse one TLV starting at ``offset`` (children are parsed recursively)."""
    if depth > MAX_DEPTH:
        raise ASN1Error("ASN.1 nesting is too deep")
    if offset + 2 > len(data):
        raise ASN1Error("unexpected end of data")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ASN1Error("multi-byte tags are not supported")
    first = data[offset + 1]
    pos = offset + 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise ASN1Error("indefinite length is not allowed in DER")
    else:
        n = first & 0x7F
        if n > 4 or pos + n > len(data):
            raise ASN1Error("bad length field")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    header_len = pos - offset
    if pos + length > len(data):
        raise ASN1Error("value runs past the end of the data")
    node = Node(tag, offset, header_len, length, data)
    if node.constructed:
        node.children = []
        p, end = pos, pos + length
        while p < end:
            child = decode(data, p, depth + 1)
            node.children.append(child)
            p = child.end
    return node


def decode_all(data: bytes) -> Node:
    """Parse a DER value that must use the whole input (trailing zeros allowed)."""
    node = decode(data)
    if data[node.end:].strip(b"\x00"):
        raise ASN1Error("extra bytes after the ASN.1 value")
    return node


def decode_oid(value: bytes) -> str:
    if not value:
        raise ASN1Error("empty OID")
    parts: List[int] = []
    n = 0
    for b in value:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    first = parts[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return ".".join(str(x) for x in head + parts[1:])


# ---------------- writer ----------------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def seq(*items: bytes) -> bytes:
    return tlv(SEQUENCE, b"".join(items))


def set_of(*items: bytes) -> bytes:
    return tlv(SET, b"".join(sorted(items)))  # DER sorts SET OF elements


def integer(n: int) -> bytes:
    length = (n.bit_length() + 8) // 8 if n >= 0 else ((-n - 1).bit_length() + 8) // 8
    return tlv(INTEGER, n.to_bytes(max(length, 1), "big", signed=True))


def oid(dotted: str) -> bytes:
    nums = [int(x) for x in dotted.split(".")]
    out = bytearray()
    for i, n in enumerate([nums[0] * 40 + nums[1]] + nums[2:]):
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append(0x80 | (n & 0x7F))
            n >>= 7
        out += bytes(reversed(chunk))
    return tlv(OID, bytes(out))


def null() -> bytes:
    return b"\x05\x00"


def octets(b: bytes) -> bytes:
    return tlv(OCTET_STRING, b)


def bits(b: bytes) -> bytes:
    return tlv(BIT_STRING, b"\x00" + b)


def utf8(s: str) -> bytes:
    return tlv(UTF8_STRING, s.encode("utf-8"))


def printable(s: str) -> bytes:
    return tlv(PRINTABLE_STRING, s.encode("ascii"))


def ia5(s: str) -> bytes:
    return tlv(IA5_STRING, s.encode("ascii"))


def boolean(v: bool) -> bytes:
    return tlv(BOOLEAN, b"\xff" if v else b"\x00")


def time(dt: datetime) -> bytes:
    dt = dt.astimezone(timezone.utc)
    if 1950 <= dt.year < 2050:
        return tlv(UTC_TIME, dt.strftime("%y%m%d%H%M%SZ").encode())
    return tlv(GENERALIZED_TIME, dt.strftime("%Y%m%d%H%M%SZ").encode())


def explicit(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


def implicit_constructed(number: int, inner_content: bytes) -> bytes:
    return tlv(0xA0 | number, inner_content)
