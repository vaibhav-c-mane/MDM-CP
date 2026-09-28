"""Elliptic-curve signatures (ECDSA) with the NIST curves P-256 and P-384.

An elliptic curve over the finite field Z_p is the set of points (x, y) with
    y^2 ≡ x^3 + a·x + b  (mod p)
plus a "point at infinity" O. Points form a group under the chord-and-tangent
rule. Multiplying a point by an integer k (k·G = G + G + ... + G) is fast
with double-and-add (the same idea as square-and-multiply), but undoing it
(finding k from k·G) is the hard "elliptic curve discrete logarithm problem".

ECDSA verification of signature (r, s) on hash z with public key Q:
    w  = s^-1 mod n
    u1 = z·w mod n,  u2 = r·w mod n
    X  = u1·G + u2·Q
    valid  <=>  X.x mod n == r
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .number_theory import mod_inverse

Point = Optional[Tuple[int, int]]  # None is the point at infinity O


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int  # order of G (a prime)

    @property
    def g(self) -> Tuple[int, int]:
        return (self.gx, self.gy)

    @property
    def byte_len(self) -> int:
        return (self.p.bit_length() + 7) // 8

    def on_curve(self, pt: Point) -> bool:
        if pt is None:
            return True
        x, y = pt
        if not (0 <= x < self.p and 0 <= y < self.p):
            return False
        return (y * y - (x * x * x + self.a * x + self.b)) % self.p == 0

    def add(self, P: Point, Q: Point) -> Point:
        """Group law: P + Q."""
        if P is None:
            return Q
        if Q is None:
            return P
        (x1, y1), (x2, y2) = P, Q
        p = self.p
        if x1 == x2 and (y1 + y2) % p == 0:
            return None  # P + (-P) = O
        if P == Q:
            lam = (3 * x1 * x1 + self.a) * mod_inverse(2 * y1 % p, p) % p  # tangent slope
        else:
            lam = (y2 - y1) * mod_inverse((x2 - x1) % p, p) % p  # chord slope
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    def multiply(self, k: int, P: Point) -> Point:
        """k·P by double-and-add (reads the bits of k, like square-and-multiply)."""
        result: Point = None
        addend = P
        k %= self.n
        while k:
            if k & 1:
                result = self.add(result, addend)
            addend = self.add(addend, addend)
            k >>= 1
        return result


P256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)

P384 = Curve(
    "P-384",
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
    a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
    b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
    gx=0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
    gy=0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F,
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
)

CURVES_BY_OID: Dict[str, Curve] = {
    "1.2.840.10045.3.1.7": P256,
    "1.3.132.0.34": P384,
}


def decode_point(curve: Curve, data: bytes) -> Tuple[int, int]:
    """Uncompressed point encoding: 0x04 || X || Y."""
    size = curve.byte_len
    if len(data) != 1 + 2 * size or data[0] != 4:
        raise ValueError("only uncompressed elliptic-curve points are supported")
    pt = (int.from_bytes(data[1:1 + size], "big"), int.from_bytes(data[1 + size:], "big"))
    if not curve.on_curve(pt):
        raise ValueError("public key point is not on the curve")
    return pt


def hash_to_z(curve: Curve, digest: bytes) -> int:
    """Use the leftmost bit_length(n) bits of the hash (FIPS 186-4)."""
    z = int.from_bytes(digest, "big")
    excess = len(digest) * 8 - curve.n.bit_length()
    return z >> excess if excess > 0 else z


def verify(curve: Curve, public: Tuple[int, int], digest: bytes, r: int, s: int) -> Dict[str, object]:
    """Verify an ECDSA signature. Returns the working as well as the answer."""
    n = curve.n
    if not (1 <= r < n and 1 <= s < n):
        return {"valid": False, "reason": "r or s is outside the range [1, n-1]"}
    z = hash_to_z(curve, digest)
    w = mod_inverse(s, n)
    u1, u2 = z * w % n, r * w % n
    X = curve.add(curve.multiply(u1, curve.g), curve.multiply(u2, public))
    if X is None:
        return {"valid": False, "reason": "u1·G + u2·Q is the point at infinity"}
    v = X[0] % n
    return {"valid": v == r, "z": z, "w": w, "u1": u1, "u2": u2, "x": X[0], "v": v, "r": r}
