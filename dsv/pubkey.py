"""Public keys and signature algorithms used inside certificates and CMS.

RSA (PKCS#1 v1.5):
    EM = s^e mod n, written as k bytes (k = size of n)
    EM must equal 00 01 FF FF ... FF 00 || DigestInfo(hash of the data)
ECDSA: see ecc.py.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from . import asn1, ecc
from .number_theory import mod_pow
from .rsa import PrivateKey, sign_int

# ----- algorithm identifiers -----
HASHES: Dict[str, str] = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
HASH_OIDS = {v: k for k, v in HASHES.items()}
WEAK_HASHES = {"md5", "sha1"}

RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
EC_PUBLIC_KEY = "1.2.840.10045.2.1"
SIG_ALGS: Dict[str, Tuple[str, Optional[str]]] = {  # oid -> (key type, hash)
    RSA_ENCRYPTION: ("rsa", None),
    "1.2.840.113549.1.1.4": ("rsa", "md5"),
    "1.2.840.113549.1.1.5": ("rsa", "sha1"),
    "1.2.840.113549.1.1.14": ("rsa", "sha224"),
    "1.2.840.113549.1.1.11": ("rsa", "sha256"),
    "1.2.840.113549.1.1.12": ("rsa", "sha384"),
    "1.2.840.113549.1.1.13": ("rsa", "sha512"),
    "1.2.840.113549.1.1.10": ("rsa-pss", None),
    "1.2.840.10045.4.1": ("ec", "sha1"),
    "1.2.840.10045.4.3.1": ("ec", "sha224"),
    "1.2.840.10045.4.3.2": ("ec", "sha256"),
    "1.2.840.10045.4.3.3": ("ec", "sha384"),
    "1.2.840.10045.4.3.4": ("ec", "sha512"),
    EC_PUBLIC_KEY: ("ec", None),
}
SHA256_WITH_RSA = "1.2.840.113549.1.1.11"


def hash_bytes(name: str, data: bytes) -> bytes:
    return hashlib.new(name, data).digest()


@dataclass
class PublicKeyInfo:
    kind: str                      # "rsa", "ec" or "unsupported"
    n: int = 0
    e: int = 0
    curve: Optional[ecc.Curve] = None
    point: Optional[Tuple[int, int]] = None
    note: str = ""

    @property
    def bits(self) -> int:
        if self.kind == "rsa":
            return self.n.bit_length()
        if self.kind == "ec" and self.curve:
            return self.curve.n.bit_length()
        return 0

    @property
    def description(self) -> str:
        if self.kind == "rsa":
            return f"RSA {self.bits}-bit (e = {self.e})"
        if self.kind == "ec" and self.curve:
            return f"Elliptic curve {self.curve.name}"
        return self.note or "unsupported key type"


def parse_spki(node: asn1.Node) -> PublicKeyInfo:
    """SubjectPublicKeyInfo ::= SEQUENCE { algorithm, BIT STRING key }"""
    alg = node[0][0].as_oid()
    key_bits = node[1].as_bits()
    if alg == RSA_ENCRYPTION:
        rsa = asn1.decode_all(key_bits)
        return PublicKeyInfo("rsa", n=rsa[0].as_int(), e=rsa[1].as_int())
    if alg == EC_PUBLIC_KEY:
        curve_oid = node[0][1].as_oid() if len(node[0]) > 1 and node[0][1].tag == asn1.OID else ""
        curve = ecc.CURVES_BY_OID.get(curve_oid)
        if curve is None:
            return PublicKeyInfo("unsupported", note=f"elliptic curve {curve_oid or '(explicit)'} is not supported")
        return PublicKeyInfo("ec", curve=curve, point=ecc.decode_point(curve, key_bits))
    return PublicKeyInfo("unsupported", note=f"key algorithm {alg} is not supported")


def rsa_spki(n: int, e: int) -> bytes:
    return asn1.seq(
        asn1.seq(asn1.oid(RSA_ENCRYPTION), asn1.null()),
        asn1.bits(asn1.seq(asn1.integer(n), asn1.integer(e))),
    )


def digest_info(hash_name: str, digest: bytes, with_null: bool = True) -> bytes:
    alg = asn1.seq(asn1.oid(HASH_OIDS[hash_name]), asn1.null()) if with_null else asn1.seq(asn1.oid(HASH_OIDS[hash_name]))
    return asn1.seq(alg, asn1.octets(digest))


def pkcs1_pad(k: int, payload: bytes) -> bytes:
    if len(payload) + 11 > k:
        raise ValueError("RSA key is too small for this hash")
    return b"\x00\x01" + b"\xff" * (k - len(payload) - 3) + b"\x00" + payload


def rsa_sign(key: PrivateKey, data: bytes, hash_name: str = "sha256") -> bytes:
    """PKCS#1 v1.5 signature: s = EM^d mod n (computed with CRT)."""
    k = (key.n.bit_length() + 7) // 8
    em = pkcs1_pad(k, digest_info(hash_name, hash_bytes(hash_name, data)))
    return sign_int(int.from_bytes(em, "big"), key).to_bytes(k, "big")


def _short(x: int, digits: int = 24) -> str:
    h = format(x, "x")
    return h if len(h) <= 2 * digits else f"{h[:digits]}…{h[-digits:]}"


@dataclass
class SignatureCheck:
    valid: bool
    algorithm: str
    message: str
    hash_name: str = ""
    maths: Optional[Dict[str, str]] = None
    unsupported: bool = False  # this project cannot check it (not the same as a bad signature)


def verify_signature(key: PublicKeyInfo, sig_alg: str, digest_alg: Optional[str],
                     data: bytes, signature: bytes) -> SignatureCheck:
    """Check `signature` over `data`. Returns the result plus the working for the UI."""
    kind, hash_name = SIG_ALGS.get(sig_alg, ("unknown", None))
    hash_name = hash_name or (HASHES.get(digest_alg or "") if digest_alg else None)
    if kind == "rsa-pss":
        return SignatureCheck(False, "RSA-PSS", "RSA-PSS signatures are not supported by this project",
                              unsupported=True)
    if kind == "unknown" or hash_name is None:
        return SignatureCheck(False, sig_alg, f"signature algorithm {sig_alg} is not supported", unsupported=True)
    if key.kind == "unsupported":
        return SignatureCheck(False, kind, key.description, unsupported=True)
    if kind != key.kind:
        return SignatureCheck(False, kind, "the signature algorithm does not match the key type")
    digest = hash_bytes(hash_name, data)
    label = f"{key.description} with {hash_name.upper()}"

    if kind == "rsa":
        k = (key.n.bit_length() + 7) // 8
        s = int.from_bytes(signature, "big")
        if s >= key.n:
            return SignatureCheck(False, label, "signature value s is not smaller than n", hash_name)
        m = mod_pow(s, key.e, key.n)
        em = m.to_bytes(k, "big")
        ok = False
        for with_null in (True, False):
            try:
                if em == pkcs1_pad(k, digest_info(hash_name, digest, with_null)):
                    ok = True
            except ValueError:
                pass
        # Show the decoded block: 00 01 FF..FF 00 || DigestInfo(hash)
        pad_end = em.find(b"\x00", 2)
        recovered = em[-len(digest):]
        maths = {
            "formula": "EM = s^e mod n",
            "n": _short(key.n), "e": str(key.e), "s": _short(s),
            "EM": em[:6].hex() + "…" + em[-(len(digest) + 4):].hex(),
            "padding": f"00 01 then {max(pad_end - 2, 0)} bytes of FF then 00" if em[:2] == b"\x00\x01" and pad_end > 0 else "padding is wrong",
            "hash in signature": recovered.hex(),
            "hash of data": digest.hex(),
        }
        msg = ("s^e mod n contains exactly the hash of the signed data" if ok
               else "s^e mod n does not contain the hash of the signed data")
        return SignatureCheck(ok, label, msg, hash_name, maths)

    # ECDSA: signature is SEQUENCE { r INTEGER, s INTEGER }
    try:
        rs = asn1.decode_all(signature)
        r, s = rs[0].as_int(), rs[1].as_int()
    except (asn1.ASN1Error, ValueError):
        return SignatureCheck(False, label, "ECDSA signature is not a valid (r, s) pair", hash_name)
    work = ecc.verify(key.curve, key.point, digest, r, s)  # type: ignore[arg-type]
    if "reason" in work:
        return SignatureCheck(False, label, str(work["reason"]), hash_name)
    maths = {
        "formula": "w = s⁻¹ mod n; u1 = z·w; u2 = r·w; X = u1·G + u2·Q; check X.x mod n = r",
        "z (hash)": _short(work["z"]), "r": _short(r), "s": _short(s),  # type: ignore[arg-type]
        "w = s⁻¹ mod n": _short(work["w"]),  # type: ignore[arg-type]
        "X.x mod n": _short(work["v"]),  # type: ignore[arg-type]
    }
    ok = bool(work["valid"])
    msg = "X.x mod n equals r" if ok else "X.x mod n does not equal r"
    return SignatureCheck(ok, label, msg, hash_name, maths)
