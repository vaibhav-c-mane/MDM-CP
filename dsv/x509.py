"""X.509 certificates: read them, build them, and check a chain of them (PKI).

A certificate says "this public key belongs to this name", and is signed by an
issuer (a Certificate Authority). Checking a chain means:

    signer cert  --signed by-->  intermediate CA  --signed by-->  root CA (trusted)

Each arrow is one signature check with the issuer's public key, which is the
same RSA/ECDSA maths used for document signatures.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from . import asn1
from .pubkey import (
    SHA256_WITH_RSA,
    SIG_ALGS,
    PublicKeyInfo,
    parse_spki,
    rsa_sign,
    rsa_spki,
    verify_signature,
)
from .rsa import PrivateKey

NAME_OIDS = {
    "2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L",
    "2.5.4.8": "ST", "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "E",
    "2.5.4.4": "SN", "2.5.4.42": "GN",
}
NAME_KEYS = {v: k for k, v in NAME_OIDS.items()}

EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_KEY_USAGE = "2.5.29.15"
EXT_SUBJECT_KEY_ID = "2.5.29.14"
KEY_USAGE_NAMES = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
                   "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"]


class CertificateError(ValueError):
    pass


@dataclass
class Certificate:
    der: bytes
    tbs: bytes
    sig_alg: str
    signature: bytes
    serial: int
    issuer_der: bytes
    subject_der: bytes
    issuer: List[Tuple[str, str]]
    subject: List[Tuple[str, str]]
    not_before: datetime
    not_after: datetime
    public_key: PublicKeyInfo
    is_ca: bool = False
    ski: Optional[bytes] = None
    key_usage: List[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def self_issued(self) -> bool:
        return self.issuer_der == self.subject_der

    def name_part(self, key: str, which: str = "subject") -> str:
        for k, v in getattr(self, which):
            if k == key:
                return v
        return ""

    @property
    def common_name(self) -> str:
        return self.name_part("CN") or self.subject_text

    @property
    def subject_text(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.subject)

    @property
    def issuer_text(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.issuer)

    def summary(self) -> Dict[str, object]:
        return {
            "name": self.common_name,
            "organization": self.name_part("O"),
            "email": self.name_part("E"),
            "country": self.name_part("C"),
            "subject": self.subject_text,
            "issuer": self.issuer_text,
            "serial": format(self.serial, "x"),
            "valid_from": self.not_before.isoformat(),
            "valid_to": self.not_after.isoformat(),
            "key": self.public_key.description,
            "is_ca": self.is_ca,
            "key_usage": self.key_usage,
            "fingerprint": self.fingerprint,
        }


def _parse_name(node: asn1.Node) -> List[Tuple[str, str]]:
    out = []
    for rdn in node.children or []:
        for atv in rdn.children or []:
            key = NAME_OIDS.get(atv[0].as_oid(), atv[0].as_oid())
            out.append((key, atv[1].as_string()))
    return out


def parse_certificate(der: bytes) -> Certificate:
    try:
        root = asn1.decode_all(der)
        tbs = root[0].expect(asn1.SEQUENCE)
        i = 1 if tbs[0].is_context(0) else 0  # optional [0] version
        serial = tbs[i].as_int()
        issuer, validity, subject, spki = tbs[i + 2], tbs[i + 3], tbs[i + 4], tbs[i + 5]
        cert = Certificate(
            der=root.raw, tbs=tbs.raw,
            sig_alg=root[1][0].as_oid(), signature=root[2].as_bits(),
            serial=serial, issuer_der=issuer.raw, subject_der=subject.raw,
            issuer=_parse_name(issuer), subject=_parse_name(subject),
            not_before=validity[0].as_time(), not_after=validity[1].as_time(),
            public_key=parse_spki(spki),
        )
        for node in tbs.children[i + 6:]:
            if node.is_context(3):
                _parse_extensions(node[0], cert)
        return cert
    except (asn1.ASN1Error, IndexError, ValueError, TypeError) as exc:
        raise CertificateError(f"could not read certificate: {exc}") from None


def _parse_extensions(exts: asn1.Node, cert: Certificate) -> None:
    for ext in exts.children or []:
        ext_oid = ext[0].as_oid()
        value = ext[len(ext) - 1].as_octets()
        if ext_oid == EXT_BASIC_CONSTRAINTS:
            bc = asn1.decode_all(value)
            cert.is_ca = bool(bc.children) and bc[0].tag == asn1.BOOLEAN and bc[0].value != b"\x00"
        elif ext_oid == EXT_SUBJECT_KEY_ID:
            cert.ski = asn1.decode_all(value).as_octets()
        elif ext_oid == EXT_KEY_USAGE:
            bits_node = asn1.decode_all(value)
            raw = bits_node.as_bits()
            flags = int.from_bytes(raw, "big") if raw else 0
            total = len(raw) * 8
            cert.key_usage = [name for i, name in enumerate(KEY_USAGE_NAMES)
                              if i < total and flags >> (total - 1 - i) & 1]


def load_certificates(data: bytes) -> List[Certificate]:
    """Read one or more certificates from PEM text or a single DER blob."""
    text = data.decode("latin-1")
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", text, re.S)
    if blocks:
        return [parse_certificate(base64.b64decode("".join(b.split()))) for b in blocks]
    return [parse_certificate(data)]


def to_pem(der: bytes) -> str:
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----\n"


def encode_name(parts: Iterable[Tuple[str, str]]) -> bytes:
    rdns = []
    for key, value in parts:
        if key == "C":
            val = asn1.printable(value)
        elif key == "E":
            val = asn1.ia5(value)
        else:
            val = asn1.utf8(value)
        rdns.append(asn1.set_of(asn1.seq(asn1.oid(NAME_KEYS[key]), val)))
    return asn1.seq(*rdns)


def build_certificate(subject: List[Tuple[str, str]], subject_key: PrivateKey,
                      issuer: Optional[Certificate], issuer_key: PrivateKey,
                      serial: int, not_before: datetime, not_after: datetime,
                      is_ca: bool) -> bytes:
    """Create and sign an X.509 v3 certificate (RSA with SHA-256)."""
    sig_alg = asn1.seq(asn1.oid(SHA256_WITH_RSA), asn1.null())
    issuer_name = issuer.subject_der if issuer else encode_name(subject)
    # keyUsage bits: CA -> keyCertSign + cRLSign (bits 5, 6); signer -> digitalSignature + nonRepudiation (bits 0, 1)
    ku = b"\x01\x06" if is_ca else b"\x06\xc0"
    extensions = asn1.explicit(3, asn1.seq(
        asn1.seq(asn1.oid(EXT_BASIC_CONSTRAINTS), asn1.boolean(True),
                 asn1.octets(asn1.seq(asn1.boolean(True)) if is_ca else asn1.seq())),
        asn1.seq(asn1.oid(EXT_KEY_USAGE), asn1.boolean(True), asn1.octets(asn1.tlv(asn1.BIT_STRING, ku))),
    ))
    tbs = asn1.seq(
        asn1.explicit(0, asn1.integer(2)),  # version 3
        asn1.integer(serial),
        sig_alg,
        issuer_name,
        asn1.seq(asn1.time(not_before), asn1.time(not_after)),
        encode_name(subject),
        rsa_spki(subject_key.n, subject_key.e),
        extensions,
    )
    signature = rsa_sign(issuer_key, tbs, "sha256")
    return asn1.seq(tbs, sig_alg, asn1.bits(signature))


# ---------------- chain building (PKI) ----------------

@dataclass
class ChainLink:
    cert: Certificate
    signed_by: Optional[Certificate]
    signature_ok: Optional[bool]
    message: str
    maths: Optional[Dict[str, str]] = None


@dataclass
class ChainResult:
    links: List[ChainLink]
    trusted: bool
    complete: bool
    message: str


class TrustStore:
    """The root certificates we trust, like the list built into a browser or Adobe."""

    def __init__(self, certs: Iterable[Certificate] = ()):
        self.certs: Dict[str, Certificate] = {c.fingerprint: c for c in certs}

    @classmethod
    def from_folder(cls, folder: Path) -> "TrustStore":
        certs: List[Certificate] = []
        if folder.is_dir():
            for f in sorted(folder.iterdir()):
                if f.suffix.lower() in (".pem", ".crt", ".cer", ".der"):
                    try:
                        certs.extend(load_certificates(f.read_bytes()))
                    except CertificateError:
                        pass
        return cls(certs)

    def contains(self, cert: Certificate) -> bool:
        return cert.fingerprint in self.certs

    def find_issuer(self, cert: Certificate) -> Optional[Certificate]:
        for c in self.certs.values():
            if c.subject_der == cert.issuer_der:
                return c
        return None


def check_cert_signature(cert: Certificate, issuer: Certificate):
    alg = cert.sig_alg
    return verify_signature(issuer.public_key, alg, None, cert.tbs, cert.signature)


def build_chain(leaf: Certificate, pool: List[Certificate], trust: TrustStore, max_len: int = 10) -> ChainResult:
    """Follow issuer names from the signer up to a root, checking each signature."""
    links: List[ChainLink] = []
    current = leaf
    seen = set()
    for _ in range(max_len):
        if current.fingerprint in seen:
            return ChainResult(links, False, False, "certificate chain contains a loop")
        seen.add(current.fingerprint)

        if trust.contains(current):
            links.append(ChainLink(current, None, None, "trusted root certificate (in the trust store)"))
            return ChainResult(links, True, True, "chain ends at a trusted root")

        if current.self_issued:
            check = check_cert_signature(current, current)
            links.append(ChainLink(current, current, check.valid,
                                   "self-signed: signed with its own key", check.maths))
            return ChainResult(links, False, True,
                               "the chain ends at a self-signed certificate that is not in the trust store")

        issuer = next((c for c in pool if c.subject_der == current.issuer_der and c is not current), None) \
            or trust.find_issuer(current)
        if issuer is None:
            links.append(ChainLink(current, None, None, f"issuer '{current.issuer_text}' was not found"))
            return ChainResult(links, False, False, "the issuer certificate is missing, so the chain is incomplete")

        check = check_cert_signature(current, issuer)
        links.append(ChainLink(current, issuer, check.valid,
                               f"signature by '{issuer.common_name}': {check.message}", check.maths))
        if not check.valid:
            return ChainResult(links, False, False, f"certificate '{current.common_name}' has a bad signature")
        if not issuer.is_ca:
            return ChainResult(links, False, False, f"'{issuer.common_name}' is not allowed to act as a CA")
        current = issuer
    return ChainResult(links, False, False, "certificate chain is too long")


def now() -> datetime:
    return datetime.now(timezone.utc)
