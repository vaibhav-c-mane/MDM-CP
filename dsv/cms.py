"""CMS / PKCS#7 SignedData: the signature format inside signed PDFs and .p7s files.

A SignedData holds:
  * the signer's certificate (and usually the CA certificates),
  * "signed attributes": the content type, the signing time and the
    message digest (hash) of the document,
  * the signature, computed over those signed attributes.

So verification has two links:
  1. hash(document) == messageDigest attribute      (document unchanged)
  2. signature over the signed attributes is valid  (made by the key owner)
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

from . import asn1
from .pubkey import HASH_OIDS, HASHES, RSA_ENCRYPTION, hash_bytes, rsa_sign
from .rsa import PrivateKey
from .x509 import Certificate, CertificateError, parse_certificate

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.113549.1.7.1"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ATTR_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ATTR_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ATTR_SIGNING_TIME = "1.2.840.113549.1.9.5"


class CMSError(ValueError):
    pass


@dataclass
class SignerInfo:
    issuer_der: Optional[bytes]
    serial: Optional[int]
    ski: Optional[bytes]
    digest_alg: str
    sig_alg: str
    signature: bytes
    signed_attrs_der: Optional[bytes]  # re-tagged as SET, ready to verify
    message_digest: Optional[bytes] = None
    signing_time: Optional[datetime] = None
    content_type: Optional[str] = None

    @property
    def hash_name(self) -> str:
        return HASHES.get(self.digest_alg, self.digest_alg)


@dataclass
class SignedData:
    content_type: str
    content: Optional[bytes]           # None when detached
    certificates: List[Certificate] = field(default_factory=list)
    signers: List[SignerInfo] = field(default_factory=list)
    cert_errors: List[str] = field(default_factory=list)

    def find_signer_cert(self, si: SignerInfo) -> Optional[Certificate]:
        for c in self.certificates:
            if si.issuer_der is not None and c.issuer_der == si.issuer_der and c.serial == si.serial:
                return c
        if si.ski is not None:
            for c in self.certificates:
                if c.ski == si.ski:
                    return c
        return self.certificates[0] if len(self.certificates) == 1 else None


def strip_pem(data: bytes) -> bytes:
    """Accept DER, or PEM/base64 text (common for .p7s files)."""
    text = data.strip()
    if text[:1] == b"\x30":
        return data
    m = re.search(rb"-----BEGIN [A-Z0-9 ]+-----(.*?)-----END [A-Z0-9 ]+-----", text, re.S)
    body = m.group(1) if m else text
    try:
        return base64.b64decode(b"".join(body.split()), validate=True)
    except ValueError:
        raise CMSError("signature file is neither DER nor base64/PEM") from None


def parse_signed_data(data: bytes) -> SignedData:
    try:
        root = asn1.decode_all(strip_pem(data))
        if root[0].as_oid() != OID_SIGNED_DATA:
            raise CMSError("this is not a CMS SignedData signature")
        sd = root[1].expect(0xA0)[0]
        encap = sd[2]
        e_type = encap[0].as_oid()
        content = None
        if len(encap) > 1:
            inner = encap[1].expect(0xA0)[0]
            content = inner.value if inner.tag == asn1.OCTET_STRING else inner.raw
        result = SignedData(e_type, content)
        for node in sd.children[3:]:
            if node.is_context(0):  # certificates
                for c in node.children or []:
                    if c.tag == asn1.SEQUENCE:
                        try:
                            result.certificates.append(parse_certificate(c.raw))
                        except CertificateError as exc:
                            result.cert_errors.append(str(exc))
            elif node.tag == asn1.SET:  # signerInfos
                for si in node.children or []:
                    result.signers.append(_parse_signer(si))
        if not result.signers:
            raise CMSError("the signature contains no signers")
        return result
    except (asn1.ASN1Error, IndexError, TypeError) as exc:
        raise CMSError(f"could not read the signature: {exc}") from None


def _parse_signer(si: asn1.Node) -> SignerInfo:
    sid = si[1]
    issuer_der = serial = ski = None
    if sid.tag == asn1.SEQUENCE:
        issuer_der, serial = sid[0].raw, sid[1].as_int()
    elif sid.is_context(0):
        ski = sid.value
    digest_alg = si[2][0].as_oid()
    idx = 3
    signed_attrs = None
    info = SignerInfo(issuer_der, serial, ski, digest_alg, "", b"", None)
    if si[idx].is_context(0):
        node = si[idx]
        # The signature covers the attributes encoded as a SET (tag 0x31), not [0].
        signed_attrs = b"\x31" + node.raw[1:]
        for attr in node.children or []:
            a_oid = attr[0].as_oid()
            val = attr[1][0]
            if a_oid == ATTR_MESSAGE_DIGEST:
                info.message_digest = val.as_octets()
            elif a_oid == ATTR_SIGNING_TIME:
                try:
                    info.signing_time = val.as_time()
                except asn1.ASN1Error:
                    pass
            elif a_oid == ATTR_CONTENT_TYPE:
                info.content_type = val.as_oid()
        idx += 1
    info.signed_attrs_der = signed_attrs
    info.sig_alg = si[idx][0].as_oid()
    info.signature = si[idx + 1].as_octets()
    return info


def parse_tst_info(der: bytes):
    """RFC 3161 TSTInfo -> (hash name, hashed message, time)."""
    t = asn1.decode_all(der)
    imprint = t[2]
    return HASHES.get(imprint[0][0].as_oid(), "?"), imprint[1].as_octets(), t[4].as_time()


def build_signed_data(content_digest: bytes, signer_cert: Certificate, key: PrivateKey,
                      extra_certs: List[Certificate], signing_time: datetime,
                      hash_name: str = "sha256", attached: Optional[bytes] = None) -> bytes:
    """Create a CMS SignedData (detached unless `attached` content is given)."""
    digest_alg = asn1.seq(asn1.oid(HASH_OIDS[hash_name]), asn1.null())
    attrs = [
        asn1.seq(asn1.oid(ATTR_CONTENT_TYPE), asn1.set_of(asn1.oid(OID_DATA))),
        asn1.seq(asn1.oid(ATTR_SIGNING_TIME), asn1.set_of(asn1.time(signing_time.astimezone(timezone.utc)))),
        asn1.seq(asn1.oid(ATTR_MESSAGE_DIGEST), asn1.set_of(asn1.octets(content_digest))),
    ]
    attrs_set = asn1.set_of(*attrs)                    # what gets signed
    signed_attrs_field = b"\xa0" + attrs_set[1:]      # stored as [0] IMPLICIT
    signature = rsa_sign(key, attrs_set, hash_name)
    signer_info = asn1.seq(
        asn1.integer(1),
        asn1.seq(signer_cert.issuer_der, asn1.integer(signer_cert.serial)),
        digest_alg,
        signed_attrs_field,
        asn1.seq(asn1.oid(RSA_ENCRYPTION), asn1.null()),
        asn1.octets(signature),
    )
    encap = asn1.seq(asn1.oid(OID_DATA)) if attached is None else \
        asn1.seq(asn1.oid(OID_DATA), asn1.explicit(0, asn1.octets(attached)))
    certs = b"".join(c.der for c in [signer_cert, *extra_certs])
    signed_data = asn1.seq(
        asn1.integer(1),
        asn1.set_of(digest_alg),
        encap,
        asn1.tlv(0xA0, certs),
        asn1.set_of(signer_info),
    )
    return asn1.seq(asn1.oid(OID_SIGNED_DATA), asn1.explicit(0, signed_data))


def content_digest(data: bytes, hash_name: str = "sha256") -> bytes:
    return hash_bytes(hash_name, data)
