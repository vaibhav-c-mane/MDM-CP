"""The verification engine: upload a file (and optionally its .p7s), get a report.

Verdicts, like online validators:
  VALID    - document unchanged, signature maths correct, signer's certificate
             chains to a trusted root and was valid at signing time.
  UNKNOWN  - document unchanged and signature maths correct, but the signer
             cannot be confirmed (untrusted/self-signed CA, expired
             certificate, weak algorithm, or changes added after signing).
  INVALID  - the document was modified or the signature maths fails.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import cms, pdf
from .pubkey import WEAK_HASHES, hash_bytes, verify_signature
from .x509 import Certificate, TrustStore, build_chain, now

VALID, UNKNOWN, INVALID = "VALID", "UNKNOWN", "INVALID"
PASS, WARN, FAIL = "pass", "warn", "fail"
RANK = {VALID: 0, UNKNOWN: 1, INVALID: 2}

HEADLINES = {
    VALID: "Signature is valid",
    UNKNOWN: "Signature is intact, but the signer could not be fully verified",
    INVALID: "Signature is NOT valid",
}


@dataclass
class Check:
    id: str
    title: str
    status: str
    message: str
    maths: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "status": self.status,
                "message": self.message, "maths": self.maths}


@dataclass
class SignatureReport:
    index: int
    kind: str
    checks: List[Check] = field(default_factory=list)
    signer: Optional[Dict[str, Any]] = None
    signing_time: Optional[str] = None
    signing_time_source: str = ""
    algorithm: str = ""
    reason: str = ""
    location: str = ""
    coverage: Optional[Dict[str, Any]] = None
    chain: List[Dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def verdict(self) -> str:
        if self.error or any(c.status == FAIL for c in self.checks):
            return INVALID
        if any(c.status == WARN for c in self.checks):
            return UNKNOWN
        return VALID

    def to_dict(self) -> Dict[str, Any]:
        v = self.verdict
        return {
            "index": self.index, "kind": self.kind, "verdict": v, "headline": HEADLINES[v],
            "signer": self.signer, "signing_time": self.signing_time,
            "signing_time_source": self.signing_time_source, "algorithm": self.algorithm,
            "reason": self.reason, "location": self.location, "coverage": self.coverage,
            "checks": [c.to_dict() for c in self.checks], "chain": self.chain, "error": self.error,
        }


def _time(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _check_cms(sd: cms.SignedData, content: bytes, report: SignatureReport,
               trust: TrustStore, fallback_time: Optional[datetime], at: datetime,
               content_label: str) -> None:
    """Run all checks for one CMS signature over `content`."""
    si = sd.signers[0]
    cert = sd.find_signer_cert(si)
    hash_name = si.hash_name

    # 1. Integrity: hash(document) == messageDigest
    if hash_name not in hashlib.algorithms_available:
        report.checks.append(Check("integrity", "Document integrity", FAIL, f"unknown hash algorithm {hash_name}"))
        return
    digest = hash_bytes(hash_name, content)
    if si.signed_attrs_der is not None:
        ok = si.message_digest == digest
        report.checks.append(Check(
            "integrity", "Document integrity", PASS if ok else FAIL,
            f"The {content_label} has not been changed since it was signed." if ok
            else f"The {content_label} was changed after signing: its hash does not match the signed hash.",
            {"formula": f"{hash_name.upper()}(signed bytes) must equal the messageDigest attribute",
             "hash of document now": digest.hex(),
             "hash stored in signature": (si.message_digest or b"").hex()}))
        signed_blob = si.signed_attrs_der
    else:
        report.checks.append(Check("integrity", "Document integrity", PASS,
                                   "No signed attributes: the signature is computed directly over the document."))
        signed_blob = content

    # 2. Signature maths with the signer's public key
    if cert is None:
        report.checks.append(Check("signature", "Signature", FAIL,
                                   "The signer's certificate is not included, so the signature cannot be checked."))
        return
    sc = verify_signature(cert.public_key, si.sig_alg, si.digest_alg, signed_blob, si.signature)
    report.algorithm = sc.algorithm
    if sc.unsupported:
        report.algorithm = sc.algorithm
        report.signer = cert.summary()
        report.checks.append(Check("signature", "Signature (public-key maths)", WARN,
                                   f"Could not be checked: {sc.message}."))
        return
    report.checks.append(Check("signature", "Signature (public-key maths)", PASS if sc.valid else FAIL,
                               ("The signature was made with the private key belonging to this certificate. " if sc.valid
                                else "The signature does not match the signer's public key. ") + f"({sc.message})",
                               sc.maths))
    report.signer = cert.summary()

    # Signing time: from the signature itself, else from the PDF, else now
    signing_time = si.signing_time or fallback_time
    report.signing_time = _time(signing_time)
    report.signing_time_source = ("claimed by the signer" if si.signing_time
                                  else "from the PDF (/M entry)" if fallback_time else "not stated")
    check_time = signing_time or at

    # 3. Certificate chain (PKI)
    chain = build_chain(cert, sd.certificates, trust)
    for link in chain.links:
        c = link.cert
        report.chain.append({
            "name": c.common_name, "subject": c.subject_text, "issuer": c.issuer_text,
            "valid_from": c.not_before.isoformat(), "valid_to": c.not_after.isoformat(),
            "is_ca": c.is_ca, "trusted_root": trust.contains(c),
            "signature_ok": link.signature_ok, "message": link.message, "maths": link.maths,
        })
    bad_link = any(l.signature_ok is False for l in chain.links)
    if chain.trusted:
        report.checks.append(Check("chain", "Certificate chain", PASS,
                                   f"Issued by a trusted certificate authority ({chain.links[-1].cert.common_name})."))
    else:
        report.checks.append(Check("chain", "Certificate chain", FAIL if bad_link else WARN,
                                   chain.message[0].upper() + chain.message[1:] + ". The signer's identity cannot be confirmed."))

    # 4. Validity period of every certificate at signing time
    problems, expired_now = [], []
    for link in chain.links:
        c = link.cert
        if check_time < c.not_before:
            problems.append(f"'{c.common_name}' was not yet valid")
        elif check_time > c.not_after:
            problems.append(f"'{c.common_name}' had expired ({c.not_after.date()})")
        elif at > c.not_after:
            expired_now.append(c.common_name)
    when = "at signing time" if signing_time else "now"
    if problems:
        report.checks.append(Check("validity", "Certificate validity", WARN, f"{'; '.join(problems)} {when}."))
    else:
        extra = f" (It has expired since then: {', '.join(expired_now)}.)" if expired_now else ""
        report.checks.append(Check("validity", "Certificate validity", PASS,
                                   f"All certificates were within their validity period {when}.{extra}"))

    # 5. Key usage
    if cert.key_usage and not ({"digitalSignature", "nonRepudiation"} & set(cert.key_usage)):
        report.checks.append(Check("usage", "Key usage", WARN,
                                   "The certificate is not allowed to be used for signatures."))

    # 6. Algorithm strength
    weak = []
    if hash_name in WEAK_HASHES:
        weak.append(f"{hash_name.upper()} is a broken hash function")
    if cert.public_key.kind == "rsa" and cert.public_key.bits < 2048:
        weak.append(f"RSA-{cert.public_key.bits} keys can be factored")
    report.checks.append(Check("algorithm", "Algorithm strength", WARN if weak else PASS,
                               "; ".join(weak) + "." if weak else f"{sc.algorithm} is considered secure."))


def _check_timestamp(sd: cms.SignedData, signed_bytes: bytes, report: SignatureReport,
                     trust: TrustStore, at: datetime) -> None:
    """PDF document timestamp (RFC 3161): the TSA signs the hash of the PDF bytes."""
    try:
        h_name, imprint, ts_time = cms.parse_tst_info(sd.content or b"")
    except Exception:
        report.error = "the timestamp token could not be read"
        return
    ok = hash_bytes(h_name, signed_bytes) == imprint if h_name in hashlib.algorithms_available else False
    report.checks.append(Check("imprint", "Timestamped hash", PASS if ok else FAIL,
                               "The timestamp covers this exact document." if ok
                               else "The document changed after it was timestamped.",
                               {"hash of document": hash_bytes(h_name, signed_bytes).hex() if ok or h_name in hashlib.algorithms_available else "",
                                "hash in timestamp": imprint.hex()}))
    _check_cms(sd, sd.content or b"", report, trust, ts_time, at, "timestamp token")
    report.signing_time, report.signing_time_source = _time(ts_time), "from the trusted timestamp"


def verify_pdf(data: bytes, trust: TrustStore, at: datetime) -> List[SignatureReport]:
    reports = []
    sigs = pdf.find_signatures(data)
    for i, ps in enumerate(sigs, start=1):
        rep = SignatureReport(i, "PDF signature", reason=ps.reason, location=ps.location)
        if ps.error:
            rep.error = ps.error
            reports.append(rep)
            continue
        signed = ps.signed_bytes(data)
        whole = ps.covers_whole_file(data)
        a, b, c, d = ps.byte_range
        rep.coverage = {"byte_range": list(ps.byte_range), "signed_bytes": len(signed),
                        "file_bytes": len(data), "hole": [b, c], "covers_whole_file": whole}
        try:
            sd = cms.parse_signed_data(ps.contents)
        except cms.CMSError as exc:
            rep.error = str(exc)
            reports.append(rep)
            continue
        if ps.sub_filter == "ETSI.RFC3161" or sd.content_type == cms.OID_TST_INFO:
            rep.kind = "Document timestamp"
            _check_timestamp(sd, signed, rep, trust, at)
        elif ps.sub_filter == "adbe.pkcs7.sha1":
            # Old style: the signed content is the SHA-1 of the byte ranges.
            inner = sd.content or b""
            ok = inner == hashlib.sha1(signed).digest()
            rep.checks.append(Check("sha1", "PDF SHA-1 digest", PASS if ok else FAIL,
                                    "Embedded SHA-1 digest matches the PDF bytes." if ok else "The PDF was changed after signing."))
            _check_cms(sd, inner, rep, trust, ps.pdf_time, at, "PDF")
        else:
            _check_cms(sd, signed, rep, trust, ps.pdf_time, at, "PDF")
        if not rep.signer and ps.name:
            rep.signer = {"name": ps.name}
        is_last = i == len(sigs)
        if whole:
            rep.checks.append(Check("coverage", "Changes after signing", PASS,
                                    "The signature covers the whole file: nothing was added afterwards."))
        elif is_last:
            rep.checks.append(Check("coverage", "Changes after signing", WARN,
                                    f"{len(data) - (c + d)} bytes were added to the file after this signature "
                                    "(an incremental update). The signed part is intact, but the added part is not covered."))
        else:
            rep.checks.append(Check("coverage", "Changes after signing", PASS,
                                    "The file was updated later (for example by the next signature); this signed revision is intact."))
        reports.append(rep)
    return reports


def verify_cms_file(sig_data: bytes, content: Optional[bytes], trust: TrustStore, at: datetime) -> List[SignatureReport]:
    sd = cms.parse_signed_data(sig_data)
    if content is None:
        if sd.content is None:
            raise cms.CMSError("this is a detached signature: also upload the original file it signs")
        content = sd.content
        kind = "Enveloping signature (.p7m)"
    else:
        kind = "Detached signature (.p7s)"
    reports = []
    for i, si in enumerate(sd.signers, start=1):
        one = cms.SignedData(sd.content_type, sd.content, sd.certificates, [si])
        rep = SignatureReport(i, kind)
        _check_cms(one, content, rep, trust, None, at, "file")
        reports.append(rep)
    return reports


def looks_like_cms(data: bytes) -> bool:
    try:
        cms.parse_signed_data(data)
        return True
    except cms.CMSError:
        return False


def verify_upload(document: bytes, filename: str, signature: Optional[bytes], trust: TrustStore,
                  at: Optional[datetime] = None) -> Dict[str, Any]:
    """Top-level entry: returns a JSON-ready report."""
    at = at or now()
    info = {"name": filename, "size": len(document), "sha256": hashlib.sha256(document).hexdigest()}
    notes = ["Revocation (OCSP/CRL) is not checked: this tool works offline.",
             "Only certificates in the trust store are trusted."]
    try:
        if signature is not None:
            info["type"] = "File + detached signature"
            reports = verify_cms_file(signature, document, trust, at)
        elif pdf.is_pdf(document):
            info["type"] = "PDF"
            reports = verify_pdf(document, trust, at)
        elif looks_like_cms(document):
            info["type"] = "CMS / PKCS#7 signature"
            reports = verify_cms_file(document, None, trust, at)
        else:
            info["type"] = "Unknown"
            reports = []
    except cms.CMSError as exc:
        return {"file": info, "overall": "ERROR", "headline": "The signature could not be read",
                "summary": str(exc), "signatures": [], "notes": notes}

    if not reports:
        hint = ("This PDF has no digital signatures." if info["type"] == "PDF"
                else "No signature found. If the signature is in a separate file (.p7s / .sig), add it too.")
        return {"file": info, "overall": "NO_SIGNATURE", "headline": "No digital signature found",
                "summary": hint, "signatures": [], "notes": notes}

    dicts = [r.to_dict() for r in reports]
    overall = max((d["verdict"] for d in dicts), key=lambda v: RANK[v])
    n = len(dicts)
    counts = {v: sum(d["verdict"] == v for d in dicts) for v in (VALID, UNKNOWN, INVALID)}
    summary = f"{n} signature{'s' if n > 1 else ''}: " + ", ".join(
        f"{counts[v]} {label}" for v, label in ((VALID, "valid"), (UNKNOWN, "need attention"), (INVALID, "invalid")) if counts[v])
    return {"file": info, "overall": overall, "headline": HEADLINES[overall] if n == 1 else
            {VALID: "All signatures are valid", UNKNOWN: "Signatures need attention",
             INVALID: "At least one signature is NOT valid"}[overall],
            "summary": summary, "signatures": dicts, "notes": notes}
