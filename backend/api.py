"""JSON API handlers. Each takes the request body (a dict) and returns a dict.

Handlers raise ApiError for bad input; the server turns that into HTTP 400.
Files travel as base64 strings; big integers travel as strings.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from dsv import attacks, explain, pki, verifier
from dsv.number_theory import is_probable_prime, mod_pow
from dsv.rsa import (
    PublicKey,
    RSAKeyError,
    generate_keypair,
    keypair_from_primes,
    sign_int,
    textbook_verify,
    verify,
)
from dsv.x509 import TrustStore

ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = ROOT / "samples"

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_MATH_BITS = 4096
MAX_FACTOR_BITS = 64


class ApiError(ValueError):
    """Bad request: the message is shown to the user."""


def trust_store() -> TrustStore:
    return TrustStore.from_folder(pki.TRUST_DIR)


# ---------- input helpers ----------

def get_file(body: Dict[str, Any], name: str, required: bool = True) -> Optional[bytes]:
    value = body.get(name)
    if value in (None, ""):
        if required:
            raise ApiError("choose a file first")
        return None
    if not isinstance(value, str):
        raise ApiError("file must be sent as base64 text")
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError("the uploaded file could not be decoded") from None
    if len(data) > MAX_FILE_BYTES:
        raise ApiError("file is larger than 10 MB")
    return data


def get_text(body: Dict[str, Any], name: str, limit: int, required: bool = False) -> str:
    value = body.get(name, "")
    if not isinstance(value, str):
        raise ApiError(f"'{name}' must be text")
    value = value.strip()
    if required and not value:
        raise ApiError(f"'{name}' is required")
    if len(value) > limit:
        raise ApiError(f"'{name}' is too long (limit {limit} characters)")
    return value


def get_int(body: Dict[str, Any], name: str, max_bits: int = MAX_MATH_BITS) -> int:
    if name not in body or body[name] in (None, ""):
        raise ApiError(f"'{name}' is required")
    value = body[name]
    if isinstance(value, bool):
        raise ApiError(f"'{name}' must be a whole number")
    if isinstance(value, int):
        n = value
    elif isinstance(value, str):
        text = value.strip().replace(" ", "").replace("_", "")
        try:
            n = int(text, 0) if text.lower().lstrip("-").startswith("0x") else int(text, 10)
        except ValueError:
            raise ApiError(f"'{name}' must be a whole number") from None
    else:
        raise ApiError(f"'{name}' must be a whole number")
    if n.bit_length() > max_bits:
        raise ApiError(f"'{name}' is too large (limit {max_bits} bits)")
    return n


def safe_filename(name: str, default: str) -> str:
    name = Path(str(name or "")).name
    name = re.sub(r"[^\w.\- ]+", "_", name).strip() or default
    return name[:120]


# ---------- verify ----------

def do_verify(body):
    document = get_file(body, "document_b64")
    signature = get_file(body, "signature_b64", required=False)
    name = safe_filename(body.get("filename", ""), "document")
    return verifier.verify_upload(document, name, signature, trust_store())


def list_samples(_body):
    path = SAMPLES_DIR / "samples.json"
    if not path.is_file():
        raise ApiError("sample files not found; run: python scripts/make_samples.py")
    return json.loads(path.read_text())


def list_trust(_body):
    return {"roots": [c.summary() for c in trust_store().certs.values()]}


# ---------- sign ----------

def list_identities(_body):
    return {"identities": [i.info() for i in pki.list_identities()]}


def new_identity(body):
    try:
        ident = pki.create_identity(get_text(body, "name", 64, True), get_text(body, "email", 190),
                                    get_text(body, "organization", 64))
    except ValueError as exc:
        raise ApiError(str(exc)) from None
    return {"identity": ident.info()}


def _identity(body):
    try:
        return pki.get_identity(str(body.get("signer", "")))
    except ValueError as exc:
        raise ApiError(str(exc)) from None


def sign_pdf(body):
    ident = _identity(body)
    title = get_text(body, "title", 120, True)
    text = get_text(body, "text", 20000, True)
    reason = get_text(body, "reason", 120) or "I approve this document"
    location = get_text(body, "location", 80)
    data = pki.sign_new_pdf(title, text, ident, reason, location)
    fname = safe_filename(re.sub(r"\s+", "-", title.lower()) + "-signed.pdf", "signed.pdf")
    return {"filename": fname, "file_b64": base64.b64encode(data).decode(), "signer": ident.cert.common_name}


def sign_file(body):
    ident = _identity(body)
    data = get_file(body, "file_b64")
    name = safe_filename(body.get("filename", ""), "file")
    sig = pki.sign_detached(data, ident)
    return {"filename": name + ".p7s", "file_b64": base64.b64encode(sig).decode(), "signer": ident.cert.common_name}


# ---------- math lab ----------

def math_gcd(body):
    return explain.gcd_steps(get_int(body, "a"), get_int(body, "b"))


def math_inverse(body):
    return explain.inverse_steps(get_int(body, "a"), get_int(body, "n"))


def math_modpow(body):
    base, exp, mod = get_int(body, "base"), get_int(body, "exponent"), get_int(body, "modulus")
    if mod < 1:
        raise ApiError("modulus must be at least 1")
    try:
        return explain.mod_pow_steps(base, exp, mod)
    except ValueError as exc:
        raise ApiError(str(exc)) from None


def math_prime(body):
    return explain.prime_report(get_int(body, "n"))


def math_crt(body):
    try:
        return explain.crt_steps(get_int(body, "r1"), get_int(body, "m1"), get_int(body, "r2"), get_int(body, "m2"))
    except ValueError as exc:
        raise ApiError(str(exc)) from None


def math_rsa(body):
    """Tiny RSA walk-through from p, q, e and a message number m."""
    p, q, e = get_int(body, "p", 64), get_int(body, "q", 64), get_int(body, "e", 64)
    m = get_int(body, "m", 128)
    try:
        key = keypair_from_primes(p, q, e)
    except (RSAKeyError, TypeError) as exc:
        raise ApiError(str(exc)) from None
    if not 0 <= m < key.n:
        raise ApiError(f"m must be between 0 and n - 1 = {key.n - 1}")
    s = sign_int(m, key, use_crt=False)
    return {"steps": explain.key_steps(key), "n": str(key.n), "d": str(key.d),
            "s": str(s), "check": str(mod_pow(s, key.e, key.n)), "m": str(m)}


def attack_factor(body):
    n = get_int(body, "n", MAX_FACTOR_BITS)
    e = get_int(body, "e", 64) if body.get("e") not in (None, "") else 65537
    if n < 4 or is_probable_prime(n):
        raise ApiError("n must be a composite number")
    try:
        broken = attacks.recover_private_key(PublicKey(n, e))
    except RSAKeyError as exc:
        raise ApiError(f"factored n, but it is not a valid RSA key: {exc}") from None
    if broken is None:
        return {"found": False}
    return {"found": True, "p": str(broken.p), "q": str(broken.q),
            "phi": str((broken.p - 1) * (broken.q - 1)), "d": str(broken.d)}


def attack_forgery(body):
    key = generate_keypair(64)
    pub = key.public_key
    m1 = get_int(body, "m1", 32) if body.get("m1") not in (None, "") else 5
    m2 = get_int(body, "m2", 32) if body.get("m2") not in (None, "") else 7
    if m1 < 0 or m2 < 0:
        raise ApiError("m1 and m2 must be non-negative")
    s1, s2 = sign_int(m1, key), sign_int(m2, key)
    m3, s3 = attacks.multiplicative_forgery(pub, (m1, s1), (m2, s2))
    em, es = attacks.existential_forgery(pub)
    return {
        "public_key": {"n": str(pub.n), "e": str(pub.e)},
        "multiplicative": {"m1": str(m1), "s1": str(s1), "m2": str(m2), "s2": str(s2),
                           "m3": str(m3), "s3": str(s3),
                           "textbook_accepts": textbook_verify(m3, s3, pub),
                           "hashed_accepts": verify(str(m3), s3, pub).valid},
        "existential": {"s": str(es), "m": str(em),
                        "textbook_accepts": textbook_verify(em, es, pub),
                        "hashed_accepts": verify(str(em), es, pub).valid},
    }


POST_ROUTES: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "/api/verify": do_verify,
    "/api/identities": new_identity,
    "/api/sign/pdf": sign_pdf,
    "/api/sign/file": sign_file,
    "/api/math/gcd": math_gcd,
    "/api/math/inverse": math_inverse,
    "/api/math/modpow": math_modpow,
    "/api/math/prime": math_prime,
    "/api/math/crt": math_crt,
    "/api/math/rsa": math_rsa,
    "/api/attacks/factor": attack_factor,
    "/api/attacks/forgery": attack_forgery,
}

GET_ROUTES: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "/api/samples": list_samples,
    "/api/identities": list_identities,
    "/api/trust": list_trust,
}
