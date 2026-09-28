"""A tiny demo Public Key Infrastructure: a root CA, an issuing CA and signers.

    DSV Demo Root CA  (in trust/, so it is trusted)
        └── DSV Demo Signing CA
              ├── Alice Sharma
              └── Bob Verma

Private keys are stored as JSON in pki/ so the app can sign demo documents.
This is for learning only: never store real private keys like this.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import cms, pdf
from .rsa import PrivateKey, generate_keypair
from .x509 import Certificate, build_certificate, parse_certificate, to_pem

ROOT_DIR = Path(__file__).resolve().parent.parent
PKI_DIR = ROOT_DIR / "pki"
TRUST_DIR = ROOT_DIR / "trust"

Name = List[Tuple[str, str]]


@dataclass
class Identity:
    id: str
    cert: Certificate
    key: PrivateKey
    chain: List[Certificate]   # issuing CA certificates, nearest first

    def info(self) -> Dict[str, object]:
        return {"id": self.id, **self.cert.summary()}


def _save_key(key: PrivateKey, path: Path) -> None:
    path.write_text(json.dumps({"n": hex(key.n), "e": key.e, "d": hex(key.d), "p": hex(key.p), "q": hex(key.q)}, indent=2))


def _load_key(path: Path) -> PrivateKey:
    d = json.loads(path.read_text())
    return PrivateKey(n=int(d["n"], 16), e=int(d["e"]), d=int(d["d"], 16), p=int(d["p"], 16), q=int(d["q"], 16))


def _serial() -> int:
    return secrets.randbits(63) | 1


def issue(subject: Name, issuer: Optional[Identity], is_ca: bool, days: int = 825,
          not_before: Optional[datetime] = None, bits: int = 2048) -> Identity:
    """Create a key pair and a certificate (self-signed if issuer is None)."""
    key = generate_keypair(bits)
    start = not_before or datetime.now(timezone.utc) - timedelta(days=1)
    der = build_certificate(subject, key, issuer.cert if issuer else None, issuer.key if issuer else key,
                            _serial(), start, start + timedelta(days=days), is_ca)
    cert = parse_certificate(der)
    chain = ([issuer.cert] + issuer.chain) if issuer else []
    return Identity("", cert, key, chain)


def save_identity(ident: Identity, folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "cert.pem").write_text(to_pem(ident.cert.der) + "".join(to_pem(c.der) for c in ident.chain))
    _save_key(ident.key, folder / "key.json")


def load_identity(folder: Path) -> Identity:
    from .x509 import load_certificates
    certs = load_certificates((folder / "cert.pem").read_bytes())
    return Identity(folder.name, certs[0], _load_key(folder / "key.json"), certs[1:])


def ensure_demo_pki(pki_dir: Path = PKI_DIR, trust_dir: Path = TRUST_DIR, log=print) -> None:
    """Create the demo CA and the Alice/Bob identities on first run."""
    if (pki_dir / "identities" / "alice" / "cert.pem").is_file():
        return
    log("Creating the demo certificate authority and signers (first run only, about 15 seconds)...")
    root = issue([("C", "IN"), ("O", "DSV Demo PKI"), ("CN", "DSV Demo Root CA")], None, True, days=3650)
    sub = issue([("C", "IN"), ("O", "DSV Demo PKI"), ("CN", "DSV Demo Signing CA")], root, True, days=3000)
    save_identity(root, pki_dir / "ca" / "root")
    save_identity(sub, pki_dir / "ca" / "signing")
    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "dsv-demo-root-ca.pem").write_text(to_pem(root.cert.der))
    people = {
        "alice": [("C", "IN"), ("O", "Sharma & Co. Legal"), ("CN", "Alice Sharma"), ("E", "alice@example.org")],
        "bob": [("C", "IN"), ("O", "Verma Tutoring"), ("CN", "Bob Verma"), ("E", "bob@example.org")],
    }
    for pid, subject in people.items():
        save_identity(issue(subject, sub, False, days=730), pki_dir / "identities" / pid)


def list_identities(pki_dir: Path = PKI_DIR) -> List[Identity]:
    folder = pki_dir / "identities"
    if not folder.is_dir():
        return []
    return [load_identity(f) for f in sorted(folder.iterdir()) if (f / "cert.pem").is_file()]


def get_identity(ident_id: str, pki_dir: Path = PKI_DIR) -> Identity:
    if not re.fullmatch(r"[a-z0-9-]{1,40}", ident_id or ""):
        raise ValueError("unknown signer")
    folder = pki_dir / "identities" / ident_id
    if not (folder / "cert.pem").is_file():
        raise ValueError("unknown signer")
    return load_identity(folder)


def create_identity(name: str, email: str, organization: str, pki_dir: Path = PKI_DIR) -> Identity:
    """Issue a new signer certificate from the demo Signing CA."""
    name, email, organization = name.strip(), email.strip(), organization.strip()
    if not name or len(name) > 64:
        raise ValueError("enter a name (up to 64 characters)")
    if email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,120}", email):
        raise ValueError("enter a valid email address or leave it empty")
    if len(organization) > 64:
        raise ValueError("organization name is too long")
    ca = load_identity(pki_dir / "ca" / "signing")
    subject: Name = [("C", "IN")]
    if organization:
        subject.append(("O", organization))
    subject.append(("CN", name))
    if email:
        try:
            email.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("email address must use plain ASCII characters") from None
        subject.append(("E", email))
    ident = issue(subject, ca, False, days=730)
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:30] or "signer"
    ident_id = f"{slug}-{secrets.token_hex(2)}"
    save_identity(ident, pki_dir / "identities" / ident_id)
    ident.id = ident_id
    return ident


def sign_detached(data: bytes, ident: Identity, when: Optional[datetime] = None,
                  hash_name: str = "sha256", attach: bool = False) -> bytes:
    """CMS signature of `data`: detached (.p7s) or with the data inside (.p7m)."""
    when = when or datetime.now(timezone.utc)
    return cms.build_signed_data(cms.content_digest(data, hash_name), ident.cert, ident.key, ident.chain,
                                 when, hash_name, attached=data if attach else None)


def sign_new_pdf(title: str, body: str, ident: Identity, reason: str = "I approve this document",
                 location: str = "", when: Optional[datetime] = None, hash_name: str = "sha256") -> bytes:
    when = when or datetime.now(timezone.utc)
    return pdf.make_pdf_with_signature(
        title, body, ident.cert.common_name, when, reason, location,
        lambda signed: sign_detached(signed, ident, when, hash_name))
