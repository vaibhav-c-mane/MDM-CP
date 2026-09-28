"""Command-line interface.

    python -m dsv verify contract.pdf
    python -m dsv verify invoice.txt --sig invoice.txt.p7s
    python -m dsv demo        # RSA step by step with small numbers
    python -m dsv attacks     # why hashing and big keys matter

Exit codes for verify: 0 = valid, 1 = invalid or needs attention, 2 = error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import attacks
from .number_theory import extended_gcd, gcd, mod_pow
from .pki import TRUST_DIR
from .rsa import generate_keypair, hash_to_int, keypair_from_primes, sign_int, textbook_verify, verify
from .verifier import verify_upload
from .x509 import TrustStore

ICONS = {"pass": "✔", "warn": "!", "fail": "✘"}


def cmd_verify(args: argparse.Namespace) -> int:
    doc = Path(args.file).read_bytes()
    sig = Path(args.sig).read_bytes() if args.sig else None
    trust = TrustStore.from_folder(Path(args.trust) if args.trust else TRUST_DIR)
    report = verify_upload(doc, Path(args.file).name, sig, trust)
    print(f"{report['headline']}  [{report['overall']}]")
    print(report["summary"])
    for s in report["signatures"]:
        signer = (s.get("signer") or {}).get("name", "unknown signer")
        print(f"\nSignature {s['index']} ({s['kind']}) by {signer}: {s['verdict']}")
        if s.get("signing_time"):
            print(f"  signed at {s['signing_time']} ({s['signing_time_source']})")
        if s.get("error"):
            print(f"  ✘ {s['error']}")
        for c in s["checks"]:
            print(f"  {ICONS[c['status']]} {c['title']}: {c['message']}")
    return 0 if report["overall"] == "VALID" else 2 if report["overall"] == "ERROR" else 1


def cmd_demo(args: argparse.Namespace) -> int:
    p, q, e = 61, 53, 17
    print("=== RSA signature with small numbers ===\n")
    n, phi = p * q, (p - 1) * (q - 1)
    print(f"1. Primes p = {p}, q = {q};  n = p*q = {n};  phi(n) = {phi}")
    g, x, y = extended_gcd(e, phi)
    key = keypair_from_primes(p, q, e)
    print(f"2. e = {e}, gcd(e, phi) = {gcd(e, phi)};  extended Euclid: {e}*({x}) + {phi}*({y}) = {g}")
    print(f"3. d = {x} mod {phi} = {key.d}")
    message = args.text or "Discrete Maths"
    h = hash_to_int(message, n)
    s = sign_int(h, key, use_crt=False)
    print(f"4. h = SHA-256({message!r}) mod n = {h}")
    print(f"5. sign:   s = h^d mod n = {s}")
    print(f"6. verify: s^e mod n = {mod_pow(s, e, n)}  -> matches h: {mod_pow(s, e, n) == h}")
    print(f"7. tampered message verifies: {verify(message + '!', s, key.public_key).valid}")
    return 0


def cmd_attacks(args: argparse.Namespace) -> int:
    key = generate_keypair(40)
    pub = key.public_key
    broken = attacks.recover_private_key(pub)
    print(f"Factor a 40-bit key n = {pub.n}: p = {broken.p}, q = {broken.q}, recovered d correct: {broken.d == key.d}")
    s1, s2 = sign_int(5, key), sign_int(7, key)
    m3, s3 = attacks.multiplicative_forgery(pub, (5, s1), (7, s2))
    print(f"Multiplicative forgery of m = {m3}: textbook RSA accepts it: {textbook_verify(m3, s3, pub)}")
    m, s = attacks.existential_forgery(pub)
    print(f"Existential forgery: textbook accepts {textbook_verify(m, s, pub)}, "
          f"hash-then-sign accepts {verify(str(m), s, pub).valid}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dsv", description="Digital Signature Verifier")
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify a signed PDF, a .p7m, or a file with its .p7s")
    v.add_argument("file")
    v.add_argument("--sig", help="detached signature file (.p7s / .sig)")
    v.add_argument("--trust", help="folder of trusted root certificates (default: trust/)")
    v.set_defaults(func=cmd_verify)
    d = sub.add_parser("demo", help="RSA with small numbers, step by step")
    d.add_argument("--text")
    d.set_defaults(func=cmd_demo)
    sub.add_parser("attacks", help="attacks on weak RSA").set_defaults(func=cmd_attacks)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
