"""RSA key generation, signing and verification built on number_theory.py.

Key generation
    1. pick distinct primes p, q
    2. n = p*q,  phi(n) = (p-1)(q-1)          (Euler's totient)
    3. choose e with 1 < e < phi(n) and gcd(e, phi(n)) = 1
    4. d = e^-1 mod phi(n)                     (extended Euclid)

Hash-then-sign
    h = SHA-256(message) mod n
    signature s = h^d mod n                    (sped up with CRT)
    verify: s^e mod n == h                     (Euler's theorem)

Why verification works: e*d = 1 + k*phi(n), so
    s^e = h^(e*d) = h * (h^phi(n))^k ≡ h (mod n)
(for gcd(h, n) = 1 by Euler's theorem; the case gcd(h, n) > 1 follows from CRT).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union

from .number_theory import (
    crt_pair,
    gcd,
    generate_prime,
    is_probable_prime,
    mod_inverse,
    mod_pow,
)

DEFAULT_E = 65537
MIN_SECURE_BITS = 2048

Message = Union[bytes, str]


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()


@dataclass(frozen=True)
class PrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self.n, self.e)


class RSAKeyError(ValueError):
    """Raised when key parameters are mathematically invalid."""


def keypair_from_primes(p: int, q: int, e: int = DEFAULT_E) -> PrivateKey:
    """Build an RSA key from chosen primes (useful for small textbook examples).

    Validates every mathematical condition and explains what is wrong.
    """
    for name, v in (("p", p), ("q", q), ("e", e)):
        if not isinstance(v, int) or isinstance(v, bool):
            raise TypeError(f"{name} must be an int")
    if not is_probable_prime(p):
        raise RSAKeyError(f"p = {p} is not prime")
    if not is_probable_prime(q):
        raise RSAKeyError(f"q = {q} is not prime")
    if p == q:
        raise RSAKeyError("p and q must be different (otherwise n = p^2 and phi(n) != (p-1)^2)")
    n = p * q
    phi = (p - 1) * (q - 1)
    if not 1 < e < phi:
        raise RSAKeyError(f"e must satisfy 1 < e < phi(n) = {phi}")
    if gcd(e, phi) != 1:
        raise RSAKeyError(f"gcd(e, phi(n)) = {gcd(e, phi)}, so e has no inverse mod phi(n)")
    d = mod_inverse(e, phi)
    return PrivateKey(n=n, e=e, d=d, p=p, q=q)


def generate_keypair(bits: int = 2048, e: Optional[int] = None) -> PrivateKey:
    """Generate an RSA key whose modulus n has exactly ``bits`` bits.

    If e is not given, 65537 is used, falling back to a smaller Fermat prime
    (257, 17, 5, 3) for tiny teaching keys where 65537 >= phi(n).
    """
    if not isinstance(bits, int) or isinstance(bits, bool):
        raise TypeError("bits must be an int")
    if bits < 8:
        raise RSAKeyError("key size must be at least 8 bits")
    if e is not None and e.bit_length() >= bits - 1:
        raise RSAKeyError(f"e = {e} is too large for a {bits}-bit key")
    candidates = (e,) if e is not None else (DEFAULT_E, 257, 17, 5, 3)
    for _ in range(10_000):
        p = generate_prime((bits + 1) // 2)
        q = generate_prime(bits // 2)
        if p == q or (p * q).bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        for cand in candidates:
            if 1 < cand < phi and gcd(cand, phi) == 1:
                return keypair_from_primes(p, q, cand)
    raise RSAKeyError("could not find suitable primes; try a larger key size or another e")


def _to_bytes(message: Message) -> bytes:
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, (bytes, bytearray)):
        return bytes(message)
    raise TypeError("message must be bytes or str")


def hash_to_int(message: Message, n: int) -> int:
    """SHA-256 digest of the message, as an integer reduced mod n.

    For n smaller than 256 bits the reduction loses information, so
    different messages can collide. That is why small keys are only for
    learning and the verifier reports a warning for them.
    """
    digest = hashlib.sha256(_to_bytes(message)).digest()
    return int.from_bytes(digest, "big") % n


def sign(message: Message, key: PrivateKey, use_crt: bool = True) -> int:
    """Sign the SHA-256 hash of ``message``. Returns the signature integer s."""
    h = hash_to_int(message, key.n)
    return sign_int(h, key, use_crt)


def sign_int(m: int, key: PrivateKey, use_crt: bool = True) -> int:
    """Raw RSA: m^d mod n. Used by sign() and by the textbook-RSA attack demos."""
    if not 0 <= m < key.n:
        raise ValueError("value to sign must be in [0, n)")
    if not use_crt:
        return mod_pow(m, key.d, key.n)
    # CRT speed-up: compute mod p and mod q separately, then recombine.
    dp = key.d % (key.p - 1)
    dq = key.d % (key.q - 1)
    sp = mod_pow(m, dp, key.p)
    sq = mod_pow(m, dq, key.q)
    return crt_pair(sp, key.p, sq, key.q)


@dataclass
class VerificationResult:
    valid: bool
    reason: str
    message: str
    warnings: List[str] = field(default_factory=list)
    steps: Dict[str, int] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return self.valid


def parse_signature(signature: Union[int, str]) -> int:
    """Accept an int, a decimal string, or a hex string starting with 0x."""
    if isinstance(signature, bool):
        raise ValueError("signature must be a number")
    if isinstance(signature, int):
        return signature
    if isinstance(signature, str):
        text = signature.strip().lower()
        if not text:
            raise ValueError("signature is empty")
        try:
            return int(text, 16) if text.startswith(("0x", "-0x")) else int(text, 10)
        except ValueError:
            raise ValueError("signature is not a valid decimal or 0x-hex number") from None
    raise ValueError("signature must be an int or a string")


def check_public_key(key: PublicKey) -> Optional[str]:
    """Return an error message if the public key is structurally invalid."""
    if not isinstance(key.n, int) or not isinstance(key.e, int):
        return "n and e must be integers"
    if key.n < 6:
        return "modulus n is too small to be a product of two distinct primes"
    if key.n % 2 == 0:
        return "modulus n is even, so one of its factors is 2"
    if key.e < 3:
        return "public exponent e must be at least 3"
    if key.e % 2 == 0:
        return "public exponent e is even, so it cannot be coprime to phi(n)"
    if key.e >= key.n:
        return "public exponent e must be smaller than n"
    if is_probable_prime(key.n):
        return "modulus n is prime, so it is not a product of two primes"
    return None


def verify(message: Message, signature: Union[int, str], key: PublicKey) -> VerificationResult:
    """Verify an RSA hash-then-sign signature and explain the outcome."""
    problem = check_public_key(key)
    if problem:
        return VerificationResult(False, "MALFORMED_KEY", problem)

    try:
        s = parse_signature(signature)
    except ValueError as exc:
        return VerificationResult(False, "MALFORMED_SIGNATURE", str(exc))

    try:
        h = hash_to_int(message, key.n)
    except TypeError as exc:
        return VerificationResult(False, "INVALID_INPUT", str(exc))

    warnings: List[str] = []
    if key.bits < MIN_SECURE_BITS:
        warnings.append(
            f"key is only {key.bits} bits; below {MIN_SECURE_BITS} bits it can be factored"
            " (fine for learning, not for real use)"
        )
    if key.bits < 256:
        warnings.append("key is smaller than the 256-bit hash, so the hash is reduced mod n")

    if not 0 <= s < key.n:
        return VerificationResult(
            False, "SIGNATURE_OUT_OF_RANGE",
            f"signature must be in [0, n); got a value with {s.bit_length()} bits",
            warnings,
        )

    recovered = mod_pow(s, key.e, key.n)
    steps = {"h": h, "s": s, "s^e mod n": recovered}
    if recovered == h:
        return VerificationResult(True, "VALID", "s^e mod n equals the message hash", warnings, steps)
    return VerificationResult(
        False, "INVALID_SIGNATURE",
        "s^e mod n does not equal the message hash: the message or signature was changed,"
        " or the wrong public key was used",
        warnings, steps,
    )


def textbook_verify(m: int, s: int, key: PublicKey) -> bool:
    """Unhashed RSA check s^e ≡ m (mod n). Insecure; used only to show attacks."""
    return 0 <= s < key.n and mod_pow(s, key.e, key.n) == m % key.n
