"""Step-by-step traces of the algorithms, used by the web app to show the working.

Each function returns plain dicts/lists so they can be sent as JSON.
Big numbers are returned as strings because JavaScript cannot hold
integers above 2^53 exactly.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .number_theory import (
    crt_pair,
    extended_gcd,
    fermat_test,
    gcd,
    is_probable_prime,
    mod_inverse,
    mod_pow,
)
from .rsa import PrivateKey

MAX_TRACE_ROWS = 64


def gcd_steps(a: int, b: int) -> Dict[str, Any]:
    """Euclid's divisions plus the extended-Euclid coefficients."""
    rows: List[Dict[str, str]] = []
    x, y = abs(a), abs(b)
    while y != 0 and len(rows) < 500:
        q, r = divmod(x, y)
        rows.append({"a": str(x), "q": str(q), "b": str(y), "r": str(r)})
        x, y = y, r
    g, s, t = extended_gcd(a, b)
    return {
        "gcd": str(g),
        "x": str(s),
        "y": str(t),
        "bezout": f"{a}·({s}) + {b}·({t}) = {g}",
        "divisions": rows,
        "truncated": len(rows) >= 500,
    }


def inverse_steps(a: int, n: int) -> Dict[str, Any]:
    info = gcd_steps(a % n if n > 0 else a, n)
    info["a"], info["n"] = str(a), str(n)
    try:
        inv = mod_inverse(a, n)
        info["inverse"] = str(inv)
        info["check"] = f"{a} × {inv} mod {n} = {(a * inv) % n}"
    except ValueError as exc:
        info["inverse"] = None
        info["error"] = str(exc)
    return info


def mod_pow_steps(base: int, exponent: int, modulus: int) -> Dict[str, Any]:
    """Square-and-multiply table: one row per bit of the exponent."""
    result = mod_pow(base, exponent, modulus)
    rows: List[Dict[str, str]] = []
    if modulus > 1 and exponent >= 0:
        r, x, e, i = 1, base % modulus, exponent, 0
        while e > 0 and i < MAX_TRACE_ROWS:
            bit = e & 1
            if bit:
                r = (r * x) % modulus
            rows.append({"i": str(i), "bit": str(bit), "power": str(x), "result": str(r)})
            x = (x * x) % modulus
            e >>= 1
            i += 1
    bits = exponent.bit_length() if exponent > 0 else 0
    return {
        "result": str(result),
        "binary": bin(exponent)[2:] if exponent >= 0 else "-" + bin(exponent)[3:],
        "rows": rows,
        "truncated": bits > MAX_TRACE_ROWS,
        "multiplications": {
            "naive": str(max(exponent - 1, 0)),
            "fast": str(bits + bin(exponent).count("1") - 2 if exponent > 0 else 0),
        },
    }


def prime_report(n: int) -> Dict[str, Any]:
    """Compare the Fermat test with Miller-Rabin, and factor small numbers."""
    fermat = {str(a): fermat_test(n, a) for a in (2, 3, 5, 7) if n > a + 1 and gcd(a, n) == 1}
    factors: List[str] = []
    if 1 < n < 10**12:
        m, f = n, 2
        while f * f <= m:
            while m % f == 0:
                factors.append(str(f))
                m //= f
            f += 1 if f == 2 else 2
        if m > 1:
            factors.append(str(m))
    mr = is_probable_prime(n)
    return {
        "n": str(n),
        "miller_rabin": mr,
        "fermat": fermat,
        "fooled_fermat": (not mr) and bool(fermat) and all(fermat.values()),
        "factors": factors,
    }


def crt_steps(r1: int, m1: int, r2: int, m2: int) -> Dict[str, Any]:
    x = crt_pair(r1, m1, r2, m2)
    return {
        "x": str(x),
        "modulus": str(m1 * m2),
        "check": f"{x} mod {m1} = {x % m1}, {x} mod {m2} = {x % m2}",
    }


def key_steps(key: PrivateKey) -> List[str]:
    """Human-readable derivation of a key, for the key generation page."""
    phi = (key.p - 1) * (key.q - 1)
    g, x, _ = extended_gcd(key.e, phi)
    return [
        f"Choose primes p = {key.p} and q = {key.q}",
        f"n = p × q = {key.n}  ({key.n.bit_length()} bits)",
        f"φ(n) = (p − 1)(q − 1) = {phi}",
        f"Choose e = {key.e}; gcd(e, φ(n)) = {gcd(key.e, phi)}",
        f"Extended Euclid: e·({x}) + φ(n)·(…) = {g}",
        f"d = {x} mod φ(n) = {key.d}",
        f"Check: e × d mod φ(n) = {(key.e * key.d) % phi}",
    ]
