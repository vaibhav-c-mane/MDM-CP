"""Number theory toolkit written from scratch.

Every function here is a classic Discrete Mathematics algorithm:

* gcd / extended_gcd   - Euclidean algorithm and Bezout's identity
* mod_inverse          - multiplicative inverse in Z_n
* mod_pow              - fast modular exponentiation (square-and-multiply)
* is_probable_prime    - Miller-Rabin primality test (Fermat's little theorem)
* generate_prime       - random prime of a given bit length
* crt_pair             - Chinese Remainder Theorem for two coprime moduli

No cryptography library is used. Python's built-in ``pow(b, e, m)`` is
deliberately NOT used so the algorithms stay visible; the tests compare our
results against it.
"""

from __future__ import annotations

import secrets
from typing import Tuple

# Small primes used for quick trial division before Miller-Rabin.
SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97,
)


def _require_int(name: str, value: object) -> None:
    # bool is a subclass of int; reject it so True/False are not treated as 1/0.
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")


def gcd(a: int, b: int) -> int:
    """Greatest common divisor using the Euclidean algorithm.

    gcd(a, b) = gcd(b, a mod b), and gcd(a, 0) = |a|.
    By convention gcd(0, 0) = 0. The result is never negative.
    """
    _require_int("a", a)
    _require_int("b", b)
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)  (Bezout's identity).
    g is always >= 0.
    """
    _require_int("a", a)
    _require_int("b", b)
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    if old_r < 0:  # make gcd non-negative when inputs are negative
        old_r, old_x, old_y = -old_r, -old_x, -old_y
    return old_r, old_x, old_y


def lcm(a: int, b: int) -> int:
    """Least common multiple: lcm(a, b) = |a*b| / gcd(a, b); lcm(0, x) = 0."""
    if a == 0 or b == 0:
        _require_int("a", a)
        _require_int("b", b)
        return 0
    return abs(a * b) // gcd(a, b)


def mod_inverse(a: int, n: int) -> int:
    """Return x in [0, n) with a*x ≡ 1 (mod n).

    Exists only when gcd(a, n) = 1. Raises ValueError otherwise.
    """
    _require_int("a", a)
    _require_int("n", n)
    if n < 2:
        raise ValueError("modulus must be >= 2")
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"{a} has no inverse modulo {n} (gcd = {g})")
    return x % n


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    """Compute base**exponent mod modulus with square-and-multiply.

    Runs in O(log exponent) multiplications. Handles:
      * modulus == 1           -> 0 (everything is 0 mod 1)
      * exponent == 0          -> 1
      * negative base          -> reduced into [0, modulus)
      * negative exponent      -> uses the modular inverse of base
    """
    _require_int("base", base)
    _require_int("exponent", exponent)
    _require_int("modulus", modulus)
    if modulus < 1:
        raise ValueError("modulus must be >= 1")
    if modulus == 1:
        return 0
    if exponent < 0:
        base = mod_inverse(base, modulus)
        exponent = -exponent

    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:  # current binary digit of the exponent is 1
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin primality test.

    Write n - 1 = 2^s * d with d odd. For a random witness a, n is composite
    if a^d ≢ 1 and a^(2^r * d) ≢ -1 (mod n) for every 0 <= r < s.
    A composite passes one round with probability <= 1/4, so 40 rounds give
    error probability <= 4^-40. Unlike the plain Fermat test, Carmichael
    numbers (561, 1105, ...) are correctly rejected.
    """
    _require_int("n", n)
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)  # witness in [2, n-2]
        x = mod_pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # a is a witness that n is composite
    return True


def fermat_test(n: int, a: int) -> bool:
    """Single Fermat test: True if a^(n-1) ≡ 1 (mod n).

    Kept for teaching: Carmichael numbers fool it for every a coprime to n.
    """
    if n < 3:
        return n == 2
    return mod_pow(a, n - 1, n) == 1


def generate_prime(bits: int) -> int:
    """Return a random prime with exactly ``bits`` bits (bits >= 2)."""
    _require_int("bits", bits)
    if bits < 2:
        raise ValueError("a prime needs at least 2 bits")
    if bits == 2:
        return 2 + secrets.randbelow(2)  # 2 or 3
    while True:
        # Force the top bit (exact size) and the bottom bit (odd).
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def crt_pair(r1: int, m1: int, r2: int, m2: int) -> int:
    """Chinese Remainder Theorem for two coprime moduli.

    Returns the unique x in [0, m1*m2) with x ≡ r1 (mod m1), x ≡ r2 (mod m2).
    """
    _require_int("m1", m1)
    _require_int("m2", m2)
    if m1 < 1 or m2 < 1:
        raise ValueError("moduli must be positive")
    if gcd(m1, m2) != 1:
        raise ValueError("moduli must be coprime")
    if m2 == 1:
        return r1 % m1
    inv = mod_inverse(m1 % m2, m2)
    k = ((r2 - r1) * inv) % m2
    return (r1 + m1 * k) % (m1 * m2)
