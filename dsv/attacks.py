"""Attacks on weak RSA signatures, to show WHY the rules in rsa.py exist.

* factor_trial_division / pollard_rho  - small n can be factored, which
  reveals phi(n) and therefore the private exponent d.
* recover_private_key                  - full key recovery from a factored n.
* multiplicative_forgery               - textbook RSA is multiplicative:
  (s1*s2)^e = m1*m2 (mod n), so two signatures give a third for free.
* existential_forgery                  - pick any s, publish m = s^e mod n.

Hashing the message before signing (rsa.sign) defeats the two forgeries,
because the attacker cannot find a message whose hash equals m1*m2 or s^e.
"""

from __future__ import annotations

import secrets
from typing import Optional, Tuple

from .number_theory import gcd, is_probable_prime, mod_pow
from .rsa import PrivateKey, PublicKey, keypair_from_primes


def factor_trial_division(n: int, limit: Optional[int] = None) -> Optional[int]:
    """Return the smallest prime factor of n by trial division up to sqrt(n)."""
    if n < 4:
        return None
    if n % 2 == 0:
        return 2
    f = 3
    bound = limit if limit is not None else n
    while f * f <= n and f <= bound:
        if n % f == 0:
            return f
        f += 2
    return None


def pollard_rho(n: int, max_steps: int = 1_000_000) -> Optional[int]:
    """Pollard's rho factorisation using f(x) = x^2 + c mod n and Floyd's cycle detection.

    Expected about sqrt(p) steps where p is the smallest prime factor.
    """
    if n < 4 or is_probable_prime(n):
        return None
    if n % 2 == 0:
        return 2
    for _ in range(20):  # retry with a different constant c if a run fails
        c = 1 + secrets.randbelow(n - 1)
        x = y = 2 + secrets.randbelow(n - 2)
        d = 1
        steps = 0
        while d == 1 and steps < max_steps:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = gcd(abs(x - y), n)
            steps += 1
        if 1 < d < n:
            return d
    return None


def recover_private_key(public: PublicKey) -> Optional[PrivateKey]:
    """Break a small key: factor n, rebuild phi(n), compute d."""
    p = factor_trial_division(public.n, limit=1_000_000) or pollard_rho(public.n)
    if p is None:
        return None
    q = public.n // p
    return keypair_from_primes(min(p, q), max(p, q), public.e)


def multiplicative_forgery(
    public: PublicKey, pair1: Tuple[int, int], pair2: Tuple[int, int]
) -> Tuple[int, int]:
    """From (m1, s1) and (m2, s2) build (m1*m2 mod n, s1*s2 mod n)."""
    (m1, s1), (m2, s2) = pair1, pair2
    return (m1 * m2) % public.n, (s1 * s2) % public.n


def existential_forgery(public: PublicKey) -> Tuple[int, int]:
    """Choose a random signature s and compute the 'message' it signs."""
    s = 2 + secrets.randbelow(public.n - 2)
    return mod_pow(s, public.e, public.n), s
