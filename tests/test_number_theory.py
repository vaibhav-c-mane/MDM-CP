import random
import unittest

from dsv.number_theory import (
    crt_pair,
    extended_gcd,
    fermat_test,
    gcd,
    generate_prime,
    is_probable_prime,
    lcm,
    mod_inverse,
    mod_pow,
)

CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265]
KNOWN_PRIMES = [2, 3, 5, 97, 7919, 104729, 2**31 - 1, 2**61 - 1, 2**127 - 1]


class TestGcd(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(gcd(48, 18), 6)
        self.assertEqual(gcd(17, 5), 1)

    def test_zero_cases(self):  # NT-01
        self.assertEqual(gcd(0, 0), 0)
        self.assertEqual(gcd(0, 7), 7)
        self.assertEqual(gcd(7, 0), 7)

    def test_negative_inputs(self):  # NT-02
        self.assertEqual(gcd(-48, 18), 6)
        self.assertEqual(gcd(48, -18), 6)
        self.assertEqual(gcd(-48, -18), 6)

    def test_equal_and_one(self):
        self.assertEqual(gcd(13, 13), 13)
        self.assertEqual(gcd(1, 10**50), 1)

    def test_rejects_non_integers(self):  # NT-03
        for bad in (1.5, "4", None, True):
            with self.assertRaises(TypeError):
                gcd(bad, 4)

    def test_matches_builtin_randomly(self):
        import math
        rng = random.Random(1)
        for _ in range(500):
            a, b = rng.randint(-10**12, 10**12), rng.randint(-10**12, 10**12)
            self.assertEqual(gcd(a, b), math.gcd(a, b))


class TestExtendedGcd(unittest.TestCase):
    def test_bezout_identity_holds(self):  # NT-04
        rng = random.Random(2)
        for _ in range(500):
            a, b = rng.randint(-10**9, 10**9), rng.randint(-10**9, 10**9)
            g, x, y = extended_gcd(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(g, gcd(a, b))
            self.assertGreaterEqual(g, 0)

    def test_zero(self):
        self.assertEqual(extended_gcd(0, 0)[0], 0)
        g, x, y = extended_gcd(0, 5)
        self.assertEqual((g, 0 * x + 5 * y), (5, 5))

    def test_lcm(self):
        self.assertEqual(lcm(4, 6), 12)
        self.assertEqual(lcm(0, 6), 0)
        self.assertEqual(lcm(-4, 6), 12)


class TestModInverse(unittest.TestCase):
    def test_textbook(self):
        self.assertEqual(mod_inverse(17, 3120), 2753)
        self.assertEqual(mod_inverse(3, 11), 4)

    def test_no_inverse_when_not_coprime(self):  # NT-05
        with self.assertRaises(ValueError):
            mod_inverse(6, 9)
        with self.assertRaises(ValueError):
            mod_inverse(0, 7)

    def test_bad_modulus(self):  # NT-06
        for n in (1, 0, -5):
            with self.assertRaises(ValueError):
                mod_inverse(3, n)

    def test_negative_and_large_a(self):  # NT-07
        self.assertEqual((mod_inverse(-3, 11) * -3) % 11, 1)
        self.assertEqual((mod_inverse(14, 11) * 14) % 11, 1)

    def test_matches_builtin(self):
        rng = random.Random(3)
        for _ in range(300):
            n = rng.randint(2, 10**12)
            a = rng.randint(1, n - 1)
            if gcd(a, n) == 1:
                self.assertEqual(mod_inverse(a, n), pow(a, -1, n))


class TestModPow(unittest.TestCase):
    def test_matches_builtin_pow(self):  # NT-08
        rng = random.Random(4)
        for _ in range(500):
            b, e, m = rng.randint(0, 10**30), rng.randint(0, 10**30), rng.randint(1, 10**30)
            self.assertEqual(mod_pow(b, e, m), pow(b, e, m))

    def test_exponent_zero(self):  # NT-09
        self.assertEqual(mod_pow(5, 0, 7), 1)
        self.assertEqual(mod_pow(0, 0, 7), 1)  # convention 0^0 = 1

    def test_modulus_one(self):  # NT-10
        self.assertEqual(mod_pow(5, 3, 1), 0)
        self.assertEqual(mod_pow(5, 0, 1), 0)

    def test_base_zero_and_multiple_of_modulus(self):
        self.assertEqual(mod_pow(0, 5, 7), 0)
        self.assertEqual(mod_pow(14, 5, 7), 0)

    def test_negative_base(self):  # NT-11
        self.assertEqual(mod_pow(-2, 3, 7), (-8) % 7)

    def test_negative_exponent(self):  # NT-12
        self.assertEqual(mod_pow(3, -1, 11), 4)
        self.assertEqual(mod_pow(3, -2, 11), pow(3, -2, 11))
        with self.assertRaises(ValueError):
            mod_pow(6, -1, 9)  # 6 has no inverse mod 9

    def test_bad_modulus(self):
        with self.assertRaises(ValueError):
            mod_pow(2, 3, 0)
        with self.assertRaises(ValueError):
            mod_pow(2, 3, -7)

    def test_huge_numbers(self):
        m = 2**2048 - 1
        self.assertEqual(mod_pow(3, 2**2000 + 12345, m), pow(3, 2**2000 + 12345, m))

    def test_fermat_little_theorem(self):  # NT-13
        for p in (7, 97, 7919):
            for a in (2, 3, 10, p - 1):
                self.assertEqual(mod_pow(a, p - 1, p), 1)


class TestPrimality(unittest.TestCase):
    def test_non_primes_below_two(self):  # NT-14
        for n in (-7, -1, 0, 1):
            self.assertFalse(is_probable_prime(n))

    def test_small_primes_and_composites(self):
        primes = [p for p in range(2, 1000) if all(p % d for d in range(2, int(p**0.5) + 1))]
        for n in range(1000):
            self.assertEqual(is_probable_prime(n), n in primes, n)

    def test_known_large_primes(self):  # NT-15
        for p in KNOWN_PRIMES:
            self.assertTrue(is_probable_prime(p), p)

    def test_carmichael_numbers_rejected(self):  # NT-16
        for n in CARMICHAEL:
            self.assertFalse(is_probable_prime(n), n)

    def test_fermat_test_is_fooled_by_carmichael(self):  # NT-17
        self.assertTrue(fermat_test(561, 2))  # 561 = 3*11*17 but passes Fermat
        self.assertFalse(is_probable_prime(561))

    def test_strong_pseudoprimes(self):  # NT-18
        # 2047 = 23*89 and 3215031751 fool Miller-Rabin for some fixed bases.
        for n in (2047, 1373653, 3215031751):
            self.assertFalse(is_probable_prime(n), n)

    def test_product_of_two_large_primes(self):
        self.assertFalse(is_probable_prime((2**61 - 1) * (2**31 - 1)))

    def test_perfect_square_of_prime(self):
        self.assertFalse(is_probable_prime(7919 * 7919))


class TestGeneratePrime(unittest.TestCase):
    def test_exact_bit_length(self):  # NT-19
        for bits in (2, 3, 8, 16, 64, 256):
            p = generate_prime(bits)
            self.assertEqual(p.bit_length(), bits)
            self.assertTrue(is_probable_prime(p))

    def test_too_few_bits(self):  # NT-20
        for bits in (1, 0, -3):
            with self.assertRaises(ValueError):
                generate_prime(bits)


class TestCrt(unittest.TestCase):
    def test_basic(self):  # NT-21
        x = crt_pair(2, 3, 3, 5)
        self.assertEqual((x % 3, x % 5), (2, 3))
        self.assertEqual(x, 8)

    def test_not_coprime(self):
        with self.assertRaises(ValueError):
            crt_pair(1, 4, 3, 6)

    def test_modulus_one(self):
        self.assertEqual(crt_pair(4, 7, 0, 1), 4)

    def test_random(self):
        rng = random.Random(5)
        for _ in range(300):
            m1, m2 = generate_prime(20), generate_prime(21)
            r1, r2 = rng.randrange(m1), rng.randrange(m2)
            x = crt_pair(r1, m1, r2, m2)
            self.assertEqual((x % m1, x % m2), (r1, r2))
            self.assertTrue(0 <= x < m1 * m2)


if __name__ == "__main__":
    unittest.main()
