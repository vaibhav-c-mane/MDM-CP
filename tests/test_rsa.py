import unittest

from dsv.number_theory import mod_pow
from dsv.rsa import (
    PublicKey,
    RSAKeyError,
    generate_keypair,
    hash_to_int,
    keypair_from_primes,
    parse_signature,
    sign,
    sign_int,
    verify,
)

KEY = generate_keypair(1024)          # shared key for most tests
OTHER = generate_keypair(1024)        # a different signer
TOY = keypair_from_primes(61, 53, 17)  # textbook example, n = 3233


class TestKeyGeneration(unittest.TestCase):
    def test_textbook_example(self):  # RSA-01
        self.assertEqual((TOY.n, TOY.d), (3233, 2753))

    def test_e_times_d_is_one_mod_phi(self):  # RSA-02
        phi = (KEY.p - 1) * (KEY.q - 1)
        self.assertEqual((KEY.e * KEY.d) % phi, 1)
        self.assertEqual(KEY.p * KEY.q, KEY.n)

    def test_exact_bit_length(self):  # RSA-03
        for bits in (8, 16, 64, 512):
            self.assertEqual(generate_keypair(bits).n.bit_length(), bits)

    def test_tiny_key_falls_back_to_small_e(self):  # RSA-04
        key = generate_keypair(16)
        self.assertLess(key.e, (key.p - 1) * (key.q - 1))

    def test_key_too_small(self):  # RSA-05
        with self.assertRaises(RSAKeyError):
            generate_keypair(4)

    def test_e_too_large_for_key(self):
        with self.assertRaises(RSAKeyError):
            generate_keypair(16, e=65537)

    def test_p_not_prime(self):  # RSA-06
        with self.assertRaises(RSAKeyError):
            keypair_from_primes(15, 53, 17)

    def test_p_equals_q(self):  # RSA-07
        with self.assertRaises(RSAKeyError):
            keypair_from_primes(61, 61, 17)

    def test_e_not_coprime_to_phi(self):  # RSA-08
        with self.assertRaises(RSAKeyError):
            keypair_from_primes(61, 53, 3)  # phi = 3120 is divisible by 3

    def test_e_out_of_range(self):  # RSA-09
        for e in (1, 0, -17, 3120, 5000):
            with self.assertRaises(RSAKeyError):
                keypair_from_primes(61, 53, e)

    def test_non_integer_parameters(self):
        with self.assertRaises(TypeError):
            keypair_from_primes(61.0, 53, 17)


class TestSignVerify(unittest.TestCase):
    def test_round_trip(self):  # SIG-01
        s = sign("hello", KEY)
        r = verify("hello", s, KEY.public_key)
        self.assertTrue(r.valid)
        self.assertEqual(r.reason, "VALID")

    def test_crt_equals_plain_exponentiation(self):  # SIG-02
        h = hash_to_int("abc", KEY.n)
        self.assertEqual(sign_int(h, KEY, use_crt=True), sign_int(h, KEY, use_crt=False))

    def test_deterministic(self):  # SIG-03
        self.assertEqual(sign("same", KEY), sign("same", KEY))

    def test_tampered_message(self):  # SIG-04
        s = sign("pay 100", KEY)
        r = verify("pay 900", s, KEY.public_key)
        self.assertFalse(r.valid)
        self.assertEqual(r.reason, "INVALID_SIGNATURE")

    def test_one_character_and_whitespace_changes(self):  # SIG-05
        s = sign("Hello", KEY)
        for changed in ("hello", "Hello ", " Hello", "Hello\n"):
            self.assertFalse(verify(changed, s, KEY.public_key).valid, repr(changed))

    def test_tampered_signature(self):  # SIG-06
        s = sign("msg", KEY)
        for bad in (s + 1, s - 1, s ^ 1, s ^ (1 << 500)):
            self.assertFalse(verify("msg", bad, KEY.public_key).valid)

    def test_wrong_public_key(self):  # SIG-07
        s = sign("msg", KEY)
        self.assertFalse(verify("msg", s, OTHER.public_key).valid)

    def test_signature_equal_to_n(self):  # SIG-08
        r = verify("msg", KEY.n, KEY.public_key)
        self.assertEqual(r.reason, "SIGNATURE_OUT_OF_RANGE")

    def test_signature_plus_n_is_rejected(self):  # SIG-09  (s + n ≡ s mod n)
        s = sign("msg", KEY)
        self.assertEqual(verify("msg", s + KEY.n, KEY.public_key).reason, "SIGNATURE_OUT_OF_RANGE")

    def test_negative_signature(self):  # SIG-10
        self.assertEqual(verify("msg", -1, KEY.public_key).reason, "SIGNATURE_OUT_OF_RANGE")

    def test_zero_and_one_signatures(self):  # SIG-11
        for s in (0, 1):
            self.assertFalse(verify("msg", s, KEY.public_key).valid)

    def test_empty_message(self):  # SIG-12
        s = sign("", KEY)
        self.assertTrue(verify("", s, KEY.public_key).valid)
        self.assertFalse(verify(" ", s, KEY.public_key).valid)

    def test_unicode_message(self):  # SIG-13
        text = "नमस्ते 世界 🔐"
        s = sign(text, KEY)
        self.assertTrue(verify(text, s, KEY.public_key).valid)
        self.assertTrue(verify(text.encode("utf-8"), s, KEY.public_key).valid)

    def test_binary_and_large_message(self):  # SIG-14
        data = bytes(range(256)) * 4096  # 1 MiB with every byte value
        s = sign(data, KEY)
        self.assertTrue(verify(data, s, KEY.public_key).valid)
        self.assertFalse(verify(data[:-1], s, KEY.public_key).valid)

    def test_signature_as_strings(self):  # SIG-15
        s = sign("msg", KEY)
        self.assertTrue(verify("msg", hex(s), KEY.public_key).valid)
        self.assertTrue(verify("msg", str(s), KEY.public_key).valid)
        self.assertTrue(verify("msg", f"  {hex(s).upper().replace('X', 'x')}\n", KEY.public_key).valid)

    def test_malformed_signature_strings(self):  # SIG-16
        for bad in ("", "   ", "xyz", "0xZZ", "12.5"):
            self.assertEqual(verify("msg", bad, KEY.public_key).reason, "MALFORMED_SIGNATURE")

    def test_signature_wrong_type(self):
        for bad in (None, 1.0, True, [1]):
            self.assertEqual(verify("msg", bad, KEY.public_key).reason, "MALFORMED_SIGNATURE")

    def test_message_wrong_type(self):  # SIG-17
        s = sign("msg", KEY)
        self.assertEqual(verify(12345, s, KEY.public_key).reason, "INVALID_INPUT")

    def test_sign_value_out_of_range(self):
        with self.assertRaises(ValueError):
            sign_int(KEY.n, KEY)
        with self.assertRaises(ValueError):
            sign_int(-1, KEY)

    def test_h_not_coprime_to_n_still_verifies(self):  # SIG-18
        # Euler's theorem needs gcd(h, n) = 1, but RSA still works via CRT.
        for h in (0, 1, TOY.p, TOY.q, 2 * TOY.p):
            s = sign_int(h, TOY)
            self.assertEqual(mod_pow(s, TOY.e, TOY.n), h)


class TestKeyChecksAndWarnings(unittest.TestCase):
    def test_malformed_public_keys(self):  # KEY-01..06
        cases = [
            PublicKey(n=4, e=3),        # too small
            PublicKey(n=3234, e=17),    # even n
            PublicKey(n=3233, e=1),     # e < 3
            PublicKey(n=3233, e=16),    # even e
            PublicKey(n=3233, e=4000),  # e >= n
            PublicKey(n=7919, e=17),    # n is prime
        ]
        for key in cases:
            self.assertEqual(verify("m", 5, key).reason, "MALFORMED_KEY", key)

    def test_small_key_warnings(self):  # KEY-07
        s = sign("m", TOY)
        r = verify("m", s, TOY.public_key)
        self.assertTrue(r.valid)
        self.assertEqual(len(r.warnings), 2)

    def test_2048_bit_key_has_no_warning(self):  # KEY-08
        key = generate_keypair(2048)
        r = verify("m", sign("m", key), key.public_key)
        self.assertTrue(r.valid)
        self.assertEqual(r.warnings, [])

    def test_hash_collision_with_toy_key(self):  # KEY-09
        # With n = 3233 the hash is reduced mod n, so collisions are easy to find.
        seen = {}
        for i in range(10000):
            h = hash_to_int(f"doc-{i}", TOY.n)
            if h in seen:
                a, b = seen[h], f"doc-{i}"
                break
            seen[h] = f"doc-{i}"
        else:
            self.fail("expected a collision (birthday bound ~ sqrt(3233))")
        s = sign(a, TOY)
        self.assertTrue(verify(b, s, TOY.public_key).valid)  # why small keys are unsafe

    def test_parse_signature(self):
        self.assertEqual(parse_signature("0x1f"), 31)
        self.assertEqual(parse_signature("31"), 31)
        self.assertEqual(parse_signature(31), 31)


if __name__ == "__main__":
    unittest.main()
