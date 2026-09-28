import unittest

from dsv.attacks import (existential_forgery, factor_trial_division, multiplicative_forgery,
                         pollard_rho, recover_private_key)
from dsv.rsa import generate_keypair, keypair_from_primes, sign_int, textbook_verify, verify


class TestFactoring(unittest.TestCase):
    def test_trial_division(self):  # ATK-01
        self.assertEqual(factor_trial_division(3233), 53)
        self.assertEqual(factor_trial_division(1024), 2)
        self.assertIsNone(factor_trial_division(97))

    def test_pollard_rho(self):  # ATK-02
        n = 1000003 * 1000033
        self.assertIn(pollard_rho(n), (1000003, 1000033))
        self.assertIsNone(pollard_rho(1000003))

    def test_recover_small_key(self):  # ATK-03
        key = generate_keypair(48)
        broken = recover_private_key(key.public_key)
        self.assertEqual(broken.d, key.d)


class TestForgery(unittest.TestCase):
    key = keypair_from_primes(1000003, 1000033, 65537)

    def test_multiplicative(self):  # ATK-04
        pub = self.key.public_key
        m, s = multiplicative_forgery(pub, (5, sign_int(5, self.key)), (7, sign_int(7, self.key)))
        self.assertEqual(m, 35)
        self.assertTrue(textbook_verify(m, s, pub))
        self.assertFalse(verify(str(m), s, pub).valid)  # hashing stops it

    def test_existential(self):  # ATK-05
        pub = self.key.public_key
        m, s = existential_forgery(pub)
        self.assertTrue(textbook_verify(m, s, pub))
        self.assertFalse(verify(str(m), s, pub).valid)


if __name__ == "__main__":
    unittest.main()
