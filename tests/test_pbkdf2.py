"""PBKDF2 tests: known-answer (SHA-256), length, determinism, salt uniqueness."""

import hashlib
import os
import unittest

from cryptocore.kdf import pbkdf2_hmac_sha256
from cryptocore.kdf.hkdf import derive_key


class TestPBKDF2Vectors(unittest.TestCase):
    """Known-answer tests for PBKDF2-HMAC-SHA256."""

    def _check(self, password, salt, iterations, dklen, expected_hex):
        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result.hex(), expected_hex)

    def test_case1(self):
        self._check(
            b"password", b"salt", 1, 32,
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
        )

    def test_case2(self):
        self._check(
            b"password", b"salt", 2, 32,
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
        )

    def test_case3(self):
        self._check(
            b"password", b"salt", 4096, 32,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        )

    def test_case4(self):
        self._check(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
            "c635518c7dac47e9",
        )


class TestPBKDF2Lengths(unittest.TestCase):
    def test_various_lengths(self):
        for length in (1, 7, 20, 31, 32, 33, 64, 100):
            result = pbkdf2_hmac_sha256(b"pw", b"salt", 10, length)
            self.assertEqual(len(result), length)
            expected = hashlib.pbkdf2_hmac("sha256", b"pw", b"salt", 10, length)
            self.assertEqual(result, expected)


class TestPBKDF2Determinism(unittest.TestCase):
    def test_same_input_same_output(self):
        a = pbkdf2_hmac_sha256(b"pw", b"salt", 1000, 32)
        b = pbkdf2_hmac_sha256(b"pw", b"salt", 1000, 32)
        self.assertEqual(a, b)

    def test_different_iterations_differ(self):
        a = pbkdf2_hmac_sha256(b"pw", b"salt", 1000, 32)
        b = pbkdf2_hmac_sha256(b"pw", b"salt", 1001, 32)
        self.assertNotEqual(a, b)


class TestKeyHierarchy(unittest.TestCase):
    def test_deterministic(self):
        master = b"0" * 32
        a = derive_key(master, "encryption", 32)
        b = derive_key(master, "encryption", 32)
        self.assertEqual(a, b)

    def test_context_separation(self):
        master = b"0" * 32
        k1 = derive_key(master, "encryption", 32)
        k2 = derive_key(master, "authentication", 32)
        self.assertNotEqual(k1, k2)

    def test_various_lengths(self):
        master = b"0" * 32
        for length in (1, 16, 32, 64, 100):
            self.assertEqual(len(derive_key(master, "ctx", length)), length)


class TestSaltUniqueness(unittest.TestCase):
    def test_1000_unique_salts(self):
        salts = {os.urandom(16) for _ in range(1000)}
        self.assertEqual(len(salts), 1000)