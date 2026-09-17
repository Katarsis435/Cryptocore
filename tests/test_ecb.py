"""Unit tests for AES-128 ECB + PKCS#7 implementation."""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.modes.ecb import ecb_encrypt, ecb_decrypt, pkcs7_pad, pkcs7_unpad


class TestPKCS7(unittest.TestCase):
    def test_pad_full_block(self):
        self.assertEqual(pkcs7_pad(b"A" * 16), b"A" * 16 + b"\x10" * 16)

    def test_pad_partial(self):
        self.assertEqual(pkcs7_pad(b"A" * 5), b"A" * 5 + b"\x0b" * 11)

    def test_pad_unpad_roundtrip(self):
        for n in range(0, 40):
            data = b"x" * n
            self.assertEqual(pkcs7_unpad(pkcs7_pad(data)), data)

    def test_unpad_invalid(self):
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"A" * 16)


class TestECB(unittest.TestCase):
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

    def test_roundtrip_text(self):
        pt = b"Hello, CryptoCore!"
        ct = ecb_encrypt(pt, self.KEY)
        self.assertEqual(ecb_decrypt(ct, self.KEY), pt)

    def test_roundtrip_binary(self):
        pt = bytes(range(256)) * 3
        ct = ecb_encrypt(pt, self.KEY)
        self.assertEqual(ecb_decrypt(ct, self.KEY), pt)

    def test_known_vector(self):
        # NIST FIPS-197 AES-128 ECB test vector (single block, no padding)
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        from Crypto.Cipher import AES
        ct = AES.new(key, AES.MODE_ECB).encrypt(pt)
        self.assertEqual(ct, expected_ct)

    def test_bad_key_length(self):
        with self.assertRaises(ValueError):
            ecb_encrypt(b"data", b"shortkey")


if __name__ == "__main__":
    unittest.main()