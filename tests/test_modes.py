"""Tests for CBC, CFB, OFB, CTR modes."""

import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptocore.modes import cbc, cfb, ofb, ctr

KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
IV = bytes.fromhex("101112131415161718191a1b1c1d1e1f")


class TestCBC(unittest.TestCase):
    def test_roundtrip_text(self):
        pt = b"Hello, CBC mode!"
        ct = cbc.cbc_encrypt(pt, KEY, IV)
        self.assertEqual(cbc.cbc_decrypt(ct, KEY, IV), pt)

    def test_roundtrip_binary(self):
        pt = bytes(range(256)) * 3
        ct = cbc.cbc_encrypt(pt, KEY, IV)
        self.assertEqual(cbc.cbc_decrypt(ct, KEY, IV), pt)

    def test_padding_block(self):
        pt = bytes(16)
        ct = cbc.cbc_encrypt(pt, KEY, IV)
        self.assertEqual(len(ct), 32)

    def test_iv_wrong_length(self):
        with self.assertRaises(ValueError):
            cbc.cbc_encrypt(b"data", KEY, b"tooshort")


class TestCFB(unittest.TestCase):
    def test_roundtrip_text(self):
        pt = b"Hello, CFB mode!"
        ct = cfb.cfb_encrypt(pt, KEY, IV)
        self.assertEqual(cfb.cfb_decrypt(ct, KEY, IV), pt)

    def test_no_padding_length(self):
        pt = b"x" * 20
        ct = cfb.cfb_encrypt(pt, KEY, IV)
        self.assertEqual(len(ct), 20)

    def test_roundtrip_binary(self):
        pt = bytes(range(256))
        self.assertEqual(cfb.cfb_decrypt(cfb.cfb_encrypt(pt, KEY, IV), KEY, IV), pt)


class TestOFB(unittest.TestCase):
    def test_roundtrip(self):
        pt = b"Hello, OFB mode!"
        self.assertEqual(ofb.ofb_decrypt(ofb.ofb_encrypt(pt, KEY, IV), KEY, IV), pt)

    def test_no_padding_length(self):
        pt = b"x" * 20
        self.assertEqual(len(ofb.ofb_encrypt(pt, KEY, IV)), 20)

    def test_symmetric(self):
        # OFB: encrypt == decrypt
        pt = b"AAAA"
        self.assertEqual(ofb.ofb_encrypt(pt, KEY, IV), ofb.ofb_decrypt(pt, KEY, IV))


class TestCTR(unittest.TestCase):
    def test_roundtrip(self):
        pt = b"Hello, CTR mode!"
        self.assertEqual(ctr.ctr_decrypt(ctr.ctr_encrypt(pt, KEY, IV), KEY, IV), pt)

    def test_no_padding_length(self):
        pt = b"x" * 20
        self.assertEqual(len(ctr.ctr_encrypt(pt, KEY, IV)), 20)

    def test_symmetric(self):
        pt = b"AAAA"
        self.assertEqual(ctr.ctr_encrypt(pt, KEY, IV), ctr.ctr_decrypt(pt, KEY, IV))


if __name__ == "__main__":
    unittest.main()