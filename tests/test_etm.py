"""Encrypt-then-MAC tests (AEAD-1, TEST-9)."""

import os
import unittest

from cryptocore.aead import etm


class TestEtM(unittest.TestCase):
    def test_roundtrip(self):
        key = os.urandom(16)
        msg = b"secret payload"
        aad = b"metadata"
        out = etm.encrypt(key, msg, aad)
        self.assertEqual(etm.decrypt(key, out, aad), msg)

    def test_wrong_aad(self):
        key = os.urandom(16)
        out = etm.encrypt(key, b"msg", b"right")
        with self.assertRaises(etm.AuthenticationError):
            etm.decrypt(key, out, b"wrong")

    def test_tampered_ciphertext(self):
        key = os.urandom(16)
        out = bytearray(etm.encrypt(key, b"msg", b""))
        out[20] ^= 0x01
        with self.assertRaises(etm.AuthenticationError):
            etm.decrypt(key, bytes(out), b"")

    def test_tampered_tag(self):
        key = os.urandom(16)
        out = bytearray(etm.encrypt(key, b"msg", b""))
        out[-1] ^= 0x01
        with self.assertRaises(etm.AuthenticationError):
            etm.decrypt(key, bytes(out), b"")

    def test_empty_aad(self):
        key = os.urandom(16)
        out = etm.encrypt(key, b"x")
        self.assertEqual(etm.decrypt(key, out), b"x")