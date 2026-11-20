"""GCM tests: NIST vectors, round-trip, tamper detection."""

import os
import unittest

from cryptocore.modes.gcm import GCM, AuthenticationError


class TestNISTVectors(unittest.TestCase):
    """Test Cases 1-3 from NIST SP 800-38D Appendix B."""

    def _check(self, key, iv, pt, aad, expected_ct, expected_tag):
        gcm = GCM(bytes.fromhex(key), bytes.fromhex(iv))
        out = gcm.encrypt(bytes.fromhex(pt), bytes.fromhex(aad))
        self.assertEqual(out[12:-16].hex(), expected_ct)
        self.assertEqual(out[-16:].hex(), expected_tag)

    def test_case1(self):
        self._check(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        )

    def test_case2(self):
        self._check(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        )

    def test_case3(self):
        key = "feffe9928665731c6d6a8f9467308308"
        iv = "cafebabefacedbaddecaf888"
        pt = ("d9313225f88406e5a55909c5aff5269a"
              "86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b391aafd255")
        ct = ("42831ec2217774244b7221b784d0d49c"
              "e3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa05"
              "1ba30b396a0aac973d58e091473f5985")
        tag = "4d5c2af327cd64a62cf35abd2ba6fab4"
        self._check(key, iv, pt, "", ct, tag)


    def test_case4_with_aad(self):
        """NIST SP 800-38D Appendix B, Test Case 4: with AAD."""
        key = "feffe9928665731c6d6a8f9467308308"
        iv = "cafebabefacedbaddecaf888"
        pt = ("d9313225f88406e5a55909c5aff5269a"
              "86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39")
        aad = ("feedfacedeadbeeffeedfacedeadbeef"
               "abaddad2")
        ct = ("42831ec2217774244b7221b784d0d49c"
              "e3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa05"
              "1ba30b396a0aac973d58e091")
        tag = "5bc94fbc3221a5db94fae95ae7121a47"
        self._check(key, iv, pt, aad, ct, tag)



class TestRoundTrip(unittest.TestCase):
    def test_roundtrip_no_aad(self):
        key = os.urandom(16)
        msg = b"hello world, this is a test message"
        gcm = GCM(key)
        out = gcm.encrypt(msg)
        gcm2 = GCM(key, gcm.nonce)
        self.assertEqual(gcm2.decrypt(out), msg)

    def test_roundtrip_with_aad(self):
        key = os.urandom(16)
        msg = b"another message"
        aad = b"header:meta"
        gcm = GCM(key)
        out = gcm.encrypt(msg, aad)
        gcm2 = GCM(key, gcm.nonce)
        self.assertEqual(gcm2.decrypt(out, aad), msg)

    def test_empty_plaintext(self):
        key = os.urandom(16)
        gcm = GCM(key)
        out = gcm.encrypt(b"")
        gcm2 = GCM(key, gcm.nonce)
        self.assertEqual(gcm2.decrypt(out), b"")


class TestTamperDetection(unittest.TestCase):
    def test_wrong_aad(self):
        key = os.urandom(16)
        gcm = GCM(key)
        out = gcm.encrypt(b"secret", b"correct_aad")
        gcm2 = GCM(key, gcm.nonce)
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(out, b"wrong_aad")

    def test_tampered_ciphertext(self):
        key = os.urandom(16)
        gcm = GCM(key)
        out = bytearray(gcm.encrypt(b"secret message", b"aad"))
        out[15] ^= 0x01
        gcm2 = GCM(key, gcm.nonce)
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(bytes(out), b"aad")

    def test_tampered_tag(self):
        key = os.urandom(16)
        gcm = GCM(key)
        out = bytearray(gcm.encrypt(b"secret", b""))
        out[-1] ^= 0x01
        gcm2 = GCM(key, gcm.nonce)
        with self.assertRaises(AuthenticationError):
            gcm2.decrypt(bytes(out), b"")


class TestNonceUniqueness(unittest.TestCase):
    def test_1000_unique_nonces(self):
        key = os.urandom(16)
        nonces = {GCM(key).nonce for _ in range(1000)}
        self.assertEqual(len(nonces), 1000)