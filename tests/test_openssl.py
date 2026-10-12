"""Automated cross-check of CBC, CFB, OFB, CTR against OpenSSL.

Both directions are tested:
    CryptoCore -> OpenSSL
    OpenSSL -> CryptoCore

Skipped if `openssl` is not in PATH.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptocore.modes import cbc, cfb, ofb, ctr

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)
IV_HEX = "101112131415161718191a1b1c1d1e1f"
IV = bytes.fromhex(IV_HEX)

OPENSSL_SUFFIX = {
    "cbc": "-aes-128-cbc",
    "cfb": "-aes-128-cfb",
    "ofb": "-aes-128-ofb",
    "ctr": "-aes-128-ctr",
}

OUR_ENCRYPT = {
    "cbc": cbc.cbc_encrypt,
    "cfb": cfb.cfb_encrypt,
    "ofb": ofb.ofb_encrypt,
    "ctr": ctr.ctr_encrypt,
}

OUR_DECRYPT = {
    "cbc": cbc.cbc_decrypt,
    "cfb": cfb.cfb_decrypt,
    "ofb": ofb.ofb_decrypt,
    "ctr": ctr.ctr_decrypt,
}


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _openssl_encrypt(mode: str, plaintext: bytes, iv: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        inp, out = tmp / "in.bin", tmp / "out.bin"
        inp.write_bytes(plaintext)
        subprocess.run(
            ["openssl", "enc", OPENSSL_SUFFIX[mode],
             "-K", KEY_HEX, "-iv", iv.hex(),
             "-in", str(inp), "-out", str(out)],
            check=True, capture_output=True,
        )
        return out.read_bytes()


def _openssl_decrypt(mode: str, ciphertext: bytes, iv: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        inp, out = tmp / "in.bin", tmp / "out.bin"
        inp.write_bytes(ciphertext)
        subprocess.run(
            ["openssl", "enc", OPENSSL_SUFFIX[mode], "-d",
             "-K", KEY_HEX, "-iv", iv.hex(),
             "-in", str(inp), "-out", str(out)],
            check=True, capture_output=True,
        )
        return out.read_bytes()


@unittest.skipUnless(_openssl_available(), "openssl binary not found in PATH")
class TestOpenSSLModeCompat(unittest.TestCase):
    """CryptoCore <-> OpenSSL byte-for-byte compatibility for each mode."""

    PLAINTEXTS = {
        "short": b"Hello!",
        "block": bytes(range(16)),
        "long": bytes(range(256)) * 2,
        "notmult16": b"x" * 21,
    }

    def _check_ciphertext_equals(self, mode: str, pt: bytes):
        # CryptoCore ciphertext (without IV prefix)
        ours = OUR_ENCRYPT[mode](pt, KEY, IV)
        # OpenSSL ciphertext
        theirs = _openssl_encrypt(mode, pt, IV)
        self.assertEqual(ours, theirs,
                         f"{mode}: ciphertext differs from OpenSSL for len={len(pt)}")

    def _check_cryptocore_to_openssl(self, mode: str, pt: bytes):
        # Our ciphertext (with IV) — but we pass IV explicitly to OpenSSL
        ours_ct = OUR_ENCRYPT[mode](pt, KEY, IV)
        decrypted_by_openssl = _openssl_decrypt(mode, ours_ct, IV)
        self.assertEqual(decrypted_by_openssl, pt,
                         f"{mode}: OpenSSL could not decrypt our ciphertext")

    def _check_openssl_to_cryptocore(self, mode: str, pt: bytes):
        # OpenSSL ciphertext
        ossl_ct = _openssl_encrypt(mode, pt, IV)
        decrypted_by_us = OUR_DECRYPT[mode](ossl_ct, KEY, IV)
        self.assertEqual(decrypted_by_us, pt,
                         f"{mode}: we could not decrypt OpenSSL ciphertext")

    def test_all_modes_both_directions(self):
        for mode in ("cbc", "cfb", "ofb", "ctr"):
            for name, pt in self.PLAINTEXTS.items():
                with self.subTest(mode=mode, case=name, direction="ours->openssl"):
                    self._check_cryptocore_to_openssl(mode, pt)
                with self.subTest(mode=mode, case=name, direction="openssl->ours"):
                    self._check_openssl_to_cryptocore(mode, pt)
                with self.subTest(mode=mode, case=name, direction="byte-equal"):
                    self._check_ciphertext_equals(mode, pt)


if __name__ == "__main__":
    unittest.main()