"""Automated cross-check of our AES-128 ECB output against OpenSSL.

Skips silently if the `openssl` binary is not available in PATH.
"""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.modes.ecb import ecb_encrypt

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)


def _openssl_available() -> bool:
    return shutil.which("openssl") is not None


@unittest.skipUnless(_openssl_available(), "openssl binary not found in PATH")
class TestOpenSSLCompatibility(unittest.TestCase):
    """Compare our ciphertext byte-for-byte with `openssl enc -aes-128-ecb`."""

    def _openssl_encrypt(self, plaintext: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            inp = tmp / "in.bin"
            out = tmp / "out.bin"
            inp.write_bytes(plaintext)

            # OpenSSL's enc applies PKCS#7 padding by default (like us).
            subprocess.run(
                [
                    "openssl", "enc", "-aes-128-ecb",
                    "-K", KEY_HEX,
                    "-in", str(inp),
                    "-out", str(out),
                ],
                check=True,
                capture_output=True,
            )
            return out.read_bytes()

    def test_matches_openssl_on_text(self):
        pt = b"Hello CryptoCore!"
        ours = ecb_encrypt(pt, KEY)
        theirs = self._openssl_encrypt(pt)
        self.assertEqual(ours, theirs,
                         "Our ciphertext differs from OpenSSL output.")

    def test_matches_openssl_on_full_block(self):
        pt = bytes(range(16))
        self.assertEqual(ecb_encrypt(pt, KEY), self._openssl_encrypt(pt))

    def test_matches_openssl_on_binary(self):
        pt = bytes(range(256)) * 3
        self.assertEqual(ecb_encrypt(pt, KEY), self._openssl_encrypt(pt))

    def test_matches_openssl_on_empty(self):
        pt = b""
        self.assertEqual(ecb_encrypt(pt, KEY), self._openssl_encrypt(pt))


if __name__ == "__main__":
    unittest.main()