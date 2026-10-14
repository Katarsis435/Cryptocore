"""CLI-level test: encryption without --key, then decryption with printed key."""

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestAutoKeyRoundtrip(unittest.TestCase):
    def test_auto_key_then_decrypt(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            pt = tmp / "pt.bin"
            ct = tmp / "ct.bin"
            dec = tmp / "dec.bin"
            pt.write_bytes(b"Hello from Sprint 3!\n" * 5)

            # 1. Encrypt without --key; capture stdout.
            enc = subprocess.run(
                [sys.executable, "-m", "cryptocore.cli_parser",
                 "--algorithm", "aes", "--mode", "cbc", "--encrypt",
                 "--input", str(pt), "--output", str(ct)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(enc.returncode, 0,
                             f"encryption failed: {enc.stderr}")

            # 2. Extract key from stdout.
            m = re.search(r"Generated random key:\s*([0-9a-fA-F]{32})",
                          enc.stdout)
            self.assertIsNotNone(m, f"key not found in output:\n{enc.stdout}")
            key_hex = m.group(1)

            # 3. Decrypt with the extracted key.
            dec_run = subprocess.run(
                [sys.executable, "-m", "cryptocore.cli_parser",
                 "--algorithm", "aes", "--mode", "cbc", "--decrypt",
                 "--key", key_hex,
                 "--input", str(ct), "--output", str(dec)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(dec_run.returncode, 0,
                             f"decryption failed: {dec_run.stderr}")

            # 4. Compare.
            self.assertEqual(pt.read_bytes(), dec.read_bytes())


if __name__ == "__main__":
    unittest.main()