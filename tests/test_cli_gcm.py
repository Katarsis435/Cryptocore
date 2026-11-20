"""CLI tests for --mode gcm (CLI-1..5, IO-1..3, TEST-2..4)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

KEY = "00112233445566778899aabbccddeeff"


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "cryptocore.cli_parser", *args],
        capture_output=True, text=True, check=False,
    )


class TestGcmCLI(unittest.TestCase):
    def test_roundtrip_with_aad(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            src = p / "pt.txt"; src.write_bytes(b"hello gcm")
            enc = p / "ct.bin"; dec = p / "dt.txt"
            r = _run("--algorithm", "aes", "--mode", "gcm", "--encrypt",
                     "--key", KEY, "--aad", "aabbccdd",
                     "--input", str(src), "--output", str(enc))
            self.assertEqual(r.returncode, 0, r.stderr)
            r = _run("--algorithm", "aes", "--mode", "gcm", "--decrypt",
                     "--key", KEY, "--aad", "aabbccdd",
                     "--input", str(enc), "--output", str(dec))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(dec.read_bytes(), b"hello gcm")

    def test_wrong_aad_fails_and_no_output(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            src = p / "pt.txt"; src.write_bytes(b"payload")
            enc = p / "ct.bin"; dec = p / "should_not_exist.txt"
            _run("--algorithm", "aes", "--mode", "gcm", "--encrypt",
                 "--key", KEY, "--aad", "aabbccdd",
                 "--input", str(src), "--output", str(enc))
            r = _run("--algorithm", "aes", "--mode", "gcm", "--decrypt",
                     "--key", KEY, "--aad", "deadbeef",
                     "--input", str(enc), "--output", str(dec))
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("auth", r.stderr.lower())
            self.assertFalse(dec.exists())

    def test_tampered_ciphertext_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            src = p / "pt.txt"; src.write_bytes(b"payload payload payload")
            enc = p / "ct.bin"; dec = p / "out.txt"
            _run("--algorithm", "aes", "--mode", "gcm", "--encrypt",
                 "--key", KEY, "--input", str(src), "--output", str(enc))
            data = bytearray(enc.read_bytes())
            data[13] ^= 0x01
            enc.write_bytes(bytes(data))
            r = _run("--algorithm", "aes", "--mode", "gcm", "--decrypt",
                     "--key", KEY, "--input", str(enc), "--output", str(dec))
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(dec.exists())