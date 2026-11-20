"""HMAC tests: RFC 4231 vectors + CLI verify + tamper detection."""

import os
import subprocess
import sys
import unittest

from cryptocore.mac import HMAC


class TestRFC4231(unittest.TestCase):
    def _check(self, key_hex, data, expected):
        self.assertEqual(
            HMAC.compute(bytes.fromhex(key_hex), data, "sha256"),
            expected,
        )

    def test_case1(self):
        self._check("0b" * 20, b"Hi There",
                    "b0344c61d8db38535ca8afceaf0bf12b"
                    "881dc200c9833da726e9376c2e32cff7")

    def test_case2(self):
        self._check("4a656665",
                    b"what do ya want for nothing?",
                    "5bdcc146bf60754e6a042426089575c7"
                    "5a003f089d2739839dec58b964ec3843")

    def test_case3(self):
        self._check("aa" * 20, b"\xdd" * 50,
                    "773ea91e36800e46854db8ebd09181a7"
                    "2959098b3ef8c122d9635514ced565fe")

    def test_case4(self):
        self._check("0102030405060708090a0b0c0d0e0f10111213141516171819",
                    b"\xcd" * 50,
                    "82558a389a443c0ea4cc819899f2083a"
                    "85f0faa3e578f8077a2e3ff46729665b")

    def test_long_key(self):
        # RFC 4231 case 6 — key longer than block size (131 bytes of 0xaa)
        key = b"\xaa" * 131
        data = b"Test Using Larger Than Block-Size Key - Hash Key First"
        self.assertEqual(
            HMAC.compute(key, data, "sha256"),
            "60e431591ee0b67f0d8a26aacbf5b77f"
            "8e0bc6213728c5140546040f0ee37f54",
        )


def _run(args):
    return subprocess.run(
        [sys.executable, "-m", "cryptocore.cli_parser", "dgst", *args],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )


class TestHMACCli(unittest.TestCase):
    def test_generate_and_verify(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            msg = os.path.join(d, "m.txt")
            hf = os.path.join(d, "hmac.txt")
            with open(msg, "wb") as f:
                f.write(b"hello")
            r = _run(["--algorithm", "sha256", "--hmac",
                      "--key", "00" * 16, "--input", msg])
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(hf, "w") as f:
                f.write(r.stdout)
            r2 = _run(["--algorithm", "sha256", "--hmac",
                       "--key", "00" * 16, "--input", msg, "--verify", hf])
            self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_tampered_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            msg = os.path.join(d, "m.txt")
            hf = os.path.join(d, "hmac.txt")
            with open(msg, "wb") as f:
                f.write(b"original")
            r = _run(["--algorithm", "sha256", "--hmac",
                      "--key", "00" * 16, "--input", msg])
            with open(hf, "w") as f:
                f.write(r.stdout)
            with open(msg, "wb") as f:
                f.write(b"modified")
            r2 = _run(["--algorithm", "sha256", "--hmac",
                       "--key", "00" * 16, "--input", msg, "--verify", hf])
            self.assertNotEqual(r2.returncode, 0)

    def test_wrong_key(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            msg = os.path.join(d, "m.txt")
            hf = os.path.join(d, "hmac.txt")
            with open(msg, "wb") as f:
                f.write(b"data")
            r = _run(["--algorithm", "sha256", "--hmac",
                      "--key", "00" * 16, "--input", msg])
            with open(hf, "w") as f:
                f.write(r.stdout)
            r2 = _run(["--algorithm", "sha256", "--hmac",
                       "--key", "ff" * 16, "--input", msg, "--verify", hf])
            self.assertNotEqual(r2.returncode, 0)

    def test_hmac_requires_key(self):
        r = _run(["--algorithm", "sha256", "--hmac", "--input", "-"])
        self.assertNotEqual(r.returncode, 0)