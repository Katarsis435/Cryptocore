"""CLI tests for the `derive` subcommand."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "cryptocore.cli_parser", "derive", *args],
        capture_output=True, text=True, check=False,
    )


class TestDeriveCLI(unittest.TestCase):
    def test_stdout_format(self):
        r = _run("--password", "pw", "--salt", "a1b2c3d4", "--iterations", "10",
                 "--length", "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        parts = r.stdout.strip().split()
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[0]), 32)   # 16 bytes hex
        self.assertEqual(parts[1], "a1b2c3d4")

    def test_random_salt_when_absent(self):
        r = _run("--password", "pw", "--iterations", "10", "--length", "16")
        self.assertEqual(r.returncode, 0, r.stderr)
        parts = r.stdout.strip().split()
        self.assertEqual(len(parts), 2)
        self.assertEqual(len(parts[1]), 32)  # 16-byte salt in hex

    def test_output_file_raw_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "key.bin"
            r = _run("--password", "pw", "--salt", "00", "--iterations", "10",
                     "--length", "32", "--output", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(out.exists())
            self.assertEqual(len(out.read_bytes()), 32)

    def test_invalid_iterations(self):
        r = _run("--password", "pw", "--iterations", "0")
        self.assertNotEqual(r.returncode, 0)

    def test_invalid_salt_hex(self):
        r = _run("--password", "pw", "--salt", "zzzz")
        self.assertNotEqual(r.returncode, 0)