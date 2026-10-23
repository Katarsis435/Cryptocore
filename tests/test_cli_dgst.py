"""CLI tests for the `dgst` subcommand."""

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class TestDgstCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "cryptocore.cli_parser", "dgst", *args],
            capture_output=True, text=True, check=False,
        )

    def test_sha256_stdout_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.txt"
            p.write_bytes(b"abc")
            r = self._run("--algorithm", "sha256", "--input", str(p))
            self.assertEqual(r.returncode, 0, r.stderr)
            expected = hashlib.sha256(b"abc").hexdigest()
            self.assertEqual(r.stdout.strip(), f"{expected}  {p}")

    def test_sha3_256_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.txt"
            p.write_bytes(b"abc")
            r = self._run("--algorithm", "sha3-256", "--input", str(p))
            self.assertEqual(r.returncode, 0, r.stderr)
            expected = hashlib.sha3_256(b"abc").hexdigest()
            self.assertEqual(r.stdout.strip(), f"{expected}  {p}")

    def test_output_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.txt"
            p.write_bytes(b"abc")
            out = Path(tmp) / "hash.txt"
            r = self._run("--algorithm", "sha256", "--input", str(p),
                          "--output", str(out))
            self.assertEqual(r.returncode, 0, r.stderr)
            content = out.read_text(encoding="utf-8").strip()
            self.assertEqual(content,
                             f"{hashlib.sha256(b'abc').hexdigest()}  {p}")

    def test_rejects_key_arg(self):
        """CLI-3: dgst must not accept encryption-specific args."""
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.txt"
            p.write_bytes(b"x")
            r = self._run("--algorithm", "sha256", "--input", str(p),
                          "--key", "a" * 32)
            self.assertNotEqual(r.returncode, 0)

    def test_rejects_mode_arg(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.txt"
            p.write_bytes(b"x")
            r = self._run("--algorithm", "sha256", "--input", str(p),
                          "--mode", "cbc")
            self.assertNotEqual(r.returncode, 0)

    def test_missing_file(self):
        r = self._run("--algorithm", "sha256", "--input", "no_such_xyz.bin")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not found", r.stderr.lower())


if __name__ == "__main__":
    unittest.main()