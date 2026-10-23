"""Tests for SHA-256 and SHA3-256 implementations."""

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from cryptocore.hash import get_hasher, REGISTRY
from cryptocore.hash.sha256 import SHA256, sha256
from cryptocore.hash.sha3_256 import SHA3_256, sha3_256
from cryptocore.hash_io import hash_file


class TestSHA256NISTVectors(unittest.TestCase):
    """NIST FIPS 180-4 known-answer tests (TEST-1)."""

    def test_empty(self):
        # TEST-2
        self.assertEqual(
            sha256(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )

    def test_abc(self):
        self.assertEqual(
            sha256(b"abc").hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_two_block(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(
            sha256(msg).hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        )

    def test_million_a(self):
        msg = b"a" * 1_000_000
        self.assertEqual(
            sha256(msg).hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        )


class TestSHA3_256NISTVectors(unittest.TestCase):
    """NIST FIPS 202 known-answer tests (TEST-1)."""

    def test_empty(self):
        self.assertEqual(
            sha3_256(b"").hex(),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        )

    def test_abc(self):
        self.assertEqual(
            sha3_256(b"abc").hex(),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        )

    def test_two_block(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        self.assertEqual(
            sha3_256(msg).hex(),
            "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
        )


class TestStreamingAPI(unittest.TestCase):
    """Same result whether fed in one chunk or many (HASH-5)."""

    def test_sha256_chunked(self):
        data = os.urandom(1000)
        one_shot = SHA256()
        one_shot.update(data)
        chunked = SHA256()
        for i in range(0, len(data), 7):
            chunked.update(data[i:i + 7])
        self.assertEqual(one_shot.hexdigest(), chunked.hexdigest())

    def test_sha3_chunked(self):
        data = os.urandom(1000)
        one_shot = SHA3_256()
        one_shot.update(data)
        chunked = SHA3_256()
        for i in range(0, len(data), 7):
            chunked.update(data[i:i + 7])
        self.assertEqual(one_shot.hexdigest(), chunked.hexdigest())


class TestAgainstHashlib(unittest.TestCase):
    """Cross-check against Python hashlib for many sizes (TEST-3 style)."""

    def test_sha256_matches_hashlib(self):
        for size in [0, 1, 55, 56, 63, 64, 65, 100, 1000, 10000]:
            data = os.urandom(size)
            self.assertEqual(
                sha256(data).hex(),
                hashlib.sha256(data).hexdigest(),
                f"mismatch at size={size}",
            )

    def test_sha3_256_matches_hashlib(self):
        for size in [0, 1, 135, 136, 137, 1000, 10000]:
            data = os.urandom(size)
            self.assertEqual(
                sha3_256(data).hex(),
                hashlib.sha3_256(data).hexdigest(),
                f"mismatch at size={size}",
            )


class TestHashFile(unittest.TestCase):
    """hash_file reads files in chunks (HASH-4, HASH-5, IO-1, IO-2)."""

    def test_small_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "f.bin"
            data = b"Hello"
            p.write_bytes(data)
            h = SHA256()
            self.assertEqual(hash_file(str(p), h), sha256(data).hex())

    def test_large_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "big.bin"
            data = os.urandom(5_000_000)   # 5 MB
            p.write_bytes(data)
            h = SHA256()
            self.assertEqual(hash_file(str(p), h), sha256(data).hex())

    def test_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            hash_file("no_such_file_xyz.bin", SHA256())


class TestAvalanche(unittest.TestCase):
    """TEST-5 (Should): flipping one bit changes ~50% of digest bits."""

    def _diff_bits(self, h1_hex, h2_hex):
        n = int(h1_hex, 16) ^ int(h2_hex, 16)
        return bin(n).count("1")

    def test_sha256_avalanche(self):
        d1 = sha256(b"Hello, world!").hex()
        d2 = sha256(b"Hello, world?").hex()
        diff = self._diff_bits(d1, d2)
        self.assertGreater(diff, 100)
        self.assertLess(diff, 156)

    def test_sha3_256_avalanche(self):
        d1 = sha3_256(b"Hello, world!").hex()
        d2 = sha3_256(b"Hello, world?").hex()
        diff = self._diff_bits(d1, d2)
        self.assertGreater(diff, 100)
        self.assertLess(diff, 156)


class TestRegistry(unittest.TestCase):
    def test_registry_contains_both(self):
        self.assertIn("sha256", REGISTRY)
        self.assertIn("sha3-256", REGISTRY)

    def test_get_hasher(self):
        self.assertIs(get_hasher("sha256"), SHA256)
        self.assertIs(get_hasher("sha3-256"), SHA3_256)

    def test_unknown(self):
        with self.assertRaises(ValueError):
            get_hasher("md5")


if __name__ == "__main__":
    unittest.main()