"""Heavy PBKDF2 tests: RFC vectors with 4096 iterations and timing (TEST-8).

Skipped by default. To run:
    $env:RUN_PERF = "1"; python -m unittest tests.test_pbkdf2_perf -v   # PowerShell
    RUN_PERF=1 python -m unittest tests.test_pbkdf2_perf -v              # bash
"""

import os
import time
import unittest

from cryptocore.kdf import pbkdf2_hmac_sha256

RUN_PERF = os.environ.get("RUN_PERF") == "1"


@unittest.skipUnless(RUN_PERF, "set RUN_PERF=1 to run heavy PBKDF2 tests")
class TestPBKDF2HeavyVectors(unittest.TestCase):
    def _check(self, password, salt, iterations, dklen, expected_hex):
        result = pbkdf2_hmac_sha256(password, salt, iterations, dklen)
        self.assertEqual(result.hex(), expected_hex)

    def test_case3_4096_iterations(self):
        self._check(
            b"password", b"salt", 4096, 32,
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a",
        )

    def test_case4_4096_iterations(self):
        self._check(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1"
            "c635518c7dac47e9",
        )


@unittest.skipUnless(RUN_PERF, "set RUN_PERF=1 to run timing tests")
class TestPBKDF2Performance(unittest.TestCase):
    """TEST-8: measure PBKDF2 time for 10k / 100k / 1M iterations."""

    def _time(self, iterations):
        t0 = time.perf_counter()
        pbkdf2_hmac_sha256(b"pw", b"salt", iterations, 32)
        return time.perf_counter() - t0

    def test_10k_under_2s(self):
        elapsed = self._time(10_000)
        print(f"\n[PERF] 10k iterations: {elapsed:.3f}s")
        self.assertLess(elapsed, 2.0)

    def test_100k_under_20s(self):
        elapsed = self._time(100_000)
        print(f"\n[PERF] 100k iterations: {elapsed:.3f}s")
        self.assertLess(elapsed, 20.0)

    def test_1m_under_120s(self):
        elapsed = self._time(1_000_000)
        print(f"\n[PERF] 1M iterations: {elapsed:.3f}s")
        self.assertLess(elapsed, 120.0)