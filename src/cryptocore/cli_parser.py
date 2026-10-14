"""Tests for the CSPRNG module and key generation."""

import unittest

from cryptocore.csprng import (
    generate_random_bytes,
    generate_key,
    generate_iv,
    CSPRNGError,
    BLOCK_SIZE,
)


class TestGenerateRandomBytes(unittest.TestCase):
    def test_correct_length(self):
        for n in (1, 16, 32, 1000):
            self.assertEqual(len(generate_random_bytes(n)), n)

    def test_zero_length(self):
        self.assertEqual(generate_random_bytes(0), b"")

    def test_negative_length(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_not_integer(self):
        with self.assertRaises(ValueError):
            generate_random_bytes("16")

    def test_returns_bytes(self):
        self.assertIsInstance(generate_random_bytes(16), bytes)

    def test_different_calls_differ(self):
        a = generate_random_bytes(32)
        b = generate_random_bytes(32)
        self.assertNotEqual(a, b)


class TestGenerateKeyAndIV(unittest.TestCase):
    def test_key_length(self):
        self.assertEqual(len(generate_key()), BLOCK_SIZE)

    def test_iv_length(self):
        self.assertEqual(len(generate_iv()), BLOCK_SIZE)

    def test_key_uniqueness_1000(self):
        # TEST-2: 1000 keys of 16 bytes must all be unique.
        seen = set()
        for _ in range(1000):
            k = generate_key()
            self.assertNotIn(k, seen, f"Duplicate key generated: {k.hex()}")
            seen.add(k)
        self.assertEqual(len(seen), 1000)


class TestHammingWeight(unittest.TestCase):
    """TEST-4 (Should): average bit-weight should be close to 50%."""

    def test_average_hamming_weight(self):
        # Generate 1000 keys, count total ones across all bits.
        trials = 1000
        bits_per_key = BLOCK_SIZE * 8
        ones = 0
        for _ in range(trials):
            k = generate_key()
            ones += bin(int.from_bytes(k, "big")).count("1")
        total_bits = trials * bits_per_key
        ratio = ones / total_bits
        # With 128_000 bits, standard deviation ~ sqrt(N)/2 ~ 178,
        # so 0.5 +/- 0.02 is ~11 sigma. Very safe bound.
        self.assertGreater(ratio, 0.48)
        self.assertLess(ratio, 0.52)


if __name__ == "__main__":
    unittest.main()