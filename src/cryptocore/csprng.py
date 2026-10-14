"""Cryptographically Secure Pseudo-Random Number Generator (CSPRNG).

This module is the single source of randomness for the whole tool.
It uses os.urandom(), which on all modern platforms is backed by the
operating system's CSPRNG (getrandom(2) / /dev/urandom on Linux,
BCryptGenRandom on Windows, SecRandomCopyBytes on macOS).

The Python `random` module is *not* used anywhere: it is a Mersenne
Twister PRNG and is NOT suitable for cryptographic purposes.
"""

import os

BLOCK_SIZE = 16  # AES block size in bytes


class CSPRNGError(RuntimeError):
    """Raised when the OS random source cannot produce bytes."""


def generate_random_bytes(num_bytes: int) -> bytes:
    """Return `num_bytes` cryptographically secure random bytes.

    Parameters
    ----------
    num_bytes : int
        Number of random bytes to generate. Must be a non-negative integer.

    Returns
    -------
    bytes
        A bytes object of exactly `num_bytes` bytes.

    Raises
    ------
    ValueError
        If `num_bytes` is negative or not an integer.
    CSPRNGError
        If the OS random source fails (extremely rare on modern systems).
    """
    if not isinstance(num_bytes, int):
        raise ValueError("num_bytes must be an integer.")
    if num_bytes < 0:
        raise ValueError("num_bytes must be non-negative.")

    try:
        return os.urandom(num_bytes)
    except OSError as e:
        # os.urandom can fail on exotic systems or under some sandboxes.
        raise CSPRNGError(
            f"OS random source failed to produce {num_bytes} bytes: {e}"
        ) from e


def generate_key() -> bytes:
    """Return a fresh 16-byte AES-128 key."""
    return generate_random_bytes(BLOCK_SIZE)


def generate_iv() -> bytes:
    """Return a fresh 16-byte IV (AES block size)."""
    return generate_random_bytes(BLOCK_SIZE)