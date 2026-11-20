"""Encrypt-then-MAC AEAD (AEAD-1).

Formula: C = E(Ke, P), T = MAC(Km, C || AAD), output = nonce || C || T

Keys are derived from a 16-byte master key via SHA-256:
    key_material = SHA-256(master_key)
    Ke = key_material[:16]
    Km = key_material[16:]
"""

import os

from cryptocore.hash import get_hasher
from cryptocore.mac import HMAC
from cryptocore.modes import ctr


NONCE_SIZE = 16
TAG_SIZE = 32  # full SHA-256 HMAC output


class AuthenticationError(Exception):
    pass


def _derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    h = get_hasher("sha256")()
    h.update(master_key)
    km = h.digest()
    return km[:16], km[16:]


def _consttime_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def encrypt(master_key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    k_enc, k_mac = _derive_keys(master_key)
    nonce = os.urandom(NONCE_SIZE)

    ciphertext = ctr.ctr_encrypt(plaintext, k_enc, nonce)

    mac = HMAC(k_mac, "sha256")
    mac.update(nonce)
    mac.update(ciphertext)
    mac.update(aad)
    tag = mac.digest()

    return nonce + ciphertext + tag


def decrypt(master_key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise AuthenticationError("Input too short.")
    k_enc, k_mac = _derive_keys(master_key)

    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:-TAG_SIZE]
    tag = data[-TAG_SIZE:]

    mac = HMAC(k_mac, "sha256")
    mac.update(nonce)
    mac.update(ciphertext)
    mac.update(aad)
    expected = mac.digest()

    # Verify BEFORE decryption (AEAD-6 analog)
    if not _consttime_eq(tag, expected):
        raise AuthenticationError(
            "Authentication failed: AAD mismatch or ciphertext tampered."
        )

    return ctr.ctr_decrypt(ciphertext, k_enc, nonce)