"""AES-GCM (NIST SP 800-38D) implemented from scratch."""

import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16
TAG_SIZE = 16
NONCE_SIZE = 12  # recommended by NIST SP 800-38D

# Irreducible polynomial x^128 + x^7 + x^2 + x + 1
_R = 0xE1000000000000000000000000000000


class AuthenticationError(Exception):
    """Raised when the GCM tag does not verify."""


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _mult_gf(x: int, y: int) -> int:
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _pad16(b: bytes) -> bytes:
    rem = len(b) % BLOCK_SIZE
    if rem == 0:
        return b
    return b + b"\x00" * (BLOCK_SIZE - rem)


def _consttime_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


class GCM:
    def __init__(self, key: bytes, nonce: bytes | None = None):
        if len(key) != 16:
            raise ValueError("AES-128 requires a 16-byte key.")
        self._aes = AES.new(key, AES.MODE_ECB)
        self.nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError(
                f"GCM nonce must be {NONCE_SIZE} bytes, got {len(self.nonce)}."
            )
        self._H = _bytes_to_int(self._aes.encrypt(b"\x00" * BLOCK_SIZE))

    def _ghash(self, aad: bytes, ciphertext: bytes) -> int:
        data = _pad16(aad) + _pad16(ciphertext)
        len_block = (len(aad) * 8).to_bytes(8, "big") + \
                    (len(ciphertext) * 8).to_bytes(8, "big")
        data += len_block
        y = 0
        for i in range(0, len(data), BLOCK_SIZE):
            block = _bytes_to_int(data[i:i + BLOCK_SIZE])
            y = _mult_gf(y ^ block, self._H)
        return y

    def _ctr(self, initial_counter: bytes, data: bytes) -> bytes:
        out = bytearray()
        counter = _bytes_to_int(initial_counter)
        for off in range(0, len(data), BLOCK_SIZE):
            block = self._aes.encrypt(counter.to_bytes(BLOCK_SIZE, "big"))
            chunk = data[off:off + BLOCK_SIZE]
            out += _xor(chunk, block[:len(chunk)])
            counter = (counter + 1) % (1 << 128)
        return bytes(out)

    def _j0(self) -> bytes:
        return self.nonce + b"\x00\x00\x00\x01"

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        j0 = self._j0()
        inc32 = j0[:-4] + ((_bytes_to_int(j0[-4:]) + 1) % (1 << 32)).to_bytes(4, "big")
        ciphertext = self._ctr(inc32, plaintext)

        s = self._ghash(aad, ciphertext)
        ek_j0 = _bytes_to_int(self._aes.encrypt(j0))
        tag = (ek_j0 ^ s).to_bytes(BLOCK_SIZE, "big")

        return self.nonce + ciphertext + tag

    def decrypt(self, data: bytes, aad: bytes = b"") -> bytes:
        if len(data) < NONCE_SIZE + TAG_SIZE:
            raise AuthenticationError("Input too short to contain nonce and tag.")

        nonce = data[:NONCE_SIZE]
        ciphertext = data[NONCE_SIZE:-TAG_SIZE]
        tag = data[-TAG_SIZE:]

        j0 = nonce + b"\x00\x00\x00\x01"
        s = self._ghash(aad, ciphertext)
        ek_j0 = _bytes_to_int(self._aes.encrypt(j0))
        expected_tag = (ek_j0 ^ s).to_bytes(BLOCK_SIZE, "big")

        if not _consttime_eq(tag, expected_tag):
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext tampered."
            )

        inc32 = j0[:-4] + ((_bytes_to_int(j0[-4:]) + 1) % (1 << 32)).to_bytes(4, "big")
        return self._ctr(inc32, ciphertext)