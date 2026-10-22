"""SHA-256 implementation from scratch per NIST FIPS 180-4.

Streaming API:
    hasher = SHA256()
    hasher.update(chunk1)
    hasher.update(chunk2)
    digest = hasher.digest()        # 32 bytes
    hexdigest = hasher.hexdigest()  # 64 lowercase hex chars

The implementation uses only the standard library (struct, no hashlib).
"""

import struct

# First 32 bits of the fractional parts of the cube roots of the first 64 primes.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# First 32 bits of the fractional parts of the square roots of the first 8 primes.
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

MASK32 = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def _ch(x, y, z):
    return (x & y) ^ (~x & z) & MASK32


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _bsig0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _bsig1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ssig0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _ssig1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


class SHA256:
    BLOCK_SIZE = 64            # 512 bits
    DIGEST_SIZE = 32           # 256 bits
    name = "sha256"

    def __init__(self):
        self._h = list(H0)
        self._buffer = b""
        self._length = 0       # total bytes fed

    # -- public API --
    def update(self, data: bytes) -> "SHA256":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SHA256.update expects bytes-like object")
        self._length += len(data)
        self._buffer += bytes(data)
        # process full 64-byte blocks
        while len(self._buffer) >= self.BLOCK_SIZE:
            block, self._buffer = self._buffer[:self.BLOCK_SIZE], \
                                  self._buffer[self.BLOCK_SIZE:]
            self._process_block(block)
        return self

    def digest(self) -> bytes:
        h = self._h[:]
        buffer = self._buffer
        total_bits = self._length * 8

        # Padding: 0x80 || 0x00... || 8-byte big-endian length
        pad_len = self.BLOCK_SIZE - ((len(buffer) + 1 + 8) % self.BLOCK_SIZE)
        if pad_len == self.BLOCK_SIZE:
            pad_len = 0
        padded = buffer + b"\x80" + b"\x00" * pad_len + \
                 total_bits.to_bytes(8, "big")

        # Process padded blocks without mutating self
        for i in range(0, len(padded), self.BLOCK_SIZE):
            self._process_block(padded[i:i + self.BLOCK_SIZE], state=h)

        return b"".join(x.to_bytes(4, "big") for x in h)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SHA256":
        other = SHA256()
        other._h = self._h[:]
        other._buffer = self._buffer
        other._length = self._length
        return other

    # -- internals --
    def _process_block(self, block: bytes, state=None):
        if state is None:
            state = self._h
        w = list(struct.unpack(">16I", block))
        for i in range(16, 64):
            s0 = _ssig0(w[i - 15])
            s1 = _ssig1(w[i - 2])
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & MASK32)

        a, b, c, d, e, f, g, h = state

        for i in range(64):
            t1 = (h + _bsig1(e) + _ch(e, f, g) + K[i] + w[i]) & MASK32
            t2 = (_bsig0(a) + _maj(a, b, c)) & MASK32
            h = g
            g = f
            f = e
            e = (d + t1) & MASK32
            d = c
            c = b
            b = a
            a = (t1 + t2) & MASK32

        for i, v in enumerate((a, b, c, d, e, f, g, h)):
            state[i] = (state[i] + v) & MASK32


def sha256(data: bytes) -> bytes:
    """One-shot helper."""
    h = SHA256()
    h.update(data)
    return h.digest()