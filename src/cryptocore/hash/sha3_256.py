"""SHA3-256 implementation from scratch per NIST FIPS 202.

Sponge construction (Keccak-f[1600]) with rate = 1088 bits (136 bytes)
and capacity = 512 bits, output 256 bits.

Streaming API identical to SHA256.
"""

# Round constants for Keccak-f[1600] (FIPS 202, sec. 3.2.5)
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

# Rotation offsets (FIPS 202, table 2) — flattened for the 5x5 lane matrix
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

MASK64 = 0xFFFFFFFFFFFFFFFF


def _rol(x: int, n: int) -> int:
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f(a):
    """Keccak-f[1600] permutation on a 5x5 list of 64-bit lanes."""
    for rnd in range(24):
        # θ (theta)
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                a[x][y] ^= d[x]

        # ρ (rho) and π (pi)
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(a[x][y], _ROT[x][y])

        # χ (chi)
        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        # ι (iota)
        a[0][0] ^= _RC[rnd]

    return a


class SHA3_256:
    RATE = 136                 # bytes (1088 bits)
    DIGEST_SIZE = 32           # 256 bits
    name = "sha3-256"

    def __init__(self):
        self._state = [[0] * 5 for _ in range(5)]
        self._buffer = b""

    def update(self, data: bytes) -> "SHA3_256":
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SHA3_256.update expects bytes-like object")
        self._buffer += bytes(data)
        while len(self._buffer) >= self.RATE:
            block = self._buffer[:self.RATE]
            self._buffer = self._buffer[self.RATE:]
            self._absorb_block(block)
        return self

    def digest(self) -> bytes:
        state = [[self._state[x][y] for y in range(5)] for x in range(5)]

        # Padding: SHA3 uses 0x06 (multirate padding with '01' domain separator)
        # then zeros, then last byte 0x80.
        pad = bytearray(self._buffer)
        pad.append(0x06)
        pad += b"\x00" * ((self.RATE - len(pad) % self.RATE) % self.RATE - 1)
        if len(pad) % self.RATE == 0:
            pad[-1] |= 0x80
        else:
            pad = pad[:-1] + bytes([0x80])
        # simpler explicit form:
        pad = bytearray(self._buffer) + b"\x06"
        pad += b"\x00" * (self.RATE - len(pad) % self.RATE)
        pad[-1] |= 0x80

        # absorb padded blocks into the copy
        for i in range(0, len(pad), self.RATE):
            self._absorb_block_into(state, pad[i:i + self.RATE])

        # squeeze first 32 bytes
        out = bytearray()
        while len(out) < self.DIGEST_SIZE:
            for x in range(5):
                for y in range(5):
                    if len(out) >= self.DIGEST_SIZE:
                        break
                    lane = state[x][y]
                    out += lane.to_bytes(8, "little")
                if len(out) >= self.DIGEST_SIZE:
                    break
            if len(out) < self.DIGEST_SIZE:
                state = _keccak_f(state)
        return bytes(out[:self.DIGEST_SIZE])

    def hexdigest(self) -> str:
        return self.digest().hex()

    def _absorb_block(self, block: bytes):
        for i in range(0, self.RATE, 8):
            lane = int.from_bytes(block[i:i + 8], "little")
            x = (i // 8) % 5
            y = (i // 8) // 5
            self._state[x][y] ^= lane
        _keccak_f(self._state)

    @staticmethod
    def _absorb_block_into(state, block: bytes):
        for i in range(0, len(block), 8):
            lane = int.from_bytes(block[i:i + 8], "little")
            x = (i // 8) % 5
            y = (i // 8) // 5
            state[x][y] ^= lane
        _keccak_f(state)


def sha3_256(data: bytes) -> bytes:
    h = SHA3_256()
    h.update(data)
    return h.digest()