"""SHA3-256 implementation from scratch per NIST FIPS 202.

Sponge construction (Keccak-f[1600]) with rate = 1088 bits (136 bytes)
and capacity = 512 bits, output 256 bits.
"""

MASK64 = (1 << 64) - 1

# Round constants for Keccak-f[1600]
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

# Rotation offsets R[x][y], x = column, y = row
# (FIPS 202, Table 2, stored as offsets[x][y])
_ROT = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rol(x, n):
    n %= 64
    if n == 0:
        return x & MASK64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f(state):
    """In-place Keccak-f[1600] permutation.

    `state` is a 5x5 list of lists of 64-bit ints: state[x][y].
    """
    for rnd in range(24):
        # --- theta ---
        C = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
             for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= D[x]

        # --- rho + pi ---
        # B[y][(2*x + 3*y) % 5] = rol(A[x][y], r[x][y])
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                B[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])

        # --- chi ---
        # A[x][y] = B[x][y] ^ ((~B[x+1][y]) & B[x+2][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = B[x][y] ^ ((~B[(x + 1) % 5][y] & MASK64) &
                                         B[(x + 2) % 5][y])

        # --- iota ---
        state[0][0] ^= _RC[rnd]


class SHA3_256:
    RATE = 136                 # bytes (1088 bits)
    DIGEST_SIZE = 32           # 256 bits
    name = "sha3-256"

    def __init__(self):
        # state[x][y], all zero
        self._state = [[0] * 5 for _ in range(5)]
        self._buffer = b""

    # ---------------- absorb ----------------
    def _absorb_block(self, block: bytes):
        # block is exactly RATE = 136 bytes
        # Each 8-byte little-endian lane goes to position (x = i % 5, y = i // 5)
        for i in range(self.RATE // 8):     # 17 lanes
            lane = int.from_bytes(block[i * 8:(i + 1) * 8], "little")
            x = i % 5
            y = i // 5
            self._state[x][y] ^= lane
        _keccak_f(self._state)

    # ---------------- public API ----------------
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
        # Work on a copy of the state so digest() is non-destructive
        state = [[self._state[x][y] for y in range(5)] for x in range(5)]

        # Padding for SHA3: append 0x06, zeros, 0x80 at the last byte of block
        pad = bytearray(self._buffer)
        pad.append(0x06)
        # Fill until multiple of RATE
        while len(pad) % self.RATE != 0:
            pad.append(0x00)
        pad[-1] ^= 0x80

        # Absorb all padded blocks into the local copy
        for i in range(0, len(pad), self.RATE):
            block = bytes(pad[i:i + self.RATE])
            for j in range(self.RATE // 8):
                lane = int.from_bytes(block[j * 8:(j + 1) * 8], "little")
                x = j % 5
                y = j // 5
                state[x][y] ^= lane
            _keccak_f(state)

        # Squeeze 32 bytes.
        # Order: for y in range(5): for x in range(5): take state[x][y]
        out = bytearray()
        for y in range(5):
            for x in range(5):
                if len(out) >= self.DIGEST_SIZE:
                    break
                out += state[x][y].to_bytes(8, "little")
            if len(out) >= self.DIGEST_SIZE:
                break
        # If somehow not enough (not possible for 256-bit output with 136-byte rate),
        # squeeze another block by calling _keccak_f — not needed here.
        return bytes(out[:self.DIGEST_SIZE])

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha3_256(data: bytes) -> bytes:
    h = SHA3_256()
    h.update(data)
    return h.digest()