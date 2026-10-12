"""AES-128 CTR mode.

CTR:
    C_i = P_i XOR E(nonce || counter_i)
Counter is a 16-byte big-endian value initialized from IV,
incremented by 1 for each block.
Streaming mode, no padding.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _increment(counter: bytes) -> bytes:
    """Increment 128-bit big-endian counter by 1, with wraparound."""
    n = int.from_bytes(counter, "big")
    n = (n + 1) % (1 << 128)
    return n.to_bytes(BLOCK_SIZE, "big")


def ctr_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CTR IV (initial counter) must be 16 bytes.")
    if not plaintext:
        return b""

    cipher = AES.new(key, AES.MODE_ECB)
    counter = iv
    out = bytearray()
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        keystream = cipher.encrypt(counter)
        out += _xor(block, keystream[:len(block)])
        counter = _increment(counter)
    return bytes(out)


def ctr_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # CTR is symmetric
    return ctr_encrypt(ciphertext, key, iv)