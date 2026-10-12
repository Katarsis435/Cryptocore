"""AES-128 OFB mode.

OFB:
    O_0 = IV
    O_i = E(O_{i-1})
    C_i = P_i XOR O_i    (MSB(O_i, len(P_i)) for last partial)
Streaming mode, no padding.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _keystream(prev: bytes, key: bytes, length: int) -> tuple[bytes, bytes]:
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    cur = prev
    while len(out) < length:
        cur = cipher.encrypt(cur)
        out += cur
    return bytes(out[:length]), cur


def ofb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("OFB IV must be 16 bytes.")
    if not plaintext:
        return b""

    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    cur = iv
    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        cur = cipher.encrypt(cur)
        out += _xor(block, cur[:len(block)])
    return bytes(out)


def ofb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    # OFB is symmetric: encryption == decryption
    return ofb_encrypt(ciphertext, key, iv)