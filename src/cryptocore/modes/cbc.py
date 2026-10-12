"""AES-128 CBC mode with PKCS#7 padding, implemented manually.

CBC: C_i = E(P_i XOR C_{i-1}), C_0 uses IV as previous block.
We only use pycryptodome as a single-block AES primitive.
"""

from Crypto.Cipher import AES
from .ecb import pkcs7_pad, pkcs7_unpad

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes.")

    padded = pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)  # primitive only

    prev = iv
    out = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        xored = _xor(block, prev)
        encrypted = cipher.encrypt(xored)
        out += encrypted
        prev = encrypted
    return bytes(out)


def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CBC IV must be 16 bytes.")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("CBC ciphertext length must be a non-zero multiple of 16.")

    cipher = AES.new(key, AES.MODE_ECB)

    prev = iv
    out = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        decrypted = cipher.decrypt(block)
        out += _xor(decrypted, prev)
        prev = block

    return pkcs7_unpad(bytes(out))