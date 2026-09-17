"""AES-128 ECB mode implementation with PKCS#7 padding.

The AES primitive itself is provided by pycryptodome (Crypto.Cipher.AES).
The ECB logic (block splitting, PKCS#7 padding, per-block invocation)
is implemented here.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16  # AES block size in bytes


def pkcs7_pad(data: bytes) -> bytes:
    """Pad `data` to a multiple of BLOCK_SIZE using PKCS#7."""
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove and validate PKCS#7 padding."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid ciphertext length for AES block cipher.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt `plaintext` with AES-128 in ECB mode + PKCS#7."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext)
    return cipher.encrypt(padded)


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt `ciphertext` with AES-128 in ECB mode + PKCS#7."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a non-zero multiple of 16 bytes.")
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return pkcs7_unpad(decrypted)