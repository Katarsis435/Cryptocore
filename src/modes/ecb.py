"""AES-128 ECB mode implementation with PKCS#7 padding.

The AES primitive (single-block transform) is provided by pycryptodome.
The ECB mode logic — block splitting, per-block invocation of the
primitive, and PKCS#7 padding — is implemented here explicitly.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Invalid ciphertext length for AES block cipher.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid PKCS#7 padding.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding.")
    return data[:-pad_len]


def _xor_dummy():  # placeholder if needed later
    pass


def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-128 in ECB mode + PKCS#7.

    ECB logic implemented manually:
      1. Pad plaintext to a multiple of BLOCK_SIZE (PKCS#7).
      2. Split padded data into BLOCK_SIZE-byte blocks.
      3. Encrypt each block independently with the AES primitive.
      4. Concatenate ciphertext blocks.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")

    padded = pkcs7_pad(plaintext)
    cipher = AES.new(key, AES.MODE_ECB)  # primitive: single-block transform

    out = bytearray()
    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset:offset + BLOCK_SIZE]
        out += cipher.encrypt(block)     # per-block call — student logic
    return bytes(out)


def ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt with AES-128 in ECB mode + PKCS#7.

    ECB logic implemented manually:
      1. Validate that ciphertext length is a non-zero multiple of BLOCK_SIZE.
      2. Split ciphertext into BLOCK_SIZE-byte blocks.
      3. Decrypt each block independently with the AES primitive.
      4. Concatenate plaintext blocks.
      5. Remove and validate PKCS#7 padding.
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a non-zero multiple of 16 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)

    out = bytearray()
    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        out += cipher.decrypt(block)     # per-block call — student logic

    return pkcs7_unpad(bytes(out))