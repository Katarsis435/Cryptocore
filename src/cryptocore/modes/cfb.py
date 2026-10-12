"""AES-128 CFB mode with full-block segments (CFB-128).

CFB (encryption):
    C_i = P_i XOR E(C_{i-1})     for full blocks
    last partial: C_last = P_last XOR MSB(E(C_{n-1}), len(P_last))
    C_0 uses IV as previous block.

CFB (decryption):
    P_i = C_i XOR E(C_{i-1})
Streaming mode, no padding. Output length = input length.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _encrypt_blocks(data: bytes, key: bytes) -> bytes:
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CFB IV must be 16 bytes.")

    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out = bytearray()

    for offset in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[offset:offset + BLOCK_SIZE]
        keystream = cipher.encrypt(prev)
        cipher_block = _xor(block, keystream[:len(block)])
        out += cipher_block
        # feedback uses full block from ciphertext; last partial: pad with zeros conceptually?
        # For CFB-128, we only feed full blocks; last partial does not feed further.
        if len(block) == BLOCK_SIZE:
            prev = cipher_block
        # If partial block at the end — done, no more feedback needed
    return bytes(out)


def cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("CFB IV must be 16 bytes.")
    if not ciphertext:
        raise ValueError("CFB ciphertext is empty.")

    cipher = AES.new(key, AES.MODE_ECB)
    prev = iv
    out = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset:offset + BLOCK_SIZE]
        keystream = cipher.encrypt(prev)
        plain_block = _xor(block, keystream[:len(block)])
        out += plain_block
        if len(block) == BLOCK_SIZE:
            prev = block
    return bytes(out)