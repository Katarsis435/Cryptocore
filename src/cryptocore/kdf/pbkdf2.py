"""PBKDF2-HMAC-SHA256 (RFC 2898) from scratch."""

from cryptocore.mac import HMAC


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    if iterations < 1:
        raise ValueError("iterations must be >= 1")
    if dklen < 1:
        raise ValueError("dklen must be >= 1")

    blocks_needed = (dklen + 31) // 32  # SHA-256 gives 32 bytes
    derived = bytearray()

    for i in range(1, blocks_needed + 1):
        # U1 = HMAC(P, S || INT_32_BE(i))
        mac = HMAC(password, "sha256")
        mac.update(salt)
        mac.update(i.to_bytes(4, "big"))
        u_prev = mac.digest()
        block = bytearray(u_prev)

        # U2..Uc
        for _ in range(2, iterations + 1):
            mac = HMAC(password, "sha256")
            mac.update(u_prev)
            u_curr = mac.digest()
            for j in range(32):
                block[j] ^= u_curr[j]
            u_prev = u_curr

        derived.extend(block)

    return bytes(derived[:dklen])