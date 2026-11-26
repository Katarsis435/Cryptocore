"""Key hierarchy: derive subkeys from a master key deterministically."""

from cryptocore.mac import HMAC


def derive_key(master_key: bytes, context: str, length: int = 32) -> bytes:
    if isinstance(context, str):
        context = context.encode("utf-8")
    if length < 1:
        raise ValueError("length must be >= 1")

    derived = bytearray()
    counter = 1

    while len(derived) < length:
        mac = HMAC(master_key, "sha256")
        mac.update(context)
        mac.update(counter.to_bytes(4, "big"))
        derived.extend(mac.digest())
        counter += 1

    return bytes(derived[:length])