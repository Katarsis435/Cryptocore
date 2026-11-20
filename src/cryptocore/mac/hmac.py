"""HMAC (RFC 2104) using the from-scratch SHA-256 / SHA3-256.

Streaming API:
    mac = HMAC(key, "sha256")
    mac.update(chunk1)
    mac.update(chunk2)
    hex_digest = mac.hexdigest()
"""

from cryptocore.hash import get_hasher


class HMAC:
    BLOCK_SIZE = 64  # SHA-256 / SHA3-256 block size in bytes

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        self._hasher_cls = get_hasher(hash_function)
        self.block_size = self.BLOCK_SIZE
        self.key = self._process_key(bytes(key))

        ipad = bytes(b ^ 0x36 for b in self.key)
        opad = bytes(b ^ 0x5c for b in self.key)

        self._inner = self._hasher_cls()
        self._inner.update(ipad)

        self._opad = opad
        self._outer = self._hasher_cls()
        self._finalized = False

    def _process_key(self, key: bytes) -> bytes:
        if len(key) > self.block_size:
            h = self._hasher_cls()
            h.update(key)
            key = h.digest()
        if len(key) < self.block_size:
            key = key + b"\x00" * (self.block_size - len(key))
        return key

    def update(self, data: bytes) -> None:
        if self._finalized:
            raise ValueError("HMAC already finalized")
        self._inner.update(data)

    def digest(self) -> bytes:
        if not self._finalized:
            inner_digest = self._inner.digest()
            self._outer.update(self._opad)
            self._outer.update(inner_digest)
            self._finalized = True
        return self._outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    @classmethod
    def compute(cls, key: bytes, message: bytes,
                hash_function: str = "sha256") -> str:
        mac = cls(key, hash_function)
        mac.update(message)
        return mac.hexdigest()