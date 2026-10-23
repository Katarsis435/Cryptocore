"""Hash functions implemented from scratch (SHA-256, SHA3-256)."""

from .sha256 import SHA256, sha256
from .sha3_256 import SHA3_256, sha3_256

REGISTRY = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def get_hasher(algorithm: str):
    try:
        return REGISTRY[algorithm]
    except KeyError:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}. "
            f"Supported: {', '.join(sorted(REGISTRY))}"
        )