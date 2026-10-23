"""Streaming helpers for hash computation."""
"""отдельный файл чтобы не смешивать с file_io.py (тот для шифрования — читает целиком)."""

import sys


CHUNK_SIZE = 8192  # 8 KiB


def hash_file(path: str, hasher, chunk_size: int = CHUNK_SIZE) -> str:
    """Return hex digest of file at `path`, reading it in chunks.

    Supports arbitrarily large files (HASH-4, HASH-5, IO-2).
    Uses binary mode (IO-1).
    If path == "-", reads from stdin (binary).
    """
    if path == "-":
        stream = sys.stdin.buffer
        close = False
    else:
        try:
            stream = open(path, "rb")
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file not found: {path}")
        except OSError as e:
            raise OSError(f"Cannot open {path}: {e}")
        close = True

    try:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    finally:
        if close:
            stream.close()

    return hasher.hexdigest()