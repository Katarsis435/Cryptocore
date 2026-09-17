"""Binary-safe file input/output helpers."""

from pathlib import Path


def read_binary(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if not p.is_file():
        raise IsADirectoryError(f"Input path is not a file: {path}")
    return p.read_bytes()


def write_binary(path: str, data: bytes) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)