"""Command-line parser for cryptocore (Sprint 4).

Top-level commands:
    cryptocore --algorithm ... --mode ... --encrypt|--decrypt ...   (Sprints 1-3)
    cryptocore dgst --algorithm <hash> --input <file> [--output <file>]  (Sprint 4)
"""

import argparse
import sys

BLOCK_MODES = {"ecb", "cbc"}
STREAM_MODES = {"cfb", "ofb", "ctr"}
ALL_MODES = BLOCK_MODES | STREAM_MODES
IV_MODES = ALL_MODES - {"ecb"}

BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# Encrypt / decrypt parser (Sprints 1-3, unchanged interface)
# ---------------------------------------------------------------------------

def build_enc_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128 file encryptor: ECB, CBC, CFB, OFB, CTR.",
    )
    parser.add_argument("--algorithm", required=True, choices=["aes"])
    parser.add_argument("--mode", required=True, choices=sorted(ALL_MODES))
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", action="store_true")
    group.add_argument("--decrypt", action="store_true")
    parser.add_argument("--key", required=False, default=None)
    parser.add_argument("--iv", required=False, default=None)
    parser.add_argument("--input", required=True, dest="input_file")
    parser.add_argument("--output", required=False, dest="output_file")
    return parser


# ---------------------------------------------------------------------------
# dgst parser (Sprint 4)
# ---------------------------------------------------------------------------

def build_dgst_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Compute a cryptographic hash of a file.",
    )
    parser.add_argument("--algorithm", required=True,
                        choices=["sha256", "sha3-256"],
                        help="Hash algorithm.")
    parser.add_argument("--input", required=True, dest="input_file",
                        help="Input file ('-' for stdin).")
    parser.add_argument("--output", required=False, dest="output_file",
                        help="Write HASH  FILE line to this file instead of stdout.")
    return parser


# ---------------------------------------------------------------------------
# dgst command implementation
# ---------------------------------------------------------------------------

def run_dgst(argv) -> int:
    parser = build_dgst_parser()
    args = parser.parse_args(argv)

    from cryptocore.hash import get_hasher
    from cryptocore.hash_io import hash_file

    try:
        hasher_cls = get_hasher(args.algorithm)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    hasher = hasher_cls()
    try:
        digest_hex = hash_file(args.input_file, hasher)
    except (OSError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # CLI-4 format: HASH  FILE_PATH
    line = f"{digest_hex}  {args.input_file}\n"

    if args.output_file:
        try:
            with open(args.output_file, "w", encoding="utf-8") as f:
                f.write(line)
        except OSError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        print(f"OK: hash written to '{args.output_file}'")
    else:
        sys.stdout.write(line)
    return 0


# ---------------------------------------------------------------------------
# Encryption / decryption dispatch (unchanged logic from Sprint 3)
# ---------------------------------------------------------------------------

def parse_key(hex_key: str) -> bytes:
    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("--key must be a valid hexadecimal string.")
    if len(key) != BLOCK_SIZE:
        raise ValueError(
            f"--key must be 16 bytes (32 hex chars) for AES-128, "
            f"got {len(key)} bytes."
        )
    return key


def parse_iv(hex_iv: str) -> bytes:
    try:
        iv = bytes.fromhex(hex_iv)
    except ValueError:
        raise ValueError("--iv must be a valid hexadecimal string.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"--iv must be 16 bytes (32 hex chars), got {len(iv)} bytes.")
    return iv


def default_output(input_file: str, encrypt: bool) -> str:
    return input_file + ".enc" if encrypt else input_file + ".dec"


def warn_if_weak_key(key: bytes) -> None:
    if key == b"\x00" * BLOCK_SIZE:
        print("warning: key is all zeros — this is trivially weak.",
              file=sys.stderr)
    elif key == b"\xff" * BLOCK_SIZE:
        print("warning: key is all 0xFF — this is trivially weak.",
              file=sys.stderr)
    elif key == bytes(range(BLOCK_SIZE)):
        print("warning: key is a consecutive sequence 00 01 02 ... 0f — "
              "this is trivially weak.", file=sys.stderr)


def run_encdec(argv) -> int:
    parser = build_enc_parser()
    args = parser.parse_args(argv)

    auto_generated = False
    if args.key is not None:
        try:
            key = parse_key(args.key)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.encrypt:
            warn_if_weak_key(key)
    else:
        if args.decrypt:
            print("error: --key is required for decryption.", file=sys.stderr)
            return 2
        from cryptocore.csprng import generate_key, CSPRNGError
        try:
            key = generate_key()
        except CSPRNGError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
        auto_generated = True

    if args.encrypt and args.iv is not None:
        print("error: --iv must not be provided during encryption.",
              file=sys.stderr)
        return 2
    if args.mode == "ecb" and args.iv is not None:
        print("error: --iv is not used in ECB mode.", file=sys.stderr)
        return 2

    user_iv = None
    if args.iv is not None:
        try:
            user_iv = parse_iv(args.iv)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    if auto_generated:
        print(f"[INFO] Generated random key: {key.hex()}")

    from cryptocore.file_io import read_binary, write_binary
    from cryptocore.modes import ecb, cbc, cfb, ofb, ctr

    output_path = args.output_file or default_output(args.input_file, args.encrypt)

    try:
        data = read_binary(args.input_file)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        if args.encrypt:
            result = _do_encrypt(args.mode, data, key, ecb, cbc, cfb, ofb, ctr)
        else:
            result = _do_decrypt(args.mode, data, key, user_iv,
                                 ecb, cbc, cfb, ofb, ctr)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        write_binary(output_path, result)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    op = "encrypted" if args.encrypt else "decrypted"
    print(f"OK: {op} '{args.input_file}' -> '{output_path}'")
    return 0


def _do_encrypt(mode, data, key, ecb, cbc, cfb, ofb, ctr):
    from cryptocore.csprng import generate_random_bytes
    if mode == "ecb":
        return ecb.ecb_encrypt(data, key)
    iv = generate_random_bytes(BLOCK_SIZE)
    if mode == "cbc":
        return iv + cbc.cbc_encrypt(data, key, iv)
    if mode == "cfb":
        return iv + cfb.cfb_encrypt(data, key, iv)
    if mode == "ofb":
        return iv + ofb.ofb_encrypt(data, key, iv)
    if mode == "ctr":
        return iv + ctr.ctr_encrypt(data, key, iv)
    raise ValueError(f"Unsupported mode: {mode}")


def _do_decrypt(mode, data, key, user_iv, ecb, cbc, cfb, ofb, ctr):
    if mode == "ecb":
        return ecb.ecb_decrypt(data, key)
    if user_iv is not None:
        iv = user_iv
        ciphertext = data
    else:
        if len(data) < BLOCK_SIZE:
            raise ValueError(
                f"Input file is too short to contain an IV "
                f"(need at least {BLOCK_SIZE} bytes, got {len(data)})."
            )
        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
    if mode == "cbc":
        return cbc.cbc_decrypt(ciphertext, key, iv)
    if mode == "cfb":
        return cfb.cfb_decrypt(ciphertext, key, iv)
    if mode == "ofb":
        return ofb.ofb_decrypt(ciphertext, key, iv)
    if mode == "ctr":
        return ctr.ctr_decrypt(ciphertext, key, iv)
    raise ValueError(f"Unsupported mode: {mode}")


# ---------------------------------------------------------------------------
# Top-level dispatch
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv and argv[0] == "dgst":
        return run_dgst(argv[1:])
    return run_encdec(argv)


if __name__ == "__main__":
    sys.exit(main())