"""Command-line parser for cryptocore (Sprint 2).

Modes:
    ecb, cbc — block modes, PKCS#7 padding, IV for cbc only
    cfb, ofb, ctr — streaming modes, no padding, IV always required
"""

import argparse
import os
import sys

BLOCK_MODES = {"ecb", "cbc"}
STREAM_MODES = {"cfb", "ofb", "ctr"}
ALL_MODES = BLOCK_MODES | STREAM_MODES
IV_MODES = ALL_MODES - {"ecb"}  # modes that use IV

BLOCK_SIZE = 16


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128 file encryptor: ECB, CBC, CFB, OFB, CTR.",
    )
    parser.add_argument("--algorithm", required=True, choices=["aes"])
    parser.add_argument("--mode", required=True, choices=sorted(ALL_MODES))

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", action="store_true")
    group.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", required=True,
                        help="Hex-encoded 16-byte key (32 hex chars).")
    parser.add_argument("--iv", required=False, default=None,
                        help="Hex-encoded 16-byte IV (decryption only).")
    parser.add_argument("--input", required=True, dest="input_file")
    parser.add_argument("--output", required=False, dest="output_file")

    return parser


def parse_key(hex_key: str) -> bytes:
    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("--key must be a valid hexadecimal string.")
    if len(key) != 16:
        raise ValueError(
            f"--key must be 16 bytes (32 hex chars) for AES-128, got {len(key)} bytes."
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


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # -------- validate key --------
    try:
        key = parse_key(args.key)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # -------- validate --iv usage --------
    if args.encrypt and args.iv is not None:
        print("error: --iv must not be provided during encryption "
              "(IV is generated automatically).", file=sys.stderr)
        return 2

    # For ECB, --iv is meaningless.
    if args.mode == "ecb" and args.iv is not None:
        print("error: --iv is not used in ECB mode.", file=sys.stderr)
        return 2

    # -------- parse user-supplied IV if any --------
    user_iv = None
    if args.iv is not None:
        try:
            user_iv = parse_iv(args.iv)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2

    # -------- lazy imports --------
    from cryptocore.file_io import read_binary, write_binary
    from cryptocore.modes import ecb, cbc, cfb, ofb, ctr

    output_path = args.output_file or default_output(args.input_file, args.encrypt)

    # -------- read input --------
    try:
        data = read_binary(args.input_file)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        if args.encrypt:
            result = _do_encrypt(args.mode, data, key, ecb, cbc, cfb, ofb, ctr)
        else:
            result = _do_decrypt(args.mode, data, key, user_iv, ecb, cbc, cfb, ofb, ctr)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    try:
        write_binary(output_path, result)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"OK: {'encrypted' if args.encrypt else 'decrypted'} "
          f"'{args.input_file}' -> '{output_path}'")
    return 0


def _do_encrypt(mode, data, key, ecb, cbc, cfb, ofb, ctr):
    if mode == "ecb":
        return ecb.ecb_encrypt(data, key)

    iv = os.urandom(BLOCK_SIZE)

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

    # non-ECB: extract IV either from --iv or first 16 bytes
    if user_iv is not None:
        iv = user_iv
        ciphertext = data
    else:
        if len(data) < BLOCK_SIZE:
            raise ValueError(
                "Input file is too short to contain an IV "
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


if __name__ == "__main__":
    sys.exit(main())