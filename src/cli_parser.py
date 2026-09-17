"""Command-line argument parser for the cryptocore tool."""

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128 ECB file encryptor/decryptor (Sprint 1).",
    )
    parser.add_argument("--algorithm", required=True, choices=["aes"],
                        help="Cipher algorithm (only 'aes' is supported).")
    parser.add_argument("--mode", required=True, choices=["ecb"],
                        help="Cipher mode (only 'ecb' is supported).")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", action="store_true",
                       help="Encrypt the input file.")
    group.add_argument("--decrypt", action="store_true",
                       help="Decrypt the input file.")

    parser.add_argument("--key", required=True,
                        help="Hex-encoded key (32 hex chars = 16 bytes for AES-128).")
    parser.add_argument("--input", required=True, dest="input_file",
                        help="Path to input file.")
    parser.add_argument("--output", required=False, dest="output_file",
                        help="Path to output file (auto-generated if omitted).")

    return parser


def parse_key(hex_key: str) -> bytes:
    """Validate and decode the hex key."""
    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        raise ValueError("--key must be a valid hexadecimal string.")
    if len(key) != 16:
        raise ValueError(
            f"--key must be 16 bytes (32 hex chars) for AES-128, got {len(key)} bytes."
        )
    return key


def default_output(input_file: str, encrypt: bool) -> str:
    return input_file + ".enc" if encrypt else input_file + ".dec"


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        key = parse_key(args.key)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    # Import here so argparse errors surface before crypto import cost
    from src.modes.ecb import ecb_encrypt, ecb_decrypt
    from src.file_io import read_binary, write_binary

    output_path = args.output_file or default_output(args.input_file, args.encrypt)

    try:
        data = read_binary(args.input_file)
        if args.encrypt:
            result = ecb_encrypt(data, key)
        else:
            result = ecb_decrypt(data, key)
        write_binary(output_path, result)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"OK: {'encrypted' if args.encrypt else 'decrypted'} "
          f"'{args.input_file}' -> '{output_path}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())