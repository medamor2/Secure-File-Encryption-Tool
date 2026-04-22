"""CLI entrypoint for TPM-based secure file encryption tool."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from crypto_utils import decrypt_file, encrypt_file, generate_key
from tpm_utils import seal_key, unseal_key


def configure_logging(verbose: bool = False) -> None:
    """Configure application logging.

    Args:
        verbose: Enable debug logging when True.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def handle_encrypt(file_path: str) -> int:
    """Encrypt a file and seal the generated key.

    Args:
        file_path: Path to plaintext file.

    Returns:
        int: Process return code.
    """
    logger = logging.getLogger("main")
    try:
        key = generate_key()
        encrypted_path = encrypt_file(file_path, key)
        seal_key(key)

        logger.info("Encryption successful.")
        logger.info("Encrypted file: %s", encrypted_path)
        logger.info("Key sealed successfully (TPM or secure simulation).")
        return 0
    except Exception as exc:
        logger.error("Encryption failed: %s", exc)
        return 1


def handle_decrypt(file_path: str) -> int:
    """Unseal key and decrypt a file.

    Args:
        file_path: Path to encrypted file.

    Returns:
        int: Process return code.
    """
    logger = logging.getLogger("main")
    try:
        key = unseal_key()
        decrypted_path = decrypt_file(file_path, key)

        logger.info("Decryption successful.")
        logger.info("Decrypted file: %s", decrypted_path)
        return 0
    except Exception as exc:
        logger.error("Decryption failed: %s", exc)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for the tool.

    Returns:
        argparse.ArgumentParser: Configured parser.
    """
    parser = argparse.ArgumentParser(
        description="TPM-Based Secure File Encryption Tool",
    )
    parser.add_argument("command", choices=["encrypt", "decrypt"], help="Action to perform")
    parser.add_argument("file", help="Path to input file")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose (debug) logging",
    )
    return parser


def main() -> int:
    """Program entrypoint.

    Returns:
        int: Exit code.
    """
    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)

    target = Path(args.file)
    if not target.exists() or not target.is_file():
        logging.getLogger("main").error("File does not exist: %s", target)
        return 1

    if args.command == "encrypt":
        return handle_encrypt(str(target))
    if args.command == "decrypt":
        return handle_decrypt(str(target))

    logging.getLogger("main").error("Unknown command: %s", args.command)
    return 1


if __name__ == "__main__":
    sys.exit(main())
