"""Cryptographic utilities for secure file encryption and decryption.

This module uses AES-256 in GCM mode to provide confidentiality and integrity.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


logger = logging.getLogger(__name__)

# File format:
# [12-byte nonce][ciphertext+16-byte GCM tag]
GCM_NONCE_SIZE = 12
AES_256_KEY_SIZE = 32


def generate_key() -> bytes:
    """Generate a cryptographically secure 256-bit key.

    Returns:
        bytes: 32-byte AES-256 key.
    """
    key = AESGCM.generate_key(bit_length=256)
    logger.debug("Generated a new AES-256 key (%d bytes).", len(key))
    return key


def encrypt_file(input_path: str | Path, key: bytes) -> Path:
    """Encrypt a file using AES-256-GCM.

    Args:
        input_path: Path to the plaintext file.
        key: AES-256 key (32 bytes).

    Returns:
        Path: Path to the encrypted output file (<input>.enc).

    Raises:
        ValueError: If key size is invalid.
        FileNotFoundError: If input file does not exist.
        OSError: If file operations fail.
    """
    if len(key) != AES_256_KEY_SIZE:
        raise ValueError("Invalid AES-256 key length. Expected 32 bytes.")

    source = Path(input_path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"Input file not found: {source}")

    plaintext = source.read_bytes()
    nonce = os.urandom(GCM_NONCE_SIZE)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    output_path = source.with_suffix(source.suffix + ".enc")
    output_path.write_bytes(nonce + ciphertext)

    logger.info("Encrypted file written to: %s", output_path)
    return output_path


def decrypt_file(input_path: str | Path, key: bytes) -> Path:
    """Decrypt a file encrypted with AES-256-GCM from this project.

    Args:
        input_path: Path to encrypted file.
        key: AES-256 key (32 bytes).

    Returns:
        Path: Path to decrypted output file (<input without .enc> or <input>.dec).

    Raises:
        ValueError: If key length or file format is invalid.
        FileNotFoundError: If input file does not exist.
        OSError: If file operations fail.
    """
    if len(key) != AES_256_KEY_SIZE:
        raise ValueError("Invalid AES-256 key length. Expected 32 bytes.")

    source = Path(input_path)
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"Encrypted file not found: {source}")

    data = source.read_bytes()
    if len(data) <= GCM_NONCE_SIZE:
        raise ValueError("Encrypted file is too small or malformed.")

    nonce, ciphertext = data[:GCM_NONCE_SIZE], data[GCM_NONCE_SIZE:]

    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    if source.suffix == ".enc":
        output_path = source.with_suffix("")
    else:
        output_path = source.with_suffix(source.suffix + ".dec")

    output_path.write_bytes(plaintext)
    logger.info("Decrypted file written to: %s", output_path)
    return output_path
