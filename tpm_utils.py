"""TPM key sealing utilities with a secure simulation fallback.

On Linux, this module attempts to use tpm2-tools to seal/unseal the AES key
inside TPM NV storage with a PCR policy. If TPM access is unavailable, it
falls back to a local simulation that encrypts the key at rest using a
machine-bound wrapping key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import platform
import subprocess
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
STATE_DIR = BASE_DIR / ".secure_store"
STATE_DIR.mkdir(parents=True, exist_ok=True)

SIM_SEALED_FILE = STATE_DIR / "sim_sealed_key.json"
TPM_META_FILE = STATE_DIR / "tpm_meta.json"

SIM_NONCE_SIZE = 12
SIM_SALT_SIZE = 16
SIM_PBKDF2_ITERS = 200_000


def _run_command(command: list[str]) -> subprocess.CompletedProcess:
    """Run a subprocess command and capture output.

    Args:
        command: Command and arguments.

    Returns:
        subprocess.CompletedProcess: Completed command.

    Raises:
        RuntimeError: If command fails.
    """
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(command)}\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result


def _has_tpm2_tools() -> bool:
    """Check if tpm2-tools are available on PATH."""
    if platform.system().lower() != "linux":
        return False
    try:
        _run_command(["tpm2_getcap", "-c", "properties-fixed"])
        return True
    except Exception:
        return False


def _tpm_seal_key(key: bytes) -> None:
    """Seal key in TPM NV storage with PCR-bound policy.

    Security decision:
    - The key is stored inside TPM NV storage and guarded by a PCR policy.
    - Unseal succeeds only when the system's measured state matches policy.

    Args:
        key: AES-256 key bytes.

    Raises:
        RuntimeError: If TPM operations fail.
    """
    nv_index = "0x1500020"
    pcr_selection = "sha256:7"

    key_file = STATE_DIR / "key.bin"
    policy_file = STATE_DIR / "policy.digest"
    session_file = STATE_DIR / "session.ctx"

    key_file.write_bytes(key)

    try:
        # Build policy digest tied to selected PCR.
        _run_command(["tpm2_startauthsession", "--policy-session", "-S", str(session_file)])
        _run_command(["tpm2_policypcr", "-S", str(session_file), "-l", pcr_selection, "-L", str(policy_file)])
        _run_command(["tpm2_flushcontext", str(session_file)])

        # Recreate NV index to avoid stale state.
        try:
            _run_command(["tpm2_nvundefine", nv_index, "-C", "o"])
        except Exception:
            pass

        _run_command([
            "tpm2_nvdefine",
            nv_index,
            "-C",
            "o",
            "-s",
            str(len(key)),
            "-L",
            str(policy_file),
            "-a",
            "policyread|policywrite|ownerread|ownerwrite",
        ])

        _run_command(["tpm2_startauthsession", "--policy-session", "-S", str(session_file)])
        _run_command(["tpm2_policypcr", "-S", str(session_file), "-l", pcr_selection])
        _run_command([
            "tpm2_nvwrite",
            nv_index,
            "-C",
            "o",
            "-i",
            str(key_file),
            "-P",
            f"session:{session_file}",
        ])
        _run_command(["tpm2_flushcontext", str(session_file)])

        meta = {
            "mode": "tpm",
            "nv_index": nv_index,
            "pcr_selection": pcr_selection,
            "key_size": len(key),
        }
        TPM_META_FILE.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        logger.info("Key sealed using TPM NV index %s", nv_index)
    finally:
        if key_file.exists():
            key_file.unlink(missing_ok=True)
        if session_file.exists():
            session_file.unlink(missing_ok=True)


def _tpm_unseal_key() -> bytes:
    """Unseal key from TPM NV storage using PCR policy session.

    Returns:
        bytes: Unsealed AES key.

    Raises:
        RuntimeError: If TPM metadata or unseal process fails.
    """
    if not TPM_META_FILE.exists():
        raise RuntimeError("TPM metadata not found. Did you run encryption first?")

    meta = json.loads(TPM_META_FILE.read_text(encoding="utf-8"))
    nv_index = meta["nv_index"]
    pcr_selection = meta["pcr_selection"]
    key_size = int(meta["key_size"])

    session_file = STATE_DIR / "session.ctx"
    out_file = STATE_DIR / "unsealed.bin"

    try:
        _run_command(["tpm2_startauthsession", "--policy-session", "-S", str(session_file)])
        _run_command(["tpm2_policypcr", "-S", str(session_file), "-l", pcr_selection])
        _run_command([
            "tpm2_nvread",
            nv_index,
            "-C",
            "o",
            "-s",
            str(key_size),
            "-P",
            f"session:{session_file}",
            "-o",
            str(out_file),
        ])
        key = out_file.read_bytes()
        logger.info("Key unsealed from TPM NV index %s", nv_index)
        return key
    finally:
        if session_file.exists():
            session_file.unlink(missing_ok=True)
        if out_file.exists():
            out_file.unlink(missing_ok=True)


def _machine_fingerprint() -> str:
    """Create a machine-bound fingerprint used by simulation mode.

    Returns:
        str: Stable machine context identifier.
    """
    raw = "|".join(
        [
            platform.system(),
            platform.release(),
            platform.machine(),
            platform.node(),
            os.environ.get("COMPUTERNAME", ""),
            os.environ.get("HOSTNAME", ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _derive_simulation_wrap_key(salt: bytes, fingerprint: str) -> bytes:
    """Derive a local wrapping key from machine fingerprint and salt.

    Args:
        salt: Random PBKDF2 salt.
        fingerprint: Machine-bound fingerprint string.

    Returns:
        bytes: 32-byte key for AES-GCM wrapping.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=SIM_PBKDF2_ITERS,
    )
    return kdf.derive(fingerprint.encode("utf-8"))


def _sim_seal_key(key: bytes) -> None:
    """Seal key in simulation mode by encrypting key-at-rest locally.

    Security decision:
    - The plaintext AES data key is never written to disk.
    - Wrapped key is encrypted using AES-GCM with a machine-bound derived key.

    Args:
        key: AES-256 data key bytes.
    """
    fingerprint = _machine_fingerprint()
    salt = os.urandom(SIM_SALT_SIZE)
    nonce = os.urandom(SIM_NONCE_SIZE)

    wrap_key = _derive_simulation_wrap_key(salt, fingerprint)
    wrapped = AESGCM(wrap_key).encrypt(nonce, key, associated_data=None)

    payload = {
        "mode": "simulation",
        "fingerprint": fingerprint,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "wrapped_key": base64.b64encode(wrapped).decode("ascii"),
    }
    SIM_SEALED_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.warning("TPM unavailable; used simulation mode for key sealing.")


def _sim_unseal_key() -> bytes:
    """Unseal key in simulation mode after validating machine state.

    Returns:
        bytes: Unsealed AES key.

    Raises:
        RuntimeError: If machine fingerprint changed or payload is missing.
    """
    if not SIM_SEALED_FILE.exists():
        raise RuntimeError("Simulation key blob not found. Did you run encryption first?")

    payload = json.loads(SIM_SEALED_FILE.read_text(encoding="utf-8"))
    current_fingerprint = _machine_fingerprint()

    if payload.get("fingerprint") != current_fingerprint:
        raise RuntimeError(
            "System state validation failed in simulation mode: machine fingerprint mismatch."
        )

    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    wrapped_key = base64.b64decode(payload["wrapped_key"])

    wrap_key = _derive_simulation_wrap_key(salt, current_fingerprint)
    key = AESGCM(wrap_key).decrypt(nonce, wrapped_key, associated_data=None)
    logger.info("Key unsealed from simulation protected storage.")
    return key


def seal_key(key: bytes) -> None:
    """Seal an AES key using TPM when available, else simulation fallback.

    Args:
        key: AES-256 data key bytes.

    Raises:
        ValueError: If key length is invalid.
        RuntimeError: If both TPM and simulation sealing fail.
    """
    if len(key) != 32:
        raise ValueError("Expected 32-byte AES-256 key.")

    if _has_tpm2_tools():
        try:
            _tpm_seal_key(key)
            return
        except Exception as exc:
            logger.error("TPM sealing failed, falling back to simulation: %s", exc)

    _sim_seal_key(key)


def unseal_key() -> bytes:
    """Unseal AES key from TPM or simulation fallback.

    Returns:
        bytes: 32-byte AES key.

    Raises:
        RuntimeError: If key cannot be recovered.
    """
    # Prefer TPM path when metadata exists and tools are available.
    if TPM_META_FILE.exists() and _has_tpm2_tools():
        try:
            key = _tpm_unseal_key()
            if len(key) != 32:
                raise RuntimeError("Recovered TPM key length is invalid.")
            return key
        except Exception as exc:
            logger.error("TPM unseal failed: %s", exc)

    key = _sim_unseal_key()
    if len(key) != 32:
        raise RuntimeError("Recovered simulation key length is invalid.")
    return key
