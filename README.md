# TPM-Based Secure File Encryption Tool

Author: Mohamed Moncef Amor  
License: All rights reserved

## Project Description
This project is a secure file encryption/decryption CLI tool that protects file encryption keys using a Trusted Platform Module (TPM) when available.

The tool encrypts files with AES-256-GCM, then seals the AES key so it can only be recovered under valid system conditions. If TPM is not available, the project uses a secure simulation fallback that still avoids storing the key in plaintext.

## Features
1. Encrypt a file using AES-256-GCM.
2. Generate a cryptographically secure random encryption key.
3. Seal (securely store) the key using TPM when possible.
4. Unseal the key only when system state is valid.
5. Decrypt the file using the unsealed key.
6. CLI commands:
   - `python main.py encrypt <file>`
   - `python main.py decrypt <file>`

## Project Structure
- `main.py`: Command-line interface and orchestration.
- `crypto_utils.py`: AES-256-GCM encryption/decryption utilities.
- `tpm_utils.py`: TPM sealing/unsealing logic with secure simulation fallback.
- `requirements.txt`: Python dependencies.
- `README.md`: Documentation.

## How TPM Is Used
On Linux systems, the tool attempts to use `tpm2-tools`:
- Creates a PCR-bound policy (default PCR selection: `sha256:7`).
- Stores the AES key in TPM NV storage under policy constraints.
- During decryption, key recovery requires policy satisfaction, binding unseal to measured system state.

If TPM commands fail or TPM is unavailable, the code automatically falls back to simulation mode.

## TPM Simulation Fallback (When TPM Is Not Available)
Simulation mode is designed to be safer than plaintext key storage:
- The AES data key is wrapped (encrypted) using AES-GCM.
- The wrapping key is derived from a machine fingerprint and random salt with PBKDF2-HMAC-SHA256.
- Only the wrapped key, salt, nonce, and fingerprint hash are stored.
- The plaintext AES data key is never written to disk.
- Unseal checks fingerprint consistency before decrypting the wrapped key.

Important: This fallback is not equivalent to hardware TPM guarantees, but it preserves key-at-rest protection and basic machine binding.

## Installation
1. Ensure Python 3.10+ is installed.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Optional (Linux TPM path): install `tpm2-tools` via your package manager.

## Usage Examples
Encrypt a file:

```bash
python main.py encrypt secret.txt
```

Decrypt a file:

```bash
python main.py decrypt secret.txt.enc
```

Enable verbose logs:

```bash
python main.py encrypt secret.txt --verbose
```

## Security Explanation
Why TPM is important:
- TPM is hardware-backed and resists extraction attacks better than software-only storage.
- TPM policy-based unsealing can require valid platform measurements (PCR state), reducing risk from offline key theft.
- If encrypted files are copied away, key recovery remains constrained by TPM policy.

Security best practices used in this project:
- AES-256-GCM for authenticated encryption (confidentiality + integrity).
- Cryptographically secure random key generation.
- No plaintext key persistence on disk.
- Explicit error handling and logging.
- Modular design to separate cryptographic and platform-trust responsibilities.

## Limitations
- TPM logic currently targets Linux systems with `tpm2-tools`.
- TPM setup/permissions can vary by platform and distribution.
- Simulation fallback provides stronger protection than plaintext storage but is not a replacement for hardware-rooted trust.
- The tool currently keeps one active sealed key store; key management versioning/rotation is minimal.

## Notes
- Handle encrypted outputs and sealed metadata carefully.
- For high-assurance deployments, prefer real TPM mode and define stricter PCR policy strategy.

All rights reserved.
