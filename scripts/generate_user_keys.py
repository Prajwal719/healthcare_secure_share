"""
generate_user_keys.py — Generate application-layer RSA key pairs for users.

PURPOSE vs. TLS certificates:
    TLS client certificates (from generate_certs.py) authenticate the
    *network connection*.  Application RSA keys (generated here) are used for:
      • RSA-OAEP: wrapping per-file AES keys (confidentiality)
      • RSA-PSS:  signing file uploads (authentication + non-repudiation)
    These are completely separate key pairs with separate storage and separate
    passwords. This is the principle of key separation.

WHY SEPARATE KEYS FOR SIGN AND ENCRYPT:
    RFC 4270 and NIST SP 800-57 both recommend using different keys for
    signing and encryption, because:
      1. Some attacks (e.g. Bleichenbacher) apply only to encryption keys.
      2. Legal non-repudiation requires that only the signer ever held the
         signing key — sharing with a KMS for wrapping would undermine this.
    For simplicity in this course project we use ONE key pair per user for
    both operations (acceptable at this scale), but the limitation is
    documented in LIMITATIONS.md.

Output (under keys/):
    keys/<username>_app_private.pem  — Encrypted RSA-3072 private key
    keys/<username>_app_public.pem   — Unencrypted RSA-3072 public key

Usage:
    cd healthcare_secure_share
    python scripts/generate_user_keys.py --username doctor --password "MySecurePass1!"
    # Or interactive password prompt:
    python scripts/generate_user_keys.py --username doctor
"""

import argparse
import getpass
import sys
from pathlib import Path

from common.crypto_utils import (
    generate_rsa_keypair,
    serialize_private_key,
    serialize_public_key,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = PROJECT_ROOT / "keys"


def generate_user_app_keys(username: str, password: bytes, overwrite: bool = False) -> None:
    """
    Generate and store an RSA-3072 key pair for a given user.

    Private key stored encrypted (PKCS8, BestAvailableEncryption).
    Public key stored in plaintext (no secret material).

    Args:
        username:  The user's account name.  Used as the file name prefix.
        password:  Passphrase to encrypt the private key PEM.
        overwrite: If False (default), raises FileExistsError if keys exist.

    Raises:
        ValueError:       If username or password is empty.
        FileExistsError:  If keys already exist and overwrite=False.
    """
    if not username:
        raise ValueError("Username must not be empty.")
    if not password:
        raise ValueError("Password must not be empty.")

    # Sanitise username for safe use in filenames
    safe = "".join(c for c in username if c.isalnum() or c in "-_")
    if not safe:
        raise ValueError(f"Username '{username}' contains no safe characters.")

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_path = KEYS_DIR / f"{safe}_app_private.pem"
    pub_path = KEYS_DIR / f"{safe}_app_public.pem"

    if not overwrite:
        for path in (priv_path, pub_path):
            if path.exists():
                raise FileExistsError(
                    f"Key file already exists: {path}. "
                    "Use --overwrite to replace it."
                )

    print(f"Generating RSA-3072 application key pair for '{safe}'...")
    private_key, public_key = generate_rsa_keypair()

    # Save encrypted private key
    priv_pem = serialize_private_key(private_key, password)
    priv_path.write_bytes(priv_pem)
    try:
        priv_path.chmod(0o600)  # Owner-read-only (no-op on Windows)
    except NotImplementedError:
        pass
    print(f"  Private key -> {priv_path.relative_to(PROJECT_ROOT)}")

    # Save unencrypted public key (can be freely distributed)
    pub_pem = serialize_public_key(public_key)
    pub_path.write_bytes(pub_pem)
    print(f"  Public key  -> {pub_path.relative_to(PROJECT_ROOT)}")
    print("[OK] Done. Keep your password safe -- lost passwords cannot be recovered.")


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Generate an application-layer RSA-3072 key pair for a user or escrow authority.",
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Account username (used as key filename prefix).",
    )
    parser.add_argument(
        "--escrow",
        action="store_true",
        help="Generate institutional escrow key pair (username='escrow').",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Private key encryption password (prompted if omitted).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing key files for this user.",
    )
    args = parser.parse_args()

    username = "escrow" if args.escrow else args.username
    if not username:
        parser.error("Either --username or --escrow must be specified.")

    password = args.password
    if password is None:
        if args.escrow:
            from common.config import ESCROW_KEY_PASSWORD
            password = ESCROW_KEY_PASSWORD
            print(f"Using default institutional escrow password: {password}")
        else:
            password = getpass.getpass(f"Key password for '{username}': ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("ERROR: Passwords do not match.", file=sys.stderr)
                sys.exit(1)

    if not password:
        print("ERROR: Password must not be empty.", file=sys.stderr)
        sys.exit(1)

    try:
        generate_user_app_keys(username, password.encode(), overwrite=args.overwrite)
    except FileExistsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
