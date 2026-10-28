"""
keystore.py — Client-side application key management.

Responsibilities:
    1. Load a user's encrypted private key from disk (requires the user's
       passphrase — never stored or cached in memory beyond the operation).
    2. Load a user's (or any registered user's) public key from disk.
    3. Enumerate all known public keys (used to check recipient eligibility
       when sharing a file).
    4. Provide a session-scoped private key cache with explicit clear().

WHY KEYS ON DISK (and its limitations):
    A production system would use a Hardware Security Module (HSM) or a
    managed key store (AWS KMS, Azure Key Vault). For a course project on
    localhost, disk-stored PKCS8-encrypted PEM files are the practical
    alternative. Limitations are documented in LIMITATIONS.md:
      - Keys are only as safe as the disk encryption and OS access controls.
      - A memory dump of a running client process could expose the decrypted key.
      - There is no key rotation or revocation mechanism for application keys.

SESSION CACHE RATIONALE:
    Decrypting a PKCS8 key on every crypto operation would require asking the
    user for their password repeatedly.  We hold the decrypted key in a
    PrivateKeySession object that is explicitly cleared (zeroed) on logout.
    Python's garbage collector does not guarantee immediate memory zeroing, so
    this is a best-effort mitigation, documented as a limitation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from common.config import ESCROW_KEY_PASSWORD, ESCROW_USERNAME
from common.crypto_utils import (
    generate_rsa_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = PROJECT_ROOT / "keys"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def private_key_path(username: str) -> Path:
    """
    Return the expected path for a user's encrypted private key PEM.

    Args:
        username: The account username.

    Returns:
        Path to ``keys/<username>_app_private.pem``.
    """
    safe = _safe_name(username)
    return KEYS_DIR / f"{safe}_app_private.pem"


def public_key_path(username: str) -> Path:
    """
    Return the expected path for a user's public key PEM.

    Args:
        username: The account username.

    Returns:
        Path to ``keys/<username>_app_public.pem``.
    """
    safe = _safe_name(username)
    return KEYS_DIR / f"{safe}_app_public.pem"


def _safe_name(username: str) -> str:
    """Sanitise a username for use in a filename."""
    safe = "".join(c for c in username if c.isalnum() or c in "-_")
    if not safe:
        raise ValueError(f"Username '{username}' produces an empty safe name.")
    return safe


# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------


def load_user_private_key(username: str, password: bytes) -> RSAPrivateKey:
    """
    Load and decrypt a user's application private key from disk.

    The returned key object is held in Python's heap. The caller should
    clear any references as soon as the crypto operation is done.

    Args:
        username: The account username.
        password: The passphrase used when the key was generated.

    Returns:
        The decrypted RSAPrivateKey.

    Raises:
        FileNotFoundError: If the PEM file does not exist.
        ValueError:        If the password is wrong or the PEM is malformed.
        ValueError:        If username is empty or unsafe.
    """
    path = private_key_path(username)
    if not path.exists():
        raise FileNotFoundError(
            f"Private key not found for user '{username}'. "
            f"Run scripts/generate_user_keys.py --username {username}"
        )
    pem_data = path.read_bytes()
    return load_private_key(pem_data, password)


def load_user_public_key(username: str) -> RSAPublicKey:
    """
    Load a user's application public key from disk.

    Public keys are not encrypted and do not require a password.

    Args:
        username: The account username.

    Returns:
        The RSAPublicKey.

    Raises:
        FileNotFoundError: If the PEM file does not exist.
    """
    path = public_key_path(username)
    if not path.exists():
        raise FileNotFoundError(
            f"Public key not found for user '{username}'. "
            f"Run scripts/generate_user_keys.py --username {username}"
        )
    return load_public_key(path.read_bytes())


def load_all_public_keys() -> dict[str, RSAPublicKey]:
    """
    Enumerate and load all public keys in the keys/ directory.

    Used by the server when verifying signatures (it needs the uploader's
    public key) and by the client when sharing files (it needs each
    recipient's public key to wrap the AES key).

    Returns:
        Dict mapping username → RSAPublicKey for every ``*_app_public.pem``
        found in KEYS_DIR.  Empty dict if KEYS_DIR does not exist.
    """
    if not KEYS_DIR.exists():
        return {}

    result: dict[str, RSAPublicKey] = {}
    for pem_path in KEYS_DIR.glob("*_app_public.pem"):
        username = pem_path.stem.removesuffix("_app_public")
        try:
            result[username] = load_public_key(pem_path.read_bytes())
        except Exception:
            # Skip corrupt or unreadable key files — log in production
            continue
    return result


def get_public_key_pem(username: str) -> bytes:
    """
    Return the raw PEM bytes of a user's public key.

    Used when a client needs to send its public key to the server during
    registration, so the server can store it for future file-sharing
    operations.

    Args:
        username: The account username.

    Returns:
        PEM bytes of the public key.

    Raises:
        FileNotFoundError: If no key exists for this user.
    """
    path = public_key_path(username)
    if not path.exists():
        raise FileNotFoundError(f"Public key not found for '{username}'.")
    return path.read_bytes()


def public_key_exists(username: str) -> bool:
    """Return True if a public key PEM exists for *username*."""
    return public_key_path(username).exists()


def private_key_exists(username: str) -> bool:
    """Return True if a private key PEM exists for *username*."""
    return private_key_path(username).exists()


def ensure_escrow_keys(password: bytes | None = None) -> tuple[RSAPrivateKey, RSAPublicKey]:
    """
    Ensure institutional key escrow keys exist in KEYS_DIR; generate them if missing.
    Returns (private_key, public_key).
    """
    pw = password or ESCROW_KEY_PASSWORD.encode()
    priv_p = private_key_path(ESCROW_USERNAME)
    pub_p = public_key_path(ESCROW_USERNAME)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if priv_p.exists() and pub_p.exists():
        try:
            priv_k = load_private_key(priv_p.read_bytes(), pw)
            pub_k = load_public_key(pub_p.read_bytes())
            return priv_k, pub_k
        except Exception:
            pass

    priv_k, pub_k = generate_rsa_keypair()
    priv_p.write_bytes(serialize_private_key(priv_k, pw))
    pub_p.write_bytes(serialize_public_key(pub_k))
    return priv_k, pub_k


def load_escrow_public_key() -> Optional[RSAPublicKey]:
    """Load institutional escrow public key if available, else None."""
    pub_p = public_key_path(ESCROW_USERNAME)
    if pub_p.exists():
        try:
            return load_public_key(pub_p.read_bytes())
        except Exception:
            return None
    return None


def load_escrow_private_key(password: bytes | None = None) -> Optional[RSAPrivateKey]:
    """Load institutional escrow private key if available, else None."""
    pw = password or ESCROW_KEY_PASSWORD.encode()
    priv_p = private_key_path(ESCROW_USERNAME)
    if priv_p.exists():
        try:
            return load_private_key(priv_p.read_bytes(), pw)
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Session-scoped private key cache
# ---------------------------------------------------------------------------


class PrivateKeySession:
    """
    Holds a decrypted private key for the duration of a client session.

    The key is decrypted once at login and held until logout() is called,
    avoiding repeated password prompts for each file operation.

    SECURITY NOTE:
        Python does not offer guaranteed memory zeroing; the private key
        material will remain reachable until garbage-collected.  In a
        production system this would require a native extension or ctypes
        to scrub the memory.  This limitation is documented in LIMITATIONS.md.

    Usage:
        session = PrivateKeySession()
        session.load("doctor", b"mypassword")
        ...
        key = session.get()            # use the key
        ...
        session.clear()                # on logout
    """

    def __init__(self) -> None:
        self._key: Optional[RSAPrivateKey] = None
        self._username: Optional[str] = None

    def load(self, username: str, password: bytes) -> None:
        """
        Decrypt and cache the private key for *username*.

        Args:
            username: Account username.
            password: Passphrase for the private key.

        Raises:
            FileNotFoundError: If no private key exists.
            ValueError:        On wrong password or corrupt file.
        """
        self._key = load_user_private_key(username, password)
        self._username = username

    def get(self) -> RSAPrivateKey:
        """
        Return the cached private key.

        Raises:
            RuntimeError: If load() has not been called or the session was cleared.
        """
        if self._key is None:
            raise RuntimeError(
                "No private key loaded. Call load() after login before "
                "performing any crypto operations."
            )
        return self._key

    def clear(self) -> None:
        """
        Remove the private key reference from this object.

        After this call, get() will raise RuntimeError.  This is a
        best-effort memory cleanup — Python's GC will reclaim the memory
        in its own time.
        """
        self._key = None
        self._username = None

    @property
    def username(self) -> Optional[str]:
        """The username whose key is currently loaded, or None."""
        return self._username

    @property
    def is_loaded(self) -> bool:
        """True if a key is currently cached."""
        return self._key is not None
