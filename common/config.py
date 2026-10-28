"""
config.py — Central configuration for the Secure Healthcare File-Sharing Protocol.

WHY A SINGLE CONFIG MODULE:
    All security-sensitive parameters live here so that:
    1. An auditor can review every cryptographic constant in one place.
    2. Changes (e.g., increasing PBKDF iterations before deployment) are
       made in exactly one file with no risk of inconsistency.
    3. No magic numbers are scattered through business logic.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Directory layout (resolved relative to the project root)
# ---------------------------------------------------------------------------
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CERTS_DIR: Path = PROJECT_ROOT / "certs"
KEYS_DIR: Path = PROJECT_ROOT / "keys"
DB_PATH: Path = PROJECT_ROOT / "server" / "healthcare.db"

# ---------------------------------------------------------------------------
# AES-256-GCM parameters
# WHY AES-256-GCM:
#   - AES-256 provides 256-bit security — well beyond the 128-bit minimum
#     recommended by NIST for long-term confidentiality.
#   - GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with
#     Associated Data) mode, combining confidentiality AND integrity in a
#     single primitive. This eliminates the "encrypt-then-MAC" complexity
#     and the risk of MAC-then-encrypt vulnerabilities (e.g., padding oracle).
#   - GCM is hardware-accelerated on modern CPUs (AES-NI + CLMUL), making
#     it the fastest secure option.
# ---------------------------------------------------------------------------
AES_KEY_SIZE_BYTES: int = 32          # 256 bits
# WHY 96-bit nonce: GCM's proof of security holds tightly for 96-bit nonces
# (they map directly to the counter block without hashing). NIST SP 800-38D
# explicitly recommends 96 bits for deterministic IV generation.
GCM_NONCE_SIZE_BYTES: int = 12        # 96 bits
# GCM produces a 128-bit authentication tag — the maximum allowed by the spec.
# Shorter tags (e.g., 96-bit) reduce the authentication security margin.
GCM_TAG_SIZE_BYTES: int = 16          # 128 bits

# ---------------------------------------------------------------------------
# RSA parameters
# WHY RSA-3072:
#   - NIST SP 800-131A (rev 2, 2019) specifies that 2048-bit RSA provides
#     ~112-bit security through 2030. 3072-bit provides ~128-bit security,
#     matching AES-256's security level and extending the key's usable life.
#   - RSA-OAEP (key wrapping) and RSA-PSS (signing) are both provably secure
#     under the RSA assumption, unlike PKCS#1 v1.5 which has known attacks
#     (Bleichenbacher, ROBOT). We never use PKCS#1 v1.5.
# ---------------------------------------------------------------------------
RSA_KEY_SIZE_BITS: int = 3072
RSA_PUBLIC_EXPONENT: int = 65537      # Standard Fermat prime, widely audited

# ---------------------------------------------------------------------------
# Password hashing — scrypt
# WHY scrypt over bcrypt/Argon2:
#   - scrypt is memory-hard (requires large RAM), making GPU/ASIC brute-force
#     extremely expensive, unlike bcrypt which is only CPU-hard.
#   - The 'cryptography' library ships scrypt natively; no extra dependency.
#   - Parameters below satisfy OWASP 2023 recommendations (n=2^17 minimum).
# WHY PBKDF2 as fallback:
#   - The spec mandates >= 600,000 iterations of PBKDF2-HMAC-SHA256 as an
#     alternative. We use scrypt as primary but keep PBKDF2 for compatibility.
# ---------------------------------------------------------------------------
SCRYPT_N: int = 2 ** 17              # CPU/memory cost factor (128 KiB blocks)
SCRYPT_R: int = 8                    # Block size multiplier
SCRYPT_P: int = 1                    # Parallelisation factor
SCRYPT_KEY_LEN: int = 32             # 256-bit derived key
SCRYPT_SALT_SIZE: int = 32           # 256-bit random salt per user

PBKDF2_ITERATIONS: int = 600_000     # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
PBKDF2_HASH: str = "sha256"

# ---------------------------------------------------------------------------
# Session tokens (HMAC-SHA256 signed)
# WHY NOT JWT: The 'cryptography' library has no JWT support. Rolling our own
# simple HMAC token is more transparent and easier for the audit examiner to
# follow than adding a jwt dependency with its own quirks.
# ---------------------------------------------------------------------------
SESSION_TOKEN_EXPIRY_SECONDS: int = 900   # 15 minutes
# HMAC key is derived fresh each server start and stored only in memory.
# This means tokens are automatically invalidated on server restart, which
# is a desirable security property in a healthcare context.
TOKEN_HMAC_KEY_SIZE: int = 32             # 256-bit HMAC key

# ---------------------------------------------------------------------------
# Replay protection
# WHY 30-second window: Balances clock-drift tolerance (NTP sync is ~ms
# accurate on LANs) against the replay window. RFC 5905 recommends < 1 s
# drift on a well-synced LAN, so 30 s is generous while still blocking stale
# captures from hours-old network dumps.
# ---------------------------------------------------------------------------
REPLAY_WINDOW_SECONDS: int = 30
REPLAY_CACHE_MAX_SIZE: int = 10_000      # Bounded LRU set of seen message IDs

# ---------------------------------------------------------------------------
# Account lockout
# WHY 5 attempts: NIST SP 800-63B recommends locking after no more than 100
# failed attempts, but for a healthcare demo we use 5 to keep the attack
# simulation fast. This is documented as a tunable parameter.
# ---------------------------------------------------------------------------
MAX_LOGIN_ATTEMPTS: int = 5
LOCKOUT_DURATION_SECONDS: int = 300      # 5-minute cooldown

# ---------------------------------------------------------------------------
# Network / TLS
# ---------------------------------------------------------------------------
SERVER_HOST: str = "127.0.0.1"
SERVER_PORT: int = 9443
# Maximum raw message size accepted from a peer (prevents memory exhaustion).
MAX_MESSAGE_SIZE_BYTES: int = 64 * 1024 * 1024   # 64 MiB

# TLS: we prefer TLS 1.3; ssl.SSLContext will negotiate down to 1.2 if the
# peer does not support 1.3. Anything below 1.2 is rejected at the context
# level (ssl.PROTOCOL_TLS_CLIENT / ssl.PROTOCOL_TLS_SERVER already do this).
TLS_MIN_VERSION: str = "TLSv1.2"

# IP allowlist — only addresses in this set may connect to the server.
# An empty set means "accept all" (development mode). In production this
# should be locked to specific subnets.
IP_ALLOWLIST: set[str] = set()           # Populated from environment/config

# ---------------------------------------------------------------------------
# Audit log
# WHY hash-chaining: Creates a tamper-evident log — modifying any past entry
# breaks the chain from that point forward, which verify_audit_log detects.
# This mirrors the structure used in blockchain and certificate transparency logs.
# ---------------------------------------------------------------------------
AUDIT_GENESIS_HASH: str = "0" * 64      # SHA-256 of the virtual "genesis" block

# ---------------------------------------------------------------------------
# Roles and permissions
# ---------------------------------------------------------------------------
ROLES: set[str] = {"doctor", "nurse", "patient", "admin"}

# Permission map: role → set of allowed actions
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "doctor":  {"upload", "download", "list", "share", "revoke", "break_glass"},
    "nurse":   {"download", "list"},
    "patient": {"download", "list"},          # filtered to own files server-side
    "admin":   {"list_users", "audit_log", "manage_users", "download", "list"},
}

# ---------------------------------------------------------------------------
# Key Escrow & Break-Glass parameters
# WHY KEY ESCROW:
#   In hospital emergency situations, a patient may be unable to consent or the
#   original attending doctor may be unavailable. Under HIPAA § 164.512(j),
#   emergency access is permissible. Key Escrow allows the server/authority to
#   unwrap an institutional escrow copy of the AES key and re-wrap it for the
#   attending doctor upon verified emergency justification and mandatory audit logging.
# ---------------------------------------------------------------------------
ESCROW_USERNAME: str = "escrow"
ESCROW_KEY_PASSWORD: str = "EscrowPass1!"
AUDIT_CHECKPOINT_FILE: Path = PROJECT_ROOT / "server" / "audit_checkpoints.json"

# ---------------------------------------------------------------------------
# Miscellaneous
# ---------------------------------------------------------------------------
# Length prefix for protocol framing: 4-byte big-endian unsigned int.
# Supports messages up to 4 GiB; we cap at MAX_MESSAGE_SIZE_BYTES above.
FRAME_LENGTH_PREFIX_BYTES: int = 4
