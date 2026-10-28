"""
storage.py — SQLite persistence layer for the Secure Healthcare File-Sharing Protocol.

Schema overview:
  users        — accounts, hashed passwords, roles, lockout state, public keys
  files        — encrypted ciphertext, nonce, AAD, signature, uploader
  wrapped_keys — per-recipient RSA-OAEP wrapped AES keys (one row per access grant)
  audit_log    — hash-chained tamper-evident event log

Thread Safety:
    SQLite's default mode is "serialised" when compiled with
    SQLITE_THREADSAFE=1 (the default on all major platforms), but Python's
    sqlite3 module still raises ProgrammingError if the same connection is
    used from multiple threads without check_same_thread=False.  We pass
    check_same_thread=False and protect ALL mutations with a threading.Lock
    so concurrent server threads do not interleave writes.

WHY SQLITE (not PostgreSQL / MySQL):
    The spec requires no paid services and localhost-only operation.  SQLite
    is zero-configuration, ships with Python's stdlib, and is more than fast
    enough for a single-server healthcare demo.  Its limitation (no network
    access, coarse write lock) is documented in LIMITATIONS.md.

WHY STORE ONLY CIPHERTEXT:
    The server stores only the AES-GCM ciphertext, never the plaintext or
    the AES key.  Even a fully compromised database reveals nothing about
    file contents without the AES key, which is itself wrapped by the
    recipient's RSA key.  An attacker who steals the database AND a user's
    RSA private key could decrypt that user's files — this residual risk is
    documented in THREAT_MODEL.md.
"""

import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from common.config import (
    DB_PATH,
    ESCROW_KEY_PASSWORD,
    ESCROW_USERNAME,
    LOCKOUT_DURATION_SECONDS,
    MAX_LOGIN_ATTEMPTS,
)


# ---------------------------------------------------------------------------
# Data transfer objects (plain dataclasses — no ORM dependency)
# ---------------------------------------------------------------------------


@dataclass
class UserRecord:
    """Represents one row in the users table."""
    user_id: str
    username: str
    role: str
    password_hash: bytes
    password_salt: bytes
    scrypt_n: int
    scrypt_r: int
    scrypt_p: int
    public_key_pem: Optional[str]   # RSA public key PEM (for file operations)
    totp_secret: Optional[str]       # Base32 TOTP secret (None if 2FA not enabled)
    failed_attempts: int
    locked_until: float              # Unix timestamp; 0.0 means not locked
    created_at: float


@dataclass
class FileRecord:
    """Represents one row in the files table."""
    file_id: str
    filename: str
    ciphertext: bytes                # AES-256-GCM ciphertext (includes tag)
    nonce: bytes                     # 96-bit GCM nonce
    aad: str                         # JSON string bound as GCM AAD
    signature: bytes                 # RSA-PSS signature over (ciphertext||nonce||aad)
    uploader_id: str
    uploaded_at: float


@dataclass
class WrappedKeyRecord:
    """One RSA-OAEP wrapped AES key for one recipient."""
    file_id: str
    recipient_id: str
    wrapped_key: bytes               # RSA-OAEP(AES_key, recipient_public_key)
    granted_by: str
    granted_at: float


# ---------------------------------------------------------------------------
# Database class
# ---------------------------------------------------------------------------


class Database:
    """
    Thread-safe SQLite wrapper providing all persistence operations.

    One Database instance is created by the server at startup and shared
    across all connection-handler threads.  The internal _lock ensures that
    no two threads execute SQL concurrently.

    Usage:
        db = Database()          # uses config.DB_PATH
        db = Database(":memory:") # for testing
    """

    def __init__(self, db_path: Optional[str | Path] = None) -> None:
        path = Path(db_path) if db_path else DB_PATH
        # Create parent directory if needed (skip for :memory: databases)
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(
            str(path),
            check_same_thread=False,   # We enforce safety with _lock below
        )
        # Row factory: rows are accessible by column name (e.g. row["username"])
        self._conn.row_factory = sqlite3.Row
        # Enable WAL mode: concurrent reads do not block writers
        self._conn.execute("PRAGMA journal_mode=WAL;")
        # Enforce foreign key constraints (SQLite disables them by default)
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._lock = threading.Lock()
        self._init_schema()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a write statement under the lock and commit."""
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def _query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """Execute a SELECT and return the first row (or None)."""
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _query_all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute a SELECT and return all rows."""
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self._conn.close()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """
        Create all tables if they do not exist.

        Called once at startup.  Using IF NOT EXISTS makes the call
        idempotent — safe to call on every server restart.
        """
        ddl_statements = [
            # Users table
            # WHY store scrypt params alongside the hash:
            #   If we ever increase SCRYPT_N, existing hashes were computed
            #   with the old params and must be verified the same way.
            #   Storing params per-user allows seamless migration.
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id       TEXT PRIMARY KEY,
                username      TEXT UNIQUE NOT NULL,
                role          TEXT NOT NULL,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                scrypt_n      INTEGER NOT NULL,
                scrypt_r      INTEGER NOT NULL,
                scrypt_p      INTEGER NOT NULL,
                public_key_pem TEXT,
                totp_secret   TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    REAL    NOT NULL DEFAULT 0.0,
                created_at      REAL    NOT NULL
            )
            """,
            # Files table — ciphertext only, no plaintext ever stored
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id     TEXT PRIMARY KEY,
                filename    TEXT NOT NULL,
                ciphertext  BLOB NOT NULL,
                nonce       BLOB NOT NULL,
                aad         TEXT NOT NULL,
                signature   BLOB NOT NULL,
                uploader_id TEXT NOT NULL,
                uploaded_at REAL NOT NULL,
                FOREIGN KEY (uploader_id) REFERENCES users(user_id)
            )
            """,
            # Wrapped AES keys — one row per (file, recipient) pair.
            # WHY a separate table: sharing a file with a new user means
            # inserting one row (new wrapped key) without touching the file row.
            # Revoking means deleting one row.  The ciphertext is never modified.
            """
            CREATE TABLE IF NOT EXISTS wrapped_keys (
                file_id      TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                wrapped_key  BLOB NOT NULL,
                granted_by   TEXT NOT NULL,
                granted_at   REAL NOT NULL,
                PRIMARY KEY (file_id, recipient_id),
                FOREIGN KEY (file_id)      REFERENCES files(file_id),
                FOREIGN KEY (recipient_id) REFERENCES users(user_id)
            )
            """,
            # Hash-chained audit log — managed exclusively by AuditLog class
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                entry_id   INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  REAL    NOT NULL,
                actor_id   TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                details    TEXT    NOT NULL,
                ip_address TEXT    NOT NULL DEFAULT '',
                prev_hash  TEXT    NOT NULL,
                entry_hash TEXT    NOT NULL
            )
            """,
            # Indexes for common access patterns
            "CREATE INDEX IF NOT EXISTS idx_files_uploader ON files(uploader_id)",
            "CREATE INDEX IF NOT EXISTS idx_wk_recipient   ON wrapped_keys(recipient_id)",
            "CREATE INDEX IF NOT EXISTS idx_audit_actor    ON audit_log(actor_id)",
        ]
        with self._lock:
            for stmt in ddl_statements:
                self._conn.execute(stmt)
            self._conn.commit()

    # ------------------------------------------------------------------
    # User operations
    # ------------------------------------------------------------------

    def create_user(
        self,
        username: str,
        role: str,
        password_hash: bytes,
        password_salt: bytes,
        scrypt_n: int,
        scrypt_r: int,
        scrypt_p: int,
        public_key_pem: Optional[str] = None,
        totp_secret: Optional[str] = None,
    ) -> str:
        """
        Insert a new user and return the generated user_id (UUID4).

        Args:
            username:      Unique login name.
            role:          One of 'doctor', 'nurse', 'patient', 'admin'.
            password_hash: scrypt-derived key (256-bit).
            password_salt: Random salt (256-bit).
            scrypt_n/r/p:  KDF parameters stored for future verification.
            public_key_pem: RSA public key PEM for file encryption/signature verification.
            totp_secret:   Base32 TOTP secret (None if 2FA not enabled).

        Returns:
            The new user_id string (UUID4).

        Raises:
            sqlite3.IntegrityError: If username already exists.
            ValueError:             If role is not valid.
        """
        from common.config import ROLES
        if role not in ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of {ROLES}.")

        user_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO users
              (user_id, username, role, password_hash, password_salt,
               scrypt_n, scrypt_r, scrypt_p, public_key_pem, totp_secret,
               failed_attempts, locked_until, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,0,0.0,?)
            """,
            (
                user_id, username, role,
                password_hash, password_salt,
                scrypt_n, scrypt_r, scrypt_p,
                public_key_pem, totp_secret,
                time.time(),
            ),
        )
        return user_id

    def get_user_by_username(self, username: str) -> Optional[UserRecord]:
        """
        Fetch a UserRecord by username, or None if not found.

        Args:
            username: The login name to look up.

        Returns:
            UserRecord or None.
        """
        row = self._query_one(
            "SELECT * FROM users WHERE username = ?", (username,)
        )
        return _row_to_user(row) if row else None

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        """Fetch a UserRecord by user_id, or None."""
        row = self._query_one("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return _row_to_user(row) if row else None

    def increment_failed_attempts(self, user_id: str) -> int:
        """
        Increment the failed login counter for a user.

        If the counter reaches MAX_LOGIN_ATTEMPTS, the account is locked
        for LOCKOUT_DURATION_SECONDS seconds.

        Args:
            user_id: The user's UUID.

        Returns:
            The new failed_attempts count after increment.
        """
        self._execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE user_id = ?",
            (user_id,),
        )
        row = self._query_one(
            "SELECT failed_attempts FROM users WHERE user_id = ?", (user_id,)
        )
        new_count: int = row["failed_attempts"] if row else 1

        if new_count >= MAX_LOGIN_ATTEMPTS:
            locked_until = time.time() + LOCKOUT_DURATION_SECONDS
            self._execute(
                "UPDATE users SET locked_until = ? WHERE user_id = ?",
                (locked_until, user_id),
            )
        return new_count

    def reset_failed_attempts(self, user_id: str) -> None:
        """Reset the failed login counter and clear the lockout timestamp."""
        self._execute(
            "UPDATE users SET failed_attempts = 0, locked_until = 0.0 WHERE user_id = ?",
            (user_id,),
        )

    def update_public_key(self, user_id: str, public_key_pem: str) -> None:
        """Update the stored RSA public key PEM for a user."""
        self._execute(
            "UPDATE users SET public_key_pem = ? WHERE user_id = ?",
            (public_key_pem, user_id),
        )

    def list_users(self) -> list[UserRecord]:
        """Return all users (admin function)."""
        rows = self._query_all("SELECT * FROM users ORDER BY created_at")
        return [_row_to_user(r) for r in rows]

    def delete_user(self, user_id: str) -> None:
        """Remove a user account (admin function)."""
        self._execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    def ensure_escrow_user(self, public_key_pem: Optional[str] = None) -> str:
        """
        Ensure the institutional escrow user exists in the database.
        Returns the escrow user's user_id.
        """
        row = self._query_one("SELECT user_id, public_key_pem FROM users WHERE username = ?", (ESCROW_USERNAME,))
        if row:
            if public_key_pem and not row["public_key_pem"]:
                self._execute("UPDATE users SET public_key_pem = ? WHERE user_id = ?", (public_key_pem, row["user_id"]))
            return row["user_id"]

        from common.crypto_utils import scrypt_hash_password
        ph = scrypt_hash_password(ESCROW_KEY_PASSWORD)
        escrow_id = "00000000-0000-0000-0000-000000000001"
        self._execute(
            """
            INSERT INTO users
              (user_id, username, role, password_hash, password_salt,
               scrypt_n, scrypt_r, scrypt_p, public_key_pem, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                escrow_id,
                ESCROW_USERNAME,
                "admin",
                ph.derived_key,
                ph.salt,
                ph.n,
                ph.r,
                ph.p,
                public_key_pem,
                time.time(),
            ),
        )
        return escrow_id

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    def store_file(
        self,
        filename: str,
        ciphertext: bytes,
        nonce: bytes,
        aad: str,
        signature: bytes,
        uploader_id: str,
    ) -> str:
        """
        Persist an encrypted file and return its generated file_id.

        The caller must also call store_wrapped_key() to give the uploader
        access to their own file (and any other initial recipients).

        Args:
            filename:    Original filename (stored for UI display; NOT used in
                         decryption — the ciphertext is self-contained).
            ciphertext:  AES-256-GCM ciphertext bytes (includes tag).
            nonce:       96-bit GCM nonce.
            aad:         JSON string that was authenticated as GCM AAD.
            signature:   RSA-PSS signature over (ciphertext || nonce || aad bytes).
            uploader_id: user_id of the uploading user.

        Returns:
            The new file_id (UUID4).
        """
        file_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO files
              (file_id, filename, ciphertext, nonce, aad, signature, uploader_id, uploaded_at)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (file_id, filename, ciphertext, nonce, aad, signature, uploader_id, time.time()),
        )
        return file_id

    def get_file(self, file_id: str) -> Optional[FileRecord]:
        """
        Retrieve a FileRecord by file_id, or None.

        Does NOT check whether the calling user has access — the caller
        (server request handler) must verify that a wrapped_keys row
        exists for (file_id, requesting_user_id) before calling this.
        """
        row = self._query_one("SELECT * FROM files WHERE file_id = ?", (file_id,))
        return _row_to_file(row) if row else None

    def list_files_for_user(self, user_id: str) -> list[dict]:
        """
        Return metadata for all files the user is authorised to access.

        Joins files + wrapped_keys + users to resolve uploader username.
        Returns a list of dicts (not FileRecord) — ciphertext excluded.
        """
        rows = self._query_all(
            """
            SELECT f.file_id, f.filename, f.uploader_id,
                   u.username AS uploader_name,
                   f.uploaded_at,
                   LENGTH(f.ciphertext) AS file_size
            FROM   files f
            JOIN   wrapped_keys wk ON f.file_id = wk.file_id
            JOIN   users u         ON f.uploader_id = u.user_id
            WHERE  wk.recipient_id = ?
            ORDER  BY f.uploaded_at DESC
            """,
            (user_id,),
        )
        return [
            {
                "file_id":       r["file_id"],
                "filename":      r["filename"],
                "uploader_id":   r["uploader_id"],
                "uploader_name": r["uploader_name"],
                "uploaded_at":   r["uploaded_at"],
                "file_size":     r["file_size"],
            }
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Wrapped key operations (access control)
    # ------------------------------------------------------------------

    def store_wrapped_key(
        self,
        file_id: str,
        recipient_id: str,
        wrapped_key: bytes,
        granted_by: str,
    ) -> None:
        """
        Store an RSA-OAEP wrapped AES key for a recipient.

        This is how access is granted — the uploader calls this for each
        intended recipient (including themselves) after upload.

        Uses INSERT OR REPLACE so that sharing the same file with the same
        user a second time (e.g., after a key rotation) updates the entry.

        Args:
            file_id:      The file this key belongs to.
            recipient_id: The user who can unwrap this key.
            wrapped_key:  RSA-OAEP(AES_key, recipient_public_key).
            granted_by:   user_id of who performed the share action.

        Raises:
            sqlite3.IntegrityError: If file_id or recipient_id do not exist.
        """
        self._execute(
            """
            INSERT OR REPLACE INTO wrapped_keys
              (file_id, recipient_id, wrapped_key, granted_by, granted_at)
            VALUES (?,?,?,?,?)
            """,
            (file_id, recipient_id, wrapped_key, granted_by, time.time()),
        )

    def get_wrapped_key(self, file_id: str, recipient_id: str) -> Optional[bytes]:
        """
        Return the wrapped AES key for a specific (file, recipient) pair.

        Returns None if the recipient has no access to this file.

        Args:
            file_id:      The target file.
            recipient_id: The requesting user's ID.

        Returns:
            Wrapped key bytes, or None if no access.
        """
        row = self._query_one(
            "SELECT wrapped_key FROM wrapped_keys WHERE file_id = ? AND recipient_id = ?",
            (file_id, recipient_id),
        )
        return bytes(row["wrapped_key"]) if row else None

    def revoke_access(self, file_id: str, recipient_id: str) -> bool:
        """
        Remove a user's access to a file by deleting their wrapped key.

        After this call the user can no longer download the AES key for
        this file.  Note: if the user previously downloaded the file, they
        may have cached the plaintext locally — this is a known limitation
        documented in LIMITATIONS.md.

        Args:
            file_id:      The file to revoke access to.
            recipient_id: The user losing access.

        Returns:
            True if a row was deleted (access existed), False otherwise.
        """
        cur = self._execute(
            "DELETE FROM wrapped_keys WHERE file_id = ? AND recipient_id = ?",
            (file_id, recipient_id),
        )
        return cur.rowcount > 0

    def list_recipients(self, file_id: str) -> list[str]:
        """Return all user_ids that have a wrapped key for a given file."""
        rows = self._query_all(
            "SELECT recipient_id FROM wrapped_keys WHERE file_id = ?", (file_id,)
        )
        return [r["recipient_id"] for r in rows]

    def has_access(self, file_id: str, user_id: str) -> bool:
        """Return True if user_id has a wrapped key for file_id."""
        return self.get_wrapped_key(file_id, user_id) is not None

    # ------------------------------------------------------------------
    # Audit log (raw access — AuditLog class wraps this)
    # ------------------------------------------------------------------

    def append_audit_entry(
        self,
        actor_id: str,
        action: str,
        details: str,
        ip_address: str,
        prev_hash: str,
        entry_hash: str,
    ) -> int:
        """
        Append one row to the audit_log table.

        Called exclusively by AuditLog.log_event() — do not call directly.

        Returns:
            The auto-incremented entry_id.
        """
        cur = self._execute(
            """
            INSERT INTO audit_log
              (timestamp, actor_id, action, details, ip_address, prev_hash, entry_hash)
            VALUES (?,?,?,?,?,?,?)
            """,
            (time.time(), actor_id, action, details, ip_address, prev_hash, entry_hash),
        )
        return cur.lastrowid

    def get_all_audit_entries(self) -> list[sqlite3.Row]:
        """Return all audit log rows in insertion order (ascending entry_id)."""
        return self._query_all("SELECT * FROM audit_log ORDER BY entry_id ASC")

    def get_recent_audit_entries(self, limit: int = 100) -> list[sqlite3.Row]:
        """Return the most recent *limit* audit entries (newest first)."""
        return self._query_all(
            "SELECT * FROM audit_log ORDER BY entry_id DESC LIMIT ?", (limit,)
        )

    def get_last_audit_hash(self) -> str:
        """Return the entry_hash of the most recent audit entry."""
        from common.config import AUDIT_GENESIS_HASH
        row = self._query_one(
            "SELECT entry_hash FROM audit_log ORDER BY entry_id DESC LIMIT 1"
        )
        return row["entry_hash"] if row else AUDIT_GENESIS_HASH


# ---------------------------------------------------------------------------
# Row → dataclass converters (private)
# ---------------------------------------------------------------------------


def _row_to_user(row: sqlite3.Row) -> UserRecord:
    return UserRecord(
        user_id=row["user_id"],
        username=row["username"],
        role=row["role"],
        password_hash=bytes(row["password_hash"]),
        password_salt=bytes(row["password_salt"]),
        scrypt_n=row["scrypt_n"],
        scrypt_r=row["scrypt_r"],
        scrypt_p=row["scrypt_p"],
        public_key_pem=row["public_key_pem"],
        totp_secret=row["totp_secret"],
        failed_attempts=row["failed_attempts"],
        locked_until=row["locked_until"],
        created_at=row["created_at"],
    )


def _row_to_file(row: sqlite3.Row) -> FileRecord:
    return FileRecord(
        file_id=row["file_id"],
        filename=row["filename"],
        ciphertext=bytes(row["ciphertext"]),
        nonce=bytes(row["nonce"]),
        aad=row["aad"],
        signature=bytes(row["signature"]),
        uploader_id=row["uploader_id"],
        uploaded_at=row["uploaded_at"],
    )
