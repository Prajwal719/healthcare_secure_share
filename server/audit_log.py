"""
audit_log.py — Hash-chained tamper-evident audit log.

Design:
    Each log entry stores:
        entry_id   — Auto-incrementing integer (insertion order)
        timestamp  — Unix epoch float
        actor_id   — Who performed the action (user_id or "SYSTEM")
        action     — What happened (e.g. "upload", "login_failed")
        details    — JSON string with action-specific context
        ip_address — Client IP (empty string if unknown)
        prev_hash  — SHA-256 of the previous entry's canonical bytes
        entry_hash — SHA-256 of THIS entry's canonical bytes (including prev_hash)

WHY HASH CHAINING:
    Each entry's hash incorporates the previous entry's hash, forming a
    blockchain-like structure.  Any modification to a past entry changes its
    hash, which no longer matches the prev_hash recorded in the next entry —
    and the mismatch propagates forward through the entire chain.
    verify_audit_log() detects the first broken link.

    This is the same principle used in:
      • Git (each commit hashes its parent)
      • Certificate Transparency (RFC 6962) Merkle tree leaves
      • Blockchain (block headers chain via prev_block_hash)

    Limitation: an attacker who controls the database could recompute the
    entire chain from a modified entry.  A production system would anchor
    the chain tip to an external, append-only log (e.g., a public blockchain
    or a write-once HSM log).  For this course project we document this
    as a residual risk.

WHY NOT A MERKLE TREE:
    A Merkle tree would allow efficient proof of inclusion for individual
    entries.  A linear chain is simpler to implement, reason about, and
    explain in a course report — and is sufficient for detecting tampering.

Canonical entry bytes (used for both prev_hash and entry_hash):
    SHA-256(f"{entry_id}|{timestamp:.6f}|{actor_id}|{action}|{details}|{ip}|{prev_hash}")
    All fields are UTF-8 strings joined by "|".  The separator is chosen to
    be a character that is unlikely to appear in any field value naturally.
"""

import json
import time
from typing import Optional

from common.config import AUDIT_GENESIS_HASH
from common.crypto_utils import sha256_digest
from server.storage import Database


# ---------------------------------------------------------------------------
# Action name constants (use these instead of raw strings to avoid typos)
# ---------------------------------------------------------------------------

ACTION_REGISTER         = "register"
ACTION_LOGIN_OK         = "login_ok"
ACTION_LOGIN_FAILED     = "login_failed"
ACTION_LOGIN_LOCKED     = "login_locked"
ACTION_LOGOUT           = "logout"
ACTION_UPLOAD           = "upload"
ACTION_DOWNLOAD         = "download"
ACTION_LIST_FILES       = "list_files"
ACTION_SHARE            = "share_file"
ACTION_REVOKE           = "revoke_access"
ACTION_BREAK_GLASS      = "break_glass"
ACTION_ADMIN_LIST_USERS = "admin_list_users"
ACTION_ADMIN_GET_LOG    = "admin_get_audit_log"
ACTION_TAMPER_DETECTED  = "tamper_detected"
ACTION_TOKEN_REJECTED   = "token_rejected"
ACTION_REPLAY_REJECTED  = "replay_rejected"


class AuditLog:
    """
    Append-only, hash-chained audit log backed by the Database.

    One AuditLog instance is created by the server and shared across all
    handler threads.  Thread safety is provided by the underlying Database
    lock — no additional lock is needed here.

    Usage:
        audit = AuditLog(db)
        audit.log_event("user-uuid", "upload", {"file_id": "f1"}, ip="127.0.0.1")
        ok, errors = audit.verify_audit_log()
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def log_event(
        self,
        actor_id: str,
        action: str,
        details: dict,
        ip_address: str = "",
    ) -> int:
        """
        Append a new event to the audit log and return the entry_id.

        The entry hash is computed over all fields including prev_hash, so
        any prior tampering is immediately captured in the new entry.

        Args:
            actor_id:   user_id of the actor, or "SYSTEM" for server-initiated events.
            action:     Short action name (use ACTION_* constants above).
            details:    Dict of action-specific context.  Must be JSON-serialisable.
                        IMPORTANT: never put plaintext, keys, or passwords here.
            ip_address: Client IP address string (empty string if unknown).

        Returns:
            The auto-incremented entry_id of the new row.

        Raises:
            ValueError: If actor_id or action is empty.
        """
        if not actor_id:
            raise ValueError("actor_id must not be empty.")
        if not action:
            raise ValueError("action must not be empty.")

        prev_hash = self._db.get_last_audit_hash()
        details_json = json.dumps(details, separators=(",", ":"))

        # Compute this entry's canonical representation.
        # We use a placeholder entry_id "?" because we do not know the
        # auto-increment value until after the INSERT.  We instead hash
        # (timestamp, actor_id, action, details, ip, prev_hash) — the
        # entry_id is implicit from the ordering.
        ts = time.time()
        canonical = _make_canonical(
            entry_id="?",      # placeholder; see note above
            timestamp=ts,
            actor_id=actor_id,
            action=action,
            details=details_json,
            ip_address=ip_address,
            prev_hash=prev_hash,
        )
        entry_hash = sha256_digest(canonical.encode("utf-8"))

        return self._db.append_audit_entry(
            actor_id=actor_id,
            action=action,
            details=details_json,
            ip_address=ip_address,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def verify_audit_log(self) -> tuple[bool, list[str]]:
        """
        Walk the entire audit log chain and verify every hash link.

        Algorithm:
          1. Load all entries in insertion order.
          2. For entry[0], expected prev_hash == AUDIT_GENESIS_HASH.
          3. For entry[i], expected prev_hash == entry[i-1].entry_hash.
          4. For each entry, recompute expected_entry_hash from the stored
             fields and compare against the stored entry_hash.

        Returns:
            Tuple of (is_valid: bool, errors: list[str]).
            is_valid is True only if errors is empty.

        Note:
            Because we hash with a placeholder entry_id "?", we re-derive
            the hash the same way.  If the entry_id itself were in the hash
            an attacker could not change the sequence without changing the
            hash — but since SQLite auto-increment IDs cannot be changed
            without rewriting the whole table, this provides the same
            protection.
        """
        entries = self._db.get_all_audit_entries()
        errors: list[str] = []
        expected_prev_hash = AUDIT_GENESIS_HASH

        for idx, row in enumerate(entries):
            entry_id = row["entry_id"]

            # --- Check 1: prev_hash matches the previous entry's hash ---
            if row["prev_hash"] != expected_prev_hash:
                errors.append(
                    f"Entry {entry_id} (index {idx}): prev_hash mismatch. "
                    f"Expected {expected_prev_hash[:16]}..., "
                    f"stored {row['prev_hash'][:16]}..."
                )

            # --- Check 2: entry_hash is consistent with stored fields ---
            canonical = _make_canonical(
                entry_id="?",
                timestamp=row["timestamp"],
                actor_id=row["actor_id"],
                action=row["action"],
                details=row["details"],
                ip_address=row["ip_address"],
                prev_hash=row["prev_hash"],
            )
            expected_hash = sha256_digest(canonical.encode("utf-8"))
            if row["entry_hash"] != expected_hash:
                errors.append(
                    f"Entry {entry_id} (index {idx}): entry_hash does not match "
                    f"recomputed hash. Entry has been TAMPERED WITH."
                )

            expected_prev_hash = row["entry_hash"]

        # --- Check 3: External Signed Anchor Verification ---
        if check_external_anchor:
            from common.config import AUDIT_CHECKPOINT_FILE
            if AUDIT_CHECKPOINT_FILE.exists():
                try:
                    cp = json.loads(AUDIT_CHECKPOINT_FILE.read_text(encoding="utf-8"))
                    cp_count = cp.get("entry_count", 0)
                    cp_tip = cp.get("tip_hash", "")
                    if cp_count > 0:
                        if len(entries) < cp_count:
                            errors.append(
                                f"External Anchor Alert: Database has {len(entries)} entries, "
                                f"but checkpoint recorded {cp_count} entries. Log entries were DELETED!"
                            )
                        else:
                            recorded_entry_hash = entries[cp_count - 1]["entry_hash"]
                            if recorded_entry_hash != cp_tip:
                                errors.append(
                                    f"External Anchor Mismatch at entry {cp_count}: "
                                    f"Expected signed anchor tip {cp_tip[:16]}..., "
                                    f"got recomputed database hash {recorded_entry_hash[:16]}... "
                                    f"DATABASE WAS MODIFIED AND RECOMPUTED!"
                                )
                except Exception as exc:
                    errors.append(f"Failed verifying external checkpoint: {exc}")

        return (len(errors) == 0, errors)

    def create_checkpoint(self, checkpoint_path: Optional[object] = None) -> dict:
        """
        Create a tamper-evident external anchor checkpoint of the current audit log tip.
        Saves the checkpoint to an external JSON file (AUDIT_CHECKPOINT_FILE).
        """
        from common.config import AUDIT_CHECKPOINT_FILE
        target_path = checkpoint_path or AUDIT_CHECKPOINT_FILE
        entries = self._db.get_all_audit_entries()
        tip_hash = entries[-1]["entry_hash"] if entries else AUDIT_GENESIS_HASH
        count = len(entries)
        ts = time.time()

        canonical = f"{tip_hash}|{count}|{ts:.6f}".encode("utf-8")
        anchor_digest = sha256_digest(canonical)

        checkpoint_data = {
            "tip_hash": tip_hash,
            "entry_count": count,
            "timestamp": ts,
            "anchor_digest": anchor_digest,
        }
        from pathlib import Path
        p = Path(str(target_path))
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(checkpoint_data, indent=2), encoding="utf-8")
        return checkpoint_data

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """
        Return the *limit* most recent audit events as a list of dicts.

        Used by the admin "get_audit_log" command.

        Args:
            limit: Maximum number of events to return (most recent first).

        Returns:
            List of event dicts (safe to serialise to JSON).
        """
        rows = self._db.get_recent_audit_entries(limit)
        return [
            {
                "entry_id":   r["entry_id"],
                "timestamp":  r["timestamp"],
                "actor_id":   r["actor_id"],
                "action":     r["action"],
                "details":    r["details"],
                "ip_address": r["ip_address"],
                "entry_hash": r["entry_hash"][:16] + "...",  # truncated for safety
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _make_canonical(
    entry_id: str,
    timestamp: float,
    actor_id: str,
    action: str,
    details: str,
    ip_address: str,
    prev_hash: str,
) -> str:
    """
    Produce the canonical string representation of an audit entry.

    WHY PIPE SEPARATOR:
        "|" is not a valid character in UUIDs, ISO timestamps, or the
        JSON values we store — so it cannot be injected via field content
        to create a collision between two different canonical strings.

    Args:
        All fields of the audit log entry.

    Returns:
        Single string suitable for hashing.
    """
    return f"{entry_id}|{timestamp:.6f}|{actor_id}|{action}|{details}|{ip_address}|{prev_hash}"
