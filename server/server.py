"""
server.py — Mutual-TLS threaded server for the Secure Healthcare File-Sharing Protocol.

Architecture:
    - One thread per client connection (ThreadingTCPServer).
    - Mutual TLS: server presents its cert; client MUST present a CA-signed cert.
    - All business logic dispatched via _HANDLERS dict keyed by action string.
    - One shared Database, AuditLog, and ReplayGuard across all threads.

Security properties enforced here:
    - IP allowlist checked before any data is read.
    - Replay guard checked on every authenticated request.
    - RBAC checked before every privileged action.
    - Signatures verified on upload; wrapped keys verified on download.
    - Break-glass access is permitted but heavily logged.
"""

import json
import os
import socketserver
import ssl
import threading
import time
from pathlib import Path
from typing import Any, Callable

from common.config import (
    CERTS_DIR,
    IP_ALLOWLIST,
    MAX_MESSAGE_SIZE_BYTES,
    ROLE_PERMISSIONS,
    SERVER_HOST,
    SERVER_PORT,
)
from common.crypto_utils import (
    load_public_key,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_verify,
    serialize_public_key,
    sha256_digest,
)
from common.protocol import (
    ProtocolError,
    b64decode,
    b64encode,
    build_response,
    recv_message,
    send_message,
)
from common.replay_guard import ReplayGuard, ReplayError
from server.audit_log import (
    ACTION_ADMIN_GET_LOG,
    ACTION_ADMIN_LIST_USERS,
    ACTION_BREAK_GLASS,
    ACTION_DOWNLOAD,
    ACTION_LIST_FILES,
    ACTION_LOGIN_FAILED,
    ACTION_LOGIN_LOCKED,
    ACTION_LOGIN_OK,
    ACTION_LOGOUT,
    ACTION_REGISTER,
    ACTION_REPLAY_REJECTED,
    ACTION_REVOKE,
    ACTION_SHARE,
    ACTION_TOKEN_REJECTED,
    ACTION_UPLOAD,
    AuditLog,
)
from server.auth import (
    AccountLockedError,
    AuthError,
    InvalidCredentialsError,
    InvalidTokenError,
    PermissionDeniedError,
    TotpRequiredError,
    authenticate_user,
    check_permission,
    issue_token,
    verify_token,
)
from server.storage import Database

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Shared server state (initialised in HealthcareServer.__init__)
# ---------------------------------------------------------------------------
_db: Database
_audit: AuditLog
_replay: ReplayGuard


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class ClientHandler(socketserver.BaseRequestHandler):
    """
    Handles one client connection in its own thread.

    self.request is the raw socket; we wrap it in SSL in setup().
    """

    def setup(self) -> None:
        """Wrap the raw socket in the server's SSL context."""
        self.ssl_sock = self.server.ssl_context.wrap_socket(
            self.request, server_side=True
        )
        self.client_ip: str = self.client_address[0]

    def handle(self) -> None:
        """Main request/response loop for one client connection."""
        # IP allowlist check — reject before reading any data
        if IP_ALLOWLIST and self.client_ip not in IP_ALLOWLIST:
            self._send_error("IP not in allowlist.")
            return

        try:
            while True:
                try:
                    envelope = recv_message(self.ssl_sock)
                except ProtocolError:
                    break
                except OSError:
                    break

                action = envelope.get("action", "")
                if action == "logout":
                    self._handle_logout(envelope)
                    break

                response = self._dispatch(envelope)
                send_message(self.ssl_sock, response)

        except OSError:
            pass
        finally:
            try:
                self.ssl_sock.close()
            except OSError:
                pass

    def finish(self) -> None:
        pass  # SSL socket closed in handle()

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, envelope: dict) -> dict:
        """Route an envelope to the correct handler function."""
        action = envelope.get("action", "")
        handlers: dict[str, Callable] = {
            "register":         self._handle_register,
            "login":            self._handle_login,
            "upload":           self._handle_upload,
            "download":         self._handle_download,
            "list_files":       self._handle_list_files,
            "share_file":       self._handle_share_file,
            "revoke_access":    self._handle_revoke_access,
            "list_users":       self._handle_list_users,
            "get_audit_log":        self._handle_get_audit_log,
            "verify_audit_log":     self._handle_verify_audit_log,
            "checkpoint_audit_log": self._handle_checkpoint_audit_log,
            "manage_user":          self._handle_manage_user,
            "break_glass":      self._handle_break_glass,
            "ping":             lambda e: build_response(True, {"pong": True}),
        }
        handler = handlers.get(action)
        if handler is None:
            return build_response(False, {}, error=f"Unknown action '{action}'.")
        try:
            return handler(envelope)
        except PermissionDeniedError as exc:
            return build_response(False, {}, error=str(exc))
        except InvalidTokenError as exc:
            _audit.log_event("SYSTEM", ACTION_TOKEN_REJECTED,
                             {"reason": str(exc)}, self.client_ip)
            return build_response(False, {}, error="Token invalid or expired.")
        except ReplayError as exc:
            _audit.log_event("SYSTEM", ACTION_REPLAY_REJECTED,
                             {"reason": str(exc)}, self.client_ip)
            return build_response(False, {}, error="Replay detected.")
        except AuthError as exc:
            return build_response(False, {}, error=str(exc))
        except Exception as exc:
            # Never leak internal details to the client
            return build_response(False, {}, error="Internal server error.")

    # ------------------------------------------------------------------
    # Auth helpers
    # ------------------------------------------------------------------

    def _require_auth(self, envelope: dict) -> tuple[str, str]:
        """
        Validate token and replay fields. Returns (user_id, role).
        Raises InvalidTokenError or ReplayError on failure.
        """
        token = envelope.get("token")
        if not token:
            raise InvalidTokenError("No token provided.")
        user_id, role = verify_token(token)
        _replay.check_and_record(
            msg_id=envelope["msg_id"],
            timestamp=envelope["timestamp"],
            counter=envelope["counter"],
            session_id=user_id,
        )
        return user_id, role

    def _send_error(self, msg: str) -> None:
        try:
            send_message(self.ssl_sock, build_response(False, {}, error=msg))
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------

    def _handle_register(self, envelope: dict) -> dict:
        p = envelope["payload"]
        username = str(p.get("username", ""))[:64]
        password = str(p.get("password", ""))
        role = str(p.get("role", ""))
        pub_key_pem = p.get("public_key_pem", "")

        if not username or not password or not role:
            return build_response(False, {}, error="username, password, role required.")

        from common.config import ROLES
        if role not in ROLES:
            return build_response(False, {}, error=f"Invalid role '{role}'.")

        from common.crypto_utils import scrypt_hash_password
        ph = scrypt_hash_password(password)

        try:
            user_id = _db.create_user(
                username=username,
                role=role,
                password_hash=ph.derived_key,
                password_salt=ph.salt,
                scrypt_n=ph.n,
                scrypt_r=ph.r,
                scrypt_p=ph.p,
                public_key_pem=pub_key_pem if pub_key_pem else None,
            )
        except Exception as exc:
            return build_response(False, {}, error="Registration failed (username taken?).")

        _audit.log_event(user_id, ACTION_REGISTER,
                         {"username": username, "role": role}, self.client_ip)
        return build_response(True, {"user_id": user_id})

    def _handle_login(self, envelope: dict) -> dict:
        p = envelope["payload"]
        username = str(p.get("username", ""))[:64]
        password = str(p.get("password", ""))
        totp_code = p.get("totp_code")

        try:
            user, token = authenticate_user(
                _db, username, password, totp_code, self.client_ip
            )
        except AccountLockedError as exc:
            _audit.log_event("SYSTEM", ACTION_LOGIN_LOCKED,
                             {"username": username}, self.client_ip)
            return build_response(False, {}, error=str(exc))
        except (InvalidCredentialsError, AuthError) as exc:
            _audit.log_event("SYSTEM", ACTION_LOGIN_FAILED,
                             {"username": username}, self.client_ip)
            return build_response(False, {}, error=str(exc))

        _audit.log_event(user.user_id, ACTION_LOGIN_OK,
                         {"username": username}, self.client_ip)
        return build_response(True, {"token": token, "role": user.role,
                                     "user_id": user.user_id})

    def _handle_logout(self, envelope: dict) -> None:
        token = envelope.get("token")
        if token:
            try:
                user_id, _ = verify_token(token)
                _replay.reset_session(user_id)
                _audit.log_event(user_id, ACTION_LOGOUT, {}, self.client_ip)
            except InvalidTokenError:
                pass
        try:
            send_message(self.ssl_sock, build_response(True, {}))
        except OSError:
            pass

    def _handle_upload(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "upload")
        p = envelope["payload"]

        filename = str(p.get("filename", "unknown"))[:255]
        ciphertext = b64decode(p["ciphertext"])
        nonce = b64decode(p["nonce"])
        aad_str = str(p["aad"])
        signature = b64decode(p["signature"])
        wrapped_key_self = b64decode(p["wrapped_key_self"])

        # Verify signature: covers ciphertext || nonce || aad_bytes
        user = _db.get_user_by_id(user_id)
        if not user or not user.public_key_pem:
            return build_response(False, {}, error="No public key on file for uploader.")

        pub_key = load_public_key(user.public_key_pem.encode())
        signed_data = ciphertext + nonce + aad_str.encode("utf-8")
        if not rsa_pss_verify(signed_data, signature, pub_key):
            return build_response(False, {}, error="Signature verification failed.")

        file_id = _db.store_file(
            filename=filename,
            ciphertext=ciphertext,
            nonce=nonce,
            aad=aad_str,
            signature=signature,
            uploader_id=user_id,
        )
        _db.store_wrapped_key(file_id, user_id, wrapped_key_self, user_id)

        # Store institutional key escrow copy if provided
        wrapped_key_escrow_b64 = p.get("wrapped_key_escrow")
        if wrapped_key_escrow_b64:
            try:
                wrapped_key_escrow = b64decode(wrapped_key_escrow_b64)
                escrow_id = _db.ensure_escrow_user()
                _db.store_wrapped_key(file_id, escrow_id, wrapped_key_escrow, user_id)
            except Exception:
                pass

        _audit.log_event(user_id, ACTION_UPLOAD,
                         {"file_id": file_id, "filename": filename}, self.client_ip)
        return build_response(True, {"file_id": file_id})

    def _handle_download(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "download")
        p = envelope["payload"]
        file_id = str(p.get("file_id", ""))

        # Patient role: can only access own files
        file_rec = _db.get_file(file_id)
        if not file_rec:
            return build_response(False, {}, error="File not found.")

        if role == "patient" and file_rec.uploader_id != user_id:
            if not _db.has_access(file_id, user_id):
                return build_response(False, {}, error="Access denied.")

        wrapped_key = _db.get_wrapped_key(file_id, user_id)
        if wrapped_key is None:
            return build_response(False, {}, error="Access denied.")

        _audit.log_event(user_id, ACTION_DOWNLOAD,
                         {"file_id": file_id}, self.client_ip)
        return build_response(True, {
            "file_id":     file_id,
            "filename":    file_rec.filename,
            "ciphertext":  b64encode(file_rec.ciphertext),
            "nonce":       b64encode(file_rec.nonce),
            "aad":         file_rec.aad,
            "signature":   b64encode(file_rec.signature),
            "wrapped_key": b64encode(wrapped_key),
            "uploader_id": file_rec.uploader_id,
        })

    def _handle_list_files(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "list")
        files = _db.list_files_for_user(user_id)
        _audit.log_event(user_id, ACTION_LIST_FILES, {}, self.client_ip)
        return build_response(True, {"files": files})

    def _handle_share_file(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "share")
        p = envelope["payload"]
        file_id = str(p.get("file_id", ""))
        recipient_username = str(p.get("recipient_username", ""))
        wrapped_key_for_recipient = b64decode(p["wrapped_key_for_recipient"])

        if not _db.has_access(file_id, user_id):
            return build_response(False, {}, error="You do not have access to this file.")

        recipient = _db.get_user_by_username(recipient_username)
        if not recipient:
            return build_response(False, {}, error="Recipient not found.")

        _db.store_wrapped_key(file_id, recipient.user_id,
                              wrapped_key_for_recipient, user_id)
        _audit.log_event(user_id, ACTION_SHARE,
                         {"file_id": file_id, "recipient": recipient_username},
                         self.client_ip)
        return build_response(True, {})

    def _handle_revoke_access(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "revoke")
        p = envelope["payload"]
        file_id = str(p.get("file_id", ""))
        target_username = str(p.get("target_username", ""))

        target = _db.get_user_by_username(target_username)
        if not target:
            return build_response(False, {}, error="Target user not found.")

        removed = _db.revoke_access(file_id, target.user_id)
        _audit.log_event(user_id, ACTION_REVOKE,
                         {"file_id": file_id, "target": target_username},
                         self.client_ip)
        return build_response(True, {"revoked": removed})

    def _handle_list_users(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "list_users")
        users = _db.list_users()
        _audit.log_event(user_id, ACTION_ADMIN_LIST_USERS, {}, self.client_ip)
        result = [
            {"user_id": u.user_id, "username": u.username,
             "role": u.role, "created_at": u.created_at}
            for u in users
        ]
        return build_response(True, {"users": result})

    def _handle_get_audit_log(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "audit_log")
        limit = int(envelope["payload"].get("limit", 50))
        limit = min(limit, 500)
        events = _audit.get_recent_events(limit)
        _audit.log_event(user_id, ACTION_ADMIN_GET_LOG,
                         {"limit": limit}, self.client_ip)
        return build_response(True, {"events": events})

    def _handle_verify_audit_log(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "audit_log")
        ok, errors = _audit.verify_audit_log()
        return build_response(True, {"valid": ok, "errors": errors})

    def _handle_checkpoint_audit_log(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "audit_log")
        cp = _audit.create_checkpoint()
        return build_response(True, {"checkpoint": cp})

    def _handle_manage_user(self, envelope: dict) -> dict:
        user_id, role = self._require_auth(envelope)
        check_permission(role, "manage_users")
        p = envelope["payload"]
        op = str(p.get("operation", ""))
        target_username = str(p.get("target_username", ""))

        target = _db.get_user_by_username(target_username)
        if not target:
            return build_response(False, {}, error="User not found.")

        if op == "delete":
            _db.delete_user(target.user_id)
            return build_response(True, {"deleted": target_username})
        elif op == "unlock":
            _db.reset_failed_attempts(target.user_id)
            return build_response(True, {"unlocked": target_username})
        else:
            return build_response(False, {}, error=f"Unknown operation '{op}'.")

    def _handle_break_glass(self, envelope: dict) -> dict:
        """
        Emergency access: allows a doctor to access any file.
        WHY: In a real emergency, a doctor may need to access a patient's
        records even without prior sharing. This is permitted but creates
        a highly visible audit trail.
        """
        user_id, role = self._require_auth(envelope)
        check_permission(role, "break_glass")
        p = envelope["payload"]
        file_id = str(p.get("file_id", ""))
        reason = str(p.get("reason", ""))[:500]

        file_rec = _db.get_file(file_id)
        if not file_rec:
            return build_response(False, {}, error="File not found.")

        # Log BEFORE granting access — the log entry must exist even if
        # the subsequent operations fail
        _audit.log_event(user_id, ACTION_BREAK_GLASS,
                         {"file_id": file_id, "reason": reason,
                          "ALERT": "EMERGENCY_ACCESS_GRANTED"},
                         self.client_ip)

        # Find any existing wrapped key to return (uploader's copy)
        uploader_key = _db.get_wrapped_key(file_id, file_rec.uploader_id)
        if uploader_key is None:
            return build_response(False, {}, error="No key available for break-glass.")

        # Check if requesting user already has a wrapped key
        existing = _db.get_wrapped_key(file_id, user_id)
        final_wrapped_key = existing

        if not final_wrapped_key:
            # Institutional Key Escrow: unwrap using Escrow Private Key and re-wrap for the accessor
            try:
                from client.keystore import load_escrow_private_key
                escrow_id = _db.ensure_escrow_user()
                escrow_wrapped = _db.get_wrapped_key(file_id, escrow_id)
                escrow_priv = load_escrow_private_key()
                accessor_user = _db.get_user_by_id(user_id)

                if escrow_wrapped and escrow_priv and accessor_user and accessor_user.public_key_pem:
                    aes_key = rsa_oaep_unwrap(escrow_wrapped, escrow_priv)
                    accessor_pub = load_public_key(accessor_user.public_key_pem.encode())
                    re_wrapped = rsa_oaep_wrap(aes_key, accessor_pub)
                    _db.store_wrapped_key(file_id, user_id, re_wrapped, granted_by="ESCROW_BREAK_GLASS")
                    final_wrapped_key = re_wrapped
            except Exception:
                pass

        if not final_wrapped_key:
            # Fallback to uploader's copy if escrow key was not configured
            final_wrapped_key = uploader_key

        return build_response(True, {
            "file_id":     file_id,
            "filename":    file_rec.filename,
            "ciphertext":  b64encode(file_rec.ciphertext),
            "nonce":       b64encode(file_rec.nonce),
            "aad":         file_rec.aad,
            "signature":   b64encode(file_rec.signature),
            "wrapped_key": b64encode(final_wrapped_key),
            "uploader_id": file_rec.uploader_id,
            "break_glass": True,
        })


# ---------------------------------------------------------------------------
# Server class
# ---------------------------------------------------------------------------

class HealthcareServer(socketserver.ThreadingTCPServer):
    """
    Threaded TCP server with mutual TLS.

    WHY ThreadingTCPServer (not asyncio):
        The cryptography operations (scrypt, RSA) are CPU-bound and release
        the GIL. Threads are simpler to reason about for a course project
        and avoid the complexity of async-safe database access.
    """
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        host: str = SERVER_HOST,
        port: int = SERVER_PORT,
        db_path: str | None = None,
        ssl_password: bytes | None = None,
    ) -> None:
        global _db, _audit, _replay
        _db = Database(db_path)
        _audit = AuditLog(_db)
        _replay = ReplayGuard()

        # Ensure institutional key escrow exists
        try:
            from client.keystore import ensure_escrow_keys
            _, escrow_pub = ensure_escrow_keys()
            _db.ensure_escrow_user(public_key_pem=serialize_public_key(escrow_pub).decode())
        except Exception:
            pass

        if ssl_password is not None:
            self.ssl_context = build_ssl_context_with_password(ssl_password)
        else:
            self.ssl_context = _build_ssl_context()
        super().__init__((host, port), ClientHandler)
        print(f"[Server] Listening on {host}:{port} (mutual TLS)")

    def get_request(self):
        """Accept a raw TCP connection; SSL wrapping happens in ClientHandler.setup()."""
        return super().get_request()


def _build_ssl_context() -> ssl.SSLContext:
    """
    Build a mutual-TLS SSLContext for the server.

    WHY PROTOCOL_TLS_SERVER + minimum TLS 1.2:
        ssl.PROTOCOL_TLS_SERVER enables the server side of TLS negotiation.
        Setting minimum_version to TLSv1_2 rejects SSLv3, TLS 1.0, and TLS 1.1
        which have known vulnerabilities (POODLE, BEAST, CRIME).
        TLS 1.3 is preferred when both sides support it.

    WHY CERT_REQUIRED:
        This enforces mutual TLS — the server will reject any client that
        does not present a certificate signed by our CA. This is the
        network-layer authentication layer.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(CERTS_DIR / "ca.crt"))
    ctx.load_cert_chain(
        certfile=str(CERTS_DIR / "server.crt"),
        keyfile=str(CERTS_DIR / "server.key"),
        password=_get_server_key_password(),
    )
    return ctx


def _get_server_key_password() -> bytes | None:
    """
    Return the server key password from environment variable.
    WHY environment variable: never hardcode secrets in source code.
    Falls back to None (unencrypted key) if env var is not set.
    """
    pw = os.environ.get("SERVER_KEY_PASSWORD", "")
    return pw.encode() if pw else None


def build_ssl_context_with_password(password: bytes | None = None) -> ssl.SSLContext:
    """Build SSL context with an explicit password (used by tests)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(CERTS_DIR / "ca.crt"))
    ctx.load_cert_chain(
        certfile=str(CERTS_DIR / "server.crt"),
        keyfile=str(CERTS_DIR / "server.key"),
        password=password,
    )
    return ctx


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Start the healthcare server."""
    import argparse
    parser = argparse.ArgumentParser(description="Healthcare Secure Share Server")
    parser.add_argument("--host", default=SERVER_HOST)
    parser.add_argument("--port", type=int, default=SERVER_PORT)
    parser.add_argument("--db", default=None, help="SQLite DB path (default: server/healthcare.db)")
    args = parser.parse_args()

    server = HealthcareServer(args.host, args.port, args.db)
    print("[Server] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
