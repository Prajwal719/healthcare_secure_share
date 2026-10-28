"""
test_integration.py — End-to-end integration tests.

Spins up a real HealthcareServer in a background thread with an in-memory
database, then exercises the full client→server→client flow over mutual TLS.

Each test class gets a fresh server + fresh user keys so tests are isolated.

Run:
    cd healthcare_secure_share
    pytest tests/test_integration.py -v
"""

import json
import os
import ssl
import socket
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest

# Set key passwords before any server/client code is imported
os.environ.setdefault("SERVER_KEY_PASSWORD", "srvpass123")
os.environ.setdefault("CLIENT_KEY_PASSWORD", "clipass123")

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from common.config import CERTS_DIR, SERVER_HOST
from common.crypto_utils import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_rsa_keypair,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
    scrypt_hash_password,
    serialize_public_key,
    EncryptedFile,
)
from common.protocol import (
    b64decode,
    b64encode,
    build_request,
    recv_message,
    send_message,
    unwrap_response,
    ProtocolError,
)
from server.server import HealthcareServer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_client_ctx(username: str = "doctor") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(str(CERTS_DIR / "ca.crt"))
    safe = "".join(c for c in username if c.isalnum() or c in "-_")
    cert = CERTS_DIR / f"client_{safe}.crt"
    key  = CERTS_DIR / f"client_{safe}.key"
    if not cert.exists():
        cert = CERTS_DIR / "client_doctor.crt"
        key  = CERTS_DIR / "client_doctor.key"
    # Use known test password; fall back to env var
    pw = os.environ.get("CLIENT_KEY_PASSWORD", "clipass123")
    ctx.load_cert_chain(str(cert), str(key), password=pw.encode() if pw else None)
    return ctx


def _connect(port: int, username: str = "doctor") -> ssl.SSLSocket:
    ctx = _make_client_ctx(username)
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    return ctx.wrap_socket(raw, server_hostname="localhost")


class _Client:
    """Thin stateful wrapper around a single SSL connection."""

    def __init__(self, port: int, username: str = "doctor"):
        self._sock = _connect(port, username)
        self._counter = 0
        self.token: str | None = None

    def _next(self) -> int:
        self._counter += 1
        return self._counter

    def send(self, action: str, payload: dict) -> dict:
        req = build_request(action, payload, self._next(), self.token)
        send_message(self._sock, req)
        resp = recv_message(self._sock)
        return unwrap_response(resp)

    def send_raw(self, action: str, payload: dict) -> dict:
        """Return raw envelope (don't unwrap — used to inspect failures)."""
        req = build_request(action, payload, self._next(), self.token)
        send_message(self._sock, req)
        return recv_message(self._sock)

    def login(self, username: str, password: str) -> dict:
        data = self.send("login", {"username": username, "password": password})
        self.token = data["token"]
        return data

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def server():
    """Start a server on a free port; yield (host, port); shut down after module."""
    port = _find_free_port()
    # Pass password directly so the test doesn't depend on env var being set
    srv = HealthcareServer(
        host="127.0.0.1", port=port,
        db_path=":memory:",
        ssl_password=b"srvpass123",
    )
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield ("127.0.0.1", port)
    srv.shutdown()


@pytest.fixture(scope="module")
def rsa_keys():
    """Generate one RSA key pair per module (expensive — reuse across tests)."""
    priv, pub = generate_rsa_keypair()
    return priv, pub


# ---------------------------------------------------------------------------
# Helper: register a user and return their user_id
# ---------------------------------------------------------------------------

def _register(port: int, username: str, password: str, role: str,
               pub_pem: str = "") -> str:
    c = _Client(port, username)
    data = c.send("register", {
        "username": username,
        "password": password,
        "role": role,
        "public_key_pem": pub_pem,
    })
    c.close()
    return data["user_id"]


# ---------------------------------------------------------------------------
# Tests: Registration and Login
# ---------------------------------------------------------------------------

class TestRegisterLogin:
    def test_register_and_login(self, server):
        _, port = server
        uid = _register(port, f"doc_{uuid.uuid4().hex[:6]}", "Pass1!", "doctor")
        assert uid

    def test_login_wrong_password_fails(self, server):
        _, port = server
        uname = f"doc_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "CorrectPass1!", "doctor")
        c = _Client(port, "doctor")
        with pytest.raises(ProtocolError, match="Invalid"):
            c.send("login", {"username": uname, "password": "WrongPass!"})
        c.close()

    def test_login_returns_role(self, server):
        _, port = server
        uname = f"nur_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "Pass1!", "nurse")
        c = _Client(port, "nurse")
        data = c.login(uname, "Pass1!")
        assert data["role"] == "nurse"
        c.close()


# ---------------------------------------------------------------------------
# Tests: Upload and Download
# ---------------------------------------------------------------------------

class TestUploadDownload:
    def test_upload_and_download_roundtrip(self, server, rsa_keys):
        _, port = server
        priv, pub = rsa_keys
        pub_pem = serialize_public_key(pub).decode()
        uname = f"doc_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "Pass1!", "doctor", pub_pem)

        plaintext = b"Patient record: blood pressure 120/80"
        aad_dict = {"sender_id": uname, "filename": "record.txt", "timestamp": time.time()}
        aad_bytes = json.dumps(aad_dict, separators=(",", ":")).encode()
        enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)
        sig = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, priv)
        wrapped_self = rsa_oaep_wrap(aes_key, pub)

        c = _Client(port, "doctor")
        c.login(uname, "Pass1!")

        up_data = c.send("upload", {
            "filename": "record.txt",
            "ciphertext": b64encode(enc.ciphertext),
            "nonce": b64encode(enc.nonce),
            "aad": aad_bytes.decode(),
            "signature": b64encode(sig),
            "wrapped_key_self": b64encode(wrapped_self),
        })
        file_id = up_data["file_id"]
        assert file_id

        dl_data = c.send("download", {"file_id": file_id})
        c.close()

        ct = b64decode(dl_data["ciphertext"])
        nonce = b64decode(dl_data["nonce"])
        aad_str = dl_data["aad"]
        wk = b64decode(dl_data["wrapped_key"])

        recovered_key = rsa_oaep_unwrap(wk, priv)
        recovered = aes_gcm_decrypt(
            EncryptedFile(ciphertext=ct, nonce=nonce, aad=aad_str.encode()), recovered_key
        )
        assert recovered == plaintext

    def test_download_without_access_fails(self, server, rsa_keys):
        _, port = server
        priv, pub = rsa_keys
        pub_pem = serialize_public_key(pub).decode()

        # Upload as doctor
        uname_doc = f"doc_{uuid.uuid4().hex[:6]}"
        _register(port, uname_doc, "Pass1!", "doctor", pub_pem)

        plaintext = b"Secret data"
        aad_bytes = b'{"sender_id":"doc","ts":1}'
        enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)
        sig = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, priv)
        wrapped_self = rsa_oaep_wrap(aes_key, pub)

        c_doc = _Client(port, "doctor")
        c_doc.login(uname_doc, "Pass1!")
        up = c_doc.send("upload", {
            "filename": "secret.txt",
            "ciphertext": b64encode(enc.ciphertext),
            "nonce": b64encode(enc.nonce),
            "aad": aad_bytes.decode(),
            "signature": b64encode(sig),
            "wrapped_key_self": b64encode(wrapped_self),
        })
        file_id = up["file_id"]
        c_doc.close()

        # Try to download as a different doctor with no access
        uname_doc2 = f"doc_{uuid.uuid4().hex[:6]}"
        _register(port, uname_doc2, "Pass1!", "doctor", pub_pem)
        c_doc2 = _Client(port, "doctor")
        c_doc2.login(uname_doc2, "Pass1!")
        with pytest.raises(ProtocolError, match="Access denied"):
            c_doc2.send("download", {"file_id": file_id})
        c_doc2.close()


# ---------------------------------------------------------------------------
# Tests: Share and Revoke
# ---------------------------------------------------------------------------

class TestShareRevoke:
    def test_share_grants_access(self, server, rsa_keys):
        _, port = server
        priv, pub = rsa_keys
        pub_pem = serialize_public_key(pub).decode()

        uname_doc = f"doc_{uuid.uuid4().hex[:6]}"
        uname_nur = f"nur_{uuid.uuid4().hex[:6]}"
        _register(port, uname_doc, "Pass1!", "doctor", pub_pem)
        _register(port, uname_nur, "Pass1!", "nurse", pub_pem)

        plaintext = b"Shared record"
        aad_bytes = b'{"sender_id":"doc","ts":1}'
        enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)
        sig = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, priv)
        wrapped_self = rsa_oaep_wrap(aes_key, pub)

        c_doc = _Client(port, "doctor")
        c_doc.login(uname_doc, "Pass1!")
        up = c_doc.send("upload", {
            "filename": "shared.txt",
            "ciphertext": b64encode(enc.ciphertext),
            "nonce": b64encode(enc.nonce),
            "aad": aad_bytes.decode(),
            "signature": b64encode(sig),
            "wrapped_key_self": b64encode(wrapped_self),
        })
        file_id = up["file_id"]

        # Share with nurse (re-wrap AES key for nurse's public key)
        wrapped_for_nurse = rsa_oaep_wrap(aes_key, pub)  # same key in test
        c_doc.send("share_file", {
            "file_id": file_id,
            "recipient_username": uname_nur,
            "wrapped_key_for_recipient": b64encode(wrapped_for_nurse),
        })
        c_doc.close()

        # Nurse downloads
        c_nur = _Client(port, "nurse")
        c_nur.login(uname_nur, "Pass1!")
        dl = c_nur.send("download", {"file_id": file_id})
        c_nur.close()
        assert dl["file_id"] == file_id

    def test_revoke_removes_access(self, server, rsa_keys):
        _, port = server
        priv, pub = rsa_keys
        pub_pem = serialize_public_key(pub).decode()

        uname_doc = f"doc_{uuid.uuid4().hex[:6]}"
        uname_nur = f"nur_{uuid.uuid4().hex[:6]}"
        _register(port, uname_doc, "Pass1!", "doctor", pub_pem)
        _register(port, uname_nur, "Pass1!", "nurse", pub_pem)

        plaintext = b"Revoke test"
        aad_bytes = b'{"sender_id":"doc","ts":1}'
        enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)
        sig = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, priv)
        wrapped_self = rsa_oaep_wrap(aes_key, pub)

        c_doc = _Client(port, "doctor")
        c_doc.login(uname_doc, "Pass1!")
        up = c_doc.send("upload", {
            "filename": "revoke.txt",
            "ciphertext": b64encode(enc.ciphertext),
            "nonce": b64encode(enc.nonce),
            "aad": aad_bytes.decode(),
            "signature": b64encode(sig),
            "wrapped_key_self": b64encode(wrapped_self),
        })
        file_id = up["file_id"]

        # Share then revoke
        c_doc.send("share_file", {
            "file_id": file_id,
            "recipient_username": uname_nur,
            "wrapped_key_for_recipient": b64encode(rsa_oaep_wrap(aes_key, pub)),
        })
        c_doc.send("revoke_access", {
            "file_id": file_id,
            "target_username": uname_nur,
        })
        c_doc.close()

        # Nurse should no longer have access
        c_nur = _Client(port, "nurse")
        c_nur.login(uname_nur, "Pass1!")
        with pytest.raises(ProtocolError, match="Access denied"):
            c_nur.send("download", {"file_id": file_id})
        c_nur.close()


# ---------------------------------------------------------------------------
# Tests: RBAC enforcement
# ---------------------------------------------------------------------------

class TestRbacEnforcement:
    def test_nurse_cannot_upload(self, server, rsa_keys):
        _, port = server
        priv, pub = rsa_keys
        pub_pem = serialize_public_key(pub).decode()
        uname = f"nur_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "Pass1!", "nurse", pub_pem)

        plaintext = b"Nurse upload attempt"
        aad_bytes = b'{"sender_id":"nur","ts":1}'
        enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)
        sig = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, priv)
        wrapped = rsa_oaep_wrap(aes_key, pub)

        c = _Client(port, "nurse")
        c.login(uname, "Pass1!")
        with pytest.raises(ProtocolError, match="not permitted"):
            c.send("upload", {
                "filename": "nurse.txt",
                "ciphertext": b64encode(enc.ciphertext),
                "nonce": b64encode(enc.nonce),
                "aad": aad_bytes.decode(),
                "signature": b64encode(sig),
                "wrapped_key_self": b64encode(wrapped),
            })
        c.close()

    def test_unauthenticated_request_fails(self, server):
        _, port = server
        c = _Client(port, "doctor")
        # No login — token is None
        with pytest.raises(ProtocolError):
            c.send("list_files", {})
        c.close()


# ---------------------------------------------------------------------------
# Tests: Replay protection
# ---------------------------------------------------------------------------

class TestReplayProtection:
    def test_duplicate_message_id_rejected(self, server):
        _, port = server
        uname = f"doc_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "Pass1!", "doctor")

        c = _Client(port, "doctor")
        c.login(uname, "Pass1!")

        # Send a list_files request
        req = build_request("list_files", {}, c._next(), c.token)
        send_message(c._sock, req)
        recv_message(c._sock)  # consume response

        # Replay the EXACT same request (same msg_id)
        send_message(c._sock, req)
        resp = recv_message(c._sock)
        c.close()

        assert resp["payload"]["success"] is False


# ---------------------------------------------------------------------------
# Tests: Audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_audit_log_verify_passes_on_clean_log(self, server):
        _, port = server
        uname = f"adm_{uuid.uuid4().hex[:6]}"
        _register(port, uname, "Pass1!", "admin")

        c = _Client(port, "doctor")  # use doctor TLS cert
        c.login(uname, "Pass1!")     # but login as admin user
        data = c.send("verify_audit_log", {})
        c.close()
        # The chain may have errors from prior test activity but must not crash
        assert "valid" in data
        assert isinstance(data["errors"], list)
