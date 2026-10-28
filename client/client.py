"""
client.py — CLI client for the Secure Healthcare File-Sharing Protocol.

All cryptographic operations happen CLIENT-SIDE before data is sent:
    - File encryption (AES-256-GCM) with fresh key + nonce
    - Key wrapping (RSA-OAEP) with recipient's public key
    - Signing (RSA-PSS) of ciphertext || nonce || aad

The server NEVER sees plaintext or AES keys.

Usage examples:
    python -m client.client register --username doctor --password "Pass1!" --role doctor
    python -m client.client login    --username doctor --password "Pass1!"
    python -m client.client upload   --username doctor --password "Pass1!" --file report.txt
    python -m client.client download --username doctor --password "Pass1!" --file-id <uuid>
    python -m client.client list     --username doctor --password "Pass1!"
    python -m client.client share    --username doctor --password "Pass1!" --file-id <uuid> --recipient nurse
    python -m client.client revoke   --username doctor --password "Pass1!" --file-id <uuid> --target nurse
    python -m client.client audit    --username admin  --password "Pass1!"
    python -m client.client verify-log --username admin --password "Pass1!"
"""

import argparse
import json
import os
import ssl
import socket
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from common.config import CERTS_DIR, SERVER_HOST, SERVER_PORT
from common.crypto_utils import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    load_public_key,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
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
from client.keystore import (
    PrivateKeySession,
    get_public_key_pem,
    load_user_public_key,
    public_key_exists,
)


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def _connect(username: str, cert_password: bytes | None = None) -> ssl.SSLSocket:
    """
    Open a mutual-TLS connection to the server.

    Args:
        username:      Used to select the client certificate (client_<username>.crt).
        cert_password: Password for the client TLS key (from SERVER_KEY_PASSWORD env).

    Returns:
        Connected SSLSocket.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(str(CERTS_DIR / "ca.crt"))

    safe = "".join(c for c in username if c.isalnum() or c in "-_")
    cert_file = CERTS_DIR / f"client_{safe}.crt"
    key_file = CERTS_DIR / f"client_{safe}.key"

    if not cert_file.exists():
        # Fall back to a generic client cert if per-user cert not found
        cert_file = CERTS_DIR / "client_doctor.crt"
        key_file = CERTS_DIR / "client_doctor.key"

    pw = os.environ.get("CLIENT_KEY_PASSWORD", "")
    ctx.load_cert_chain(
        certfile=str(cert_file),
        keyfile=str(key_file),
        password=pw.encode() if pw else None,
    )

    raw_sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=30)
    ssl_sock = ctx.wrap_socket(raw_sock, server_hostname="localhost")
    return ssl_sock


# ---------------------------------------------------------------------------
# Session state (counter increments per request)
# ---------------------------------------------------------------------------

class _Session:
    def __init__(self) -> None:
        self.token: str | None = None
        self.counter: int = 0

    def next_counter(self) -> int:
        self.counter += 1
        return self.counter

    def send_recv(self, sock: ssl.SSLSocket, action: str, payload: dict) -> dict:
        """Send a request and return the unwrapped response data dict."""
        req = build_request(action, payload, self.next_counter(), self.token)
        send_message(sock, req)
        resp = recv_message(sock)
        return unwrap_response(resp)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_register(args: argparse.Namespace) -> None:
    """Register a new user account."""
    pub_key_pem = ""
    if public_key_exists(args.username):
        pub_key_pem = get_public_key_pem(args.username).decode()

    sess = _Session()
    with _connect(args.username) as sock:
        data = sess.send_recv(sock, "register", {
            "username": args.username,
            "password": args.password,
            "role": args.role,
            "public_key_pem": pub_key_pem,
        })
    print(f"[OK] Registered. user_id={data.get('user_id')}")


def cmd_login(args: argparse.Namespace) -> str:
    """Login and return the session token."""
    sess = _Session()
    payload = {"username": args.username, "password": args.password}
    if hasattr(args, "totp") and args.totp:
        payload["totp_code"] = args.totp

    with _connect(args.username) as sock:
        data = sess.send_recv(sock, "login", payload)

    token = data["token"]
    print(f"[OK] Logged in as {args.username} (role={data.get('role')})")
    print(f"     Token: {token[:40]}...")
    return token


def cmd_upload(args: argparse.Namespace) -> None:
    """Encrypt a file client-side and upload the ciphertext."""
    file_path = Path(args.file)
    if not file_path.exists():
        print(f"[ERROR] File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    plaintext = file_path.read_bytes()

    # Load private key for signing
    key_session = PrivateKeySession()
    key_session.load(args.username, args.password.encode())
    private_key = key_session.get()

    # Build AAD: binds metadata to the ciphertext
    # (file_id unknown yet, use filename + timestamp as proxy)
    aad_dict = {
        "sender_id": args.username,
        "filename": file_path.name,
        "timestamp": time.time(),
    }
    aad_bytes = json.dumps(aad_dict, separators=(",", ":")).encode("utf-8")

    # Encrypt
    enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)

    # Sign: ciphertext || nonce || aad
    signed_data = enc.ciphertext + enc.nonce + aad_bytes
    signature = rsa_pss_sign(signed_data, private_key)

    # Wrap AES key for self
    pub_key = private_key.public_key()
    wrapped_key_self = rsa_oaep_wrap(aes_key, pub_key)

    # Login first
    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]

        # Institutional key escrow wrapping
        upload_payload = {
            "filename":        file_path.name,
            "ciphertext":      b64encode(enc.ciphertext),
            "nonce":           b64encode(enc.nonce),
            "aad":             aad_bytes.decode("utf-8"),
            "signature":       b64encode(signature),
            "wrapped_key_self": b64encode(wrapped_key_self),
        }
        try:
            from client.keystore import load_escrow_public_key
            escrow_pub = load_escrow_public_key()
            if escrow_pub:
                wrapped_key_escrow = rsa_oaep_wrap(aes_key, escrow_pub)
                upload_payload["wrapped_key_escrow"] = b64encode(wrapped_key_escrow)
        except Exception:
            pass

        data = sess.send_recv(sock, "upload", upload_payload)

    key_session.clear()
    print(f"[OK] Uploaded '{file_path.name}' -> file_id={data.get('file_id')}")


def cmd_download(args: argparse.Namespace) -> None:
    """Download and decrypt a file."""
    key_session = PrivateKeySession()
    key_session.load(args.username, args.password.encode())
    private_key = key_session.get()

    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]

        data = sess.send_recv(sock, "download", {"file_id": args.file_id})

    ciphertext = b64decode(data["ciphertext"])
    nonce = b64decode(data["nonce"])
    aad_str = data["aad"]
    signature = b64decode(data["signature"])
    wrapped_key = b64decode(data["wrapped_key"])
    uploader_id = data.get("uploader_id", "")

    # Verify signature using uploader's public key
    aad_bytes = aad_str.encode("utf-8")
    signed_data = ciphertext + nonce + aad_bytes

    # Try to load uploader's public key from local keystore
    uploader_username = uploader_id  # In demo, user_id == username for simplicity
    sig_ok = False
    try:
        uploader_pub = load_user_public_key(uploader_username)
        from common.crypto_utils import rsa_pss_verify
        sig_ok = rsa_pss_verify(signed_data, signature, uploader_pub)
    except FileNotFoundError:
        print(f"[WARN] Cannot verify signature: no public key for uploader '{uploader_username}'")
        sig_ok = None  # Unknown

    if sig_ok is False:
        print("[ERROR] Signature verification FAILED — file may be tampered!", file=sys.stderr)
        sys.exit(1)
    elif sig_ok:
        print("[OK] Signature verified.")

    # Unwrap AES key
    aes_key = rsa_oaep_unwrap(wrapped_key, private_key)

    # Decrypt
    enc = EncryptedFile(ciphertext=ciphertext, nonce=nonce, aad=aad_bytes)
    plaintext = aes_gcm_decrypt(enc, aes_key)

    # Save output
    out_path = Path(args.output) if hasattr(args, "output") and args.output else Path(data["filename"])
    out_path.write_bytes(plaintext)
    key_session.clear()
    print(f"[OK] Decrypted '{data['filename']}' -> {out_path}")


def cmd_list(args: argparse.Namespace) -> None:
    """List files accessible to the user."""
    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]
        data = sess.send_recv(sock, "list_files", {})

    files = data.get("files", [])
    if not files:
        print("No files accessible.")
        return
    print(f"{'file_id':<38} {'filename':<30} {'uploader':<20} uploaded_at")
    print("-" * 100)
    for f in files:
        ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(f["uploaded_at"]))
        print(f"{f['file_id']:<38} {f['filename']:<30} {f['uploader_id']:<20} {ts}")


def cmd_share(args: argparse.Namespace) -> None:
    """Share a file with another user by re-wrapping the AES key."""
    # Download the wrapped key for self, unwrap it, re-wrap for recipient
    key_session = PrivateKeySession()
    key_session.load(args.username, args.password.encode())
    private_key = key_session.get()

    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]

        # Download to get the wrapped key
        dl_data = sess.send_recv(sock, "download", {"file_id": args.file_id})
        wrapped_key_self = b64decode(dl_data["wrapped_key"])
        aes_key = rsa_oaep_unwrap(wrapped_key_self, private_key)

        # Load recipient's public key
        try:
            recipient_pub = load_user_public_key(args.recipient)
        except FileNotFoundError:
            print(f"[ERROR] No public key found for '{args.recipient}'.", file=sys.stderr)
            sys.exit(1)

        wrapped_for_recipient = rsa_oaep_wrap(aes_key, recipient_pub)

        sess.send_recv(sock, "share_file", {
            "file_id": args.file_id,
            "recipient_username": args.recipient,
            "wrapped_key_for_recipient": b64encode(wrapped_for_recipient),
        })

    key_session.clear()
    print(f"[OK] Shared file {args.file_id} with '{args.recipient}'.")


def cmd_revoke(args: argparse.Namespace) -> None:
    """Revoke a user's access to a file."""
    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]
        data = sess.send_recv(sock, "revoke_access", {
            "file_id": args.file_id,
            "target_username": args.target,
        })
    print(f"[OK] Revoked access. removed={data.get('revoked')}")


def cmd_audit(args: argparse.Namespace) -> None:
    """Fetch and display the audit log (admin only)."""
    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]
        data = sess.send_recv(sock, "get_audit_log", {"limit": 50})

    events = data.get("events", [])
    print(f"{'#':<5} {'timestamp':<22} {'actor':<38} {'action':<25} details")
    print("-" * 120)
    for e in reversed(events):
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["timestamp"]))
        print(f"{e['entry_id']:<5} {ts:<22} {e['actor_id']:<38} {e['action']:<25} {e['details'][:60]}")


def cmd_verify_log(args: argparse.Namespace) -> None:
    """Verify the audit log chain integrity (admin only)."""
    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]
        data = sess.send_recv(sock, "verify_audit_log", {})

    if data.get("valid"):
        print("[OK] Audit log chain is VALID — no tampering detected.")
    else:
        print("[FAIL] Audit log chain is INVALID — TAMPERING DETECTED!")
        for err in data.get("errors", []):
            print(f"  {err}")


def cmd_break_glass(args: argparse.Namespace) -> None:
    """Request emergency break-glass access to a file (doctor role)."""
    key_session = PrivateKeySession()
    key_session.load(args.username, args.password.encode())
    private_key = key_session.get()

    sess = _Session()
    with _connect(args.username) as sock:
        login_data = sess.send_recv(sock, "login", {
            "username": args.username,
            "password": args.password,
        })
        sess.token = login_data["token"]

        data = sess.send_recv(sock, "break_glass", {
            "file_id": args.file_id,
            "reason": args.reason,
        })

    ciphertext = b64decode(data["ciphertext"])
    nonce = b64decode(data["nonce"])
    aad_str = data["aad"]
    wrapped_key = b64decode(data["wrapped_key"])

    # Unwrap AES key using the requesting doctor's OWN private key (via Key Escrow re-wrap)
    try:
        aes_key = rsa_oaep_unwrap(wrapped_key, private_key)
    except Exception as e:
        print(f"[FAIL] Could not unwrap key with private key: {e}", file=sys.stderr)
        sys.exit(1)

    enc = EncryptedFile(ciphertext=ciphertext, nonce=nonce, aad=aad_str.encode("utf-8"))
    plaintext = aes_gcm_decrypt(enc, aes_key)
    key_session.clear()

    out_path = Path(args.output) if args.output else Path(f"EMERGENCY_{data.get('filename', 'recovered.bin')}")
    out_path.write_bytes(plaintext)
    print(f"[EMERGENCY ACCESS GRANTED] Decrypted {len(plaintext)} bytes -> {out_path}")


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Healthcare Secure Share CLI Client"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def _add_auth(p: argparse.ArgumentParser) -> None:
        p.add_argument("--username", required=True)
        p.add_argument("--password", required=True)

    # register
    p_reg = sub.add_parser("register")
    _add_auth(p_reg)
    p_reg.add_argument("--role", required=True, choices=["doctor","nurse","patient","admin"])

    # login
    p_login = sub.add_parser("login")
    _add_auth(p_login)
    p_login.add_argument("--totp", default=None)

    # upload
    p_up = sub.add_parser("upload")
    _add_auth(p_up)
    p_up.add_argument("--file", required=True)

    # download
    p_dl = sub.add_parser("download")
    _add_auth(p_dl)
    p_dl.add_argument("--file-id", required=True)
    p_dl.add_argument("--output", default=None)

    # list
    p_ls = sub.add_parser("list")
    _add_auth(p_ls)

    # share
    p_sh = sub.add_parser("share")
    _add_auth(p_sh)
    p_sh.add_argument("--file-id", required=True)
    p_sh.add_argument("--recipient", required=True)

    # revoke
    p_rv = sub.add_parser("revoke")
    _add_auth(p_rv)
    p_rv.add_argument("--file-id", required=True)
    p_rv.add_argument("--target", required=True)

    # audit
    p_au = sub.add_parser("audit")
    _add_auth(p_au)

    # verify-log
    p_vl = sub.add_parser("verify-log")
    _add_auth(p_vl)

    # break-glass
    p_bg = sub.add_parser("break-glass")
    _add_auth(p_bg)
    p_bg.add_argument("--file-id", required=True, help="File ID to emergency access")
    p_bg.add_argument("--reason", required=True, help="Clinical emergency justification")
    p_bg.add_argument("--output", default=None, help="Output path for decrypted file")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    commands = {
        "register":    cmd_register,
        "login":       cmd_login,
        "upload":      cmd_upload,
        "download":    cmd_download,
        "list":        cmd_list,
        "share":       cmd_share,
        "revoke":      cmd_revoke,
        "audit":       cmd_audit,
        "verify-log":  cmd_verify_log,
        "break-glass": cmd_break_glass,
    }

    try:
        commands[args.command](args)
    except ProtocolError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
