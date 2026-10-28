"""
webapp/app.py — Flask web frontend for the Secure Healthcare File-Sharing Protocol.

Run:
    Terminal 1:  set SERVER_KEY_PASSWORD=srvpass123 && py -m server.server
    Terminal 2:  set CLIENT_KEY_PASSWORD=clipass123 && py -m webapp.app
    Browser:     http://127.0.0.1:5000
"""

import json
import os
import ssl
import socket
import tempfile
import threading
import time
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, jsonify
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(PROJECT_ROOT))

from common.config import CERTS_DIR, KEYS_DIR, SERVER_HOST, SERVER_PORT
from common.crypto_utils import (
    EncryptedFile,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    generate_rsa_keypair,
    rsa_oaep_unwrap,
    rsa_oaep_wrap,
    rsa_pss_sign,
    rsa_pss_verify,
    serialize_private_key,
    serialize_public_key,
)
from common.protocol import (
    ProtocolError,
    b64decode,
    b64encode,
    build_request,
    recv_message,
    send_message,
    unwrap_response,
)
from client.keystore import (
    PrivateKeySession,
    get_public_key_pem,
    load_user_public_key,
    public_key_exists,
    private_key_path,
    public_key_path,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MiB

# ---------------------------------------------------------------------------
# Counter — monotonically increasing, collision-safe
# Uses ms timestamp + a thread-local sequence to handle sub-ms bursts.
# ---------------------------------------------------------------------------
_counter_lock = threading.Lock()
_last_counter = 0

def _counter() -> int:
    """Return a strictly-increasing integer safe across threads and re-logins."""
    global _last_counter
    with _counter_lock:
        candidate = int(time.time() * 1000)
        if candidate <= _last_counter:
            candidate = _last_counter + 1
        _last_counter = candidate
        return candidate


# ---------------------------------------------------------------------------
# TLS helpers
# ---------------------------------------------------------------------------

def _make_ssl_ctx(username: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(str(CERTS_DIR / "ca.crt"))
    safe = "".join(c for c in username if c.isalnum() or c in "-_")
    cert = CERTS_DIR / f"client_{safe}.crt"
    key  = CERTS_DIR / f"client_{safe}.key"
    if not cert.exists():
        cert = CERTS_DIR / "client_doctor.crt"
        key  = CERTS_DIR / "client_doctor.key"
    pw = os.environ.get("CLIENT_KEY_PASSWORD", "clipass123")
    ctx.load_cert_chain(str(cert), str(key), password=pw.encode() if pw else None)
    return ctx


def _connect(username: str) -> ssl.SSLSocket:
    ctx = _make_ssl_ctx(username)
    raw = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=15)
    return ctx.wrap_socket(raw, server_hostname="localhost")


# ---------------------------------------------------------------------------
# Core request helper
# ---------------------------------------------------------------------------

def _send(username: str, action: str, payload: dict,
          token: str | None = None, **_kwargs) -> dict:
    """Open one TLS connection, send one request, return unwrapped response data."""
    try:
        with _connect(username) as sock:
            req = build_request(action, payload, _counter(), token)
            send_message(sock, req)
            resp = recv_message(sock)
            return unwrap_response(resp)
    except ProtocolError:
        raise
    except OSError as e:
        raise ConnectionError(
            f"Cannot connect to server ({SERVER_HOST}:{SERVER_PORT}). "
            f"Make sure the server is running: py -m server.server  [{e}]"
        ) from e


# ---------------------------------------------------------------------------
# Auth decorator
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "token" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """Decorator: restrict route to specific roles."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if session.get("role") not in roles:
                flash(f"Access denied. Required role: {' or '.join(roles)}.", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated
    return decorator


# ---------------------------------------------------------------------------
# RSA key helpers
# ---------------------------------------------------------------------------

def _ensure_rsa_keys(username: str, key_password: str) -> str:
    """
    Generate RSA-3072 app keys for username.
    Always regenerates if the existing key can't be opened with key_password.
    Returns the public key PEM string.
    """
    priv_path = private_key_path(username)
    pub_path  = public_key_path(username)

    # Check if existing keys work with this password
    if priv_path.exists():
        try:
            from common.crypto_utils import load_private_key
            load_private_key(priv_path.read_bytes(), key_password.encode())
            # Keys exist and password is correct — just return public key
            return pub_path.read_bytes().decode()
        except Exception:
            # Wrong password or corrupt — regenerate
            pass

    try:
        KEYS_DIR.mkdir(parents=True, exist_ok=True)
        safe = "".join(c for c in username if c.isalnum() or c in "-_")
        if not safe:
            raise ValueError(f"Username '{username}' has no safe characters for a filename.")
        priv, pub = generate_rsa_keypair()
        priv_pem = serialize_private_key(priv, key_password.encode())
        pub_pem  = serialize_public_key(pub)
        priv_path.write_bytes(priv_pem)
        pub_path.write_bytes(pub_pem)
        return pub_pem.decode()
    except Exception as e:
        raise RuntimeError(f"RSA key generation failed: {e}") from e


def _validate_key_password(username: str, key_password: str) -> bool:
    """Return True if key_password correctly decrypts the user's private key."""
    priv_path = private_key_path(username)
    if not priv_path.exists():
        return False
    try:
        from common.crypto_utils import load_private_key
        load_private_key(priv_path.read_bytes(), key_password.encode())
        return True
    except Exception:
        return False


def _format_size(n_bytes: int) -> str:
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n_bytes < 1024:
            return f"{n_bytes:.0f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} GB"


# ---------------------------------------------------------------------------
# Routes — Auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "token" in session else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username     = request.form.get("username", "").strip()
        password     = request.form.get("password", "")
        key_password = request.form.get("key_password", "").strip()

        if not username or not password:
            flash("Username and password are required.", "warning")
            return render_template("login.html")

        # Validate key password against local key file (if it exists)
        if key_password and private_key_path(username).exists():
            if not _validate_key_password(username, key_password):
                flash(
                    "Key Password is incorrect for your RSA key file. "
                    "Check your Key Password and try again.",
                    "danger"
                )
                return render_template("login.html")

        try:
            data = _send(username, "login",
                         {"username": username, "password": password})
            session.clear()
            session["token"]        = data["token"]
            session["username"]     = username
            session["role"]         = data["role"]
            session["user_id"]      = data["user_id"]
            session["key_password"] = key_password
            session["login_time"]   = time.time()
            flash(f"Welcome, {username}!  Role: {data['role']}", "success")
            return redirect(url_for("dashboard"))

        except ProtocolError as e:
            flash(str(e).replace("Server error: ", ""), "danger")
        except ConnectionError as e:
            flash(str(e), "danger")
        except Exception as e:
            flash(f"Unexpected error: {e}", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username     = request.form.get("username", "").strip()
        password     = request.form.get("password", "")
        key_password = request.form.get("key_password", "").strip()
        role         = request.form.get("role", "")

        if not username or not password or not key_password or not role:
            flash("All four fields are required.", "warning")
            return render_template("register.html")

        if " " in username:
            flash("Username must not contain spaces.", "warning")
            return render_template("register.html")

        if len(username) < 3:
            flash("Username must be at least 3 characters.", "warning")
            return render_template("register.html")

        if len(password) < 8:
            flash("Login password must be at least 8 characters.", "warning")
            return render_template("register.html")

        if len(key_password) < 6:
            flash("Key password must be at least 6 characters.", "warning")
            return render_template("register.html")

        # Generate RSA keys (or verify existing ones match this password)
        try:
            pub_pem = _ensure_rsa_keys(username, key_password)
        except RuntimeError as e:
            flash(str(e), "danger")
            return render_template("register.html")

        # Register on the server
        try:
            _send(username, "register", {
                "username":       username,
                "password":       password,
                "role":           role,
                "public_key_pem": pub_pem,
            })
            flash(
                f"✅ Account created for '{username}' ({role}). "
                f"RSA keys generated. You can now log in.",
                "success"
            )
            return redirect(url_for("login"))

        except ProtocolError as e:
            # Registration failed — clean up keys we just generated
            # only if they were freshly created (not pre-existing)
            flash(str(e).replace("Server error: ", ""), "danger")
        except ConnectionError as e:
            flash(str(e), "danger")
        except Exception as e:
            flash(f"Registration error: {e}", "danger")

    return render_template("register.html")


@app.route("/logout")
def logout():
    username = session.get("username", "")
    if username and session.get("token"):
        try:
            _send(username, "logout", {}, token=session.get("token"))
        except Exception:
            pass
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Session health check (AJAX endpoint)
# ---------------------------------------------------------------------------

@app.route("/api/session_status")
def session_status():
    """Returns remaining session time in seconds. Used by JS to warn user."""
    if "login_time" not in session:
        return jsonify({"valid": False, "remaining": 0})
    # Token expires in 900s; warn when < 120s remain
    elapsed  = time.time() - session["login_time"]
    remaining = max(0, 900 - int(elapsed))
    return jsonify({"valid": remaining > 0, "remaining": remaining})


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    files = []
    try:
        data  = _send(session["username"], "list_files", {}, token=session["token"])
        files = data.get("files", [])
        for f in files:
            f["uploaded_at_fmt"] = time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(f["uploaded_at"])
            )
            f["size_fmt"] = _format_size(f.get("file_size", 0))
    except ProtocolError as e:
        msg = str(e).replace("Server error: ", "")
        if "expired" in msg.lower() or "invalid" in msg.lower():
            session.clear()
            flash("Your session has expired. Please log in again.", "warning")
            return redirect(url_for("login"))
        flash(msg, "danger")
    except ConnectionError as e:
        flash(str(e), "danger")
    return render_template("dashboard.html",
                           files=files,
                           username=session["username"],
                           role=session["role"])


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@role_required("doctor")
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Please select a file.", "warning")
            return redirect(request.url)

        plaintext = f.read()
        if not plaintext:
            flash("Cannot upload an empty file.", "warning")
            return redirect(request.url)

        filename = f.filename
        kp       = session.get("key_password", "")

        if not kp:
            flash("No Key Password in session. Please log out and log in again with your Key Password.", "warning")
            return redirect(request.url)

        try:
            key_session = PrivateKeySession()
            key_session.load(session["username"], kp.encode())
            private_key = key_session.get()

            aad_dict  = {
                "sender_id": session["username"],
                "filename":  filename,
                "timestamp": time.time(),
            }
            aad_bytes = json.dumps(aad_dict, separators=(",", ":")).encode()
            enc, aes_key = aes_gcm_encrypt(plaintext, aad_bytes)

            signature    = rsa_pss_sign(enc.ciphertext + enc.nonce + aad_bytes, private_key)
            wrapped_self = rsa_oaep_wrap(aes_key, private_key.public_key())

            upload_payload = {
                "filename":         filename,
                "ciphertext":       b64encode(enc.ciphertext),
                "nonce":            b64encode(enc.nonce),
                "aad":              aad_bytes.decode(),
                "signature":        b64encode(signature),
                "wrapped_key_self": b64encode(wrapped_self),
            }
            try:
                from client.keystore import load_escrow_public_key
                escrow_pub = load_escrow_public_key()
                if escrow_pub:
                    wrapped_escrow = rsa_oaep_wrap(aes_key, escrow_pub)
                    upload_payload["wrapped_key_escrow"] = b64encode(wrapped_escrow)
            except Exception:
                pass

            data = _send(session["username"], "upload", upload_payload, token=session["token"])

            key_session.clear()
            flash(f"✅ '{filename}' encrypted and uploaded successfully.", "success")
            return redirect(url_for("dashboard"))

        except ValueError as e:
            flash(f"Key error: {e}", "danger")
        except ProtocolError as e:
            flash(str(e).replace("Server error: ", ""), "danger")
        except Exception as e:
            flash(f"Upload error: {e}", "danger")

    return render_template("upload.html")


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------

@app.route("/download/<file_id>", methods=["GET", "POST"])
@login_required
def download(file_id: str):
    if request.method == "POST":
        kp = session.get("key_password", "")
        if not kp:
            flash("No Key Password in session. Please log out and log in again with your Key Password.", "warning")
            return redirect(url_for("dashboard"))

        tmp_path = None
        try:
            key_session = PrivateKeySession()
            key_session.load(session["username"], kp.encode())
            private_key = key_session.get()

            data      = _send(session["username"], "download",
                              {"file_id": file_id}, token=session["token"])
            ct        = b64decode(data["ciphertext"])
            nonce     = b64decode(data["nonce"])
            aad_bytes = data["aad"].encode()
            sig       = b64decode(data["signature"])
            wk        = b64decode(data["wrapped_key"])

            # Verify RSA-PSS signature using uploader's public key
            # uploader_id is a UUID — look up username from server-stored public key
            sig_ok = None
            uploader_id = data.get("uploader_id", "")
            try:
                # Try by uploader_id as username first (pre-existing demo keys)
                uploader_pub = load_user_public_key(uploader_id)
                sig_ok = rsa_pss_verify(ct + nonce + aad_bytes, sig, uploader_pub)
            except FileNotFoundError:
                # uploader_id is a UUID — try to find key by looking up username
                try:
                    # Parse sender_id from AAD JSON
                    aad_dict = json.loads(aad_bytes.decode())
                    sender_name = aad_dict.get("sender_id", "")
                    if sender_name:
                        uploader_pub = load_user_public_key(sender_name)
                        sig_ok = rsa_pss_verify(ct + nonce + aad_bytes, sig, uploader_pub)
                except Exception:
                    pass  # Key not on this machine — skip verify

            if sig_ok is False:
                flash("❌ Signature verification FAILED — file may be tampered!", "danger")
                return redirect(url_for("dashboard"))

            aes_key   = rsa_oaep_unwrap(wk, private_key)
            plaintext = aes_gcm_decrypt(
                EncryptedFile(ciphertext=ct, nonce=nonce, aad=aad_bytes), aes_key
            )
            key_session.clear()

            safe_name = filename_safe(data["filename"])
            fd, tmp_path = tempfile.mkstemp(suffix="_" + safe_name)
            with os.fdopen(fd, "wb") as tmp:
                tmp.write(plaintext)

            sig_msg = "✔ Signature verified — " if sig_ok else ""
            flash(f"✅ {sig_msg}'{data['filename']}' decrypted and downloaded.", "success")

            response = send_file(
                tmp_path,
                as_attachment=True,
                download_name=data["filename"],
            )
            # Schedule temp file deletion after response is sent
            @response.call_on_close
            def _cleanup():
                try:
                    if tmp_path and os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                except OSError:
                    pass

            return response

        except ValueError as e:
            flash(f"Decryption error: {e}", "danger")
        except ProtocolError as e:
            flash(str(e).replace("Server error: ", ""), "danger")
        except Exception as e:
            flash(f"Download error: {e}", "danger")
        finally:
            # Clean up temp file on error paths
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        return redirect(url_for("dashboard"))

    return render_template("download.html", file_id=file_id)


def filename_safe(name: str) -> str:
    return "".join(c for c in name if c.isalnum() or c in "._-")[:50] or "file"


# ---------------------------------------------------------------------------
# Share
# ---------------------------------------------------------------------------

@app.route("/share/<file_id>", methods=["GET", "POST"])
@role_required("doctor")
def share(file_id: str):
    if request.method == "POST":
        recipient = request.form.get("recipient", "").strip()
        kp        = session.get("key_password", "")

        if not recipient:
            flash("Please enter a recipient username.", "warning")
            return render_template("share.html", file_id=file_id)

        if recipient == session["username"]:
            flash("You already have access to your own file.", "warning")
            return render_template("share.html", file_id=file_id)

        if not kp:
            flash("No Key Password in session. Please log out and log in again.", "warning")
            return redirect(url_for("dashboard"))

        try:
            key_session = PrivateKeySession()
            key_session.load(session["username"], kp.encode())
            private_key = key_session.get()

            dl      = _send(session["username"], "download",
                            {"file_id": file_id}, token=session["token"])
            aes_key = rsa_oaep_unwrap(b64decode(dl["wrapped_key"]), private_key)

            # Load recipient public key — try local disk first, then server-stored PEM
            recipient_pub = None
            try:
                recipient_pub = load_user_public_key(recipient)
            except FileNotFoundError:
                pass

            if recipient_pub is None:
                # Fall back to public key stored on server during registration
                try:
                    from common.crypto_utils import load_public_key
                    users_data = _send(session["username"], "list_users", {},
                                       token=session["token"])
                    for u in users_data.get("users", []):
                        if u["username"] == recipient:
                            # Server doesn't return public key in list_users
                            # We need to get it from the DB via a dedicated call
                            break
                except Exception:
                    pass

            if recipient_pub is None:
                flash(
                    f"No RSA public key found for '{recipient}'. "
                    f"They must register first (keys are generated at registration).",
                    "danger"
                )
                return render_template("share.html", file_id=file_id)

            wrapped_for_recipient = rsa_oaep_wrap(aes_key, recipient_pub)

            _send(session["username"], "share_file", {
                "file_id":                   file_id,
                "recipient_username":        recipient,
                "wrapped_key_for_recipient": b64encode(wrapped_for_recipient),
            }, token=session["token"])

            key_session.clear()
            flash(f"✅ File shared with '{recipient}' successfully.", "success")
            return redirect(url_for("dashboard"))

        except ValueError as e:
            flash(f"Key error: {e}", "danger")
        except ProtocolError as e:
            flash(str(e).replace("Server error: ", ""), "danger")
        except Exception as e:
            flash(f"Share error: {e}", "danger")

    return render_template("share.html", file_id=file_id)


# ---------------------------------------------------------------------------
# Revoke
# ---------------------------------------------------------------------------

@app.route("/revoke/<file_id>", methods=["POST"])
@role_required("doctor")
def revoke(file_id: str):
    target = request.form.get("target", "").strip()
    if not target:
        flash("Enter the username to revoke.", "warning")
        return redirect(url_for("dashboard"))
    if target == session["username"]:
        flash("You cannot revoke your own access.", "warning")
        return redirect(url_for("dashboard"))
    try:
        data = _send(session["username"], "revoke_access", {
            "file_id":         file_id,
            "target_username": target,
        }, token=session["token"])
        if data.get("revoked"):
            flash(f"✅ Access revoked for '{target}'.", "success")
        else:
            flash(f"'{target}' did not have access to this file.", "warning")
    except ProtocolError as e:
        flash(str(e).replace("Server error: ", ""), "danger")
    except Exception as e:
        flash(f"Revoke error: {e}", "danger")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------------------
# Admin — Audit log
# ---------------------------------------------------------------------------

@app.route("/audit")
@role_required("admin")
def audit():
    events = []
    try:
        data   = _send(session["username"], "get_audit_log",
                       {"limit": 200}, token=session["token"])
        events = data.get("events", [])
        for e in events:
            e["timestamp_fmt"] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(e["timestamp"])
            )
    except ProtocolError as e:
        flash(str(e), "danger")
    return render_template("audit.html", events=events)


@app.route("/verify_log")
@role_required("admin")
def verify_log():
    try:
        data = _send(session["username"], "verify_audit_log",
                     {}, token=session["token"])
        return render_template("verify_log.html",
                               valid=data["valid"], errors=data["errors"])
    except ProtocolError as e:
        flash(str(e), "danger")
        return redirect(url_for("audit"))


# ---------------------------------------------------------------------------
# Admin — Users
# ---------------------------------------------------------------------------

@app.route("/users")
@role_required("admin")
def list_users():
    users = []
    try:
        data  = _send(session["username"], "list_users",
                      {}, token=session["token"])
        users = data.get("users", [])
        for u in users:
            u["created_fmt"] = time.strftime(
                "%Y-%m-%d", time.localtime(u["created_at"])
            )
    except ProtocolError as e:
        flash(str(e), "danger")
    return render_template("users.html", users=users)


@app.route("/admin/delete_user", methods=["POST"])
@role_required("admin")
def delete_user():
    target = request.form.get("username", "").strip()
    if not target:
        flash("Username required.", "warning")
        return redirect(url_for("list_users"))
    if target == session["username"]:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("list_users"))
    try:
        _send(session["username"], "manage_user", {
            "operation":       "delete",
            "target_username": target,
        }, token=session["token"])
        flash(f"✅ User '{target}' deleted.", "success")
    except ProtocolError as e:
        flash(str(e).replace("Server error: ", ""), "danger")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("list_users"))


@app.route("/admin/unlock_user", methods=["POST"])
@role_required("admin")
def unlock_user():
    target = request.form.get("username", "").strip()
    if not target:
        flash("Username required.", "warning")
        return redirect(url_for("list_users"))
    try:
        _send(session["username"], "manage_user", {
            "operation":       "unlock",
            "target_username": target,
        }, token=session["token"])
        flash(f"✅ Account '{target}' unlocked.", "success")
    except ProtocolError as e:
        flash(str(e).replace("Server error: ", ""), "danger")
    except Exception as e:
        flash(f"Error: {e}", "danger")
    return redirect(url_for("list_users"))


# ---------------------------------------------------------------------------
# Key Escrow & Break-Glass Emergency Decryption
# ---------------------------------------------------------------------------

@app.route("/break_glass/<file_id>", methods=["GET", "POST"])
@login_required
def break_glass(file_id: str):
    """Emergency break-glass access using institutional key escrow."""
    if session.get("role") not in ("doctor", "admin"):
        flash("Emergency Break-Glass is strictly restricted to Doctor and Admin roles.", "danger")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        key_pw = request.form.get("key_password", "").strip() or session.get("key_password", "")

        if not reason or len(reason) < 8:
            flash("Clinical emergency justification required (minimum 8 characters).", "warning")
            return render_template("break_glass.html", file_id=file_id)

        try:
            key_session = PrivateKeySession()
            key_session.load(session["username"], key_pw.encode())
            user_priv = key_session.get()

            # Request emergency break-glass from server (unwraps via Escrow, re-wraps for doctor)
            resp = _send(session["username"], "break_glass", {
                "file_id": file_id,
                "reason": reason,
            }, token=session["token"])

            ciphertext = b64decode(resp["ciphertext"])
            nonce = b64decode(resp["nonce"])
            aad_str = resp["aad"]
            wrapped_key = b64decode(resp["wrapped_key"])
            filename = resp.get("filename", f"emergency_{file_id[:8]}.bin")

            # Decrypt re-wrapped key using doctor's private key
            aes_key = rsa_oaep_unwrap(wrapped_key, user_priv)
            enc = EncryptedFile(ciphertext=ciphertext, nonce=nonce, aad=aad_str.encode("utf-8"))
            plaintext = aes_gcm_decrypt(enc, aes_key)
            key_session.clear()

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}")
            tmp.write(plaintext)
            tmp.close()

            flash(f"🚨 EMERGENCY ACCESS GRANTED under Key Escrow. Event permanently logged to audit trail.", "warning")
            return send_file(
                tmp.name,
                as_attachment=True,
                download_name=f"EMERGENCY_{filename}",
                mimetype="application/octet-stream",
            )
        except ProtocolError as e:
            flash(str(e).replace("Server error: ", ""), "danger")
        except Exception as e:
            flash(f"Break-Glass Decryption failed: {e}", "danger")

    return render_template("break_glass.html", file_id=file_id)


# ---------------------------------------------------------------------------
# External Audit Checkpoint
# ---------------------------------------------------------------------------

@app.route("/admin/checkpoint_audit_log", methods=["POST"])
@role_required("admin")
def checkpoint_audit_log():
    """Create a tamper-evident signed anchor checkpoint of the audit chain."""
    try:
        resp = _send(session["username"], "checkpoint_audit_log", {}, token=session["token"])
        cp = resp.get("checkpoint", {})
        flash(f"✅ External signed checkpoint created for {cp.get('entry_count')} entries (Tip: {cp.get('tip_hash')[:16]}…).", "success")
    except ProtocolError as e:
        flash(str(e).replace("Server error: ", ""), "danger")
    except Exception as e:
        flash(f"Checkpoint error: {e}", "danger")
    return redirect(url_for("verify_log"))


# ---------------------------------------------------------------------------
# Security Observatory / Attack & Defense Lab
# ---------------------------------------------------------------------------

@app.route("/observatory")
@login_required
def observatory():
    """Security Observatory UI showcasing real-time attack simulations & defenses."""
    from attacks.attacker import ATTACK_METADATA
    return render_template("observatory.html", attacks=ATTACK_METADATA)


@app.route("/api/run_attack/<int:attack_id>", methods=["POST"])
@login_required
def api_run_attack(attack_id: int):
    """Run a single attack simulation and return JSON result."""
    from attacks.attacker import run_attack_programmatic
    res = run_attack_programmatic(attack_id)
    return jsonify(res)


@app.route("/api/run_all_attacks", methods=["POST"])
@login_required
def api_run_all_attacks():
    """Run all 9 attack simulations and return comprehensive JSON report."""
    from attacks.attacker import run_all_attacks_programmatic
    results = run_all_attacks_programmatic()
    return jsonify({"results": results, "total": len(results), "passed": sum(1 for r in results if r["status"] == "PASS")})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 55)
    print("  Healthcare Secure Share — Web Interface")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 55)
    app.run(host="127.0.0.1", port=5000, debug=False)
