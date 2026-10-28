"""
protocol.py — Length-prefixed JSON message framing for the Secure Healthcare
File-Sharing Protocol.

Wire format (every message, both directions):
┌──────────────────────────────────────────┐
│  4 bytes  │  N bytes                     │
│  length   │  UTF-8 JSON envelope         │
│  (BE u32) │                              │
└──────────────────────────────────────────┘

WHY LENGTH-PREFIXED FRAMING:
    TCP is a stream protocol — it provides no message boundaries. Without
    explicit framing, a receiver cannot know where one message ends and the
    next begins. Two common alternatives are:
      • Delimiter-based (e.g., newline): breaks when the payload contains
        the delimiter, requires escaping, and is harder to size-limit.
      • Length-prefix: the receiver reads exactly N bytes — no ambiguity,
        no escaping, and trivially enforceable message-size limits.
    We use a 4-byte big-endian unsigned integer prefix (supports up to 4 GiB),
    capped at MAX_MESSAGE_SIZE_BYTES (64 MiB) to prevent memory exhaustion.

WHY JSON (not a binary format like protobuf):
    • Readability for academic inspection and debugging.
    • No schema compilation step.
    • The `cryptography` library outputs bytes; we base64-encode binary fields
      so they travel safely inside JSON strings.
    This is a deliberate trade-off: binary formats are faster/smaller, but
    transparency is more valuable in a course project.

Message envelope fields (every request/response includes all of these):
    action    : str  — command name ("upload", "download", "login", ...)
    msg_id    : str  — UUID v4, unique per message (replay detection)
    timestamp : float— Unix epoch seconds (replay time-window check)
    counter   : int  — per-session monotonically increasing integer (replay)
    token     : str | None — HMAC-signed session token (None for login/register)
    payload   : dict — action-specific fields (may contain base64 binary)
"""

import base64
import json
import socket
import struct
import time
import uuid
from typing import Any

from common.config import FRAME_LENGTH_PREFIX_BYTES, MAX_MESSAGE_SIZE_BYTES

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Raised when a received message violates the framing or schema rules."""


class MessageTooLargeError(ProtocolError):
    """Raised when the declared message length exceeds the server's safety cap."""


# ---------------------------------------------------------------------------
# Known actions — validated on receipt so typos surface immediately
# ---------------------------------------------------------------------------

VALID_ACTIONS: frozenset[str] = frozenset(
    {
        # Authentication
        "register",
        "login",
        "logout",
        # File operations
        "upload",
        "download",
        "list_files",
        "share_file",
        "revoke_access",
        # Admin
        "list_users",
        "get_audit_log",
        "verify_audit_log",
        "manage_user",
        # Emergency
        "break_glass",
        # Generic server response
        "response",
        # Attack-simulation probes (used by attacker.py only)
        "ping",
    }
)

# Fields that must be present in every envelope
_REQUIRED_ENVELOPE_FIELDS: tuple[str, ...] = (
    "action",
    "msg_id",
    "timestamp",
    "counter",
    "payload",
)

# ---------------------------------------------------------------------------
# Binary ↔ JSON helpers
# ---------------------------------------------------------------------------


def b64encode(data: bytes) -> str:
    """
    Base64-encode *data* for safe embedding in a JSON string.

    WHY standard (not URL-safe) base64:
        Standard base64 is more commonly understood and the '+' / '/'
        characters are harmless inside a JSON string value (they are not
        JSON metacharacters).
    """
    return base64.b64encode(data).decode("ascii")


def b64decode(s: str) -> bytes:
    """
    Decode a base64 string back to bytes.

    Args:
        s: ASCII base64 string (as embedded in a JSON envelope).

    Returns:
        Original bytes.

    Raises:
        ProtocolError: If the string is not valid base64.
    """
    try:
        return base64.b64decode(s)
    except Exception as exc:
        raise ProtocolError(f"Invalid base64 field: {exc}") from exc


# ---------------------------------------------------------------------------
# Low-level send / receive
# ---------------------------------------------------------------------------


def _send_raw(sock: socket.socket, data: bytes) -> None:
    """
    Send all bytes over *sock*, blocking until complete.

    Uses sendall() to handle partial sends that can occur when the kernel
    buffer is full — a single send() call is NOT guaranteed to transmit all
    bytes over a TCP socket.

    Args:
        sock: A connected TCP socket (may be an ssl.SSLSocket).
        data: Raw bytes to transmit.

    Raises:
        OSError: On socket errors.
    """
    sock.sendall(data)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """
    Receive exactly *n* bytes from *sock*, blocking until all arrive.

    WHY NOT a single recv(n):
        recv() may return fewer bytes than requested (short reads are normal
        on TCP — the OS delivers whatever is in the buffer). We must loop
        until we have the exact count.

    Args:
        sock: A connected TCP socket.
        n:    Number of bytes to read.

    Returns:
        Exactly n bytes.

    Raises:
        ProtocolError: If the connection closes before n bytes arrive.
        OSError:       On socket-level errors.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError(
                f"Connection closed after {len(buf)} bytes (expected {n})."
            )
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Message send / receive
# ---------------------------------------------------------------------------


def send_message(sock: socket.socket, envelope: dict[str, Any]) -> None:
    """
    Serialise *envelope* to JSON and transmit it with a 4-byte length prefix.

    Args:
        sock:     A connected TCP (or SSL) socket.
        envelope: A dict conforming to the message envelope schema. Use
                  build_request() or build_response() to construct it.

    Raises:
        MessageTooLargeError: If the serialised message exceeds MAX_MESSAGE_SIZE_BYTES.
        OSError:              On transmission failure.
    """
    payload_bytes: bytes = json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    if len(payload_bytes) > MAX_MESSAGE_SIZE_BYTES:
        raise MessageTooLargeError(
            f"Outgoing message {len(payload_bytes)} bytes exceeds "
            f"limit {MAX_MESSAGE_SIZE_BYTES} bytes."
        )

    # 4-byte big-endian unsigned int length prefix
    prefix: bytes = struct.pack(">I", len(payload_bytes))
    _send_raw(sock, prefix + payload_bytes)


def recv_message(sock: socket.socket) -> dict[str, Any]:
    """
    Receive one length-prefixed message from *sock* and parse it.

    Performs full schema validation on the envelope so that malformed or
    oversized messages are rejected before any business logic sees them.

    Args:
        sock: A connected TCP (or SSL) socket.

    Returns:
        Parsed envelope dict.

    Raises:
        MessageTooLargeError: If the declared length exceeds MAX_MESSAGE_SIZE_BYTES.
        ProtocolError:        On framing errors, JSON parse failures, or
                              schema validation failures.
        OSError:              On socket-level errors.
    """
    # Step 1: read 4-byte length prefix
    prefix_bytes: bytes = _recv_exact(sock, FRAME_LENGTH_PREFIX_BYTES)
    (declared_length,) = struct.unpack(">I", prefix_bytes)

    # Step 2: enforce size cap BEFORE allocating the receive buffer
    # This prevents a malicious peer from causing OOM by sending length=0xFFFFFFFF
    if declared_length > MAX_MESSAGE_SIZE_BYTES:
        raise MessageTooLargeError(
            f"Peer declared message length {declared_length} bytes, "
            f"exceeds limit {MAX_MESSAGE_SIZE_BYTES} bytes."
        )
    if declared_length == 0:
        raise ProtocolError("Zero-length message is not allowed.")

    # Step 3: receive exactly the declared number of bytes
    raw_json: bytes = _recv_exact(sock, declared_length)

    # Step 4: parse JSON
    try:
        envelope: dict[str, Any] = json.loads(raw_json.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProtocolError(f"JSON parse error: {exc}") from exc

    if not isinstance(envelope, dict):
        raise ProtocolError("Envelope must be a JSON object.")

    # Step 5: validate required fields
    _validate_envelope(envelope)

    return envelope


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


def _validate_envelope(env: dict[str, Any]) -> None:
    """
    Validate that *env* contains all required fields with correct types.

    Called by recv_message() — every received message is checked before
    being handed to business logic. This prevents crashes from missing keys
    and makes injection of unexpected field types harder.

    Args:
        env: Parsed envelope dict.

    Raises:
        ProtocolError: On any validation failure.
    """
    # Required field presence
    for field in _REQUIRED_ENVELOPE_FIELDS:
        if field not in env:
            raise ProtocolError(f"Missing required envelope field: '{field}'.")

    action = env["action"]
    if not isinstance(action, str) or action not in VALID_ACTIONS:
        raise ProtocolError(
            f"Invalid action '{action}'. Must be one of {sorted(VALID_ACTIONS)}."
        )

    msg_id = env["msg_id"]
    if not isinstance(msg_id, str) or len(msg_id) > 128:
        raise ProtocolError("'msg_id' must be a non-empty string (max 128 chars).")

    timestamp = env["timestamp"]
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        raise ProtocolError("'timestamp' must be a positive number.")

    counter = env["counter"]
    if not isinstance(counter, int) or counter < 0:
        raise ProtocolError("'counter' must be a non-negative integer.")

    payload = env["payload"]
    if not isinstance(payload, dict):
        raise ProtocolError("'payload' must be a JSON object.")

    # 'token' is optional (absent for login/register), but if present must be str
    if "token" in env and env["token"] is not None:
        if not isinstance(env["token"], str):
            raise ProtocolError("'token' must be a string or null.")


# ---------------------------------------------------------------------------
# Envelope constructors
# ---------------------------------------------------------------------------


def build_request(
    action: str,
    payload: dict[str, Any],
    counter: int,
    token: str | None = None,
) -> dict[str, Any]:
    """
    Construct a fully-formed request envelope ready to pass to send_message().

    Generates a fresh UUID v4 message ID and the current Unix timestamp
    automatically — callers must never supply these to avoid reuse errors.

    Args:
        action:  One of the VALID_ACTIONS strings.
        payload: Action-specific data dict. Binary fields must be pre-encoded
                 with b64encode().
        counter: Caller's current session counter value (monotonically increasing).
        token:   HMAC session token string, or None for pre-auth messages.

    Returns:
        Envelope dict ready for send_message().

    Raises:
        ProtocolError: If action is not in VALID_ACTIONS.
    """
    if action not in VALID_ACTIONS:
        raise ProtocolError(f"Unknown action '{action}'.")
    if not isinstance(counter, int) or counter < 0:
        raise ProtocolError("Counter must be a non-negative integer.")

    return {
        "action": action,
        "msg_id": str(uuid.uuid4()),        # UUID4: 122 bits of randomness
        "timestamp": time.time(),           # Unix epoch float
        "counter": counter,
        "token": token,
        "payload": payload,
    }


def build_response(
    success: bool,
    payload: dict[str, Any],
    error: str | None = None,
) -> dict[str, Any]:
    """
    Construct a server response envelope.

    Server responses reuse the "response" action and include a success flag
    and optional error message. The server generates its own msg_id and
    timestamp so each response is also replay-detectable.

    Args:
        success: True if the operation succeeded.
        payload: Response data (e.g., file list, wrapped key, etc.).
        error:   Human-readable error string (only set when success=False).
                 MUST NOT contain key material, stack traces, or internal paths.

    Returns:
        Envelope dict ready for send_message().
    """
    return {
        "action": "response",
        "msg_id": str(uuid.uuid4()),
        "timestamp": time.time(),
        "counter": 0,           # Counter is client→server only; responses use 0
        "token": None,
        "payload": {
            "success": success,
            "error": error,
            "data": payload,
        },
    }


# ---------------------------------------------------------------------------
# Convenience: extract the inner response data or raise
# ---------------------------------------------------------------------------


def unwrap_response(envelope: dict[str, Any]) -> dict[str, Any]:
    """
    Extract the ``data`` dict from a server response, raising on failure.

    Args:
        envelope: A parsed response envelope from recv_message().

    Returns:
        The ``payload.data`` dict on success.

    Raises:
        ProtocolError: If success=False, including the server's error message.
    """
    p = envelope.get("payload", {})
    if not p.get("success", False):
        raise ProtocolError(f"Server error: {p.get('error', 'unknown error')}")
    return p.get("data", {})
