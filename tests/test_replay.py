"""
test_replay.py — pytest suite for common/replay_guard.py and common/protocol.py

Run:
    cd healthcare_secure_share
    python -m pytest tests/test_replay.py -v
"""

import io
import json
import socket
import struct
import threading
import time
import uuid

import pytest

from common.protocol import (
    MessageTooLargeError,
    ProtocolError,
    b64decode,
    b64encode,
    build_request,
    build_response,
    recv_message,
    send_message,
    unwrap_response,
)
from common.replay_guard import (
    DuplicateMessageError,
    NonMonotonicCounterError,
    ReplayGuard,
    StaleTimestampError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fresh_msg_id() -> str:
    """Return a fresh UUID4 string."""
    return str(uuid.uuid4())


def now_ts() -> float:
    """Return the current Unix timestamp."""
    return time.time()


# ---------------------------------------------------------------------------
# ReplayGuard — Timestamp checks
# ---------------------------------------------------------------------------


class TestTimestampCheck:
    def test_fresh_timestamp_accepted(self):
        guard = ReplayGuard()
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "session_a")

    def test_stale_timestamp_rejected(self):
        """Message timestamped 31 seconds ago must be rejected."""
        guard = ReplayGuard()
        stale_ts = time.time() - 31
        with pytest.raises(StaleTimestampError, match="Possible replay"):
            guard.check_and_record(fresh_msg_id(), stale_ts, 1, "session_a")

    def test_future_timestamp_rejected(self):
        """Message timestamped 31 seconds in the future must also be rejected."""
        guard = ReplayGuard()
        future_ts = time.time() + 31
        with pytest.raises(StaleTimestampError, match="Possible replay"):
            guard.check_and_record(fresh_msg_id(), future_ts, 1, "session_a")

    def test_timestamp_at_boundary_accepted(self):
        """A timestamp exactly at the window boundary (29.9 s) must pass."""
        guard = ReplayGuard()
        borderline_ts = time.time() - 29.9
        # Should not raise
        guard.check_and_record(fresh_msg_id(), borderline_ts, 1, "session_a")

    def test_zero_timestamp_raises_value_error(self):
        guard = ReplayGuard()
        with pytest.raises(ValueError, match="positive"):
            guard.check_and_record(fresh_msg_id(), 0, 1, "session_a")

    def test_negative_timestamp_raises_value_error(self):
        guard = ReplayGuard()
        with pytest.raises(ValueError, match="positive"):
            guard.check_and_record(fresh_msg_id(), -100.0, 1, "session_a")


# ---------------------------------------------------------------------------
# ReplayGuard — Message ID uniqueness
# ---------------------------------------------------------------------------


class TestMessageIdUniqueness:
    def test_unique_ids_accepted(self):
        guard = ReplayGuard()
        for i in range(10):
            guard.check_and_record(fresh_msg_id(), now_ts(), i + 1, "session_a")

    def test_duplicate_id_rejected(self):
        """Sending the same UUID twice must trigger DuplicateMessageError."""
        guard = ReplayGuard()
        msg_id = fresh_msg_id()
        guard.check_and_record(msg_id, now_ts(), 1, "session_a")
        with pytest.raises(DuplicateMessageError, match="Replay attack"):
            # Reuse the exact same msg_id with a new counter
            guard.check_and_record(msg_id, now_ts(), 2, "session_a")

    def test_empty_msg_id_raises_value_error(self):
        guard = ReplayGuard()
        with pytest.raises(ValueError, match="non-empty string"):
            guard.check_and_record("", now_ts(), 1, "session_a")

    def test_cache_eviction_does_not_crash(self):
        """
        Filling the cache beyond its limit must evict oldest entries cleanly.
        We use a tiny limit to make the test fast.
        """
        guard = ReplayGuard()
        # Temporarily override the cache size
        from common import config as cfg
        original = cfg.REPLAY_CACHE_MAX_SIZE
        cfg.REPLAY_CACHE_MAX_SIZE = 5
        try:
            for i in range(10):
                guard.check_and_record(fresh_msg_id(), now_ts(), i + 1, "session_a")
            # After eviction the cache should hold at most 5 entries
            assert guard.stats()["seen_ids_count"] <= 5
        finally:
            cfg.REPLAY_CACHE_MAX_SIZE = original


# ---------------------------------------------------------------------------
# ReplayGuard — Monotonic counter
# ---------------------------------------------------------------------------


class TestMonotonicCounter:
    def test_strictly_increasing_counter_accepted(self):
        guard = ReplayGuard()
        for i in range(1, 6):
            guard.check_and_record(fresh_msg_id(), now_ts(), i, "session_a")

    def test_same_counter_rejected(self):
        """Replaying the same counter value (even with a new msg_id) must fail."""
        guard = ReplayGuard()
        guard.check_and_record(fresh_msg_id(), now_ts(), 5, "session_a")
        with pytest.raises(NonMonotonicCounterError):
            guard.check_and_record(fresh_msg_id(), now_ts(), 5, "session_a")

    def test_decreasing_counter_rejected(self):
        guard = ReplayGuard()
        guard.check_and_record(fresh_msg_id(), now_ts(), 10, "session_a")
        with pytest.raises(NonMonotonicCounterError):
            guard.check_and_record(fresh_msg_id(), now_ts(), 9, "session_a")

    def test_counter_zero_rejected_after_first_accepted(self):
        """Counter=0 always fails after any message with counter >= 1 is seen."""
        guard = ReplayGuard()
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "session_a")
        with pytest.raises(NonMonotonicCounterError):
            guard.check_and_record(fresh_msg_id(), now_ts(), 0, "session_a")

    def test_sessions_are_isolated(self):
        """Two different sessions must have independent counters."""
        guard = ReplayGuard()
        # Session A at counter 100
        guard.check_and_record(fresh_msg_id(), now_ts(), 100, "session_a")
        # Session B can start at counter 1 — independent of A
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "session_b")

    def test_reset_session_allows_counter_restart(self):
        """After reset_session(), counter can start from any value again."""
        guard = ReplayGuard()
        guard.check_and_record(fresh_msg_id(), now_ts(), 50, "session_a")
        guard.reset_session("session_a")
        # Now counter 1 should be accepted again
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "session_a")

    def test_negative_counter_raises_value_error(self):
        guard = ReplayGuard()
        with pytest.raises(ValueError, match="non-negative"):
            guard.check_and_record(fresh_msg_id(), now_ts(), -1, "session_a")


# ---------------------------------------------------------------------------
# ReplayGuard — Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_unique_messages_all_accepted(self):
        """
        100 threads each send a unique message concurrently.
        All must succeed — no race conditions or lost writes.
        """
        guard = ReplayGuard()
        errors: list[Exception] = []
        barrier = threading.Barrier(100)

        def worker(thread_idx: int) -> None:
            try:
                barrier.wait()   # all threads start simultaneously
                guard.check_and_record(
                    fresh_msg_id(),
                    now_ts(),
                    thread_idx + 1,
                    f"session_{thread_idx}",   # each thread has its own session
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread errors: {errors}"
        assert guard.stats()["seen_ids_count"] == 100

    def test_duplicate_message_detected_under_concurrent_load(self):
        """
        Two threads try to submit the SAME msg_id simultaneously.
        Exactly one must succeed; the other must raise DuplicateMessageError.
        """
        guard = ReplayGuard()
        shared_id = fresh_msg_id()
        results: list[str] = []
        lock = threading.Lock()

        def worker(counter: int) -> None:
            try:
                guard.check_and_record(shared_id, now_ts(), counter, f"s{counter}")
                with lock:
                    results.append("ok")
            except DuplicateMessageError:
                with lock:
                    results.append("duplicate")

        t1 = threading.Thread(target=worker, args=(1,))
        t2 = threading.Thread(target=worker, args=(2,))
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert results.count("ok") == 1
        assert results.count("duplicate") == 1


# ---------------------------------------------------------------------------
# ReplayGuard — Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_reflect_state(self):
        guard = ReplayGuard()
        assert guard.stats() == {"seen_ids_count": 0, "active_sessions": 0}
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "sess1")
        guard.check_and_record(fresh_msg_id(), now_ts(), 2, "sess1")
        guard.check_and_record(fresh_msg_id(), now_ts(), 1, "sess2")
        s = guard.stats()
        assert s["seen_ids_count"] == 3
        assert s["active_sessions"] == 2


# ---------------------------------------------------------------------------
# Protocol — b64 helpers
# ---------------------------------------------------------------------------


class TestB64Helpers:
    def test_encode_decode_roundtrip(self):
        data = b"\x00\xff\x1a\xfe" * 64
        assert b64decode(b64encode(data)) == data

    def test_invalid_base64_raises_protocol_error(self):
        with pytest.raises(ProtocolError, match="Invalid base64"):
            b64decode("!!!not-valid-base64!!!")


# ---------------------------------------------------------------------------
# Protocol — build_request / build_response
# ---------------------------------------------------------------------------


class TestBuildRequest:
    def test_request_has_all_required_fields(self):
        req = build_request("login", {"username": "alice"}, counter=1)
        for field in ("action", "msg_id", "timestamp", "counter", "payload"):
            assert field in req

    def test_unique_msg_ids_generated(self):
        ids = {build_request("ping", {}, counter=i)["msg_id"] for i in range(50)}
        assert len(ids) == 50

    def test_timestamp_is_recent(self):
        req = build_request("ping", {}, counter=1)
        assert abs(time.time() - req["timestamp"]) < 2

    def test_invalid_action_raises(self):
        with pytest.raises(ProtocolError, match="Unknown action"):
            build_request("hack_the_planet", {}, counter=1)

    def test_token_attached(self):
        req = build_request("upload", {}, counter=1, token="abc.def.ghi")
        assert req["token"] == "abc.def.ghi"


class TestBuildResponse:
    def test_success_response_structure(self):
        resp = build_response(True, {"file_id": "f1"})
        assert resp["action"] == "response"
        assert resp["payload"]["success"] is True
        assert resp["payload"]["data"] == {"file_id": "f1"}
        assert resp["payload"]["error"] is None

    def test_error_response_structure(self):
        resp = build_response(False, {}, error="Access denied")
        assert resp["payload"]["success"] is False
        assert resp["payload"]["error"] == "Access denied"


# ---------------------------------------------------------------------------
# Protocol — unwrap_response
# ---------------------------------------------------------------------------


class TestUnwrapResponse:
    def test_success_returns_data(self):
        resp = build_response(True, {"token": "xyz"})
        data = unwrap_response(resp)
        assert data == {"token": "xyz"}

    def test_failure_raises_protocol_error(self):
        resp = build_response(False, {}, error="Unauthorized")
        with pytest.raises(ProtocolError, match="Unauthorized"):
            unwrap_response(resp)


# ---------------------------------------------------------------------------
# Protocol — send_message / recv_message over a socket pair
# ---------------------------------------------------------------------------


def _make_socket_pair():
    """
    Create a connected pair of sockets using socketpair() (Unix) or a
    loopback TCP connection (Windows fallback).
    """
    try:
        return socket.socketpair()
    except AttributeError:
        # Windows: socketpair is not available before Python 3.12 on all builds
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind(("127.0.0.1", 0))
        server_sock.listen(1)
        port = server_sock.getsockname()[1]
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        conn, _ = server_sock.accept()
        server_sock.close()
        return client_sock, conn


class TestSendRecvMessage:
    def test_roundtrip_simple_message(self):
        s1, s2 = _make_socket_pair()
        try:
            env = build_request("ping", {"hello": "world"}, counter=1)
            send_message(s1, env)
            received = recv_message(s2)
            assert received["action"] == "ping"
            assert received["payload"]["hello"] == "world"
        finally:
            s1.close(); s2.close()

    def test_roundtrip_preserves_binary_payload(self):
        """Binary data base64-encoded in payload survives the round-trip."""
        import os
        s1, s2 = _make_socket_pair()
        try:
            raw_bytes = os.urandom(1024)
            env = build_request("upload", {"data": b64encode(raw_bytes)}, counter=1)
            send_message(s1, env)
            received = recv_message(s2)
            assert b64decode(received["payload"]["data"]) == raw_bytes
        finally:
            s1.close(); s2.close()

    def test_oversized_message_raises_on_send(self):
        s1, s2 = _make_socket_pair()
        try:
            from common.config import MAX_MESSAGE_SIZE_BYTES
            # Build an envelope whose JSON exceeds MAX_MESSAGE_SIZE_BYTES
            huge = build_request("ping", {"blob": "x" * (MAX_MESSAGE_SIZE_BYTES + 1)}, counter=1)
            with pytest.raises(MessageTooLargeError):
                send_message(s1, huge)
        finally:
            s1.close(); s2.close()

    def test_recv_rejects_zero_declared_length(self):
        """Manually send a 0-length prefix — recv_message must raise ProtocolError."""
        s1, s2 = _make_socket_pair()
        try:
            s1.sendall(struct.pack(">I", 0))   # 4-byte prefix declaring 0 bytes
            with pytest.raises(ProtocolError, match="Zero-length"):
                recv_message(s2)
        finally:
            s1.close(); s2.close()

    def test_recv_rejects_truncated_stream(self):
        """Declare N bytes but send fewer — recv_message must raise ProtocolError."""
        s1, s2 = _make_socket_pair()
        try:
            s1.sendall(struct.pack(">I", 1000))   # claim 1000 bytes
            s1.sendall(b"short")                  # but only send 5
            s1.close()                            # force EOF
            with pytest.raises(ProtocolError, match="closed"):
                recv_message(s2)
        finally:
            s2.close()

    def test_recv_rejects_invalid_json(self):
        s1, s2 = _make_socket_pair()
        try:
            bad = b"not json at all!!!"
            s1.sendall(struct.pack(">I", len(bad)) + bad)
            with pytest.raises(ProtocolError, match="JSON parse error"):
                recv_message(s2)
        finally:
            s1.close(); s2.close()

    def test_recv_rejects_missing_required_field(self):
        """An envelope missing 'counter' must be rejected by schema validation."""
        s1, s2 = _make_socket_pair()
        try:
            bad_env = {
                "action": "ping",
                "msg_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                # counter intentionally omitted
                "payload": {},
            }
            raw = json.dumps(bad_env).encode()
            s1.sendall(struct.pack(">I", len(raw)) + raw)
            with pytest.raises(ProtocolError, match="Missing required"):
                recv_message(s2)
        finally:
            s1.close(); s2.close()

    def test_recv_rejects_unknown_action(self):
        s1, s2 = _make_socket_pair()
        try:
            bad_env = {
                "action": "evil_action",
                "msg_id": str(uuid.uuid4()),
                "timestamp": time.time(),
                "counter": 1,
                "payload": {},
            }
            raw = json.dumps(bad_env).encode()
            s1.sendall(struct.pack(">I", len(raw)) + raw)
            with pytest.raises(ProtocolError, match="Invalid action"):
                recv_message(s2)
        finally:
            s1.close(); s2.close()
