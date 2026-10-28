"""
replay_guard.py — Nonce-Based Replay Attack Protection.

Every authenticated request carries three independent replay-prevention fields:

  1. timestamp  (float) — Unix epoch; rejected if > REPLAY_WINDOW_SECONDS old.
  2. msg_id     (str)   — UUID v4; rejected if seen before (bounded LRU cache).
  3. counter    (int)   — Per-session monotonically increasing integer; rejected
                          if ≤ the last accepted counter for that session.

WHY THREE LAYERS instead of just one?
    • Timestamp alone: an attacker can replay within the 30-second window.
    • msg_id alone: the cache must be unbounded (memory exhaustion risk),
      or have a time-limited TTL (complex to implement correctly).
    • Counter alone: requires reliable per-session state; a server crash
      loses state and allows replay of all previously seen messages.
    Combining all three gives defence-in-depth: any one layer can fail
    independently without creating a replay vulnerability.

Thread Safety:
    ReplayGuard is used by the multi-threaded server. All state mutations
    are protected by a threading.Lock so concurrent requests from different
    clients do not race on the shared msg_id cache or counter table.

Bounded Cache:
    The msg_id set is capped at REPLAY_CACHE_MAX_SIZE (10,000 entries) using
    an OrderedDict as an LRU structure.  When the cap is reached, the oldest
    entry is evicted.  This bounds memory usage: 10,000 UUIDs ≈ 360 KiB.
    Eviction of old entries is safe because the timestamp check already rejects
    messages older than 30 seconds — an evicted UUID could only be replayed
    if it arrives more than 30 s late AND happens to be in the evicted tail,
    and the timestamp check catches that case independently.
"""

import threading
import time
from collections import OrderedDict

import common.config as _cfg

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ReplayError(Exception):
    """
    Base class for all replay-detection failures.

    Subclassed so callers can handle each failure reason separately in logs.
    """


class StaleTimestampError(ReplayError):
    """Message timestamp is outside the allowed replay window."""


class DuplicateMessageError(ReplayError):
    """Message ID has already been processed (exact replay)."""


class NonMonotonicCounterError(ReplayError):
    """Session counter did not increase (counter replay)."""


# ---------------------------------------------------------------------------
# ReplayGuard
# ---------------------------------------------------------------------------


class ReplayGuard:
    """
    Stateful, thread-safe replay attack detector.

    Maintains:
        _seen_ids    : OrderedDict[msg_id → timestamp_first_seen]
                       Used as a bounded LRU set.
        _session_counters : dict[session_id → last_accepted_counter]
                       One entry per active authenticated session.

    Typical usage (in the server request handler):
        guard = ReplayGuard()           # one instance shared by all threads
        ...
        guard.check_and_record(
            msg_id=env["msg_id"],
            timestamp=env["timestamp"],
            counter=env["counter"],
            session_id=current_user_id,
        )
        # If the above raises, reject the request and close the connection.
    """

    def __init__(self) -> None:
        # Bounded LRU cache of seen message IDs.
        # OrderedDict preserves insertion order; we evict from the front (oldest).
        self._seen_ids: OrderedDict[str, float] = OrderedDict()

        # Maps session_id → last accepted counter value.
        # A value of -1 means "no message accepted yet for this session".
        self._session_counters: dict[str, int] = {}

        # Single lock protecting both data structures.
        # A fine-grained per-session lock would be faster but adds complexity
        # that is not warranted at this scale.
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_record(
        self,
        msg_id: str,
        timestamp: float,
        counter: int,
        session_id: str,
    ) -> None:
        """
        Validate a message against all three replay-protection mechanisms
        and, if valid, record it so future duplicates are rejected.

        All three checks happen BEFORE any state is mutated — this prevents
        a partially-recorded message from corrupting guard state on failure.

        Args:
            msg_id:     UUID v4 string from the message envelope.
            timestamp:  Unix epoch float from the message envelope.
            counter:    Monotonic session counter from the message envelope.
            session_id: Stable identifier for the sender's session (user_id
                        or connection UUID). Used to track per-session counters.

        Raises:
            StaleTimestampError:       Timestamp outside ±REPLAY_WINDOW_SECONDS.
            DuplicateMessageError:     msg_id seen before.
            NonMonotonicCounterError:  counter ≤ last accepted counter.
            ValueError:               On invalid argument types.
        """
        self._validate_args(msg_id, timestamp, counter, session_id)

        with self._lock:
            # --- Check 1: Timestamp freshness ---
            self._check_timestamp(timestamp)

            # --- Check 2: Message ID uniqueness ---
            self._check_msg_id(msg_id)

            # --- Check 3: Monotonic counter ---
            self._check_counter(counter, session_id)

            # --- All checks passed: record the message ---
            self._record_msg_id(msg_id, timestamp)
            self._record_counter(counter, session_id)

    def reset_session(self, session_id: str) -> None:
        """
        Remove the counter entry for *session_id* (call on logout/disconnect).

        This prevents stale counter entries from accumulating for sessions
        that will never send another message.

        Args:
            session_id: The session identifier to remove.
        """
        with self._lock:
            self._session_counters.pop(session_id, None)

    def stats(self) -> dict[str, int]:
        """
        Return current cache statistics (useful for monitoring/debugging).

        Returns:
            Dict with keys 'seen_ids_count' and 'active_sessions'.
        """
        with self._lock:
            return {
                "seen_ids_count": len(self._seen_ids),
                "active_sessions": len(self._session_counters),
            }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_args(
        msg_id: str, timestamp: float, counter: int, session_id: str
    ) -> None:
        """Lightweight type/range checks before acquiring the lock."""
        if not isinstance(msg_id, str) or not msg_id:
            raise ValueError("msg_id must be a non-empty string.")
        if not isinstance(timestamp, (int, float)) or timestamp <= 0:
            raise ValueError("timestamp must be a positive number.")
        if not isinstance(counter, int) or counter < 0:
            raise ValueError("counter must be a non-negative integer.")
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session_id must be a non-empty string.")

    def _check_timestamp(self, timestamp: float) -> None:
        """
        Reject messages outside the ±REPLAY_WINDOW_SECONDS window.

        WHY bidirectional window (not just "too old"):
            We reject messages from the future (> window) as well to guard
            against an attacker who pre-computes messages with a future
            timestamp and later replays them after the window passes.
            Minor clock skew (< 1 s on a LAN) is tolerated within the window.
        """
        now = time.time()
        age = now - timestamp
        if abs(age) > _cfg.REPLAY_WINDOW_SECONDS:
            raise StaleTimestampError(
                f"Message timestamp is {age:.1f}s from server time "
                f"(window: ±{_cfg.REPLAY_WINDOW_SECONDS}s). Possible replay."
            )

    def _check_msg_id(self, msg_id: str) -> None:
        """Reject if this UUID has been seen before."""
        if msg_id in self._seen_ids:
            raise DuplicateMessageError(
                f"Message ID '{msg_id}' has already been processed. "
                "Replay attack detected."
            )

    def _check_counter(self, counter: int, session_id: str) -> None:
        """
        Reject if counter is not strictly greater than the last accepted value.

        WHY strictly greater (not ≥):
            Allowing equal counters would permit exact replay of the last
            message in a session (same msg_id would catch it, but defence-
            in-depth requires the counter to catch it independently).
        """
        last = self._session_counters.get(session_id, -1)
        if counter <= last:
            raise NonMonotonicCounterError(
                f"Counter {counter} ≤ last accepted {last} for session "
                f"'{session_id}'. Possible replay or counter reset."
            )

    def _record_msg_id(self, msg_id: str, timestamp: float) -> None:
        """
        Add *msg_id* to the LRU cache, evicting the oldest if at capacity.

        Must be called with self._lock held.
        """
        # Move to end if already present (won't happen after _check_msg_id, but
        # OrderedDict.update is idempotent and safe)
        self._seen_ids[msg_id] = timestamp
        self._seen_ids.move_to_end(msg_id)

        # Evict oldest entries when over capacity.
        # Read from the live config object so tests can override the cap.
        while len(self._seen_ids) > _cfg.REPLAY_CACHE_MAX_SIZE:
            self._seen_ids.popitem(last=False)    # pop from front (oldest)

    def _record_counter(self, counter: int, session_id: str) -> None:
        """Update the session counter. Must be called with self._lock held."""
        self._session_counters[session_id] = counter


# ---------------------------------------------------------------------------
# Module-level singleton convenience
# ---------------------------------------------------------------------------

# The server imports and uses this singleton directly.
# Tests instantiate their own ReplayGuard() to keep tests isolated.
_default_guard: ReplayGuard | None = None


def get_default_guard() -> ReplayGuard:
    """
    Return (creating if necessary) the module-level ReplayGuard singleton.

    WHY a singleton: the server is multi-threaded and a single guard instance
    with an internal lock is safer than multiple instances that cannot see
    each other's state.
    """
    global _default_guard
    if _default_guard is None:
        _default_guard = ReplayGuard()
    return _default_guard
