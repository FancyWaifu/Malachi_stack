"""
Global state management for Malachi Stack.

Provides thread-safe state containers for neighbors, rate limiters,
challenges, and TOFU pins.
"""

import os
import json
import time
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, Set
from threading import RLock

from .config import (
    MAX_NEIGHBORS,
    NEIGHBOR_TTL,
    NONCE_CACHE_SIZE,
    RX_CTR_CACHE_SIZE,
    NDP_RL_RATE,
    NDP_RL_BURST,
    NDP_GLOBAL_RATE,
    NDP_GLOBAL_BURST,
    CHALLENGE_TTL,
    MAX_OUTSTANDING_CH,
    PINS_PATH,
    KEYDIR,
    RL_MAX_MACS,
    RL_EVICTION_AGE,
)
from .logging_setup import log


@dataclass
class NeighborEntry:
    """Information about a discovered peer."""

    mac: str
    ed_pub: bytes
    x25519_pub: bytes
    last_seen: float
    nonces_deque: deque = field(default_factory=lambda: deque(maxlen=NONCE_CACHE_SIZE))
    nonces_set: Set[bytes] = field(default_factory=set)
    key_rx: Optional[bytes] = None
    key_tx: Optional[bytes] = None
    tx_seq: int = 0
    rx_ctr_deque: deque = field(default_factory=lambda: deque(maxlen=RX_CTR_CACHE_SIZE))
    rx_ctr_set: Set[int] = field(default_factory=set)


class NeighborTable:
    """
    Thread-safe neighbor table with LRU eviction and TTL expiration.
    """

    def __init__(self, max_size: int = MAX_NEIGHBORS, ttl: float = NEIGHBOR_TTL):
        self._lock = RLock()
        self._neighbors: OrderedDict[bytes, NeighborEntry] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl

    def get(self, node_id: bytes) -> Optional[NeighborEntry]:
        """Get neighbor entry by node ID."""
        with self._lock:
            return self._neighbors.get(node_id)

    def get_or_create(
        self,
        node_id: bytes,
        mac: str,
        ed_pub: bytes,
        x25519_pub: bytes,
    ) -> NeighborEntry:
        """
        Get existing or create new neighbor entry.

        Updates existing entry's keys and timestamps, moves to end for LRU.
        """
        with self._lock:
            entry = self._neighbors.get(node_id)
            if entry is None:
                entry = NeighborEntry(
                    mac=mac,
                    ed_pub=ed_pub,
                    x25519_pub=x25519_pub,
                    last_seen=time.time(),
                )
                self._neighbors[node_id] = entry
                # Evict oldest if over capacity
                while len(self._neighbors) > self._max_size:
                    self._neighbors.popitem(last=False)
            else:
                entry.mac = mac
                entry.ed_pub = ed_pub
                entry.x25519_pub = x25519_pub
                entry.last_seen = time.time()
                self._neighbors.move_to_end(node_id)
            return entry

    def find_by_mac(self, mac: str) -> Tuple[Optional[bytes], Optional[NeighborEntry]]:
        """Find neighbor by MAC address (case-insensitive)."""
        mac = mac.lower()
        with self._lock:
            for nid, entry in self._neighbors.items():
                if entry.mac.lower() == mac:
                    return nid, entry
        return None, None

    def prune_stale(self) -> int:
        """Remove entries older than TTL. Returns count of removed entries."""
        now = time.time()
        with self._lock:
            stale = [
                nid
                for nid, entry in self._neighbors.items()
                if now - entry.last_seen > self._ttl
            ]
            for nid in stale:
                self._neighbors.pop(nid, None)
            return len(stale)

    def items(self):
        """Iterate over all neighbors (thread-safe snapshot)."""
        with self._lock:
            return list(self._neighbors.items())

    def __len__(self) -> int:
        with self._lock:
            return len(self._neighbors)

    def __contains__(self, node_id: bytes) -> bool:
        with self._lock:
            return node_id in self._neighbors


class RateLimiter:
    """
    Token bucket rate limiter with per-MAC and global limits.

    Includes automatic eviction of stale MAC entries to prevent memory leaks.
    """

    def __init__(
        self,
        per_mac_rate: float = NDP_RL_RATE,
        per_mac_burst: float = NDP_RL_BURST,
        global_rate: float = NDP_GLOBAL_RATE,
        global_burst: float = NDP_GLOBAL_BURST,
        max_macs: int = RL_MAX_MACS,
        eviction_age: float = RL_EVICTION_AGE,
    ):
        self._lock = RLock()
        self._per_mac: Dict[str, Tuple[float, float]] = {}  # mac -> (tokens, last_ts)
        self._global: Tuple[float, float] = (global_burst, time.time())

        self._per_mac_rate = per_mac_rate
        self._per_mac_burst = per_mac_burst
        self._global_rate = global_rate
        self._global_burst = global_burst
        self._max_macs = max_macs
        self._eviction_age = eviction_age
        self._last_eviction = time.time()

    def _take_token(
        self, bucket: Tuple[float, float], rate: float, burst: float
    ) -> Tuple[Tuple[float, float], bool]:
        """Try to take a token from bucket. Returns (new_bucket, allowed)."""
        tokens, last = bucket
        now = time.time()
        # Refill tokens based on elapsed time
        tokens = min(burst, tokens + (now - last) * rate)
        if tokens >= 1.0:
            return (tokens - 1.0, now), True
        return (tokens, now), False

    def _evict_stale(self) -> None:
        """Remove old MAC entries to prevent memory leak."""
        now = time.time()
        if now - self._last_eviction < 60:  # Only run every 60 seconds
            return

        self._last_eviction = now
        cutoff = now - self._eviction_age
        stale = [mac for mac, (_, ts) in self._per_mac.items() if ts < cutoff]
        for mac in stale:
            self._per_mac.pop(mac, None)

        # Also evict oldest if over capacity
        while len(self._per_mac) > self._max_macs:
            oldest = min(self._per_mac.items(), key=lambda x: x[1][1])
            self._per_mac.pop(oldest[0], None)

    def allow(self, mac: str) -> bool:
        """
        Check if request from MAC is allowed.

        Checks both per-MAC and global rate limits.
        """
        mac = mac.lower()
        with self._lock:
            self._evict_stale()

            # Check global limit
            self._global, ok_global = self._take_token(
                self._global, self._global_rate, self._global_burst
            )

            # Check per-MAC limit
            bucket = self._per_mac.get(mac, (self._per_mac_burst, time.time()))
            new_bucket, ok_mac = self._take_token(
                bucket, self._per_mac_rate, self._per_mac_burst
            )
            self._per_mac[mac] = new_bucket

            return ok_global and ok_mac


class ChallengeStore:
    """
    Store for outstanding NDP challenges.

    Tracks challenge expiry and provides automatic cleanup.
    """

    def __init__(
        self, max_challenges: int = MAX_OUTSTANDING_CH, ttl: float = CHALLENGE_TTL
    ):
        self._lock = RLock()
        self._challenges: Dict[bytes, float] = {}  # challenge -> expiry_ts
        self._max_challenges = max_challenges
        self._ttl = ttl

    def add(self, challenge: bytes) -> None:
        """Add a new challenge with expiry."""
        with self._lock:
            # Evict oldest if at capacity
            if len(self._challenges) >= self._max_challenges:
                oldest = min(self._challenges.items(), key=lambda x: x[1])
                self._challenges.pop(oldest[0], None)
            self._challenges[challenge] = time.time() + self._ttl

    def consume(self, challenge: bytes) -> bool:
        """
        Consume a challenge if valid.

        Returns True if challenge was valid and not expired.
        """
        with self._lock:
            expiry = self._challenges.pop(challenge, None)
            return expiry is not None and expiry >= time.time()

    def prune(self) -> int:
        """Remove expired challenges. Returns count removed."""
        now = time.time()
        with self._lock:
            expired = [ch for ch, exp in self._challenges.items() if exp < now]
            for ch in expired:
                self._challenges.pop(ch, None)
            return len(expired)


class PinStore:
    """
    TOFU (Trust On First Use) pin storage.

    Persists node ID -> Ed25519 public key mappings.
    """

    def __init__(self, path: str = PINS_PATH):
        self._lock = RLock()
        self._path = path
        self._pins: Dict[str, str] = self._load()

    def _load(self) -> Dict[str, str]:
        """Load pins from disk."""
        try:
            with open(self._path, "r") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save(self) -> None:
        """Save pins to disk atomically."""
        os.makedirs(KEYDIR, exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._pins, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path)

    def check_or_set(self, node_id_hex: str, ed_pub_b64: str) -> bool:
        """
        Check if pin matches or set new pin (TOFU).

        Returns True if pin matches or was newly set.
        Returns False if existing pin doesn't match (potential attack).
        """
        with self._lock:
            existing = self._pins.get(node_id_hex)
            if existing is None:
                self._pins[node_id_hex] = ed_pub_b64
                try:
                    self._save()
                except Exception:
                    pass
                log(f"[TOFU] Pinned {node_id_hex}")
                return True

            if existing != ed_pub_b64:
                log(f"[!!!] TOFU pin mismatch for {node_id_hex} - REJECTING")
                return False

            return True

    def get(self, node_id_hex: str) -> Optional[str]:
        """Get pinned public key for node ID."""
        with self._lock:
            return self._pins.get(node_id_hex)

    def is_pinned(self, node_id_hex: str, ed_pub_b64: str) -> bool:
        """Check if node is pinned with the given key."""
        with self._lock:
            return self._pins.get(node_id_hex) == ed_pub_b64


class NonceTracker:
    """
    Per-peer nonce tracking for replay detection.
    """

    @staticmethod
    def check_nonce(entry: NeighborEntry, nonce: bytes) -> bool:
        """
        Check if nonce has been seen before.

        Returns True if nonce is a replay, False if new.
        """
        if nonce in entry.nonces_set:
            return True

        # Add to cache, evicting oldest if necessary
        if len(entry.nonces_deque) == entry.nonces_deque.maxlen and entry.nonces_deque:
            dropped = entry.nonces_deque.popleft()
            entry.nonces_set.discard(dropped)

        entry.nonces_deque.append(nonce)
        entry.nonces_set.add(nonce)
        entry.last_seen = time.time()
        return False

    @staticmethod
    def check_counter(entry: NeighborEntry, counter: int) -> bool:
        """
        Check if data-plane counter has been seen.

        Returns True if counter is a replay, False if new.
        """
        if counter in entry.rx_ctr_set:
            return True

        if (
            len(entry.rx_ctr_deque) == entry.rx_ctr_deque.maxlen
            and entry.rx_ctr_deque
        ):
            old = entry.rx_ctr_deque.popleft()
            entry.rx_ctr_set.discard(old)

        entry.rx_ctr_deque.append(counter)
        entry.rx_ctr_set.add(counter)
        return False


# ---------------- Global State Singletons ----------------

_neighbors: Optional[NeighborTable] = None
_rate_limiter: Optional[RateLimiter] = None
_challenges: Optional[ChallengeStore] = None
_pins: Optional[PinStore] = None
_stop_flag: Optional[threading.Event] = None


def get_neighbors() -> NeighborTable:
    """Get global neighbor table (lazily initialized)."""
    global _neighbors
    if _neighbors is None:
        _neighbors = NeighborTable()
    return _neighbors


def get_rate_limiter() -> RateLimiter:
    """Get global rate limiter (lazily initialized)."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


def get_challenges() -> ChallengeStore:
    """Get global challenge store (lazily initialized)."""
    global _challenges
    if _challenges is None:
        _challenges = ChallengeStore()
    return _challenges


def get_pins() -> PinStore:
    """Get global pin store (lazily initialized)."""
    global _pins
    if _pins is None:
        _pins = PinStore()
    return _pins


def get_stop_flag() -> threading.Event:
    """Get global stop flag for coordinated shutdown."""
    global _stop_flag
    if _stop_flag is None:
        _stop_flag = threading.Event()
    return _stop_flag
