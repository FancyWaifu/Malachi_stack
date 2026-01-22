"""
Tests for malachi.state module.
"""

import pytest
import os
import time
import tempfile

from malachi.state import (
    NeighborEntry,
    NeighborTable,
    RateLimiter,
    ChallengeStore,
    PinStore,
    NonceTracker,
)


class TestNeighborEntry:
    """Tests for NeighborEntry."""

    def test_entry_creation(self):
        """Test neighbor entry creation."""
        entry = NeighborEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ed_pub=os.urandom(32),
            x25519_pub=os.urandom(32),
            last_seen=time.time(),
        )

        assert entry.mac == "aa:bb:cc:dd:ee:ff"
        assert entry.key_rx is None
        assert entry.key_tx is None
        assert entry.tx_seq == 0

    def test_needs_rekey(self):
        """Test rekey detection."""
        entry = NeighborEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ed_pub=os.urandom(32),
            x25519_pub=os.urandom(32),
            last_seen=time.time(),
        )

        # No keys established
        assert not entry.needs_rekey()

        # Set key establishment time in the past
        entry.key_established_at = time.time() - 3600  # 1 hour ago

        assert entry.needs_rekey()

    def test_clear_keys(self):
        """Test key clearing."""
        entry = NeighborEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ed_pub=os.urandom(32),
            x25519_pub=os.urandom(32),
            last_seen=time.time(),
        )

        entry.key_rx = os.urandom(32)
        entry.key_tx = os.urandom(32)
        entry.key_established_at = time.time()
        entry.tx_seq = 100

        entry.clear_keys()

        assert entry.key_rx is None
        assert entry.key_tx is None
        assert entry.key_established_at is None
        assert entry.tx_seq == 0


class TestNeighborTable:
    """Tests for NeighborTable."""

    def test_get_or_create_new(self):
        """Test creating new neighbor."""
        table = NeighborTable()
        node_id = os.urandom(16)

        entry = table.get_or_create(
            node_id,
            "aa:bb:cc:dd:ee:ff",
            os.urandom(32),
            os.urandom(32),
        )

        assert entry.mac == "aa:bb:cc:dd:ee:ff"
        assert node_id in table

    def test_get_or_create_existing(self):
        """Test getting existing neighbor."""
        table = NeighborTable()
        node_id = os.urandom(16)

        entry1 = table.get_or_create(
            node_id,
            "aa:bb:cc:dd:ee:ff",
            os.urandom(32),
            os.urandom(32),
        )

        entry2 = table.get_or_create(
            node_id,
            "11:22:33:44:55:66",
            os.urandom(32),
            os.urandom(32),
        )

        # Should be same entry, with updated MAC
        assert entry2.mac == "11:22:33:44:55:66"

    def test_find_by_mac(self):
        """Test finding neighbor by MAC."""
        table = NeighborTable()
        node_id = os.urandom(16)

        table.get_or_create(
            node_id,
            "aa:bb:cc:dd:ee:ff",
            os.urandom(32),
            os.urandom(32),
        )

        found_id, found_entry = table.find_by_mac("AA:BB:CC:DD:EE:FF")  # Case insensitive

        assert found_id == node_id
        assert found_entry is not None

    def test_prune_stale(self):
        """Test stale entry pruning."""
        table = NeighborTable(ttl=0.1)  # 100ms TTL
        node_id = os.urandom(16)

        table.get_or_create(
            node_id,
            "aa:bb:cc:dd:ee:ff",
            os.urandom(32),
            os.urandom(32),
        )

        time.sleep(0.2)  # Wait for entry to become stale

        removed = table.prune_stale()

        assert removed == 1
        assert node_id not in table


class TestRateLimiter:
    """Tests for RateLimiter."""

    def test_allow_within_limit(self):
        """Test allowing within rate limit."""
        limiter = RateLimiter(per_mac_rate=10, per_mac_burst=5)

        for _ in range(5):
            assert limiter.allow("aa:bb:cc:dd:ee:ff")

    def test_rate_limit_exceeded(self):
        """Test rate limiting when exceeded."""
        limiter = RateLimiter(per_mac_rate=0.1, per_mac_burst=1)

        # First should succeed
        assert limiter.allow("aa:bb:cc:dd:ee:ff")

        # Second should fail (no refill yet)
        assert not limiter.allow("aa:bb:cc:dd:ee:ff")


class TestChallengeStore:
    """Tests for ChallengeStore."""

    def test_add_and_consume(self):
        """Test adding and consuming challenge."""
        store = ChallengeStore()
        challenge = os.urandom(16)

        store.add(challenge)

        assert store.consume(challenge)
        assert not store.consume(challenge)  # Can't consume twice

    def test_challenge_expiry(self):
        """Test challenge expiration."""
        store = ChallengeStore(ttl=0.1)  # 100ms TTL
        challenge = os.urandom(16)

        store.add(challenge)
        time.sleep(0.2)

        assert not store.consume(challenge)


class TestNonceTracker:
    """Tests for NonceTracker."""

    def test_nonce_replay_detection(self):
        """Test nonce replay detection."""
        entry = NeighborEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ed_pub=os.urandom(32),
            x25519_pub=os.urandom(32),
            last_seen=time.time(),
        )

        nonce = os.urandom(24)

        # First time - not a replay
        assert not NonceTracker.check_nonce(entry, nonce)

        # Second time - is a replay
        assert NonceTracker.check_nonce(entry, nonce)

    def test_counter_replay_detection(self):
        """Test counter replay detection."""
        entry = NeighborEntry(
            mac="aa:bb:cc:dd:ee:ff",
            ed_pub=os.urandom(32),
            x25519_pub=os.urandom(32),
            last_seen=time.time(),
        )

        # First time - not a replay
        assert not NonceTracker.check_counter(entry, 1)

        # Second time - is a replay
        assert NonceTracker.check_counter(entry, 1)

        # Different counter - not a replay
        assert not NonceTracker.check_counter(entry, 2)
