"""
Tests for malachi.fragmentation module.
"""

import pytest
import os

from malachi.fragmentation import (
    Fragment,
    FragmentationManager,
    FRAG_PAYLOAD_SIZE,
    FRAG_FLAG_FIRST,
    FRAG_FLAG_LAST,
    needs_fragmentation,
)


class TestFragment:
    """Tests for Fragment class."""

    def test_pack_unpack(self):
        """Test fragment pack/unpack round-trip."""
        frag = Fragment(
            msg_id=12345,
            frag_idx=2,
            total_frags=5,
            flags=FRAG_FLAG_FIRST,
            payload=b"test payload",
        )

        packed = frag.pack()
        unpacked = Fragment.unpack(packed)

        assert unpacked.msg_id == frag.msg_id
        assert unpacked.frag_idx == frag.frag_idx
        assert unpacked.total_frags == frag.total_frags
        assert unpacked.flags == frag.flags
        assert unpacked.payload == frag.payload

    def test_unpack_too_short(self):
        """Test unpacking too-short data."""
        with pytest.raises(ValueError):
            Fragment.unpack(b"short")


class TestFragmentationManager:
    """Tests for FragmentationManager."""

    def test_no_fragmentation_needed(self):
        """Test small messages don't need fragmentation."""
        manager = FragmentationManager()
        payload = b"small message"

        fragments = manager.fragment_message(payload)

        assert len(fragments) == 1
        assert fragments[0].flags == (FRAG_FLAG_FIRST | FRAG_FLAG_LAST)
        assert fragments[0].payload == payload

    def test_fragmentation_needed(self):
        """Test large messages are fragmented."""
        manager = FragmentationManager()
        # Create payload larger than single fragment
        payload = os.urandom(FRAG_PAYLOAD_SIZE * 3)

        fragments = manager.fragment_message(payload)

        assert len(fragments) >= 3
        assert fragments[0].flags & FRAG_FLAG_FIRST
        assert fragments[-1].flags & FRAG_FLAG_LAST

    def test_reassembly(self):
        """Test fragment reassembly."""
        manager = FragmentationManager()
        peer_id = os.urandom(16)

        # Create and fragment a message
        original = os.urandom(FRAG_PAYLOAD_SIZE * 2 + 100)
        fragments = manager.fragment_message(original)

        # Reassemble
        complete = False
        reassembled = None

        for frag in fragments:
            complete, reassembled = manager.receive_fragment(peer_id, frag)

        assert complete
        assert reassembled == original

    def test_out_of_order_reassembly(self):
        """Test out-of-order fragment reassembly."""
        manager = FragmentationManager()
        peer_id = os.urandom(16)

        original = os.urandom(FRAG_PAYLOAD_SIZE * 2 + 100)
        fragments = manager.fragment_message(original)

        # Reverse order
        fragments = list(reversed(fragments))

        complete = False
        reassembled = None

        for frag in fragments:
            complete, reassembled = manager.receive_fragment(peer_id, frag)

        assert complete
        assert reassembled == original

    def test_needs_fragmentation(self):
        """Test needs_fragmentation helper."""
        small = b"small"
        large = os.urandom(FRAG_PAYLOAD_SIZE + 1)

        assert not needs_fragmentation(small)
        assert needs_fragmentation(large)

    def test_stats(self):
        """Test fragmentation statistics."""
        manager = FragmentationManager()

        stats = manager.stats()

        assert "tx_msg_counter" in stats
        assert "peers_with_pending" in stats
        assert "total_pending_messages" in stats
