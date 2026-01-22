"""
Message fragmentation and reassembly for Malachi Stack.

Enables sending messages larger than the single-frame payload cap.
"""

from __future__ import annotations

import os
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from threading import RLock

from .config import PAYLOAD_CAP, ID_LEN
from .logging_setup import log


# Fragment header overhead: msg_id(4) + frag_idx(2) + total_frags(2) + flags(1) = 9 bytes
FRAG_HEADER_SIZE = 9
FRAG_PAYLOAD_SIZE = PAYLOAD_CAP - FRAG_HEADER_SIZE - 100  # Leave room for L3/L4 headers

# Fragment flags
FRAG_FLAG_FIRST = 0x01  # First fragment
FRAG_FLAG_LAST = 0x02   # Last fragment

# Reassembly timeout
REASSEMBLY_TIMEOUT = 30.0  # Seconds before incomplete message is dropped
MAX_PENDING_MESSAGES = 64  # Maximum concurrent reassembly operations per peer


@dataclass
class Fragment:
    """A single message fragment."""
    msg_id: int
    frag_idx: int
    total_frags: int
    flags: int
    payload: bytes

    def pack(self) -> bytes:
        """Pack fragment into bytes."""
        return (
            self.msg_id.to_bytes(4, "big")
            + self.frag_idx.to_bytes(2, "big")
            + self.total_frags.to_bytes(2, "big")
            + bytes([self.flags])
            + self.payload
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Fragment":
        """Unpack fragment from bytes."""
        if len(data) < FRAG_HEADER_SIZE:
            raise ValueError(f"Fragment too short: {len(data)} < {FRAG_HEADER_SIZE}")

        msg_id = int.from_bytes(data[0:4], "big")
        frag_idx = int.from_bytes(data[4:6], "big")
        total_frags = int.from_bytes(data[6:8], "big")
        flags = data[8]
        payload = data[9:]

        return cls(
            msg_id=msg_id,
            frag_idx=frag_idx,
            total_frags=total_frags,
            flags=flags,
            payload=payload,
        )


@dataclass
class ReassemblyBuffer:
    """Buffer for reassembling fragmented messages."""
    msg_id: int
    total_frags: int
    fragments: Dict[int, bytes] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def add_fragment(self, frag: Fragment) -> bool:
        """
        Add a fragment to the buffer.

        Returns True if message is complete.
        """
        if frag.frag_idx >= self.total_frags:
            return False

        self.fragments[frag.frag_idx] = frag.payload
        return len(self.fragments) == self.total_frags

    def is_complete(self) -> bool:
        """Check if all fragments have been received."""
        return len(self.fragments) == self.total_frags

    def is_expired(self) -> bool:
        """Check if reassembly has timed out."""
        return time.time() - self.created_at > REASSEMBLY_TIMEOUT

    def reassemble(self) -> bytes:
        """
        Reassemble the complete message.

        Raises ValueError if not complete.
        """
        if not self.is_complete():
            raise ValueError("Cannot reassemble incomplete message")

        # Reconstruct in order
        return b"".join(self.fragments[i] for i in range(self.total_frags))


class FragmentationManager:
    """
    Manages message fragmentation and reassembly.

    Thread-safe for concurrent fragment handling.
    """

    def __init__(self):
        self._lock = RLock()
        self._tx_msg_counter = 0
        # peer_id -> msg_id -> ReassemblyBuffer
        self._rx_buffers: Dict[bytes, Dict[int, ReassemblyBuffer]] = defaultdict(dict)

    def fragment_message(self, payload: bytes) -> List[Fragment]:
        """
        Fragment a message into multiple fragments.

        Args:
            payload: Full message payload

        Returns:
            List of Fragment objects ready to send
        """
        with self._lock:
            msg_id = self._tx_msg_counter
            self._tx_msg_counter = (self._tx_msg_counter + 1) & 0xFFFFFFFF

        # Calculate number of fragments needed
        if len(payload) <= FRAG_PAYLOAD_SIZE:
            # Single fragment (no fragmentation needed)
            return [Fragment(
                msg_id=msg_id,
                frag_idx=0,
                total_frags=1,
                flags=FRAG_FLAG_FIRST | FRAG_FLAG_LAST,
                payload=payload,
            )]

        fragments = []
        offset = 0
        frag_idx = 0
        total_frags = (len(payload) + FRAG_PAYLOAD_SIZE - 1) // FRAG_PAYLOAD_SIZE

        while offset < len(payload):
            chunk = payload[offset:offset + FRAG_PAYLOAD_SIZE]
            flags = 0
            if frag_idx == 0:
                flags |= FRAG_FLAG_FIRST
            if offset + len(chunk) >= len(payload):
                flags |= FRAG_FLAG_LAST

            fragments.append(Fragment(
                msg_id=msg_id,
                frag_idx=frag_idx,
                total_frags=total_frags,
                flags=flags,
                payload=chunk,
            ))

            offset += FRAG_PAYLOAD_SIZE
            frag_idx += 1

        return fragments

    def receive_fragment(
        self, peer_id: bytes, frag: Fragment
    ) -> Tuple[bool, Optional[bytes]]:
        """
        Process a received fragment.

        Args:
            peer_id: Sender's node ID
            frag: Received fragment

        Returns:
            Tuple of (complete, payload):
            - (True, payload) if message is complete
            - (False, None) if more fragments needed
        """
        with self._lock:
            # Prune expired buffers
            self._prune_expired()

            peer_buffers = self._rx_buffers[peer_id]

            # Check for existing buffer
            if frag.msg_id in peer_buffers:
                buf = peer_buffers[frag.msg_id]
            else:
                # Check capacity
                if len(peer_buffers) >= MAX_PENDING_MESSAGES:
                    # Evict oldest
                    oldest_id = min(peer_buffers, key=lambda k: peer_buffers[k].created_at)
                    del peer_buffers[oldest_id]

                buf = ReassemblyBuffer(
                    msg_id=frag.msg_id,
                    total_frags=frag.total_frags,
                )
                peer_buffers[frag.msg_id] = buf

            # Add fragment
            if buf.add_fragment(frag):
                # Message complete
                try:
                    payload = buf.reassemble()
                    del peer_buffers[frag.msg_id]
                    return True, payload
                except ValueError:
                    del peer_buffers[frag.msg_id]
                    return False, None

            return False, None

    def _prune_expired(self) -> None:
        """Remove expired reassembly buffers."""
        for peer_id in list(self._rx_buffers.keys()):
            peer_buffers = self._rx_buffers[peer_id]
            expired = [
                msg_id
                for msg_id, buf in peer_buffers.items()
                if buf.is_expired()
            ]
            for msg_id in expired:
                log(f"[FRAG] Dropped expired reassembly for msg_id={msg_id}")
                del peer_buffers[msg_id]

            # Remove empty peer entries
            if not peer_buffers:
                del self._rx_buffers[peer_id]

    def stats(self) -> Dict[str, int]:
        """Get fragmentation statistics."""
        with self._lock:
            total_pending = sum(len(p) for p in self._rx_buffers.values())
            return {
                "tx_msg_counter": self._tx_msg_counter,
                "peers_with_pending": len(self._rx_buffers),
                "total_pending_messages": total_pending,
            }


# Global instance
_frag_manager: Optional[FragmentationManager] = None


def get_fragmentation_manager() -> FragmentationManager:
    """Get global fragmentation manager (lazily initialized)."""
    global _frag_manager
    if _frag_manager is None:
        _frag_manager = FragmentationManager()
    return _frag_manager


def needs_fragmentation(payload: bytes) -> bool:
    """Check if a payload needs to be fragmented."""
    return len(payload) > FRAG_PAYLOAD_SIZE
