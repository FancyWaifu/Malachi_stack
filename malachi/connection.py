"""
Connection state machine for Malachi Stack.

Provides explicit connection lifecycle management for peer sessions.
"""

from __future__ import annotations

import time
import threading
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, Optional, Callable, List
from threading import RLock

from .config import SESSION_KEY_TTL, NEIGHBOR_TTL
from .logging_setup import log
from .crypto import id_to_hex, short_id


class ConnectionState(Enum):
    """Connection state enumeration."""
    DISCONNECTED = auto()  # No connection
    DISCOVERING = auto()   # NDP DISCOVER sent, waiting for response
    CONNECTED = auto()     # Session keys established
    STALE = auto()         # Connection may be dead (no recent activity)
    EXPIRED = auto()       # Session keys expired


@dataclass
class ConnectionInfo:
    """Information about a connection to a peer."""
    peer_id: bytes
    mac: str
    state: ConnectionState = ConnectionState.DISCONNECTED
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    discover_sent_at: Optional[float] = None
    connected_at: Optional[float] = None
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def mark_connected(self) -> None:
        """Mark connection as established."""
        self.state = ConnectionState.CONNECTED
        self.connected_at = time.time()
        self.update_activity()

    def check_timeout(self, stale_threshold: float = 60.0) -> None:
        """Check and update state based on timeouts."""
        now = time.time()

        if self.state == ConnectionState.DISCOVERING:
            # Discovery timeout (10 seconds)
            if self.discover_sent_at and now - self.discover_sent_at > 10.0:
                self.state = ConnectionState.DISCONNECTED
                log(f"[CONN] Discovery timeout for {short_id(self.peer_id)}")

        elif self.state == ConnectionState.CONNECTED:
            # Check for stale connection
            if now - self.last_activity > stale_threshold:
                self.state = ConnectionState.STALE

            # Check for key expiration
            if self.connected_at and now - self.connected_at > SESSION_KEY_TTL:
                self.state = ConnectionState.EXPIRED


class ConnectionManager:
    """
    Manages connection states for all peers.

    Provides connection lifecycle management and monitoring.
    """

    def __init__(self):
        self._lock = RLock()
        self._connections: Dict[bytes, ConnectionInfo] = {}
        self._state_callbacks: List[Callable[[bytes, ConnectionState, ConnectionState], None]] = []

    def register_callback(
        self, callback: Callable[[bytes, ConnectionState, ConnectionState], None]
    ) -> None:
        """
        Register a callback for state changes.

        Callback receives (peer_id, old_state, new_state).
        """
        with self._lock:
            self._state_callbacks.append(callback)

    def _notify_state_change(
        self, peer_id: bytes, old_state: ConnectionState, new_state: ConnectionState
    ) -> None:
        """Notify callbacks of state change."""
        for callback in self._state_callbacks:
            try:
                callback(peer_id, old_state, new_state)
            except Exception as e:
                log(f"[CONN] Callback error: {e}")

    def get_or_create(self, peer_id: bytes, mac: str = "") -> ConnectionInfo:
        """Get or create connection info for a peer."""
        with self._lock:
            if peer_id not in self._connections:
                self._connections[peer_id] = ConnectionInfo(peer_id=peer_id, mac=mac)
            elif mac and not self._connections[peer_id].mac:
                self._connections[peer_id].mac = mac
            return self._connections[peer_id]

    def get(self, peer_id: bytes) -> Optional[ConnectionInfo]:
        """Get connection info for a peer."""
        with self._lock:
            return self._connections.get(peer_id)

    def set_state(self, peer_id: bytes, state: ConnectionState) -> None:
        """Set connection state for a peer."""
        with self._lock:
            conn = self.get_or_create(peer_id)
            old_state = conn.state
            if old_state != state:
                conn.state = state
                log(f"[CONN] {short_id(peer_id)}: {old_state.name} -> {state.name}")
                self._notify_state_change(peer_id, old_state, state)

    def mark_discovering(self, peer_id: bytes, mac: str) -> None:
        """Mark that discovery was initiated for a peer."""
        with self._lock:
            conn = self.get_or_create(peer_id, mac)
            conn.discover_sent_at = time.time()
            self.set_state(peer_id, ConnectionState.DISCOVERING)

    def mark_connected(self, peer_id: bytes, mac: str) -> None:
        """Mark a peer as connected (session keys established)."""
        with self._lock:
            conn = self.get_or_create(peer_id, mac)
            conn.mark_connected()
            self.set_state(peer_id, ConnectionState.CONNECTED)

    def mark_disconnected(self, peer_id: bytes) -> None:
        """Mark a peer as disconnected."""
        with self._lock:
            self.set_state(peer_id, ConnectionState.DISCONNECTED)

    def record_sent(self, peer_id: bytes, size: int) -> None:
        """Record a sent message."""
        with self._lock:
            conn = self.get(peer_id)
            if conn:
                conn.messages_sent += 1
                conn.bytes_sent += size
                conn.update_activity()

    def record_received(self, peer_id: bytes, size: int) -> None:
        """Record a received message."""
        with self._lock:
            conn = self.get(peer_id)
            if conn:
                conn.messages_received += 1
                conn.bytes_received += size
                conn.update_activity()
                # Revive stale connections
                if conn.state == ConnectionState.STALE:
                    self.set_state(peer_id, ConnectionState.CONNECTED)

    def check_timeouts(self) -> List[bytes]:
        """
        Check all connections for timeouts.

        Returns list of peer IDs that have timed out.
        """
        with self._lock:
            timed_out = []
            for peer_id, conn in self._connections.items():
                old_state = conn.state
                conn.check_timeout()
                if conn.state != old_state:
                    self._notify_state_change(peer_id, old_state, conn.state)
                if conn.state in (ConnectionState.DISCONNECTED, ConnectionState.EXPIRED):
                    timed_out.append(peer_id)
            return timed_out

    def remove(self, peer_id: bytes) -> None:
        """Remove a connection."""
        with self._lock:
            if peer_id in self._connections:
                del self._connections[peer_id]

    def list_connections(self) -> List[ConnectionInfo]:
        """Get a list of all connections."""
        with self._lock:
            return list(self._connections.values())

    def connected_peers(self) -> List[bytes]:
        """Get list of connected peer IDs."""
        with self._lock:
            return [
                peer_id
                for peer_id, conn in self._connections.items()
                if conn.state == ConnectionState.CONNECTED
            ]

    def stats(self) -> Dict[str, int]:
        """Get connection statistics."""
        with self._lock:
            by_state = {}
            for conn in self._connections.values():
                state_name = conn.state.name.lower()
                by_state[state_name] = by_state.get(state_name, 0) + 1

            return {
                "total_connections": len(self._connections),
                **by_state,
            }

    def format_summary(self) -> str:
        """Format connection summary for display."""
        with self._lock:
            lines = ["[CONNECTIONS]"]
            if not self._connections:
                lines.append("  (none)")
            else:
                for peer_id, conn in self._connections.items():
                    age = time.time() - conn.created_at
                    last = time.time() - conn.last_activity
                    lines.append(
                        f"  {short_id(peer_id)} | {conn.state.name:12} | "
                        f"mac={conn.mac} | msgs={conn.messages_sent}/{conn.messages_received} | "
                        f"last={last:.0f}s ago"
                    )
            return "\n".join(lines)


# Global instance
_conn_manager: Optional[ConnectionManager] = None


def get_connection_manager() -> ConnectionManager:
    """Get global connection manager (lazily initialized)."""
    global _conn_manager
    if _conn_manager is None:
        _conn_manager = ConnectionManager()
    return _conn_manager
