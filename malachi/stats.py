"""
Statistics and metrics collection for Malachi Stack.

Provides thread-safe counters and gauges for monitoring.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Dict, Optional


@dataclass
class PacketStats:
    """Statistics for packet handling."""

    # Counters
    packets_sent: int = 0
    packets_received: int = 0
    packets_dropped: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    # NDP stats
    ndp_discovers_sent: int = 0
    ndp_discovers_received: int = 0
    ndp_advertises_sent: int = 0
    ndp_advertises_received: int = 0
    ndp_validation_failures: int = 0

    # Encryption stats
    encrypt_operations: int = 0
    decrypt_operations: int = 0
    decrypt_failures: int = 0

    # Replay detection
    replay_detections: int = 0

    # Session keys
    keys_established: int = 0
    keys_expired: int = 0

    # Errors
    rate_limit_drops: int = 0
    parse_errors: int = 0


class StatsCollector:
    """
    Thread-safe statistics collector.

    Provides atomic counter operations and periodic stat snapshots.
    """

    def __init__(self):
        self._lock = RLock()
        self._stats = PacketStats()
        self._start_time = time.time()
        self._per_peer_stats: Dict[bytes, PacketStats] = {}

    def increment(self, stat_name: str, amount: int = 1) -> None:
        """Increment a counter by name."""
        with self._lock:
            if hasattr(self._stats, stat_name):
                current = getattr(self._stats, stat_name)
                setattr(self._stats, stat_name, current + amount)

    def increment_peer(self, peer_id: bytes, stat_name: str, amount: int = 1) -> None:
        """Increment a per-peer counter."""
        with self._lock:
            if peer_id not in self._per_peer_stats:
                self._per_peer_stats[peer_id] = PacketStats()
            peer_stats = self._per_peer_stats[peer_id]
            if hasattr(peer_stats, stat_name):
                current = getattr(peer_stats, stat_name)
                setattr(peer_stats, stat_name, current + amount)

    def get_stats(self) -> Dict[str, int]:
        """Get a copy of all global statistics."""
        with self._lock:
            return {
                "uptime_seconds": int(time.time() - self._start_time),
                "packets_sent": self._stats.packets_sent,
                "packets_received": self._stats.packets_received,
                "packets_dropped": self._stats.packets_dropped,
                "bytes_sent": self._stats.bytes_sent,
                "bytes_received": self._stats.bytes_received,
                "ndp_discovers_sent": self._stats.ndp_discovers_sent,
                "ndp_discovers_received": self._stats.ndp_discovers_received,
                "ndp_advertises_sent": self._stats.ndp_advertises_sent,
                "ndp_advertises_received": self._stats.ndp_advertises_received,
                "ndp_validation_failures": self._stats.ndp_validation_failures,
                "encrypt_operations": self._stats.encrypt_operations,
                "decrypt_operations": self._stats.decrypt_operations,
                "decrypt_failures": self._stats.decrypt_failures,
                "replay_detections": self._stats.replay_detections,
                "keys_established": self._stats.keys_established,
                "keys_expired": self._stats.keys_expired,
                "rate_limit_drops": self._stats.rate_limit_drops,
                "parse_errors": self._stats.parse_errors,
                "peers_tracked": len(self._per_peer_stats),
            }

    def get_peer_stats(self, peer_id: bytes) -> Optional[Dict[str, int]]:
        """Get statistics for a specific peer."""
        with self._lock:
            if peer_id not in self._per_peer_stats:
                return None
            ps = self._per_peer_stats[peer_id]
            return {
                "packets_sent": ps.packets_sent,
                "packets_received": ps.packets_received,
                "bytes_sent": ps.bytes_sent,
                "bytes_received": ps.bytes_received,
            }

    def reset(self) -> None:
        """Reset all statistics."""
        with self._lock:
            self._stats = PacketStats()
            self._per_peer_stats.clear()
            self._start_time = time.time()

    def format_summary(self) -> str:
        """Format statistics as a human-readable summary."""
        stats = self.get_stats()
        uptime = stats["uptime_seconds"]
        hours, remainder = divmod(uptime, 3600)
        minutes, seconds = divmod(remainder, 60)

        return "\n".join([
            f"[STATS] Uptime: {hours}h {minutes}m {seconds}s",
            f"  Packets: sent={stats['packets_sent']} recv={stats['packets_received']} "
            f"drop={stats['packets_dropped']}",
            f"  Bytes: sent={stats['bytes_sent']} recv={stats['bytes_received']}",
            f"  NDP: disc_tx={stats['ndp_discovers_sent']} disc_rx={stats['ndp_discovers_received']} "
            f"adv_tx={stats['ndp_advertises_sent']} adv_rx={stats['ndp_advertises_received']}",
            f"  Crypto: enc={stats['encrypt_operations']} dec={stats['decrypt_operations']} "
            f"fail={stats['decrypt_failures']}",
            f"  Security: replays={stats['replay_detections']} "
            f"keys_est={stats['keys_established']} keys_exp={stats['keys_expired']}",
            f"  Errors: rate_limit={stats['rate_limit_drops']} parse={stats['parse_errors']}",
        ])


# Global instance
_stats_collector: Optional[StatsCollector] = None


def get_stats_collector() -> StatsCollector:
    """Get global stats collector (lazily initialized)."""
    global _stats_collector
    if _stats_collector is None:
        _stats_collector = StatsCollector()
    return _stats_collector


# Convenience functions for common operations
def stat_packet_sent(size: int, peer_id: Optional[bytes] = None) -> None:
    """Record a sent packet."""
    collector = get_stats_collector()
    collector.increment("packets_sent")
    collector.increment("bytes_sent", size)
    if peer_id:
        collector.increment_peer(peer_id, "packets_sent")
        collector.increment_peer(peer_id, "bytes_sent", size)


def stat_packet_received(size: int, peer_id: Optional[bytes] = None) -> None:
    """Record a received packet."""
    collector = get_stats_collector()
    collector.increment("packets_received")
    collector.increment("bytes_received", size)
    if peer_id:
        collector.increment_peer(peer_id, "packets_received")
        collector.increment_peer(peer_id, "bytes_received", size)


def stat_packet_dropped() -> None:
    """Record a dropped packet."""
    get_stats_collector().increment("packets_dropped")


def stat_ndp_discover_sent() -> None:
    """Record a sent NDP DISCOVER."""
    get_stats_collector().increment("ndp_discovers_sent")


def stat_ndp_discover_received() -> None:
    """Record a received NDP DISCOVER."""
    get_stats_collector().increment("ndp_discovers_received")


def stat_ndp_advertise_sent() -> None:
    """Record a sent NDP ADVERTISE."""
    get_stats_collector().increment("ndp_advertises_sent")


def stat_ndp_advertise_received() -> None:
    """Record a received NDP ADVERTISE."""
    get_stats_collector().increment("ndp_advertises_received")


def stat_ndp_validation_failure() -> None:
    """Record an NDP validation failure."""
    get_stats_collector().increment("ndp_validation_failures")


def stat_encrypt() -> None:
    """Record an encryption operation."""
    get_stats_collector().increment("encrypt_operations")


def stat_decrypt() -> None:
    """Record a decryption operation."""
    get_stats_collector().increment("decrypt_operations")


def stat_decrypt_failure() -> None:
    """Record a decryption failure."""
    get_stats_collector().increment("decrypt_failures")


def stat_replay_detected() -> None:
    """Record a replay detection."""
    get_stats_collector().increment("replay_detections")


def stat_key_established() -> None:
    """Record a session key establishment."""
    get_stats_collector().increment("keys_established")


def stat_key_expired() -> None:
    """Record a session key expiration."""
    get_stats_collector().increment("keys_expired")


def stat_rate_limit_drop() -> None:
    """Record a rate limit drop."""
    get_stats_collector().increment("rate_limit_drops")


def stat_parse_error() -> None:
    """Record a parse error."""
    get_stats_collector().increment("parse_errors")
