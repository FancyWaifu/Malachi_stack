"""
PCAP export functionality for Malachi Stack.

Enables capturing and exporting packets for analysis.
"""

from __future__ import annotations

import os
import time
import threading
from typing import Optional, List
from threading import RLock

from scapy.all import wrpcap, Packet

from .config import KEYDIR
from .logging_setup import log


class PCAPWriter:
    """
    Thread-safe PCAP file writer.

    Buffers packets and writes them to a PCAP file.
    """

    def __init__(self, path: str, buffer_size: int = 100):
        """
        Initialize PCAP writer.

        Args:
            path: Path to output PCAP file
            buffer_size: Number of packets to buffer before flushing
        """
        self._lock = RLock()
        self._path = path
        self._buffer_size = buffer_size
        self._buffer: List[Packet] = []
        self._packet_count = 0
        self._enabled = False

    def enable(self) -> None:
        """Enable packet capture."""
        with self._lock:
            self._enabled = True
            log(f"[PCAP] Capture enabled, writing to: {self._path}")

    def disable(self) -> None:
        """Disable packet capture and flush remaining packets."""
        with self._lock:
            self._enabled = False
            self._flush()
            log(f"[PCAP] Capture disabled, {self._packet_count} packets written")

    def is_enabled(self) -> bool:
        """Check if capture is enabled."""
        with self._lock:
            return self._enabled

    def add_packet(self, pkt: Packet) -> None:
        """
        Add a packet to the capture buffer.

        Args:
            pkt: Scapy packet to capture
        """
        with self._lock:
            if not self._enabled:
                return

            self._buffer.append(pkt)
            if len(self._buffer) >= self._buffer_size:
                self._flush()

    def _flush(self) -> None:
        """Flush buffer to file."""
        if not self._buffer:
            return

        try:
            # Append to file
            wrpcap(self._path, self._buffer, append=os.path.exists(self._path))
            self._packet_count += len(self._buffer)
            self._buffer.clear()
        except Exception as e:
            log(f"[PCAP] Write error: {e}")
            self._buffer.clear()

    def stats(self) -> dict:
        """Get capture statistics."""
        with self._lock:
            return {
                "enabled": self._enabled,
                "path": self._path,
                "packets_written": self._packet_count,
                "buffer_size": len(self._buffer),
            }


class PCAPManager:
    """
    Manages PCAP capture sessions.

    Provides separate writers for TX and RX packets.
    """

    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize PCAP manager.

        Args:
            output_dir: Directory for PCAP files (default: KEYDIR/pcap)
        """
        self._output_dir = output_dir or os.path.join(KEYDIR, "pcap")
        self._lock = RLock()
        self._tx_writer: Optional[PCAPWriter] = None
        self._rx_writer: Optional[PCAPWriter] = None
        self._combined_writer: Optional[PCAPWriter] = None

    def _ensure_dir(self) -> None:
        """Ensure output directory exists."""
        os.makedirs(self._output_dir, exist_ok=True)

    def start_capture(
        self,
        name: Optional[str] = None,
        separate_tx_rx: bool = False,
    ) -> str:
        """
        Start a new capture session.

        Args:
            name: Optional capture name (default: timestamp)
            separate_tx_rx: If True, create separate files for TX and RX

        Returns:
            Path to the PCAP file(s)
        """
        with self._lock:
            self._ensure_dir()

            if name is None:
                name = time.strftime("%Y%m%d_%H%M%S")

            if separate_tx_rx:
                tx_path = os.path.join(self._output_dir, f"{name}_tx.pcap")
                rx_path = os.path.join(self._output_dir, f"{name}_rx.pcap")
                self._tx_writer = PCAPWriter(tx_path)
                self._rx_writer = PCAPWriter(rx_path)
                self._tx_writer.enable()
                self._rx_writer.enable()
                return f"{tx_path}, {rx_path}"
            else:
                combined_path = os.path.join(self._output_dir, f"{name}.pcap")
                self._combined_writer = PCAPWriter(combined_path)
                self._combined_writer.enable()
                return combined_path

    def stop_capture(self) -> dict:
        """
        Stop the current capture session.

        Returns:
            Statistics from the capture
        """
        with self._lock:
            stats = {}

            if self._tx_writer:
                self._tx_writer.disable()
                stats["tx"] = self._tx_writer.stats()
                self._tx_writer = None

            if self._rx_writer:
                self._rx_writer.disable()
                stats["rx"] = self._rx_writer.stats()
                self._rx_writer = None

            if self._combined_writer:
                self._combined_writer.disable()
                stats["combined"] = self._combined_writer.stats()
                self._combined_writer = None

            return stats

    def is_capturing(self) -> bool:
        """Check if capture is active."""
        with self._lock:
            return (
                (self._tx_writer and self._tx_writer.is_enabled())
                or (self._rx_writer and self._rx_writer.is_enabled())
                or (self._combined_writer and self._combined_writer.is_enabled())
            )

    def record_tx(self, pkt: Packet) -> None:
        """Record a transmitted packet."""
        with self._lock:
            if self._tx_writer:
                self._tx_writer.add_packet(pkt)
            if self._combined_writer:
                self._combined_writer.add_packet(pkt)

    def record_rx(self, pkt: Packet) -> None:
        """Record a received packet."""
        with self._lock:
            if self._rx_writer:
                self._rx_writer.add_packet(pkt)
            if self._combined_writer:
                self._combined_writer.add_packet(pkt)

    def stats(self) -> dict:
        """Get capture statistics."""
        with self._lock:
            result = {"capturing": self.is_capturing()}
            if self._tx_writer:
                result["tx"] = self._tx_writer.stats()
            if self._rx_writer:
                result["rx"] = self._rx_writer.stats()
            if self._combined_writer:
                result["combined"] = self._combined_writer.stats()
            return result


# Global instance
_pcap_manager: Optional[PCAPManager] = None


def get_pcap_manager() -> PCAPManager:
    """Get global PCAP manager (lazily initialized)."""
    global _pcap_manager
    if _pcap_manager is None:
        _pcap_manager = PCAPManager()
    return _pcap_manager
