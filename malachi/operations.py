"""
Operational features for Malachi.

This module implements:
- Protocol Versioning and Negotiation
- Compression Support
- Diagnostic Messages (PING/TRACE)
"""

import time
import threading
import struct
import zlib
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple, List, Callable, Any
from enum import IntEnum
import os

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Protocol Version
PROTOCOL_VERSION_MAJOR = 1
PROTOCOL_VERSION_MINOR = 0
PROTOCOL_VERSION = (PROTOCOL_VERSION_MAJOR << 8) | PROTOCOL_VERSION_MINOR

# Compression
COMPRESSION_NONE = 0x00
COMPRESSION_ZLIB = 0x01
COMPRESSION_LZ4 = 0x02  # Optional, requires lz4 package
COMPRESSION_THRESHOLD = 100  # Only compress payloads > 100 bytes

# Diagnostics
PING_TIMEOUT = 5.0
TRACE_MAX_HOPS = 16
TRACE_TIMEOUT = 10.0


# =============================================================================
# Message Types
# =============================================================================

class OperationsMsgType(IntEnum):
    """Operations message types."""
    # Version
    VERSION_REQUEST = 0x90
    VERSION_RESPONSE = 0x91
    VERSION_NEGOTIATE = 0x92

    # Diagnostics
    PING_REQUEST = 0xA0
    PING_RESPONSE = 0xA1
    TRACE_REQUEST = 0xA2
    TRACE_RESPONSE = 0xA3


# =============================================================================
# Protocol Versioning
# =============================================================================

@dataclass
class ProtocolCapabilities:
    """Protocol capabilities for negotiation."""
    version: int = PROTOCOL_VERSION
    compression: List[int] = field(default_factory=lambda: [COMPRESSION_NONE, COMPRESSION_ZLIB])
    extensions: Set[str] = field(default_factory=set)

    # Feature flags
    supports_multicast: bool = True
    supports_routing: bool = True
    supports_streams: bool = True
    supports_qos: bool = True


@dataclass
class NegotiatedSession:
    """Negotiated session parameters."""
    peer_id: bytes
    peer_version: int
    compression: int = COMPRESSION_NONE
    common_extensions: Set[str] = field(default_factory=set)
    negotiated_at: float = field(default_factory=time.time)


class VersionNegotiator:
    """
    Handles protocol version negotiation.

    Ensures compatible versions between peers and negotiates features.
    """

    def __init__(self, my_capabilities: Optional[ProtocolCapabilities] = None):
        """
        Initialize version negotiator.

        Args:
            my_capabilities: Our protocol capabilities
        """
        self._lock = threading.RLock()
        self._my_caps = my_capabilities or ProtocolCapabilities()
        self._sessions: Dict[bytes, NegotiatedSession] = {}
        self._pending: Dict[bytes, float] = {}  # peer_id -> request time

    def get_version(self) -> int:
        """Get our protocol version."""
        return self._my_caps.version

    def get_version_string(self) -> str:
        """Get human-readable version string."""
        major = self._my_caps.version >> 8
        minor = self._my_caps.version & 0xFF
        return f"{major}.{minor}"

    def is_compatible(self, peer_version: int) -> bool:
        """
        Check if peer version is compatible.

        Major version must match, minor can differ.
        """
        my_major = self._my_caps.version >> 8
        peer_major = peer_version >> 8
        return my_major == peer_major

    def negotiate(self, peer_id: bytes, peer_caps: ProtocolCapabilities) -> Optional[NegotiatedSession]:
        """
        Negotiate session parameters with peer.

        Args:
            peer_id: Peer's node ID
            peer_caps: Peer's capabilities

        Returns:
            Negotiated session or None if incompatible
        """
        if not self.is_compatible(peer_caps.version):
            logger.warning(
                f"Version mismatch with {peer_id.hex()[:8]}: "
                f"ours={self.get_version_string()}, "
                f"theirs={peer_caps.version >> 8}.{peer_caps.version & 0xFF}"
            )
            return None

        with self._lock:
            # Find common compression
            common_compression = set(self._my_caps.compression) & set(peer_caps.compression)
            # Prefer highest compression that both support
            if COMPRESSION_ZLIB in common_compression:
                compression = COMPRESSION_ZLIB
            else:
                compression = COMPRESSION_NONE

            # Find common extensions
            common_extensions = self._my_caps.extensions & peer_caps.extensions

            session = NegotiatedSession(
                peer_id=peer_id,
                peer_version=peer_caps.version,
                compression=compression,
                common_extensions=common_extensions,
            )

            self._sessions[peer_id] = session
            self._pending.pop(peer_id, None)

            return session

    def get_session(self, peer_id: bytes) -> Optional[NegotiatedSession]:
        """Get negotiated session for peer."""
        with self._lock:
            return self._sessions.get(peer_id)

    def encode_capabilities(self) -> bytes:
        """Encode our capabilities for transmission."""
        caps = self._my_caps

        # Format: version(2) + compression_count(1) + compressions + extension_count(1) + extensions
        data = struct.pack(">HB", caps.version, len(caps.compression))
        for c in caps.compression:
            data += bytes([c])

        data += bytes([len(caps.extensions)])
        for ext in caps.extensions:
            ext_bytes = ext.encode("utf-8")
            data += bytes([len(ext_bytes)]) + ext_bytes

        # Feature flags
        flags = 0
        if caps.supports_multicast:
            flags |= 0x01
        if caps.supports_routing:
            flags |= 0x02
        if caps.supports_streams:
            flags |= 0x04
        if caps.supports_qos:
            flags |= 0x08
        data += bytes([flags])

        return data

    def decode_capabilities(self, data: bytes) -> ProtocolCapabilities:
        """Decode peer capabilities."""
        if len(data) < 4:
            raise ValueError("Capabilities too short")

        version = struct.unpack(">H", data[0:2])[0]
        comp_count = data[2]

        offset = 3
        compression = []
        for _ in range(comp_count):
            compression.append(data[offset])
            offset += 1

        ext_count = data[offset]
        offset += 1

        extensions = set()
        for _ in range(ext_count):
            ext_len = data[offset]
            offset += 1
            ext = data[offset:offset + ext_len].decode("utf-8")
            extensions.add(ext)
            offset += ext_len

        flags = data[offset] if offset < len(data) else 0

        return ProtocolCapabilities(
            version=version,
            compression=compression,
            extensions=extensions,
            supports_multicast=bool(flags & 0x01),
            supports_routing=bool(flags & 0x02),
            supports_streams=bool(flags & 0x04),
            supports_qos=bool(flags & 0x08),
        )

    def encode_request(self) -> bytes:
        """Encode version request message."""
        return bytes([OperationsMsgType.VERSION_REQUEST]) + self.encode_capabilities()

    def encode_response(self) -> bytes:
        """Encode version response message."""
        return bytes([OperationsMsgType.VERSION_RESPONSE]) + self.encode_capabilities()

    def stats(self) -> Dict[str, Any]:
        """Get negotiation statistics."""
        with self._lock:
            return {
                "my_version": self.get_version_string(),
                "negotiated_sessions": len(self._sessions),
                "pending_negotiations": len(self._pending),
            }


# =============================================================================
# Compression Support
# =============================================================================

class CompressionManager:
    """
    Handles payload compression/decompression.

    Supports multiple compression algorithms.
    """

    def __init__(self, default_level: int = 6):
        """
        Initialize compression manager.

        Args:
            default_level: Default compression level (1-9)
        """
        self._default_level = default_level
        self._stats = {
            "bytes_compressed": 0,
            "bytes_original": 0,
            "packets_compressed": 0,
            "packets_skipped": 0,
        }

        # Try to import lz4
        self._has_lz4 = False
        try:
            import lz4.frame
            self._has_lz4 = True
        except ImportError:
            pass

    def compress(
        self,
        data: bytes,
        algorithm: int = COMPRESSION_ZLIB,
        level: Optional[int] = None,
    ) -> Tuple[bytes, int]:
        """
        Compress data.

        Args:
            data: Data to compress
            algorithm: Compression algorithm
            level: Compression level (1-9)

        Returns:
            Tuple of (compressed_data, algorithm_used)
        """
        if len(data) < COMPRESSION_THRESHOLD:
            self._stats["packets_skipped"] += 1
            return data, COMPRESSION_NONE

        level = level or self._default_level
        original_len = len(data)

        try:
            if algorithm == COMPRESSION_ZLIB:
                compressed = zlib.compress(data, level)
            elif algorithm == COMPRESSION_LZ4 and self._has_lz4:
                import lz4.frame
                compressed = lz4.frame.compress(data)
            else:
                return data, COMPRESSION_NONE

            # Only use compression if it actually saves space
            if len(compressed) >= original_len:
                self._stats["packets_skipped"] += 1
                return data, COMPRESSION_NONE

            self._stats["bytes_original"] += original_len
            self._stats["bytes_compressed"] += len(compressed)
            self._stats["packets_compressed"] += 1

            return compressed, algorithm

        except Exception as e:
            logger.debug(f"Compression failed: {e}")
            return data, COMPRESSION_NONE

    def decompress(self, data: bytes, algorithm: int) -> bytes:
        """
        Decompress data.

        Args:
            data: Compressed data
            algorithm: Compression algorithm used

        Returns:
            Decompressed data
        """
        if algorithm == COMPRESSION_NONE:
            return data

        try:
            if algorithm == COMPRESSION_ZLIB:
                return zlib.decompress(data)
            elif algorithm == COMPRESSION_LZ4 and self._has_lz4:
                import lz4.frame
                return lz4.frame.decompress(data)
            else:
                raise ValueError(f"Unknown compression algorithm: {algorithm}")

        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            raise

    def wrap_packet(self, data: bytes, algorithm: int = COMPRESSION_ZLIB) -> bytes:
        """
        Wrap packet with compression header.

        Args:
            data: Payload to compress
            algorithm: Compression algorithm

        Returns:
            Wrapped packet with header
        """
        compressed, used_algo = self.compress(data, algorithm)
        # Header: algorithm(1) + original_length(4) + compressed_data
        header = bytes([used_algo]) + struct.pack(">I", len(data))
        return header + compressed

    def unwrap_packet(self, data: bytes) -> bytes:
        """
        Unwrap and decompress packet.

        Args:
            data: Wrapped packet

        Returns:
            Decompressed payload
        """
        if len(data) < 5:
            raise ValueError("Packet too short")

        algorithm = data[0]
        original_len = struct.unpack(">I", data[1:5])[0]
        compressed = data[5:]

        decompressed = self.decompress(compressed, algorithm)

        if len(decompressed) != original_len:
            raise ValueError(
                f"Length mismatch: expected {original_len}, got {len(decompressed)}"
            )

        return decompressed

    def get_ratio(self) -> float:
        """Get compression ratio."""
        if self._stats["bytes_original"] == 0:
            return 1.0
        return self._stats["bytes_compressed"] / self._stats["bytes_original"]

    def stats(self) -> Dict[str, Any]:
        """Get compression statistics."""
        return {
            **self._stats,
            "compression_ratio": self.get_ratio(),
            "has_lz4": self._has_lz4,
        }


# =============================================================================
# Diagnostic Messages
# =============================================================================

@dataclass
class PingResult:
    """Result of a ping operation."""
    peer_id: bytes
    seq: int
    rtt_ms: float
    success: bool
    error: Optional[str] = None


@dataclass
class TraceHop:
    """A hop in a trace route."""
    hop_num: int
    node_id: bytes
    rtt_ms: float
    node_name: Optional[str] = None


@dataclass
class TraceResult:
    """Result of a trace operation."""
    destination: bytes
    hops: List[TraceHop]
    complete: bool
    error: Optional[str] = None


class DiagnosticsManager:
    """
    Handles diagnostic operations like ping and traceroute.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize diagnostics manager.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id

        # Pending pings
        self._pending_pings: Dict[int, Tuple[bytes, float, threading.Event]] = {}
        self._ping_seq = 0

        # Pending traces
        self._pending_traces: Dict[int, Tuple[bytes, List[TraceHop], threading.Event]] = {}
        self._trace_seq = 0

        # Statistics
        self._stats = {
            "pings_sent": 0,
            "pings_received": 0,
            "pongs_sent": 0,
            "pongs_received": 0,
            "traces_sent": 0,
            "trace_responses": 0,
        }

    def ping(
        self,
        peer_id: bytes,
        timeout: float = PING_TIMEOUT,
        send_callback: Optional[Callable[[bytes, bytes], None]] = None,
    ) -> PingResult:
        """
        Send a ping and wait for response.

        Args:
            peer_id: Peer to ping
            timeout: Timeout in seconds
            send_callback: Function to send packet

        Returns:
            PingResult
        """
        with self._lock:
            seq = self._ping_seq
            self._ping_seq += 1
            event = threading.Event()
            self._pending_pings[seq] = (peer_id, time.time(), event)
            self._stats["pings_sent"] += 1

        if send_callback:
            pkt = self.encode_ping_request(seq)
            send_callback(peer_id, pkt)

        # Wait for response
        if event.wait(timeout):
            with self._lock:
                _, sent_time, _ = self._pending_pings.pop(seq, (None, 0, None))
                rtt = (time.time() - sent_time) * 1000  # ms

            return PingResult(
                peer_id=peer_id,
                seq=seq,
                rtt_ms=rtt,
                success=True,
            )
        else:
            with self._lock:
                self._pending_pings.pop(seq, None)

            return PingResult(
                peer_id=peer_id,
                seq=seq,
                rtt_ms=0,
                success=False,
                error="Timeout",
            )

    def handle_ping_request(self, from_peer: bytes, seq: int) -> bytes:
        """
        Handle incoming ping request.

        Args:
            from_peer: Peer that sent ping
            seq: Sequence number

        Returns:
            Ping response packet
        """
        self._stats["pings_received"] += 1
        self._stats["pongs_sent"] += 1
        return self.encode_ping_response(seq)

    def handle_ping_response(self, from_peer: bytes, seq: int) -> None:
        """Handle incoming ping response."""
        with self._lock:
            self._stats["pongs_received"] += 1
            if seq in self._pending_pings:
                _, _, event = self._pending_pings[seq]
                event.set()

    def trace(
        self,
        destination: bytes,
        max_hops: int = TRACE_MAX_HOPS,
        timeout: float = TRACE_TIMEOUT,
        send_callback: Optional[Callable[[bytes, bytes, int], None]] = None,
    ) -> TraceResult:
        """
        Trace route to destination.

        Args:
            destination: Destination node
            max_hops: Maximum hops to trace
            timeout: Timeout per hop
            send_callback: Function to send packet (next_hop, data, ttl)

        Returns:
            TraceResult
        """
        hops: List[TraceHop] = []

        with self._lock:
            trace_id = self._trace_seq
            self._trace_seq += 1

        for ttl in range(1, max_hops + 1):
            with self._lock:
                event = threading.Event()
                self._pending_traces[trace_id] = (destination, hops, event)
                self._stats["traces_sent"] += 1

            if send_callback:
                pkt = self.encode_trace_request(trace_id, ttl, destination)
                send_callback(destination, pkt, ttl)

            # Wait for response
            start = time.time()
            if event.wait(timeout / max_hops):
                rtt = (time.time() - start) * 1000

                with self._lock:
                    if trace_id in self._pending_traces:
                        _, current_hops, _ = self._pending_traces[trace_id]
                        if current_hops:
                            last_hop = current_hops[-1]
                            last_hop.rtt_ms = rtt

                            # Check if we reached destination
                            if last_hop.node_id == destination:
                                self._pending_traces.pop(trace_id, None)
                                return TraceResult(
                                    destination=destination,
                                    hops=current_hops,
                                    complete=True,
                                )
            else:
                # Timeout for this hop
                hops.append(TraceHop(
                    hop_num=ttl,
                    node_id=b"\x00" * 16,  # Unknown
                    rtt_ms=0,
                ))

        with self._lock:
            self._pending_traces.pop(trace_id, None)

        return TraceResult(
            destination=destination,
            hops=hops,
            complete=False,
            error="Max hops exceeded",
        )

    def handle_trace_request(
        self,
        from_peer: bytes,
        trace_id: int,
        ttl: int,
        destination: bytes,
    ) -> Optional[bytes]:
        """
        Handle incoming trace request.

        Args:
            from_peer: Peer that sent trace
            trace_id: Trace ID
            ttl: Current TTL
            destination: Final destination

        Returns:
            Trace response if TTL expired or we are destination, None otherwise
        """
        if destination == self._my_id or ttl <= 1:
            # We are the destination or TTL expired
            return self.encode_trace_response(
                trace_id,
                self._my_id,
                is_destination=(destination == self._my_id),
            )
        # Forward with decremented TTL (handled by routing layer)
        return None

    def handle_trace_response(
        self,
        trace_id: int,
        responder_id: bytes,
        is_destination: bool,
    ) -> None:
        """Handle incoming trace response."""
        with self._lock:
            self._stats["trace_responses"] += 1

            if trace_id in self._pending_traces:
                dest, hops, event = self._pending_traces[trace_id]
                hops.append(TraceHop(
                    hop_num=len(hops) + 1,
                    node_id=responder_id,
                    rtt_ms=0,  # Will be filled in by trace()
                ))
                event.set()

    def encode_ping_request(self, seq: int) -> bytes:
        """Encode ping request."""
        timestamp = int(time.time() * 1000)  # ms
        return struct.pack(
            ">BIQ",
            OperationsMsgType.PING_REQUEST,
            seq,
            timestamp,
        )

    def encode_ping_response(self, seq: int) -> bytes:
        """Encode ping response."""
        timestamp = int(time.time() * 1000)
        return struct.pack(
            ">BIQ",
            OperationsMsgType.PING_RESPONSE,
            seq,
            timestamp,
        )

    def decode_ping(self, data: bytes) -> Tuple[int, int, int]:
        """
        Decode ping message.

        Returns:
            Tuple of (msg_type, seq, timestamp)
        """
        if len(data) < 13:
            raise ValueError("Ping too short")

        msg_type, seq, timestamp = struct.unpack(">BIQ", data[:13])
        return msg_type, seq, timestamp

    def encode_trace_request(self, trace_id: int, ttl: int, destination: bytes) -> bytes:
        """Encode trace request."""
        return struct.pack(
            ">BIB",
            OperationsMsgType.TRACE_REQUEST,
            trace_id,
            ttl,
        ) + destination

    def encode_trace_response(
        self,
        trace_id: int,
        responder_id: bytes,
        is_destination: bool,
    ) -> bytes:
        """Encode trace response."""
        flags = 0x01 if is_destination else 0x00
        return struct.pack(
            ">BIB",
            OperationsMsgType.TRACE_RESPONSE,
            trace_id,
            flags,
        ) + responder_id

    def decode_trace_request(self, data: bytes) -> Tuple[int, int, bytes]:
        """
        Decode trace request.

        Returns:
            Tuple of (trace_id, ttl, destination)
        """
        if len(data) < 22:
            raise ValueError("Trace request too short")

        _, trace_id, ttl = struct.unpack(">BIB", data[:6])
        destination = data[6:22]
        return trace_id, ttl, destination

    def decode_trace_response(self, data: bytes) -> Tuple[int, bytes, bool]:
        """
        Decode trace response.

        Returns:
            Tuple of (trace_id, responder_id, is_destination)
        """
        if len(data) < 22:
            raise ValueError("Trace response too short")

        _, trace_id, flags = struct.unpack(">BIB", data[:6])
        responder_id = data[6:22]
        is_destination = bool(flags & 0x01)
        return trace_id, responder_id, is_destination

    def stats(self) -> Dict[str, Any]:
        """Get diagnostics statistics."""
        return self._stats.copy()
