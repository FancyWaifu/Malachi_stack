"""
Protocol features for Malachi.

This module implements:
- Multicast Groups
- QoS Priority Classes
- Connection-Oriented Mode
- Streaming Support
- Request-Response Pattern
"""

import time
import threading
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple, List, Callable, Any, Union
from enum import IntEnum
from collections import deque
import hashlib
import os

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Multicast
MULTICAST_MAX_GROUPS = 256  # Maximum groups per node
MULTICAST_TTL_DEFAULT = 64  # Default TTL for multicast
MULTICAST_GROUP_PREFIX = b"\xff\x00"  # Multicast group ID prefix

# QoS
QOS_CLASSES = 8  # Number of priority classes (0-7)
QOS_DEFAULT_CLASS = 4  # Default priority (middle)

# Connection
CONN_TIMEOUT = 30.0  # Connection establishment timeout
CONN_MAX_RETRIES = 5  # Connection retry limit

# Streaming
STREAM_MAX_STREAMS = 256  # Max concurrent streams
STREAM_BUFFER_SIZE = 65536  # Stream buffer size

# Request-Response
REQ_TIMEOUT = 30.0  # Request timeout
REQ_MAX_PENDING = 1024  # Max pending requests


# =============================================================================
# Message Types
# =============================================================================

class ProtocolMsgType(IntEnum):
    """Protocol message types."""
    # Multicast
    MCAST_JOIN = 0x20
    MCAST_LEAVE = 0x21
    MCAST_DATA = 0x22
    MCAST_ANNOUNCE = 0x23

    # QoS
    QOS_UPDATE = 0x30

    # Connection
    CONN_SYN = 0x40
    CONN_SYN_ACK = 0x41
    CONN_ACK = 0x42
    CONN_FIN = 0x43
    CONN_RST = 0x44

    # Streaming
    STREAM_OPEN = 0x50
    STREAM_DATA = 0x51
    STREAM_CLOSE = 0x52
    STREAM_RST = 0x53

    # Request-Response
    REQUEST = 0x60
    RESPONSE = 0x61
    CANCEL = 0x62


# =============================================================================
# Multicast Groups
# =============================================================================

@dataclass
class MulticastGroup:
    """Represents a multicast group."""
    group_id: bytes
    name: str
    members: Set[bytes] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    ttl: int = MULTICAST_TTL_DEFAULT


class MulticastManager:
    """
    Manages multicast group membership and message delivery.

    Supports creating, joining, leaving groups and sending/receiving
    multicast messages.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize multicast manager.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id
        self._groups: Dict[bytes, MulticastGroup] = {}
        self._my_groups: Set[bytes] = set()  # Groups we belong to

        # Callbacks
        self._on_message: Optional[Callable[[bytes, bytes, bytes], None]] = None
        self._on_join: Optional[Callable[[bytes, bytes], None]] = None
        self._on_leave: Optional[Callable[[bytes, bytes], None]] = None

    def create_group(self, name: str, ttl: int = MULTICAST_TTL_DEFAULT) -> bytes:
        """
        Create a new multicast group.

        Args:
            name: Human-readable group name
            ttl: Time-to-live for messages

        Returns:
            Group ID
        """
        with self._lock:
            # Generate group ID from name
            group_id = MULTICAST_GROUP_PREFIX + hashlib.blake2b(
                name.encode(), digest_size=14
            ).digest()

            if group_id not in self._groups:
                self._groups[group_id] = MulticastGroup(
                    group_id=group_id,
                    name=name,
                    ttl=ttl,
                )

            return group_id

    def join_group(self, group_id: bytes) -> bool:
        """
        Join a multicast group.

        Args:
            group_id: Group to join

        Returns:
            True if joined successfully
        """
        with self._lock:
            if group_id not in self._groups:
                self._groups[group_id] = MulticastGroup(
                    group_id=group_id,
                    name=f"group_{group_id.hex()[:8]}",
                )

            self._groups[group_id].members.add(self._my_id)
            self._my_groups.add(group_id)
            logger.info(f"Joined multicast group {group_id.hex()[:8]}")
            return True

    def leave_group(self, group_id: bytes) -> bool:
        """
        Leave a multicast group.

        Args:
            group_id: Group to leave

        Returns:
            True if left successfully
        """
        with self._lock:
            if group_id in self._groups:
                self._groups[group_id].members.discard(self._my_id)
            self._my_groups.discard(group_id)
            logger.info(f"Left multicast group {group_id.hex()[:8]}")
            return True

    def is_member(self, group_id: bytes) -> bool:
        """Check if we are a member of a group."""
        with self._lock:
            return group_id in self._my_groups

    def add_remote_member(self, group_id: bytes, member_id: bytes) -> None:
        """Track a remote member joining a group."""
        with self._lock:
            if group_id in self._groups:
                self._groups[group_id].members.add(member_id)
                if self._on_join:
                    self._on_join(group_id, member_id)

    def remove_remote_member(self, group_id: bytes, member_id: bytes) -> None:
        """Track a remote member leaving a group."""
        with self._lock:
            if group_id in self._groups:
                self._groups[group_id].members.discard(member_id)
                if self._on_leave:
                    self._on_leave(group_id, member_id)

    def get_group_members(self, group_id: bytes) -> Set[bytes]:
        """Get members of a group."""
        with self._lock:
            if group_id in self._groups:
                return self._groups[group_id].members.copy()
            return set()

    def get_my_groups(self) -> Set[bytes]:
        """Get groups we belong to."""
        with self._lock:
            return self._my_groups.copy()

    def encode_join(self, group_id: bytes) -> bytes:
        """Encode join message."""
        return bytes([ProtocolMsgType.MCAST_JOIN]) + group_id

    def encode_leave(self, group_id: bytes) -> bytes:
        """Encode leave message."""
        return bytes([ProtocolMsgType.MCAST_LEAVE]) + group_id

    def encode_data(self, group_id: bytes, data: bytes, ttl: int = MULTICAST_TTL_DEFAULT) -> bytes:
        """Encode multicast data message."""
        return bytes([ProtocolMsgType.MCAST_DATA, ttl]) + group_id + data

    def decode_message(self, data: bytes) -> Tuple[int, bytes, bytes]:
        """
        Decode multicast message.

        Returns:
            Tuple of (msg_type, group_id, payload)
        """
        if len(data) < 17:  # type + group_id (16)
            raise ValueError("Message too short")

        msg_type = data[0]

        if msg_type == ProtocolMsgType.MCAST_DATA:
            ttl = data[1]
            group_id = data[2:18]
            payload = data[18:]
        else:
            group_id = data[1:17]
            payload = data[17:]

        return msg_type, group_id, payload

    def stats(self) -> Dict[str, Any]:
        """Get multicast statistics."""
        with self._lock:
            return {
                "groups_known": len(self._groups),
                "groups_joined": len(self._my_groups),
                "total_members": sum(len(g.members) for g in self._groups.values()),
            }


# =============================================================================
# QoS Priority Classes
# =============================================================================

class QoSClass(IntEnum):
    """Quality of Service priority classes."""
    CONTROL = 7  # Highest - control plane messages
    REALTIME = 6  # Real-time audio/video
    INTERACTIVE = 5  # Interactive applications
    STREAMING = 4  # Streaming media
    BULK_HIGH = 3  # High-priority bulk
    BULK_DEFAULT = 2  # Default bulk
    BULK_LOW = 1  # Low-priority bulk
    BACKGROUND = 0  # Lowest - background traffic


@dataclass
class QoSQueue:
    """A priority queue for a specific QoS class."""
    priority: int
    queue: deque = field(default_factory=deque)
    bytes_sent: int = 0
    packets_sent: int = 0
    bytes_dropped: int = 0
    max_size: int = 65536


class QoSScheduler:
    """
    QoS scheduler with strict priority queuing.

    Higher priority queues are serviced before lower ones.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._queues: Dict[int, QoSQueue] = {
            i: QoSQueue(priority=i) for i in range(QOS_CLASSES)
        }
        self._default_class = QOS_DEFAULT_CLASS

    def enqueue(
        self,
        data: bytes,
        priority: int = None,
        dest: bytes = None,
    ) -> bool:
        """
        Enqueue data for transmission.

        Args:
            data: Data to queue
            priority: QoS class (0-7, higher is better)
            dest: Destination peer ID

        Returns:
            True if queued successfully
        """
        if priority is None:
            priority = self._default_class

        priority = max(0, min(QOS_CLASSES - 1, priority))

        with self._lock:
            queue = self._queues[priority]

            # Check queue capacity
            current_size = sum(len(item[0]) for item in queue.queue)
            if current_size + len(data) > queue.max_size:
                queue.bytes_dropped += len(data)
                return False

            queue.queue.append((data, dest, time.time()))
            return True

    def dequeue(self) -> Optional[Tuple[bytes, bytes]]:
        """
        Dequeue highest priority data.

        Returns:
            Tuple of (data, dest) or None if empty
        """
        with self._lock:
            # Service queues in priority order
            for priority in range(QOS_CLASSES - 1, -1, -1):
                queue = self._queues[priority]
                if queue.queue:
                    data, dest, _ = queue.queue.popleft()
                    queue.bytes_sent += len(data)
                    queue.packets_sent += 1
                    return data, dest

            return None

    def has_pending(self) -> bool:
        """Check if any data is pending."""
        with self._lock:
            return any(q.queue for q in self._queues.values())

    def set_queue_max_size(self, priority: int, max_size: int) -> None:
        """Set maximum size for a queue."""
        with self._lock:
            if priority in self._queues:
                self._queues[priority].max_size = max_size

    def encode_qos_header(self, priority: int) -> bytes:
        """Encode QoS header for packet."""
        return bytes([priority])

    def stats(self) -> Dict[str, Any]:
        """Get QoS statistics."""
        with self._lock:
            stats = {}
            for priority, queue in self._queues.items():
                stats[f"class_{priority}"] = {
                    "name": QoSClass(priority).name if priority in [e.value for e in QoSClass] else f"CLASS_{priority}",
                    "pending_items": len(queue.queue),
                    "bytes_sent": queue.bytes_sent,
                    "packets_sent": queue.packets_sent,
                    "bytes_dropped": queue.bytes_dropped,
                }
            return stats


# =============================================================================
# Connection-Oriented Mode
# =============================================================================

class ConnectionState(IntEnum):
    """Connection states."""
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_WAIT_1 = 4
    FIN_WAIT_2 = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    TIME_WAIT = 8


@dataclass
class Connection:
    """Represents a connection to a peer."""
    conn_id: int
    peer_id: bytes
    state: ConnectionState = ConnectionState.CLOSED
    created_at: float = field(default_factory=time.time)
    established_at: Optional[float] = None

    # Sequence numbers
    local_seq: int = 0
    remote_seq: int = 0

    # Connection options
    mtu: int = 1400
    window_size: int = 65536

    # Retransmission state
    syn_retries: int = 0
    fin_retries: int = 0


class ConnectionManager:
    """
    Manages connection-oriented sessions.

    Implements TCP-like connection establishment and teardown.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize connection manager.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id
        self._next_conn_id = 1
        self._connections: Dict[int, Connection] = {}
        self._peer_connections: Dict[bytes, int] = {}  # peer_id -> conn_id

        # Callbacks
        self._on_established: Optional[Callable[[int, bytes], None]] = None
        self._on_closed: Optional[Callable[[int, bytes], None]] = None
        self._on_data: Optional[Callable[[int, bytes], None]] = None

    def connect(self, peer_id: bytes) -> int:
        """
        Initiate connection to peer.

        Args:
            peer_id: Peer to connect to

        Returns:
            Connection ID
        """
        with self._lock:
            if peer_id in self._peer_connections:
                return self._peer_connections[peer_id]

            conn_id = self._next_conn_id
            self._next_conn_id += 1

            conn = Connection(
                conn_id=conn_id,
                peer_id=peer_id,
                state=ConnectionState.SYN_SENT,
                local_seq=int.from_bytes(os.urandom(4), "big"),
            )

            self._connections[conn_id] = conn
            self._peer_connections[peer_id] = conn_id

            logger.debug(f"Initiating connection {conn_id} to {peer_id.hex()[:8]}")
            return conn_id

    def accept(self, peer_id: bytes, remote_seq: int) -> int:
        """
        Accept incoming connection.

        Args:
            peer_id: Connecting peer
            remote_seq: Peer's initial sequence

        Returns:
            Connection ID
        """
        with self._lock:
            if peer_id in self._peer_connections:
                conn_id = self._peer_connections[peer_id]
                conn = self._connections[conn_id]
                conn.remote_seq = remote_seq
                conn.state = ConnectionState.SYN_RECEIVED
                return conn_id

            conn_id = self._next_conn_id
            self._next_conn_id += 1

            conn = Connection(
                conn_id=conn_id,
                peer_id=peer_id,
                state=ConnectionState.SYN_RECEIVED,
                local_seq=int.from_bytes(os.urandom(4), "big"),
                remote_seq=remote_seq,
            )

            self._connections[conn_id] = conn
            self._peer_connections[peer_id] = conn_id

            return conn_id

    def on_syn_ack(self, conn_id: int, remote_seq: int) -> bool:
        """
        Handle SYN-ACK received.

        Args:
            conn_id: Connection ID
            remote_seq: Peer's sequence number

        Returns:
            True if state transition valid
        """
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn or conn.state != ConnectionState.SYN_SENT:
                return False

            conn.remote_seq = remote_seq
            conn.state = ConnectionState.ESTABLISHED
            conn.established_at = time.time()

            logger.info(f"Connection {conn_id} established")
            if self._on_established:
                self._on_established(conn_id, conn.peer_id)

            return True

    def on_ack(self, conn_id: int) -> bool:
        """Handle ACK (completes 3-way handshake for server)."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn:
                return False

            if conn.state == ConnectionState.SYN_RECEIVED:
                conn.state = ConnectionState.ESTABLISHED
                conn.established_at = time.time()
                if self._on_established:
                    self._on_established(conn_id, conn.peer_id)
                return True

            return False

    def close(self, conn_id: int) -> bool:
        """
        Initiate connection close.

        Args:
            conn_id: Connection to close

        Returns:
            True if close initiated
        """
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn or conn.state != ConnectionState.ESTABLISHED:
                return False

            conn.state = ConnectionState.FIN_WAIT_1
            return True

    def on_fin(self, conn_id: int) -> bool:
        """Handle FIN received."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn:
                return False

            if conn.state == ConnectionState.ESTABLISHED:
                conn.state = ConnectionState.CLOSE_WAIT
                return True
            elif conn.state == ConnectionState.FIN_WAIT_1:
                conn.state = ConnectionState.TIME_WAIT
                return True
            elif conn.state == ConnectionState.FIN_WAIT_2:
                conn.state = ConnectionState.TIME_WAIT
                return True

            return False

    def finalize_close(self, conn_id: int) -> None:
        """Finalize connection close."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if conn:
                peer_id = conn.peer_id
                del self._connections[conn_id]
                self._peer_connections.pop(peer_id, None)
                if self._on_closed:
                    self._on_closed(conn_id, peer_id)

    def get_connection(self, conn_id: int) -> Optional[Connection]:
        """Get connection by ID."""
        with self._lock:
            return self._connections.get(conn_id)

    def get_connection_by_peer(self, peer_id: bytes) -> Optional[Connection]:
        """Get connection by peer ID."""
        with self._lock:
            conn_id = self._peer_connections.get(peer_id)
            if conn_id:
                return self._connections.get(conn_id)
            return None

    def is_connected(self, peer_id: bytes) -> bool:
        """Check if connected to peer."""
        conn = self.get_connection_by_peer(peer_id)
        return conn is not None and conn.state == ConnectionState.ESTABLISHED

    def encode_syn(self, conn_id: int) -> bytes:
        """Encode SYN message."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn:
                raise ValueError(f"Unknown connection {conn_id}")

            return struct.pack(
                ">BIHH",
                ProtocolMsgType.CONN_SYN,
                conn.local_seq,
                conn.mtu,
                conn.window_size >> 8,  # Window in 256-byte units
            )

    def encode_syn_ack(self, conn_id: int) -> bytes:
        """Encode SYN-ACK message."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn:
                raise ValueError(f"Unknown connection {conn_id}")

            return struct.pack(
                ">BIIHH",
                ProtocolMsgType.CONN_SYN_ACK,
                conn.local_seq,
                conn.remote_seq + 1,
                conn.mtu,
                conn.window_size >> 8,
            )

    def encode_ack(self, conn_id: int) -> bytes:
        """Encode ACK message."""
        with self._lock:
            conn = self._connections.get(conn_id)
            if not conn:
                raise ValueError(f"Unknown connection {conn_id}")

            return struct.pack(
                ">BI",
                ProtocolMsgType.CONN_ACK,
                conn.remote_seq + 1,
            )

    def encode_fin(self, conn_id: int) -> bytes:
        """Encode FIN message."""
        return struct.pack(">BI", ProtocolMsgType.CONN_FIN, conn_id)

    def encode_rst(self, conn_id: int) -> bytes:
        """Encode RST message."""
        return struct.pack(">BI", ProtocolMsgType.CONN_RST, conn_id)

    def stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        with self._lock:
            by_state = {}
            for conn in self._connections.values():
                state_name = conn.state.name
                by_state[state_name] = by_state.get(state_name, 0) + 1

            return {
                "total_connections": len(self._connections),
                "by_state": by_state,
            }


# =============================================================================
# Streaming Support
# =============================================================================

class StreamState(IntEnum):
    """Stream states."""
    OPENING = 0
    OPEN = 1
    HALF_CLOSED_LOCAL = 2
    HALF_CLOSED_REMOTE = 3
    CLOSED = 4


@dataclass
class Stream:
    """Represents a bidirectional stream within a connection."""
    stream_id: int
    conn_id: int
    state: StreamState = StreamState.OPENING

    # Buffers
    send_buffer: bytearray = field(default_factory=bytearray)
    recv_buffer: bytearray = field(default_factory=bytearray)

    # Flow control
    send_window: int = STREAM_BUFFER_SIZE
    recv_window: int = STREAM_BUFFER_SIZE

    # Statistics
    bytes_sent: int = 0
    bytes_received: int = 0


class StreamManager:
    """
    Manages multiplexed streams within connections.

    Similar to HTTP/2 or QUIC stream multiplexing.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._streams: Dict[Tuple[int, int], Stream] = {}  # (conn_id, stream_id)
        self._next_stream_id: Dict[int, int] = {}  # conn_id -> next stream id

        # Callbacks
        self._on_stream_open: Optional[Callable[[int, int], None]] = None
        self._on_stream_close: Optional[Callable[[int, int], None]] = None
        self._on_stream_data: Optional[Callable[[int, int, bytes], None]] = None

    def _get_next_id(self, conn_id: int, is_client: bool) -> int:
        """Get next stream ID for connection."""
        if conn_id not in self._next_stream_id:
            # Client uses odd IDs, server uses even
            self._next_stream_id[conn_id] = 1 if is_client else 2

        stream_id = self._next_stream_id[conn_id]
        self._next_stream_id[conn_id] += 2
        return stream_id

    def open_stream(self, conn_id: int, is_client: bool = True) -> int:
        """
        Open a new stream on a connection.

        Args:
            conn_id: Connection ID
            is_client: True if we initiated the connection

        Returns:
            Stream ID
        """
        with self._lock:
            stream_id = self._get_next_id(conn_id, is_client)

            stream = Stream(
                stream_id=stream_id,
                conn_id=conn_id,
                state=StreamState.OPEN,
            )

            self._streams[(conn_id, stream_id)] = stream

            if self._on_stream_open:
                self._on_stream_open(conn_id, stream_id)

            return stream_id

    def accept_stream(self, conn_id: int, stream_id: int) -> bool:
        """Accept incoming stream."""
        with self._lock:
            key = (conn_id, stream_id)
            if key in self._streams:
                return True

            stream = Stream(
                stream_id=stream_id,
                conn_id=conn_id,
                state=StreamState.OPEN,
            )

            self._streams[key] = stream

            if self._on_stream_open:
                self._on_stream_open(conn_id, stream_id)

            return True

    def write(self, conn_id: int, stream_id: int, data: bytes) -> int:
        """
        Write data to stream.

        Args:
            conn_id: Connection ID
            stream_id: Stream ID
            data: Data to write

        Returns:
            Bytes queued (may be less than len(data) if flow controlled)
        """
        with self._lock:
            stream = self._streams.get((conn_id, stream_id))
            if not stream or stream.state not in (StreamState.OPEN, StreamState.HALF_CLOSED_REMOTE):
                return 0

            # Apply flow control
            available = stream.send_window - len(stream.send_buffer)
            to_queue = min(len(data), available)

            if to_queue > 0:
                stream.send_buffer.extend(data[:to_queue])

            return to_queue

    def read(self, conn_id: int, stream_id: int, max_bytes: int = -1) -> bytes:
        """
        Read data from stream.

        Args:
            conn_id: Connection ID
            stream_id: Stream ID
            max_bytes: Maximum bytes to read (-1 for all)

        Returns:
            Data read
        """
        with self._lock:
            stream = self._streams.get((conn_id, stream_id))
            if not stream:
                return b""

            if max_bytes < 0:
                data = bytes(stream.recv_buffer)
                stream.recv_buffer.clear()
            else:
                data = bytes(stream.recv_buffer[:max_bytes])
                del stream.recv_buffer[:max_bytes]

            # Increase receive window
            stream.recv_window += len(data)

            return data

    def receive_data(self, conn_id: int, stream_id: int, data: bytes) -> None:
        """Process received stream data."""
        with self._lock:
            key = (conn_id, stream_id)

            if key not in self._streams:
                self.accept_stream(conn_id, stream_id)

            stream = self._streams[key]
            if stream.state in (StreamState.OPEN, StreamState.HALF_CLOSED_LOCAL):
                stream.recv_buffer.extend(data)
                stream.bytes_received += len(data)
                stream.recv_window -= len(data)

                if self._on_stream_data:
                    self._on_stream_data(conn_id, stream_id, data)

    def close_stream(self, conn_id: int, stream_id: int) -> None:
        """Close stream for sending."""
        with self._lock:
            stream = self._streams.get((conn_id, stream_id))
            if not stream:
                return

            if stream.state == StreamState.OPEN:
                stream.state = StreamState.HALF_CLOSED_LOCAL
            elif stream.state == StreamState.HALF_CLOSED_REMOTE:
                stream.state = StreamState.CLOSED
                if self._on_stream_close:
                    self._on_stream_close(conn_id, stream_id)

    def remote_close(self, conn_id: int, stream_id: int) -> None:
        """Handle remote stream close."""
        with self._lock:
            stream = self._streams.get((conn_id, stream_id))
            if not stream:
                return

            if stream.state == StreamState.OPEN:
                stream.state = StreamState.HALF_CLOSED_REMOTE
            elif stream.state == StreamState.HALF_CLOSED_LOCAL:
                stream.state = StreamState.CLOSED
                if self._on_stream_close:
                    self._on_stream_close(conn_id, stream_id)

    def get_pending_send(self, conn_id: int, stream_id: int, max_bytes: int) -> bytes:
        """Get pending data to send."""
        with self._lock:
            stream = self._streams.get((conn_id, stream_id))
            if not stream:
                return b""

            data = bytes(stream.send_buffer[:max_bytes])
            del stream.send_buffer[:max_bytes]
            stream.bytes_sent += len(data)

            return data

    def encode_open(self, conn_id: int, stream_id: int) -> bytes:
        """Encode stream open message."""
        return struct.pack(">BII", ProtocolMsgType.STREAM_OPEN, conn_id, stream_id)

    def encode_data(self, conn_id: int, stream_id: int, data: bytes) -> bytes:
        """Encode stream data message."""
        return struct.pack(">BII", ProtocolMsgType.STREAM_DATA, conn_id, stream_id) + data

    def encode_close(self, conn_id: int, stream_id: int) -> bytes:
        """Encode stream close message."""
        return struct.pack(">BII", ProtocolMsgType.STREAM_CLOSE, conn_id, stream_id)

    def stats(self) -> Dict[str, Any]:
        """Get stream statistics."""
        with self._lock:
            by_state = {}
            total_buffered = 0

            for stream in self._streams.values():
                state_name = stream.state.name
                by_state[state_name] = by_state.get(state_name, 0) + 1
                total_buffered += len(stream.send_buffer) + len(stream.recv_buffer)

            return {
                "total_streams": len(self._streams),
                "by_state": by_state,
                "total_buffered": total_buffered,
            }


# =============================================================================
# Request-Response Pattern
# =============================================================================

@dataclass
class PendingRequest:
    """A pending request awaiting response."""
    request_id: int
    peer_id: bytes
    method: str
    data: bytes
    sent_at: float = field(default_factory=time.time)
    timeout: float = REQ_TIMEOUT
    callback: Optional[Callable[[Optional[bytes], Optional[Exception]], None]] = None


@dataclass
class Response:
    """A response to a request."""
    request_id: int
    status: int
    data: bytes


class RequestResponseManager:
    """
    Implements request-response messaging pattern.

    Supports async callbacks and timeouts.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._next_request_id = 1
        self._pending: Dict[int, PendingRequest] = {}

        # Request handlers
        self._handlers: Dict[str, Callable[[bytes, bytes], Tuple[int, bytes]]] = {}

        # Timeout thread
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start timeout thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._timeout_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop timeout thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def register_handler(
        self,
        method: str,
        handler: Callable[[bytes, bytes], Tuple[int, bytes]],
    ) -> None:
        """
        Register a request handler.

        Args:
            method: Method name
            handler: Handler function (peer_id, data) -> (status, response_data)
        """
        self._handlers[method] = handler

    def request(
        self,
        peer_id: bytes,
        method: str,
        data: bytes = b"",
        timeout: float = REQ_TIMEOUT,
        callback: Optional[Callable[[Optional[bytes], Optional[Exception]], None]] = None,
    ) -> int:
        """
        Send a request.

        Args:
            peer_id: Destination peer
            method: Method name
            data: Request data
            timeout: Timeout in seconds
            callback: Called with (response, error)

        Returns:
            Request ID
        """
        with self._lock:
            request_id = self._next_request_id
            self._next_request_id += 1

            self._pending[request_id] = PendingRequest(
                request_id=request_id,
                peer_id=peer_id,
                method=method,
                data=data,
                timeout=timeout,
                callback=callback,
            )

            return request_id

    def handle_request(self, peer_id: bytes, request_id: int, method: str, data: bytes) -> Tuple[int, bytes]:
        """
        Handle incoming request.

        Args:
            peer_id: Requesting peer
            request_id: Request ID
            method: Method name
            data: Request data

        Returns:
            Tuple of (status, response_data)
        """
        handler = self._handlers.get(method)
        if handler:
            try:
                return handler(peer_id, data)
            except Exception as e:
                logger.error(f"Handler error for {method}: {e}")
                return 500, str(e).encode()
        else:
            return 404, b"Method not found"

    def handle_response(self, request_id: int, status: int, data: bytes) -> None:
        """
        Handle incoming response.

        Args:
            request_id: Request ID being responded to
            status: Response status code
            data: Response data
        """
        with self._lock:
            request = self._pending.pop(request_id, None)

        if request and request.callback:
            if status >= 400:
                request.callback(None, Exception(f"Status {status}: {data.decode(errors='replace')}"))
            else:
                request.callback(data, None)

    def cancel(self, request_id: int) -> bool:
        """Cancel a pending request."""
        with self._lock:
            request = self._pending.pop(request_id, None)
            if request and request.callback:
                request.callback(None, Exception("Cancelled"))
            return request is not None

    def _timeout_loop(self) -> None:
        """Check for timed-out requests."""
        while self._running:
            time.sleep(1.0)

            with self._lock:
                now = time.time()
                timed_out = []

                for req_id, req in self._pending.items():
                    if (now - req.sent_at) > req.timeout:
                        timed_out.append(req_id)

                for req_id in timed_out:
                    req = self._pending.pop(req_id)
                    if req.callback:
                        req.callback(None, TimeoutError("Request timed out"))

    def encode_request(self, request_id: int, method: str, data: bytes) -> bytes:
        """Encode request message."""
        method_bytes = method.encode("utf-8")
        return struct.pack(">BIB", ProtocolMsgType.REQUEST, request_id, len(method_bytes)) + method_bytes + data

    def encode_response(self, request_id: int, status: int, data: bytes) -> bytes:
        """Encode response message."""
        return struct.pack(">BIH", ProtocolMsgType.RESPONSE, request_id, status) + data

    def encode_cancel(self, request_id: int) -> bytes:
        """Encode cancel message."""
        return struct.pack(">BI", ProtocolMsgType.CANCEL, request_id)

    def decode_request(self, data: bytes) -> Tuple[int, str, bytes]:
        """Decode request message."""
        if len(data) < 6:
            raise ValueError("Request too short")

        request_id = struct.unpack(">I", data[1:5])[0]
        method_len = data[5]

        if len(data) < 6 + method_len:
            raise ValueError("Request truncated")

        method = data[6:6 + method_len].decode("utf-8")
        payload = data[6 + method_len:]

        return request_id, method, payload

    def decode_response(self, data: bytes) -> Tuple[int, int, bytes]:
        """Decode response message."""
        if len(data) < 7:
            raise ValueError("Response too short")

        request_id = struct.unpack(">I", data[1:5])[0]
        status = struct.unpack(">H", data[5:7])[0]
        payload = data[7:]

        return request_id, status, payload

    def stats(self) -> Dict[str, Any]:
        """Get request-response statistics."""
        with self._lock:
            return {
                "pending_requests": len(self._pending),
                "registered_handlers": len(self._handlers),
            }
