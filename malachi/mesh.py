#!/usr/bin/env python3
"""
Malachi Mesh Networking

Comprehensive networking layer that integrates:
- Multi-hop packet forwarding
- Reliable delivery (ARQ)
- NAT traversal (STUN/TURN)
- Relay nodes
- Bootstrap nodes
- DHT (Kademlia)
- Gossip protocol
- Service discovery
- File transfer
"""

import os
import sys
import time
import json
import socket
import struct
import hashlib
import threading
import logging
import random
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Callable, Any
from collections import defaultdict
from queue import Queue, Empty, PriorityQueue
from enum import IntEnum
import heapq

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

MALACHI_PORT = 7891  # Default UDP port
STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun2.l.google.com", 19302),
]
BOOTSTRAP_NODES = [
    # Public bootstrap nodes (placeholder - would be real servers)
    # ("bootstrap1.malachi.network", 7891),
]

# Timing
HEARTBEAT_INTERVAL = 30.0
PEER_TIMEOUT = 120.0
ROUTE_UPDATE_INTERVAL = 30.0
DHT_REFRESH_INTERVAL = 3600.0
GOSSIP_INTERVAL = 5.0

# Limits
MAX_HOPS = 16
MAX_PEERS = 256
MAX_PENDING_ACKS = 1000
MAX_RETRIES = 5
RETRY_TIMEOUT = 2.0

# DHT
K_BUCKET_SIZE = 20  # Kademlia k parameter
ALPHA = 3  # Kademlia alpha (parallel lookups)

# File transfer
CHUNK_SIZE = 32768  # 32KB chunks


# =============================================================================
# Message Types
# =============================================================================

class MeshMsgType(IntEnum):
    """Mesh network message types."""
    # Core
    PING = 0x01
    PONG = 0x02
    DATA = 0x03
    ACK = 0x04

    # Routing
    FORWARD = 0x10
    ROUTE_REQUEST = 0x11
    ROUTE_REPLY = 0x12
    ROUTE_UPDATE = 0x13

    # DHT
    DHT_PING = 0x20
    DHT_PONG = 0x21
    DHT_FIND_NODE = 0x22
    DHT_FIND_NODE_REPLY = 0x23
    DHT_STORE = 0x24
    DHT_FIND_VALUE = 0x25
    DHT_FIND_VALUE_REPLY = 0x26

    # NAT
    STUN_REQUEST = 0x30
    STUN_RESPONSE = 0x31
    HOLE_PUNCH = 0x32
    RELAY_REQUEST = 0x33
    RELAY_DATA = 0x34

    # Gossip
    GOSSIP = 0x40
    GOSSIP_PULL = 0x41
    GOSSIP_PUSH = 0x42

    # Service Discovery
    SERVICE_ANNOUNCE = 0x50
    SERVICE_QUERY = 0x51
    SERVICE_REPLY = 0x52

    # File Transfer
    FILE_OFFER = 0x60
    FILE_REQUEST = 0x61
    FILE_CHUNK = 0x62
    FILE_ACK = 0x63
    FILE_COMPLETE = 0x64


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class PeerInfo:
    """Information about a network peer."""
    node_id: bytes
    address: Tuple[str, int]  # (ip, port)
    public_address: Optional[Tuple[str, int]] = None  # NAT-mapped address
    last_seen: float = field(default_factory=time.time)
    rtt_ms: float = 0.0
    is_relay: bool = False
    is_bootstrap: bool = False
    services: List[str] = field(default_factory=list)

    def is_alive(self) -> bool:
        return time.time() - self.last_seen < PEER_TIMEOUT


@dataclass
class PendingAck:
    """A message waiting for acknowledgment."""
    msg_id: int
    dest_node: bytes
    payload: bytes
    sent_at: float
    retries: int = 0
    callback: Optional[Callable[[bool], None]] = None


@dataclass
class RouteEntry:
    """Routing table entry."""
    destination: bytes
    next_hop: bytes
    metric: int  # hop count
    last_update: float = field(default_factory=time.time)

    def is_valid(self) -> bool:
        return self.metric < MAX_HOPS and time.time() - self.last_update < PEER_TIMEOUT * 2


@dataclass
class ServiceInfo:
    """A discovered service."""
    node_id: bytes
    service_type: str  # "http", "ssh", "file", etc.
    port: int
    metadata: Dict[str, str] = field(default_factory=dict)
    announced_at: float = field(default_factory=time.time)


@dataclass
class FileTransfer:
    """Active file transfer state."""
    transfer_id: bytes
    filename: str
    total_size: int
    chunk_size: int
    total_chunks: int
    received_chunks: Set[int] = field(default_factory=set)
    data: Dict[int, bytes] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)

    @property
    def progress(self) -> float:
        return len(self.received_chunks) / self.total_chunks if self.total_chunks > 0 else 0

    @property
    def is_complete(self) -> bool:
        return len(self.received_chunks) >= self.total_chunks


# =============================================================================
# DHT (Kademlia)
# =============================================================================

class KBucket:
    """A Kademlia k-bucket for storing peers at a specific distance."""

    def __init__(self, k: int = K_BUCKET_SIZE):
        self.k = k
        self.peers: List[PeerInfo] = []
        self._lock = threading.Lock()

    def add(self, peer: PeerInfo) -> bool:
        """Add peer to bucket. Returns True if added."""
        with self._lock:
            # Check if already present
            for i, p in enumerate(self.peers):
                if p.node_id == peer.node_id:
                    # Move to end (most recently seen)
                    self.peers.pop(i)
                    self.peers.append(peer)
                    return True

            # Add if room
            if len(self.peers) < self.k:
                self.peers.append(peer)
                return True

            # Bucket full - check if first entry is stale
            if not self.peers[0].is_alive():
                self.peers.pop(0)
                self.peers.append(peer)
                return True

            return False

    def remove(self, node_id: bytes) -> bool:
        """Remove peer from bucket."""
        with self._lock:
            for i, p in enumerate(self.peers):
                if p.node_id == node_id:
                    self.peers.pop(i)
                    return True
            return False

    def get_peers(self) -> List[PeerInfo]:
        """Get all peers in bucket."""
        with self._lock:
            return list(self.peers)


class KademliaTable:
    """Kademlia routing table with k-buckets."""

    def __init__(self, my_id: bytes):
        self.my_id = my_id
        self.buckets: List[KBucket] = [KBucket() for _ in range(160)]  # 160 bits for node ID
        self._lock = threading.RLock()

    @staticmethod
    def xor_distance(a: bytes, b: bytes) -> int:
        """Calculate XOR distance between two node IDs."""
        a_int = int.from_bytes(a[:16], 'big')
        b_int = int.from_bytes(b[:16], 'big')
        return a_int ^ b_int

    @staticmethod
    def bucket_index(distance: int) -> int:
        """Get bucket index for a given distance."""
        if distance == 0:
            return 0
        return distance.bit_length() - 1

    def add_peer(self, peer: PeerInfo) -> bool:
        """Add peer to appropriate bucket."""
        if peer.node_id == self.my_id:
            return False

        distance = self.xor_distance(self.my_id, peer.node_id)
        bucket_idx = self.bucket_index(distance)

        with self._lock:
            if bucket_idx < len(self.buckets):
                return self.buckets[bucket_idx].add(peer)
        return False

    def remove_peer(self, node_id: bytes) -> bool:
        """Remove peer from table."""
        distance = self.xor_distance(self.my_id, node_id)
        bucket_idx = self.bucket_index(distance)

        with self._lock:
            if bucket_idx < len(self.buckets):
                return self.buckets[bucket_idx].remove(node_id)
        return False

    def find_closest(self, target_id: bytes, count: int = K_BUCKET_SIZE) -> List[PeerInfo]:
        """Find the closest peers to a target ID."""
        all_peers = []
        with self._lock:
            for bucket in self.buckets:
                all_peers.extend(bucket.get_peers())

        # Sort by XOR distance to target
        all_peers.sort(key=lambda p: self.xor_distance(p.node_id, target_id))
        return all_peers[:count]

    def get_peer(self, node_id: bytes) -> Optional[PeerInfo]:
        """Get a specific peer by ID."""
        distance = self.xor_distance(self.my_id, node_id)
        bucket_idx = self.bucket_index(distance)

        with self._lock:
            if bucket_idx < len(self.buckets):
                for peer in self.buckets[bucket_idx].peers:
                    if peer.node_id == node_id:
                        return peer
        return None

    def get_all_peers(self) -> List[PeerInfo]:
        """Get all known peers."""
        all_peers = []
        with self._lock:
            for bucket in self.buckets:
                all_peers.extend(bucket.get_peers())
        return all_peers


# =============================================================================
# NAT Traversal
# =============================================================================

class NATTraversal:
    """Handles NAT traversal using STUN and hole punching."""

    def __init__(self, local_port: int = MALACHI_PORT):
        self.local_port = local_port
        self.public_address: Optional[Tuple[str, int]] = None
        self.nat_type: str = "unknown"
        self._sock: Optional[socket.socket] = None

    def discover_public_address(self) -> Optional[Tuple[str, int]]:
        """Discover our public IP and port using STUN."""
        for server, port in STUN_SERVERS:
            try:
                result = self._stun_request(server, port)
                if result:
                    self.public_address = result
                    return result
            except Exception as e:
                logger.debug(f"STUN request to {server} failed: {e}")
                continue
        return None

    def _stun_request(self, server: str, port: int) -> Optional[Tuple[str, int]]:
        """Send STUN binding request."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)

        try:
            sock.bind(('', self.local_port))

            # STUN Binding Request (simplified)
            # Real STUN has more complex message format
            transaction_id = os.urandom(12)
            request = struct.pack(">HH", 0x0001, 0) + transaction_id

            sock.sendto(request, (server, port))

            data, addr = sock.recvfrom(1024)

            # Parse response (simplified - real STUN parsing is more complex)
            if len(data) >= 20:
                msg_type = struct.unpack(">H", data[0:2])[0]
                if msg_type == 0x0101:  # Binding Response
                    # Look for XOR-MAPPED-ADDRESS attribute
                    offset = 20
                    while offset < len(data) - 4:
                        attr_type = struct.unpack(">H", data[offset:offset+2])[0]
                        attr_len = struct.unpack(">H", data[offset+2:offset+4])[0]

                        if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                            # Parse XOR'd address
                            family = data[offset + 5]
                            xport = struct.unpack(">H", data[offset+6:offset+8])[0]
                            port = xport ^ 0x2112

                            if family == 0x01:  # IPv4
                                xip = struct.unpack(">I", data[offset+8:offset+12])[0]
                                ip_int = xip ^ 0x2112A442
                                ip = socket.inet_ntoa(struct.pack(">I", ip_int))
                                return (ip, port)

                        offset += 4 + attr_len
                        if attr_len % 4:
                            offset += 4 - (attr_len % 4)  # Padding

            return None

        finally:
            sock.close()

    def punch_hole(self, target_address: Tuple[str, int], sock: socket.socket) -> bool:
        """Attempt UDP hole punching to target."""
        try:
            # Send a few packets to punch hole in NAT
            for _ in range(3):
                sock.sendto(b"PUNCH", target_address)
                time.sleep(0.1)
            return True
        except Exception as e:
            logger.debug(f"Hole punch failed: {e}")
            return False


# =============================================================================
# Gossip Protocol
# =============================================================================

@dataclass
class GossipMessage:
    """A gossip message."""
    msg_id: bytes
    origin: bytes
    timestamp: float
    msg_type: str  # "peer", "route", "service"
    data: bytes

    def to_bytes(self) -> bytes:
        type_bytes = self.msg_type.encode()[:16].ljust(16, b'\x00')
        return (
            self.msg_id +
            self.origin +
            struct.pack(">d", self.timestamp) +
            type_bytes +
            self.data
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> 'GossipMessage':
        return cls(
            msg_id=data[0:16],
            origin=data[16:32],
            timestamp=struct.unpack(">d", data[32:40])[0],
            msg_type=data[40:56].rstrip(b'\x00').decode(),
            data=data[56:],
        )


class GossipProtocol:
    """Epidemic gossip for efficient state propagation."""

    def __init__(self, my_id: bytes):
        self.my_id = my_id
        self.seen_messages: Dict[bytes, float] = {}  # msg_id -> timestamp
        self.message_queue: List[GossipMessage] = []
        self._lock = threading.Lock()
        self._handlers: Dict[str, Callable[[GossipMessage], None]] = {}

    def register_handler(self, msg_type: str, handler: Callable[[GossipMessage], None]):
        """Register handler for gossip message type."""
        self._handlers[msg_type] = handler

    def create_message(self, msg_type: str, data: bytes) -> GossipMessage:
        """Create a new gossip message."""
        msg = GossipMessage(
            msg_id=os.urandom(16),
            origin=self.my_id,
            timestamp=time.time(),
            msg_type=msg_type,
            data=data,
        )

        with self._lock:
            self.seen_messages[msg.msg_id] = msg.timestamp
            self.message_queue.append(msg)

        return msg

    def receive_message(self, msg: GossipMessage) -> bool:
        """Process received gossip message. Returns True if new."""
        with self._lock:
            if msg.msg_id in self.seen_messages:
                return False

            self.seen_messages[msg.msg_id] = msg.timestamp
            self.message_queue.append(msg)

        # Call handler
        handler = self._handlers.get(msg.msg_type)
        if handler:
            try:
                handler(msg)
            except Exception as e:
                logger.error(f"Gossip handler error: {e}")

        return True

    def get_messages_to_send(self, limit: int = 10) -> List[GossipMessage]:
        """Get recent messages to gossip."""
        with self._lock:
            # Return most recent messages
            return sorted(self.message_queue, key=lambda m: m.timestamp, reverse=True)[:limit]

    def cleanup(self, max_age: float = 3600.0):
        """Remove old messages."""
        now = time.time()
        with self._lock:
            self.seen_messages = {
                k: v for k, v in self.seen_messages.items()
                if now - v < max_age
            }
            self.message_queue = [
                m for m in self.message_queue
                if now - m.timestamp < max_age
            ]


# =============================================================================
# Persistent Peer Storage
# =============================================================================

class PeerStore:
    """Persistent storage for known peers."""

    def __init__(self, storage_path: Optional[Path] = None):
        if storage_path is None:
            storage_path = Path.home() / ".ministack" / "peers.json"
        self.storage_path = storage_path
        self.peers: Dict[str, dict] = {}  # hex node_id -> peer info
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        """Load peers from disk."""
        try:
            if self.storage_path.exists():
                with open(self.storage_path) as f:
                    data = json.load(f)
                    self.peers = data.get("peers", {})
                    logger.info(f"Loaded {len(self.peers)} peers from storage")
        except Exception as e:
            logger.warning(f"Failed to load peers: {e}")
            self.peers = {}

    def _save(self):
        """Save peers to disk."""
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump({"peers": self.peers, "updated": time.time()}, f, indent=2)
        except Exception as e:
            logger.debug(f"Failed to save peers: {e}")

    def add_peer(self, peer: PeerInfo):
        """Add or update a peer."""
        with self._lock:
            self.peers[peer.node_id.hex()] = {
                "address": list(peer.address),
                "public_address": list(peer.public_address) if peer.public_address else None,
                "last_seen": peer.last_seen,
                "is_relay": peer.is_relay,
                "is_bootstrap": peer.is_bootstrap,
                "services": peer.services,
            }
            self._save()

    def remove_peer(self, node_id: bytes):
        """Remove a peer."""
        with self._lock:
            self.peers.pop(node_id.hex(), None)
            self._save()

    def get_peers(self) -> List[PeerInfo]:
        """Get all stored peers."""
        with self._lock:
            result = []
            for node_id_hex, info in self.peers.items():
                try:
                    result.append(PeerInfo(
                        node_id=bytes.fromhex(node_id_hex),
                        address=tuple(info["address"]),
                        public_address=tuple(info["public_address"]) if info.get("public_address") else None,
                        last_seen=info.get("last_seen", 0),
                        is_relay=info.get("is_relay", False),
                        is_bootstrap=info.get("is_bootstrap", False),
                        services=info.get("services", []),
                    ))
                except Exception as e:
                    logger.debug(f"Failed to parse peer: {e}")
            return result


# =============================================================================
# Service Discovery
# =============================================================================

class ServiceRegistry:
    """Registry for discovered services."""

    def __init__(self, my_id: bytes):
        self.my_id = my_id
        self.local_services: Dict[str, ServiceInfo] = {}  # service_type -> info
        self.remote_services: Dict[bytes, Dict[str, ServiceInfo]] = defaultdict(dict)  # node_id -> services
        self._lock = threading.Lock()

    def register_service(self, service_type: str, port: int, metadata: Dict[str, str] = None) -> ServiceInfo:
        """Register a local service."""
        with self._lock:
            info = ServiceInfo(
                node_id=self.my_id,
                service_type=service_type,
                port=port,
                metadata=metadata or {},
            )
            self.local_services[service_type] = info
            return info

    def unregister_service(self, service_type: str):
        """Unregister a local service."""
        with self._lock:
            self.local_services.pop(service_type, None)

    def add_remote_service(self, service: ServiceInfo):
        """Add a discovered remote service."""
        with self._lock:
            self.remote_services[service.node_id][service.service_type] = service

    def find_services(self, service_type: str) -> List[ServiceInfo]:
        """Find all services of a given type."""
        with self._lock:
            results = []

            # Local services
            if service_type in self.local_services:
                results.append(self.local_services[service_type])

            # Remote services
            for node_services in self.remote_services.values():
                if service_type in node_services:
                    results.append(node_services[service_type])

            return results

    def get_local_services(self) -> List[ServiceInfo]:
        """Get all local services."""
        with self._lock:
            return list(self.local_services.values())

    def encode_announcement(self) -> bytes:
        """Encode service announcement."""
        with self._lock:
            services = []
            for svc in self.local_services.values():
                services.append({
                    "type": svc.service_type,
                    "port": svc.port,
                    "meta": svc.metadata,
                })
            return json.dumps(services).encode()

    def decode_announcement(self, node_id: bytes, data: bytes):
        """Decode and process service announcement."""
        try:
            services = json.loads(data.decode())
            with self._lock:
                for svc in services:
                    self.remote_services[node_id][svc["type"]] = ServiceInfo(
                        node_id=node_id,
                        service_type=svc["type"],
                        port=svc["port"],
                        metadata=svc.get("meta", {}),
                    )
        except Exception as e:
            logger.debug(f"Failed to decode service announcement: {e}")


# =============================================================================
# File Transfer
# =============================================================================

class FileTransferManager:
    """Manages file transfers between nodes."""

    def __init__(self, my_id: bytes, send_callback: Callable[[bytes, bytes], None]):
        self.my_id = my_id
        self._send = send_callback
        self.outgoing: Dict[bytes, dict] = {}  # transfer_id -> file info
        self.incoming: Dict[bytes, FileTransfer] = {}  # transfer_id -> transfer state
        self._lock = threading.Lock()
        self._on_complete: Optional[Callable[[bytes, str, bytes], None]] = None

    def send_file(self, dest_node: bytes, filepath: str) -> bytes:
        """Start sending a file to a node. Returns transfer ID."""
        transfer_id = os.urandom(16)

        with open(filepath, 'rb') as f:
            data = f.read()

        total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE

        with self._lock:
            self.outgoing[transfer_id] = {
                "dest": dest_node,
                "filename": os.path.basename(filepath),
                "data": data,
                "total_chunks": total_chunks,
                "acked_chunks": set(),
            }

        # Send offer
        offer = struct.pack(">16s256sQI",
            transfer_id,
            os.path.basename(filepath).encode()[:256].ljust(256, b'\x00'),
            len(data),
            total_chunks,
        )
        self._send(dest_node, bytes([MeshMsgType.FILE_OFFER]) + offer)

        return transfer_id

    def handle_offer(self, src_node: bytes, data: bytes) -> bool:
        """Handle incoming file offer. Returns True to accept."""
        transfer_id = data[0:16]
        filename = data[16:272].rstrip(b'\x00').decode()
        total_size = struct.unpack(">Q", data[272:280])[0]
        total_chunks = struct.unpack(">I", data[280:284])[0]

        with self._lock:
            self.incoming[transfer_id] = FileTransfer(
                transfer_id=transfer_id,
                filename=filename,
                total_size=total_size,
                chunk_size=CHUNK_SIZE,
                total_chunks=total_chunks,
            )

        # Request all chunks
        for chunk_idx in range(total_chunks):
            req = struct.pack(">16sI", transfer_id, chunk_idx)
            self._send(src_node, bytes([MeshMsgType.FILE_REQUEST]) + req)

        return True

    def handle_request(self, src_node: bytes, data: bytes):
        """Handle chunk request."""
        transfer_id = data[0:16]
        chunk_idx = struct.unpack(">I", data[16:20])[0]

        with self._lock:
            transfer = self.outgoing.get(transfer_id)
            if not transfer:
                return

            start = chunk_idx * CHUNK_SIZE
            end = min(start + CHUNK_SIZE, len(transfer["data"]))
            chunk_data = transfer["data"][start:end]

        # Send chunk
        chunk = struct.pack(">16sI", transfer_id, chunk_idx) + chunk_data
        self._send(src_node, bytes([MeshMsgType.FILE_CHUNK]) + chunk)

    def handle_chunk(self, src_node: bytes, data: bytes):
        """Handle received chunk."""
        transfer_id = data[0:16]
        chunk_idx = struct.unpack(">I", data[16:20])[0]
        chunk_data = data[20:]

        with self._lock:
            transfer = self.incoming.get(transfer_id)
            if not transfer:
                return

            transfer.received_chunks.add(chunk_idx)
            transfer.data[chunk_idx] = chunk_data

            if transfer.is_complete:
                # Reassemble file
                file_data = b"".join(
                    transfer.data[i] for i in range(transfer.total_chunks)
                )

                if self._on_complete:
                    self._on_complete(transfer_id, transfer.filename, file_data)

                # Send completion
                complete = struct.pack(">16s", transfer_id)
                self._send(src_node, bytes([MeshMsgType.FILE_COMPLETE]) + complete)

    def on_transfer_complete(self, callback: Callable[[bytes, str, bytes], None]):
        """Set callback for completed transfers."""
        self._on_complete = callback

    def get_progress(self, transfer_id: bytes) -> Optional[float]:
        """Get transfer progress (0.0 - 1.0)."""
        with self._lock:
            if transfer_id in self.incoming:
                return self.incoming[transfer_id].progress
            elif transfer_id in self.outgoing:
                transfer = self.outgoing[transfer_id]
                return len(transfer["acked_chunks"]) / transfer["total_chunks"]
        return None


# =============================================================================
# Main Mesh Node
# =============================================================================

class MeshNode:
    """
    Complete Malachi mesh network node.

    Integrates all networking features:
    - Multi-hop forwarding
    - Reliable delivery
    - NAT traversal
    - DHT discovery
    - Gossip protocol
    - Service discovery
    - File transfer
    """

    def __init__(
        self,
        node_id: bytes,
        port: int = MALACHI_PORT,
        storage_path: Optional[Path] = None,
    ):
        self.node_id = node_id
        self.port = port

        # Core components
        self.dht = KademliaTable(node_id)
        self.nat = NATTraversal(port)
        self.gossip = GossipProtocol(node_id)
        self.peer_store = PeerStore(storage_path)
        self.services = ServiceRegistry(node_id)

        # Routing
        self.routes: Dict[bytes, RouteEntry] = {}
        self._routes_lock = threading.Lock()

        # Reliability (ARQ)
        self._msg_counter = 0
        self._pending_acks: Dict[int, PendingAck] = {}
        self._received_ids: Dict[int, float] = {}  # msg_id -> timestamp
        self._ack_lock = threading.Lock()

        # Relay nodes
        self.relay_nodes: Set[bytes] = set()

        # File transfer
        self.file_transfer: Optional[FileTransferManager] = None

        # Network socket
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._threads: List[threading.Thread] = []

        # Callbacks
        self._on_message: Optional[Callable[[bytes, bytes], None]] = None

        # Statistics
        self._stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "packets_forwarded": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "retransmissions": 0,
        }

        # Setup gossip handlers
        self._setup_gossip_handlers()

    def _setup_gossip_handlers(self):
        """Setup handlers for gossip message types."""
        self.gossip.register_handler("peer", self._on_gossip_peer)
        self.gossip.register_handler("route", self._on_gossip_route)
        self.gossip.register_handler("service", self._on_gossip_service)

    def start(self) -> bool:
        """Start the mesh node."""
        try:
            # Create UDP socket
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(('', self.port))
            self._sock.settimeout(1.0)

            self._running = True

            # Start receiver thread
            rx_thread = threading.Thread(target=self._receive_loop, daemon=True)
            rx_thread.start()
            self._threads.append(rx_thread)

            # Start maintenance thread
            maint_thread = threading.Thread(target=self._maintenance_loop, daemon=True)
            maint_thread.start()
            self._threads.append(maint_thread)

            # Setup file transfer (uses send, not send_reliable, because file messages have their own type prefix)
            self.file_transfer = FileTransferManager(self.node_id, self._send_file_packet)

            # Discover NAT
            self.nat.discover_public_address()
            if self.nat.public_address:
                logger.info(f"Public address: {self.nat.public_address}")

            # Load persistent peers
            for peer in self.peer_store.get_peers():
                self.dht.add_peer(peer)

            # Connect to bootstrap nodes
            self._connect_bootstrap()

            logger.info(f"Mesh node started on port {self.port}")
            return True

        except Exception as e:
            logger.error(f"Failed to start mesh node: {e}")
            return False

    def stop(self):
        """Stop the mesh node."""
        self._running = False

        if self._sock:
            self._sock.close()
            self._sock = None

        for thread in self._threads:
            thread.join(timeout=2.0)
        self._threads.clear()

        logger.info("Mesh node stopped")

    def _send_file_packet(self, dest_node: bytes, data: bytes) -> bool:
        """Send a file transfer packet directly to a node."""
        peer = self.dht.get_peer(dest_node)
        if peer and peer.is_alive():
            return self._send_packet(peer.address, data)
        return False

    def send(self, dest_node: bytes, data: bytes) -> bool:
        """Send data to a node (best-effort, no reliability)."""
        peer = self.dht.get_peer(dest_node)

        if peer and peer.is_alive():
            # Direct send
            return self._send_packet(peer.address, data)

        # Check routing table
        with self._routes_lock:
            route = self.routes.get(dest_node)
            if route and route.is_valid():
                return self._forward_packet(route.next_hop, dest_node, data)

        # Try relay
        for relay_id in self.relay_nodes:
            relay = self.dht.get_peer(relay_id)
            if relay and relay.is_alive():
                return self._send_via_relay(relay, dest_node, data)

        logger.debug(f"No route to {dest_node.hex()[:8]}")
        return False

    def send_reliable(self, dest_node: bytes, data: bytes, callback: Callable[[bool], None] = None) -> int:
        """Send data with reliability (ACK required). Returns message ID."""
        with self._ack_lock:
            msg_id = self._msg_counter
            self._msg_counter = (self._msg_counter + 1) & 0xFFFFFFFF

            # Wrap data with header
            packet = struct.pack(">BIB", MeshMsgType.DATA, msg_id, 0) + data

            self._pending_acks[msg_id] = PendingAck(
                msg_id=msg_id,
                dest_node=dest_node,
                payload=packet,
                sent_at=time.time(),
                callback=callback,
            )

        self.send(dest_node, packet)
        self._stats["packets_sent"] += 1
        self._stats["bytes_sent"] += len(packet)

        return msg_id

    def broadcast(self, data: bytes):
        """Broadcast data to all known peers."""
        for peer in self.dht.get_all_peers():
            if peer.is_alive():
                self.send(peer.node_id, data)

    def find_node(self, target_id: bytes) -> Optional[PeerInfo]:
        """Find a node using DHT lookup."""
        # Check if we know directly
        peer = self.dht.get_peer(target_id)
        if peer:
            return peer

        # Iterative lookup
        closest = self.dht.find_closest(target_id, ALPHA)
        queried = set()

        for _ in range(10):  # Max iterations
            new_closest = []

            for peer in closest:
                if peer.node_id in queried:
                    continue
                queried.add(peer.node_id)

                # Send FIND_NODE request
                request = bytes([MeshMsgType.DHT_FIND_NODE]) + target_id
                self._send_packet(peer.address, request)

                # In a real implementation, we'd wait for responses
                # For now, we just return what we have

            if not new_closest:
                break

        return self.dht.get_peer(target_id)

    def join_network(self, bootstrap_address: Tuple[str, int] = None):
        """Join the network via a bootstrap node."""
        if bootstrap_address:
            # Ping bootstrap
            ping = struct.pack(">B16s", MeshMsgType.PING, self.node_id)
            self._send_packet(bootstrap_address, ping)

            # Find ourselves to populate routing table
            self.find_node(self.node_id)

    def register_service(self, service_type: str, port: int, metadata: Dict[str, str] = None):
        """Register a local service and announce it."""
        info = self.services.register_service(service_type, port, metadata)

        # Gossip the announcement
        self.gossip.create_message("service", self.services.encode_announcement())

    def find_service(self, service_type: str) -> List[ServiceInfo]:
        """Find services of a given type."""
        return self.services.find_services(service_type)

    def send_file(self, dest_node: bytes, filepath: str) -> bytes:
        """Send a file to another node. Returns transfer ID."""
        if self.file_transfer:
            return self.file_transfer.send_file(dest_node, filepath)
        raise RuntimeError("File transfer not initialized")

    def on_message(self, callback: Callable[[bytes, bytes], None]):
        """Set callback for incoming messages."""
        self._on_message = callback

    def _send_packet(self, address: Tuple[str, int], data: bytes) -> bool:
        """Send raw packet to address."""
        try:
            if self._sock:
                self._sock.sendto(data, address)
                return True
        except Exception as e:
            logger.debug(f"Send failed: {e}")
        return False

    def _forward_packet(self, next_hop: bytes, final_dest: bytes, data: bytes) -> bool:
        """Forward packet through next hop."""
        peer = self.dht.get_peer(next_hop)
        if not peer:
            return False

        # Wrap in forward header
        forward = struct.pack(">B16s16sB",
            MeshMsgType.FORWARD,
            self.node_id,  # original source
            final_dest,
            MAX_HOPS,  # TTL
        ) + data

        self._stats["packets_forwarded"] += 1
        return self._send_packet(peer.address, forward)

    def _send_via_relay(self, relay: PeerInfo, dest_node: bytes, data: bytes) -> bool:
        """Send via relay node."""
        relay_pkt = struct.pack(">B16s", MeshMsgType.RELAY_DATA, dest_node) + data
        return self._send_packet(relay.address, relay_pkt)

    def _receive_loop(self):
        """Main receive loop."""
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
                self._stats["packets_received"] += 1
                self._stats["bytes_received"] += len(data)
                self._handle_packet(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.debug(f"Receive error: {e}")

    def _handle_packet(self, data: bytes, addr: Tuple[str, int]):
        """Handle received packet."""
        if len(data) < 1:
            return

        msg_type = data[0]
        payload = data[1:]

        if msg_type == MeshMsgType.PING:
            self._handle_ping(payload, addr)
        elif msg_type == MeshMsgType.PONG:
            self._handle_pong(payload, addr)
        elif msg_type == MeshMsgType.DATA:
            self._handle_data(payload, addr)
        elif msg_type == MeshMsgType.ACK:
            self._handle_ack(payload)
        elif msg_type == MeshMsgType.FORWARD:
            self._handle_forward(payload, addr)
        elif msg_type == MeshMsgType.ROUTE_UPDATE:
            self._handle_route_update(payload, addr)
        elif msg_type == MeshMsgType.DHT_FIND_NODE:
            self._handle_dht_find_node(payload, addr)
        elif msg_type == MeshMsgType.DHT_FIND_NODE_REPLY:
            self._handle_dht_find_node_reply(payload, addr)
        elif msg_type == MeshMsgType.GOSSIP:
            self._handle_gossip(payload, addr)
        elif msg_type == MeshMsgType.SERVICE_ANNOUNCE:
            self._handle_service_announce(payload, addr)
        elif msg_type == MeshMsgType.RELAY_DATA:
            self._handle_relay(payload, addr)
        elif msg_type in (MeshMsgType.FILE_OFFER, MeshMsgType.FILE_REQUEST,
                         MeshMsgType.FILE_CHUNK, MeshMsgType.FILE_COMPLETE):
            self._handle_file_transfer(msg_type, payload, addr)

    def _handle_ping(self, data: bytes, addr: Tuple[str, int]):
        """Handle ping message."""
        if len(data) < 16:
            return

        sender_id = data[:16]

        # Add to DHT
        peer = PeerInfo(node_id=sender_id, address=addr)
        self.dht.add_peer(peer)
        self.peer_store.add_peer(peer)

        # Send pong
        pong = struct.pack(">B16s", MeshMsgType.PONG, self.node_id)
        self._send_packet(addr, pong)

    def _handle_pong(self, data: bytes, addr: Tuple[str, int]):
        """Handle pong message."""
        if len(data) < 16:
            return

        sender_id = data[:16]

        # Update peer
        peer = PeerInfo(node_id=sender_id, address=addr)
        self.dht.add_peer(peer)
        self.peer_store.add_peer(peer)

    def _handle_data(self, data: bytes, addr: Tuple[str, int]):
        """Handle data message with reliability."""
        if len(data) < 5:
            return

        msg_id = struct.unpack(">I", data[:4])[0]
        flags = data[4]
        payload = data[5:]

        # Check for duplicate
        with self._ack_lock:
            if msg_id in self._received_ids:
                # Already received - just ACK again
                pass
            else:
                self._received_ids[msg_id] = time.time()

                # Deliver to application
                if self._on_message:
                    # Need to find sender node ID from addr
                    sender_id = None
                    for peer in self.dht.get_all_peers():
                        if peer.address == addr:
                            sender_id = peer.node_id
                            break

                    if sender_id:
                        self._on_message(sender_id, payload)

        # Send ACK
        ack = struct.pack(">BI", MeshMsgType.ACK, msg_id)
        self._send_packet(addr, ack)

    def _handle_ack(self, data: bytes):
        """Handle ACK message."""
        if len(data) < 4:
            return

        msg_id = struct.unpack(">I", data[:4])[0]

        with self._ack_lock:
            pending = self._pending_acks.pop(msg_id, None)
            if pending and pending.callback:
                pending.callback(True)

    def _handle_forward(self, data: bytes, addr: Tuple[str, int]):
        """Handle forwarded packet."""
        if len(data) < 33:
            return

        original_src = data[:16]
        final_dst = data[16:32]
        ttl = data[32]
        payload = data[33:]

        if ttl <= 0:
            return  # TTL expired

        if final_dst == self.node_id:
            # Destination is us - deliver
            if self._on_message:
                self._on_message(original_src, payload)
        else:
            # Forward to next hop
            with self._routes_lock:
                route = self.routes.get(final_dst)
                if route and route.is_valid():
                    next_peer = self.dht.get_peer(route.next_hop)
                    if next_peer:
                        # Decrement TTL and forward
                        fwd = struct.pack(">B16s16sB",
                            MeshMsgType.FORWARD,
                            original_src,
                            final_dst,
                            ttl - 1,
                        ) + payload
                        self._send_packet(next_peer.address, fwd)
                        self._stats["packets_forwarded"] += 1

    def _handle_route_update(self, data: bytes, addr: Tuple[str, int]):
        """Handle routing update."""
        # Find sender by address
        sender_id = None
        for peer in self.dht.get_all_peers():
            if peer.address == addr:
                sender_id = peer.node_id
                break

        if not sender_id:
            return

        # Parse routes
        offset = 0
        while offset + 17 <= len(data):
            dest = data[offset:offset + 16]
            metric = data[offset + 16]

            with self._routes_lock:
                existing = self.routes.get(dest)
                new_metric = metric + 1

                if existing is None or new_metric < existing.metric:
                    self.routes[dest] = RouteEntry(
                        destination=dest,
                        next_hop=sender_id,
                        metric=new_metric,
                    )

            offset += 17

    def _handle_dht_find_node(self, data: bytes, addr: Tuple[str, int]):
        """Handle DHT FIND_NODE request."""
        if len(data) < 16:
            return

        target_id = data[:16]

        # Find closest nodes
        closest = self.dht.find_closest(target_id, K_BUCKET_SIZE)

        # Send reply
        reply = bytes([MeshMsgType.DHT_FIND_NODE_REPLY])
        for peer in closest:
            ip_bytes = socket.inet_aton(peer.address[0])
            reply += peer.node_id + ip_bytes + struct.pack(">H", peer.address[1])

        self._send_packet(addr, reply)

    def _handle_dht_find_node_reply(self, data: bytes, addr: Tuple[str, int]):
        """Handle DHT FIND_NODE reply."""
        offset = 0
        while offset + 22 <= len(data):  # 16 (node_id) + 4 (ip) + 2 (port)
            node_id = data[offset:offset + 16]
            ip = socket.inet_ntoa(data[offset + 16:offset + 20])
            port = struct.unpack(">H", data[offset + 20:offset + 22])[0]

            peer = PeerInfo(node_id=node_id, address=(ip, port))
            self.dht.add_peer(peer)

            offset += 22

    def _handle_gossip(self, data: bytes, addr: Tuple[str, int]):
        """Handle gossip message."""
        try:
            msg = GossipMessage.from_bytes(data)
            if self.gossip.receive_message(msg):
                # Propagate to random peers
                peers = self.dht.get_all_peers()
                random.shuffle(peers)
                for peer in peers[:3]:  # Fanout of 3
                    if peer.address != addr:
                        self._send_packet(peer.address, bytes([MeshMsgType.GOSSIP]) + data)
        except Exception as e:
            logger.debug(f"Gossip parse error: {e}")

    def _handle_service_announce(self, data: bytes, addr: Tuple[str, int]):
        """Handle service announcement."""
        # Find sender
        sender_id = None
        for peer in self.dht.get_all_peers():
            if peer.address == addr:
                sender_id = peer.node_id
                break

        if sender_id:
            self.services.decode_announcement(sender_id, data)

    def _handle_relay(self, data: bytes, addr: Tuple[str, int]):
        """Handle relay request."""
        if len(data) < 16:
            return

        dest_id = data[:16]
        payload = data[16:]

        # Forward to destination
        self.send(dest_id, payload)

    def _handle_file_transfer(self, msg_type: int, data: bytes, addr: Tuple[str, int]):
        """Handle file transfer messages."""
        if not self.file_transfer:
            return

        # Find sender
        sender_id = None
        for peer in self.dht.get_all_peers():
            if peer.address == addr:
                sender_id = peer.node_id
                break

        if not sender_id:
            return

        if msg_type == MeshMsgType.FILE_OFFER:
            self.file_transfer.handle_offer(sender_id, data)
        elif msg_type == MeshMsgType.FILE_REQUEST:
            self.file_transfer.handle_request(sender_id, data)
        elif msg_type == MeshMsgType.FILE_CHUNK:
            self.file_transfer.handle_chunk(sender_id, data)

    def _on_gossip_peer(self, msg: GossipMessage):
        """Handle gossip about new peer."""
        try:
            info = json.loads(msg.data.decode())
            peer = PeerInfo(
                node_id=bytes.fromhex(info["node_id"]),
                address=tuple(info["address"]),
            )
            self.dht.add_peer(peer)
        except Exception as e:
            logger.debug(f"Failed to parse peer gossip: {e}")

    def _on_gossip_route(self, msg: GossipMessage):
        """Handle gossip about route."""
        # Route gossip handled by regular route updates
        pass

    def _on_gossip_service(self, msg: GossipMessage):
        """Handle gossip about service."""
        self.services.decode_announcement(msg.origin, msg.data)

    def _maintenance_loop(self):
        """Periodic maintenance tasks."""
        last_heartbeat = 0
        last_route_update = 0
        last_gossip = 0

        while self._running:
            time.sleep(1.0)
            now = time.time()

            # Heartbeat to peers
            if now - last_heartbeat > HEARTBEAT_INTERVAL:
                self._send_heartbeats()
                last_heartbeat = now

            # Send route updates
            if now - last_route_update > ROUTE_UPDATE_INTERVAL:
                self._send_route_updates()
                last_route_update = now

            # Gossip
            if now - last_gossip > GOSSIP_INTERVAL:
                self._do_gossip()
                last_gossip = now

            # Retransmit unacked messages
            self._check_retransmissions()

            # Cleanup old state
            self._cleanup()

    def _send_heartbeats(self):
        """Send heartbeat to all known peers."""
        ping = struct.pack(">B16s", MeshMsgType.PING, self.node_id)
        for peer in self.dht.get_all_peers():
            if peer.is_alive():
                self._send_packet(peer.address, ping)

    def _send_route_updates(self):
        """Send routing updates to neighbors."""
        with self._routes_lock:
            if not self.routes:
                return

            # Build update packet
            update = bytes([MeshMsgType.ROUTE_UPDATE])
            for dest, route in self.routes.items():
                if route.is_valid():
                    update += dest + bytes([min(route.metric, MAX_HOPS - 1)])

        # Send to all peers
        for peer in self.dht.get_all_peers():
            if peer.is_alive():
                self._send_packet(peer.address, update)

    def _do_gossip(self):
        """Send gossip to random peers."""
        messages = self.gossip.get_messages_to_send(5)
        if not messages:
            return

        peers = self.dht.get_all_peers()
        if not peers:
            return

        random.shuffle(peers)
        for peer in peers[:3]:  # Fanout of 3
            for msg in messages:
                pkt = bytes([MeshMsgType.GOSSIP]) + msg.to_bytes()
                self._send_packet(peer.address, pkt)

    def _check_retransmissions(self):
        """Check for messages needing retransmission."""
        now = time.time()
        to_retry = []
        to_fail = []

        with self._ack_lock:
            for msg_id, pending in list(self._pending_acks.items()):
                if now - pending.sent_at > RETRY_TIMEOUT:
                    if pending.retries >= MAX_RETRIES:
                        to_fail.append(msg_id)
                    else:
                        to_retry.append(msg_id)

        # Retransmit
        for msg_id in to_retry:
            with self._ack_lock:
                pending = self._pending_acks.get(msg_id)
                if pending:
                    pending.retries += 1
                    pending.sent_at = now
                    self.send(pending.dest_node, pending.payload)
                    self._stats["retransmissions"] += 1

        # Fail after max retries
        for msg_id in to_fail:
            with self._ack_lock:
                pending = self._pending_acks.pop(msg_id, None)
                if pending and pending.callback:
                    pending.callback(False)

    def _cleanup(self):
        """Cleanup old state."""
        now = time.time()

        # Clean old received message IDs
        with self._ack_lock:
            self._received_ids = {
                k: v for k, v in self._received_ids.items()
                if now - v < 300  # 5 minutes
            }

        # Clean old gossip
        self.gossip.cleanup()

        # Expire routes
        with self._routes_lock:
            self.routes = {
                k: v for k, v in self.routes.items()
                if v.is_valid()
            }

    def _connect_bootstrap(self):
        """Connect to bootstrap nodes."""
        for host, port in BOOTSTRAP_NODES:
            try:
                addr = (socket.gethostbyname(host), port)
                ping = struct.pack(">B16s", MeshMsgType.PING, self.node_id)
                self._send_packet(addr, ping)
            except Exception as e:
                logger.debug(f"Failed to connect to bootstrap {host}: {e}")

    def stats(self) -> Dict[str, Any]:
        """Get node statistics."""
        return {
            **self._stats,
            "known_peers": len(self.dht.get_all_peers()),
            "routes": len(self.routes),
            "pending_acks": len(self._pending_acks),
            "public_address": self.nat.public_address,
            "services": len(self.services.local_services),
        }


# =============================================================================
# CLI / Testing
# =============================================================================

def test_mesh():
    """Test mesh networking."""
    print("Malachi Mesh Networking Test")
    print("=" * 50)

    # Create two nodes
    node1_id = os.urandom(16)
    node2_id = os.urandom(16)

    node1 = MeshNode(node1_id, port=7891)
    node2 = MeshNode(node2_id, port=7892)

    received = []

    def on_msg(src, data):
        received.append((src, data))
        print(f"Received: {data[:50]}")

    node1.on_message(on_msg)
    node2.on_message(on_msg)

    print(f"Node 1: {node1_id.hex()[:16]}")
    print(f"Node 2: {node2_id.hex()[:16]}")

    # Start nodes
    node1.start()
    node2.start()

    # Add each other as peers
    peer1 = PeerInfo(node_id=node1_id, address=("127.0.0.1", 7891))
    peer2 = PeerInfo(node_id=node2_id, address=("127.0.0.1", 7892))

    node1.dht.add_peer(peer2)
    node2.dht.add_peer(peer1)

    # Send messages
    print("\nSending messages...")
    node1.send_reliable(node2_id, b"Hello from node 1!")
    node2.send_reliable(node1_id, b"Hello from node 2!")

    # Wait for delivery
    time.sleep(2.0)

    print(f"\nReceived {len(received)} messages")
    print(f"Node 1 stats: {node1.stats()}")
    print(f"Node 2 stats: {node2.stats()}")

    # Stop
    node1.stop()
    node2.stop()

    print("\nTest complete!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_mesh()
