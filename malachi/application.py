"""
Application layer features for Malachi.

This module implements:
- Service Discovery (mDNS-like)
- Pub/Sub Messaging
- Distributed State (KV Store with CRDT)
"""

import time
import threading
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple, List, Callable, Any, Union
from enum import IntEnum
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Service Discovery
SERVICE_TTL = 300  # Service registration TTL (5 minutes)
SERVICE_REFRESH = 240  # Refresh before expiry
SERVICE_QUERY_TIMEOUT = 2.0  # Query response timeout

# Pub/Sub
PUBSUB_MAX_TOPICS = 1024
PUBSUB_MAX_SUBSCRIBERS = 256
PUBSUB_MESSAGE_TTL = 60  # Message expires after 60s

# Distributed State
KV_MAX_KEY_SIZE = 256
KV_MAX_VALUE_SIZE = 65536
KV_SYNC_INTERVAL = 10.0  # Sync state every 10s


# =============================================================================
# Message Types
# =============================================================================

class ApplicationMsgType(IntEnum):
    """Application message types."""
    # Service Discovery
    SERVICE_QUERY = 0xB0
    SERVICE_RESPONSE = 0xB1
    SERVICE_ANNOUNCE = 0xB2
    SERVICE_GOODBYE = 0xB3

    # Pub/Sub
    SUBSCRIBE = 0xC0
    UNSUBSCRIBE = 0xC1
    PUBLISH = 0xC2
    PUBLISH_ACK = 0xC3

    # Distributed State
    KV_GET = 0xD0
    KV_GET_RESPONSE = 0xD1
    KV_PUT = 0xD2
    KV_PUT_ACK = 0xD3
    KV_DELETE = 0xD4
    KV_SYNC = 0xD5


# =============================================================================
# Service Discovery
# =============================================================================

@dataclass
class ServiceRecord:
    """A service registration record."""
    service_type: str  # e.g., "_http._tcp"
    service_name: str  # e.g., "My Web Server"
    provider_id: bytes  # Node providing the service
    port: int
    priority: int = 0
    weight: int = 0
    properties: Dict[str, str] = field(default_factory=dict)
    registered_at: float = field(default_factory=time.time)
    ttl: int = SERVICE_TTL
    local: bool = False  # True if we provide this service


class ServiceDiscovery:
    """
    Implements mDNS-like service discovery.

    Allows nodes to advertise and discover services on the network.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize service discovery.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id

        # Services we provide
        self._local_services: Dict[str, ServiceRecord] = {}

        # Discovered services
        self._remote_services: Dict[str, List[ServiceRecord]] = defaultdict(list)

        # Query callbacks
        self._query_callbacks: Dict[str, List[Callable[[ServiceRecord], None]]] = defaultdict(list)

        # Maintenance thread
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start service discovery daemon."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._maintenance_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop service discovery daemon."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def register_service(
        self,
        service_type: str,
        service_name: str,
        port: int,
        priority: int = 0,
        weight: int = 0,
        properties: Optional[Dict[str, str]] = None,
    ) -> str:
        """
        Register a service.

        Args:
            service_type: Service type (e.g., "_http._tcp")
            service_name: Service name
            port: Service port
            priority: Priority (lower is higher priority)
            weight: Load balancing weight
            properties: Additional properties

        Returns:
            Service ID
        """
        with self._lock:
            service_id = f"{service_name}.{service_type}"

            record = ServiceRecord(
                service_type=service_type,
                service_name=service_name,
                provider_id=self._my_id,
                port=port,
                priority=priority,
                weight=weight,
                properties=properties or {},
                local=True,
            )

            self._local_services[service_id] = record
            logger.info(f"Registered service: {service_id}")

            return service_id

    def unregister_service(self, service_id: str) -> bool:
        """Unregister a service."""
        with self._lock:
            if service_id in self._local_services:
                del self._local_services[service_id]
                return True
            return False

    def query_service(
        self,
        service_type: str,
        callback: Optional[Callable[[ServiceRecord], None]] = None,
    ) -> List[ServiceRecord]:
        """
        Query for services of a type.

        Args:
            service_type: Service type to query
            callback: Called when new services are discovered

        Returns:
            Currently known services of this type
        """
        with self._lock:
            if callback:
                self._query_callbacks[service_type].append(callback)

            return list(self._remote_services.get(service_type, []))

    def handle_query(self, service_type: str) -> List[bytes]:
        """
        Handle incoming service query.

        Args:
            service_type: Queried service type

        Returns:
            List of response packets
        """
        with self._lock:
            responses = []
            for service_id, record in self._local_services.items():
                if record.service_type == service_type:
                    responses.append(self.encode_response(record))
            return responses

    def handle_response(self, record: ServiceRecord) -> None:
        """Handle incoming service response."""
        with self._lock:
            # Check if we already have this service
            services = self._remote_services[record.service_type]
            for i, existing in enumerate(services):
                if (existing.provider_id == record.provider_id and
                        existing.service_name == record.service_name):
                    # Update existing
                    services[i] = record
                    return

            # Add new service
            services.append(record)

            # Notify callbacks
            for callback in self._query_callbacks.get(record.service_type, []):
                try:
                    callback(record)
                except Exception as e:
                    logger.error(f"Query callback error: {e}")

    def handle_goodbye(self, provider_id: bytes, service_type: str, service_name: str) -> None:
        """Handle service goodbye (deregistration)."""
        with self._lock:
            services = self._remote_services.get(service_type, [])
            self._remote_services[service_type] = [
                s for s in services
                if not (s.provider_id == provider_id and s.service_name == service_name)
            ]

    def get_service(self, service_type: str) -> Optional[ServiceRecord]:
        """Get best service of a type (lowest priority, then highest weight)."""
        with self._lock:
            services = self._remote_services.get(service_type, [])
            if not services:
                return None

            # Sort by priority (ascending), then weight (descending)
            services = sorted(services, key=lambda s: (s.priority, -s.weight))
            return services[0]

    def encode_query(self, service_type: str) -> bytes:
        """Encode service query."""
        type_bytes = service_type.encode("utf-8")
        return bytes([ApplicationMsgType.SERVICE_QUERY, len(type_bytes)]) + type_bytes

    def encode_response(self, record: ServiceRecord) -> bytes:
        """Encode service response."""
        type_bytes = record.service_type.encode("utf-8")
        name_bytes = record.service_name.encode("utf-8")
        props_json = json.dumps(record.properties).encode("utf-8")

        return (
            bytes([ApplicationMsgType.SERVICE_RESPONSE])
            + record.provider_id
            + struct.pack(">BBHHBB", len(type_bytes), len(name_bytes),
                          record.port, record.ttl, record.priority, record.weight)
            + type_bytes
            + name_bytes
            + struct.pack(">H", len(props_json))
            + props_json
        )

    def encode_announce(self, record: ServiceRecord) -> bytes:
        """Encode service announcement."""
        # Same format as response, different type
        response = self.encode_response(record)
        return bytes([ApplicationMsgType.SERVICE_ANNOUNCE]) + response[1:]

    def encode_goodbye(self, service_type: str, service_name: str) -> bytes:
        """Encode service goodbye."""
        type_bytes = service_type.encode("utf-8")
        name_bytes = service_name.encode("utf-8")
        return (
            bytes([ApplicationMsgType.SERVICE_GOODBYE])
            + self._my_id
            + bytes([len(type_bytes), len(name_bytes)])
            + type_bytes
            + name_bytes
        )

    def decode_response(self, data: bytes) -> ServiceRecord:
        """Decode service response."""
        if len(data) < 24:
            raise ValueError("Response too short")

        provider_id = data[1:17]
        type_len, name_len, port, ttl, priority, weight = struct.unpack(
            ">BBHHBB", data[17:25]
        )

        offset = 25
        service_type = data[offset:offset + type_len].decode("utf-8")
        offset += type_len
        service_name = data[offset:offset + name_len].decode("utf-8")
        offset += name_len

        props_len = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        properties = json.loads(data[offset:offset + props_len].decode("utf-8"))

        return ServiceRecord(
            service_type=service_type,
            service_name=service_name,
            provider_id=provider_id,
            port=port,
            ttl=ttl,
            priority=priority,
            weight=weight,
            properties=properties,
        )

    def _maintenance_loop(self) -> None:
        """Periodic maintenance tasks."""
        last_refresh = 0.0

        while self._running:
            time.sleep(1.0)
            now = time.time()

            with self._lock:
                # Expire old services
                for service_type in list(self._remote_services.keys()):
                    services = self._remote_services[service_type]
                    self._remote_services[service_type] = [
                        s for s in services
                        if (now - s.registered_at) < s.ttl
                    ]

            # Refresh local services (would need send callback)
            if now - last_refresh > SERVICE_REFRESH:
                last_refresh = now
                # TODO: Re-announce local services

    def stats(self) -> Dict[str, Any]:
        """Get service discovery statistics."""
        with self._lock:
            return {
                "local_services": len(self._local_services),
                "remote_services": sum(
                    len(services) for services in self._remote_services.values()
                ),
                "service_types": list(self._remote_services.keys()),
            }


# =============================================================================
# Pub/Sub Messaging
# =============================================================================

@dataclass
class PubSubMessage:
    """A published message."""
    topic: str
    payload: bytes
    publisher_id: bytes
    message_id: bytes
    timestamp: float = field(default_factory=time.time)
    ttl: float = PUBSUB_MESSAGE_TTL


@dataclass
class Subscription:
    """A topic subscription."""
    topic: str
    subscriber_id: bytes
    callback: Optional[Callable[[PubSubMessage], None]] = None
    created_at: float = field(default_factory=time.time)


class PubSubManager:
    """
    Implements publish-subscribe messaging.

    Supports topic-based routing with wildcard subscriptions.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize pub/sub manager.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id

        # Topic -> subscribers
        self._subscriptions: Dict[str, List[Subscription]] = defaultdict(list)

        # Remote subscriptions we know about
        self._remote_subs: Dict[str, Set[bytes]] = defaultdict(set)

        # Message deduplication
        self._seen_messages: Dict[bytes, float] = {}

        # Message sequence
        self._msg_seq = 0

    def subscribe(
        self,
        topic: str,
        callback: Optional[Callable[[PubSubMessage], None]] = None,
    ) -> bool:
        """
        Subscribe to a topic.

        Args:
            topic: Topic to subscribe to (supports wildcards: * and #)
            callback: Called when message received

        Returns:
            True if subscribed successfully
        """
        with self._lock:
            # Check limits
            total_subs = sum(len(subs) for subs in self._subscriptions.values())
            if total_subs >= PUBSUB_MAX_SUBSCRIBERS:
                return False

            sub = Subscription(
                topic=topic,
                subscriber_id=self._my_id,
                callback=callback,
            )

            self._subscriptions[topic].append(sub)
            return True

    def unsubscribe(self, topic: str) -> bool:
        """Unsubscribe from a topic."""
        with self._lock:
            if topic in self._subscriptions:
                self._subscriptions[topic] = [
                    s for s in self._subscriptions[topic]
                    if s.subscriber_id != self._my_id
                ]
                return True
            return False

    def publish(self, topic: str, payload: bytes) -> PubSubMessage:
        """
        Publish a message to a topic.

        Args:
            topic: Topic to publish to
            payload: Message payload

        Returns:
            Published message
        """
        with self._lock:
            self._msg_seq += 1
            msg_id = hashlib.blake2b(
                self._my_id + struct.pack(">I", self._msg_seq),
                digest_size=16,
            ).digest()

            msg = PubSubMessage(
                topic=topic,
                payload=payload,
                publisher_id=self._my_id,
                message_id=msg_id,
            )

            self._seen_messages[msg_id] = time.time()

            # Deliver to local subscribers
            self._deliver_local(msg)

            return msg

    def handle_subscribe(self, peer_id: bytes, topic: str) -> None:
        """Handle remote subscription."""
        with self._lock:
            self._remote_subs[topic].add(peer_id)

    def handle_unsubscribe(self, peer_id: bytes, topic: str) -> None:
        """Handle remote unsubscription."""
        with self._lock:
            self._remote_subs[topic].discard(peer_id)

    def handle_publish(self, msg: PubSubMessage) -> bool:
        """
        Handle incoming published message.

        Args:
            msg: Published message

        Returns:
            True if message was new and processed
        """
        with self._lock:
            # Deduplication
            if msg.message_id in self._seen_messages:
                return False

            # Check TTL
            if time.time() - msg.timestamp > msg.ttl:
                return False

            self._seen_messages[msg.message_id] = time.time()

            # Deliver to local subscribers
            self._deliver_local(msg)

            return True

    def _deliver_local(self, msg: PubSubMessage) -> None:
        """Deliver message to local subscribers."""
        for topic, subs in self._subscriptions.items():
            if self._topic_matches(topic, msg.topic):
                for sub in subs:
                    if sub.callback:
                        try:
                            sub.callback(msg)
                        except Exception as e:
                            logger.error(f"Subscriber callback error: {e}")

    def _topic_matches(self, pattern: str, topic: str) -> bool:
        """
        Check if topic matches pattern.

        Wildcards:
        - * matches one level
        - # matches zero or more levels
        """
        if pattern == topic:
            return True

        pattern_parts = pattern.split("/")
        topic_parts = topic.split("/")

        p_idx = 0
        t_idx = 0

        while p_idx < len(pattern_parts) and t_idx < len(topic_parts):
            p = pattern_parts[p_idx]

            if p == "#":
                return True  # Matches everything remaining
            elif p == "*":
                # Matches one level
                p_idx += 1
                t_idx += 1
            elif p == topic_parts[t_idx]:
                p_idx += 1
                t_idx += 1
            else:
                return False

        return p_idx == len(pattern_parts) and t_idx == len(topic_parts)

    def get_subscribers(self, topic: str) -> Set[bytes]:
        """Get remote subscribers for a topic."""
        with self._lock:
            subscribers = set()
            for pattern, peers in self._remote_subs.items():
                if self._topic_matches(pattern, topic):
                    subscribers.update(peers)
            return subscribers

    def encode_subscribe(self, topic: str) -> bytes:
        """Encode subscribe message."""
        topic_bytes = topic.encode("utf-8")
        return bytes([ApplicationMsgType.SUBSCRIBE, len(topic_bytes)]) + topic_bytes

    def encode_unsubscribe(self, topic: str) -> bytes:
        """Encode unsubscribe message."""
        topic_bytes = topic.encode("utf-8")
        return bytes([ApplicationMsgType.UNSUBSCRIBE, len(topic_bytes)]) + topic_bytes

    def encode_publish(self, msg: PubSubMessage) -> bytes:
        """Encode publish message."""
        topic_bytes = msg.topic.encode("utf-8")
        return (
            bytes([ApplicationMsgType.PUBLISH])
            + msg.message_id
            + msg.publisher_id
            + struct.pack(">BQH", len(topic_bytes), int(msg.timestamp * 1000), len(msg.payload))
            + topic_bytes
            + msg.payload
        )

    def decode_publish(self, data: bytes) -> PubSubMessage:
        """Decode publish message."""
        if len(data) < 45:
            raise ValueError("Publish too short")

        message_id = data[1:17]
        publisher_id = data[17:33]
        topic_len, timestamp_ms, payload_len = struct.unpack(">BQH", data[33:44])

        offset = 44
        topic = data[offset:offset + topic_len].decode("utf-8")
        offset += topic_len
        payload = data[offset:offset + payload_len]

        return PubSubMessage(
            topic=topic,
            payload=payload,
            publisher_id=publisher_id,
            message_id=message_id,
            timestamp=timestamp_ms / 1000,
        )

    def cleanup(self) -> int:
        """Clean up expired messages from dedup cache."""
        with self._lock:
            now = time.time()
            expired = [
                msg_id for msg_id, ts in self._seen_messages.items()
                if now - ts > PUBSUB_MESSAGE_TTL
            ]
            for msg_id in expired:
                del self._seen_messages[msg_id]
            return len(expired)

    def stats(self) -> Dict[str, Any]:
        """Get pub/sub statistics."""
        with self._lock:
            return {
                "local_subscriptions": sum(
                    len(subs) for subs in self._subscriptions.values()
                ),
                "remote_subscriptions": sum(
                    len(peers) for peers in self._remote_subs.values()
                ),
                "topics": list(set(self._subscriptions.keys()) | set(self._remote_subs.keys())),
                "seen_messages": len(self._seen_messages),
            }


# =============================================================================
# Distributed State (KV Store)
# =============================================================================

@dataclass
class KVEntry:
    """A key-value entry with vector clock for conflict resolution."""
    key: str
    value: bytes
    version: Dict[bytes, int] = field(default_factory=dict)  # Vector clock
    modified_by: bytes = b""
    modified_at: float = field(default_factory=time.time)
    deleted: bool = False


class DistributedKVStore:
    """
    Distributed key-value store with CRDT-like conflict resolution.

    Uses vector clocks for causality tracking and last-writer-wins
    for conflict resolution.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize KV store.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id
        self._data: Dict[str, KVEntry] = {}
        self._version = 0  # Our local version counter

        # Sync state
        self._peers: Set[bytes] = set()
        self._pending_sync: Dict[bytes, Set[str]] = defaultdict(set)

        # Stats
        self._stats = {
            "gets": 0,
            "puts": 0,
            "deletes": 0,
            "conflicts_resolved": 0,
            "syncs_sent": 0,
            "syncs_received": 0,
        }

    def get(self, key: str) -> Optional[bytes]:
        """
        Get value for key.

        Args:
            key: Key to look up

        Returns:
            Value or None if not found
        """
        with self._lock:
            self._stats["gets"] += 1
            entry = self._data.get(key)
            if entry and not entry.deleted:
                return entry.value
            return None

    def put(self, key: str, value: bytes) -> bool:
        """
        Put a key-value pair.

        Args:
            key: Key
            value: Value

        Returns:
            True if stored successfully
        """
        if len(key) > KV_MAX_KEY_SIZE:
            return False
        if len(value) > KV_MAX_VALUE_SIZE:
            return False

        with self._lock:
            self._stats["puts"] += 1
            self._version += 1

            existing = self._data.get(key)
            if existing:
                # Update existing entry
                new_version = dict(existing.version)
            else:
                new_version = {}

            # Increment our component of vector clock
            new_version[self._my_id] = self._version

            entry = KVEntry(
                key=key,
                value=value,
                version=new_version,
                modified_by=self._my_id,
                deleted=False,
            )

            self._data[key] = entry

            # Mark for sync to all peers
            for peer in self._peers:
                self._pending_sync[peer].add(key)

            return True

    def delete(self, key: str) -> bool:
        """
        Delete a key (tombstone).

        Args:
            key: Key to delete

        Returns:
            True if deleted
        """
        with self._lock:
            self._stats["deletes"] += 1

            if key not in self._data:
                return False

            self._version += 1
            entry = self._data[key]
            entry.version[self._my_id] = self._version
            entry.deleted = True
            entry.modified_by = self._my_id
            entry.modified_at = time.time()

            for peer in self._peers:
                self._pending_sync[peer].add(key)

            return True

    def merge(self, remote_entry: KVEntry) -> bool:
        """
        Merge remote entry using vector clock comparison.

        Args:
            remote_entry: Entry from remote node

        Returns:
            True if our state changed
        """
        with self._lock:
            self._stats["syncs_received"] += 1
            key = remote_entry.key
            local_entry = self._data.get(key)

            if local_entry is None:
                # We don't have this key
                self._data[key] = remote_entry
                return True

            comparison = self._compare_versions(local_entry.version, remote_entry.version)

            if comparison < 0:
                # Remote is newer
                self._data[key] = remote_entry
                return True
            elif comparison > 0:
                # Local is newer - no change
                return False
            else:
                # Concurrent - resolve conflict
                self._stats["conflicts_resolved"] += 1
                winner = self._resolve_conflict(local_entry, remote_entry)
                if winner != local_entry:
                    self._data[key] = winner
                    return True
                return False

    def _compare_versions(
        self,
        v1: Dict[bytes, int],
        v2: Dict[bytes, int],
    ) -> int:
        """
        Compare vector clocks.

        Returns:
            -1 if v1 < v2 (v1 happened before v2)
            +1 if v1 > v2 (v1 happened after v2)
            0 if concurrent (conflict)
        """
        all_nodes = set(v1.keys()) | set(v2.keys())

        v1_less = False
        v2_less = False

        for node in all_nodes:
            c1 = v1.get(node, 0)
            c2 = v2.get(node, 0)

            if c1 < c2:
                v1_less = True
            elif c1 > c2:
                v2_less = True

        if v1_less and not v2_less:
            return -1  # v1 happened before v2
        elif v2_less and not v1_less:
            return 1  # v1 happened after v2
        else:
            return 0  # Concurrent

    def _resolve_conflict(self, e1: KVEntry, e2: KVEntry) -> KVEntry:
        """
        Resolve conflict between concurrent entries.

        Uses last-writer-wins based on timestamp, with node ID as tiebreaker.
        """
        if e1.modified_at > e2.modified_at:
            return e1
        elif e2.modified_at > e1.modified_at:
            return e2
        else:
            # Same timestamp - use node ID as tiebreaker
            if e1.modified_by > e2.modified_by:
                return e1
            else:
                return e2

    def add_peer(self, peer_id: bytes) -> None:
        """Add a peer for synchronization."""
        with self._lock:
            self._peers.add(peer_id)
            # Mark all keys for sync to new peer
            self._pending_sync[peer_id] = set(self._data.keys())

    def remove_peer(self, peer_id: bytes) -> None:
        """Remove a peer."""
        with self._lock:
            self._peers.discard(peer_id)
            self._pending_sync.pop(peer_id, None)

    def get_sync_entries(self, peer_id: bytes, max_entries: int = 10) -> List[KVEntry]:
        """Get entries to sync to a peer."""
        with self._lock:
            pending = self._pending_sync.get(peer_id, set())
            keys = list(pending)[:max_entries]

            entries = []
            for key in keys:
                if key in self._data:
                    entries.append(self._data[key])
                pending.discard(key)

            if entries:
                self._stats["syncs_sent"] += 1

            return entries

    def keys(self) -> List[str]:
        """Get all non-deleted keys."""
        with self._lock:
            return [k for k, v in self._data.items() if not v.deleted]

    def encode_entry(self, entry: KVEntry) -> bytes:
        """Encode a KV entry for transmission."""
        key_bytes = entry.key.encode("utf-8")

        # Encode vector clock
        vc_data = struct.pack(">B", len(entry.version))
        for node, ver in entry.version.items():
            vc_data += node + struct.pack(">I", ver)

        return (
            struct.pack(">BH", 1 if entry.deleted else 0, len(key_bytes))
            + key_bytes
            + entry.modified_by
            + struct.pack(">Q", int(entry.modified_at * 1000))
            + vc_data
            + struct.pack(">I", len(entry.value))
            + entry.value
        )

    def decode_entry(self, data: bytes) -> KVEntry:
        """Decode a KV entry."""
        if len(data) < 3:
            raise ValueError("Entry too short")

        deleted = bool(data[0])
        key_len = struct.unpack(">H", data[1:3])[0]

        offset = 3
        key = data[offset:offset + key_len].decode("utf-8")
        offset += key_len

        modified_by = data[offset:offset + 16]
        offset += 16

        modified_at = struct.unpack(">Q", data[offset:offset + 8])[0] / 1000
        offset += 8

        vc_count = data[offset]
        offset += 1

        version = {}
        for _ in range(vc_count):
            node = data[offset:offset + 16]
            offset += 16
            ver = struct.unpack(">I", data[offset:offset + 4])[0]
            offset += 4
            version[node] = ver

        value_len = struct.unpack(">I", data[offset:offset + 4])[0]
        offset += 4
        value = data[offset:offset + value_len]

        return KVEntry(
            key=key,
            value=value,
            version=version,
            modified_by=modified_by,
            modified_at=modified_at,
            deleted=deleted,
        )

    def encode_get(self, key: str) -> bytes:
        """Encode GET request."""
        key_bytes = key.encode("utf-8")
        return bytes([ApplicationMsgType.KV_GET, len(key_bytes)]) + key_bytes

    def encode_put(self, key: str, value: bytes) -> bytes:
        """Encode PUT request."""
        key_bytes = key.encode("utf-8")
        return (
            bytes([ApplicationMsgType.KV_PUT])
            + struct.pack(">HI", len(key_bytes), len(value))
            + key_bytes
            + value
        )

    def encode_sync(self, entries: List[KVEntry]) -> bytes:
        """Encode sync message."""
        data = bytes([ApplicationMsgType.KV_SYNC, len(entries)])
        for entry in entries:
            entry_data = self.encode_entry(entry)
            data += struct.pack(">H", len(entry_data)) + entry_data
        return data

    def decode_sync(self, data: bytes) -> List[KVEntry]:
        """Decode sync message."""
        if len(data) < 2:
            raise ValueError("Sync too short")

        count = data[1]
        entries = []
        offset = 2

        for _ in range(count):
            entry_len = struct.unpack(">H", data[offset:offset + 2])[0]
            offset += 2
            entry = self.decode_entry(data[offset:offset + entry_len])
            entries.append(entry)
            offset += entry_len

        return entries

    def stats(self) -> Dict[str, Any]:
        """Get KV store statistics."""
        with self._lock:
            return {
                **self._stats,
                "total_keys": len(self._data),
                "active_keys": len([k for k, v in self._data.items() if not v.deleted]),
                "peers": len(self._peers),
                "pending_syncs": sum(len(keys) for keys in self._pending_sync.values()),
            }
