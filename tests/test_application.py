"""
Tests for malachi.application module.
"""

import pytest
import os
import time

from malachi.application import (
    ServiceDiscovery,
    ServiceRecord,
    PubSubManager,
    PubSubMessage,
    DistributedKVStore,
    KVEntry,
)


class TestServiceDiscovery:
    """Tests for ServiceDiscovery."""

    def test_register_service(self):
        """Test service registration."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        service_id = sd.register_service(
            service_type="_http._tcp",
            service_name="Web Server",
            port=8080,
        )

        assert service_id == "Web Server._http._tcp"
        assert service_id in sd._local_services

    def test_unregister_service(self):
        """Test service unregistration."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        service_id = sd.register_service("_http._tcp", "Test", 80)
        assert sd.unregister_service(service_id)
        assert service_id not in sd._local_services

    def test_handle_query(self):
        """Test handling service query."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        sd.register_service("_http._tcp", "Test", 80)
        responses = sd.handle_query("_http._tcp")

        assert len(responses) == 1

    def test_handle_response(self):
        """Test handling service response."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        record = ServiceRecord(
            service_type="_http._tcp",
            service_name="Remote Service",
            provider_id=os.urandom(16),
            port=8080,
        )

        sd.handle_response(record)

        services = sd.query_service("_http._tcp")
        assert len(services) == 1
        assert services[0].service_name == "Remote Service"

    def test_encode_decode_response(self):
        """Test response encoding/decoding."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        record = ServiceRecord(
            service_type="_http._tcp",
            service_name="Test",
            provider_id=my_id,
            port=8080,
            priority=5,
            weight=10,
            properties={"path": "/api"},
        )

        encoded = sd.encode_response(record)
        decoded = sd.decode_response(encoded)

        assert decoded.service_type == record.service_type
        assert decoded.service_name == record.service_name
        assert decoded.port == record.port
        assert decoded.priority == record.priority
        assert decoded.properties == record.properties

    def test_get_service_priority(self):
        """Test getting service with priority ordering."""
        my_id = os.urandom(16)
        sd = ServiceDiscovery(my_id)

        # Add services with different priorities
        sd.handle_response(ServiceRecord(
            service_type="_http._tcp",
            service_name="Low Priority",
            provider_id=os.urandom(16),
            port=80,
            priority=10,
        ))

        sd.handle_response(ServiceRecord(
            service_type="_http._tcp",
            service_name="High Priority",
            provider_id=os.urandom(16),
            port=80,
            priority=1,
        ))

        best = sd.get_service("_http._tcp")
        assert best.service_name == "High Priority"


class TestPubSubManager:
    """Tests for PubSubManager."""

    def test_subscribe_unsubscribe(self):
        """Test subscribing and unsubscribing."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        assert ps.subscribe("test/topic")
        assert "test/topic" in ps._subscriptions

        assert ps.unsubscribe("test/topic")
        assert len(ps._subscriptions["test/topic"]) == 0

    def test_publish_local_delivery(self):
        """Test that publish delivers to local subscribers."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        received = []

        def callback(msg):
            received.append(msg)

        ps.subscribe("test/topic", callback)
        ps.publish("test/topic", b"hello")

        assert len(received) == 1
        assert received[0].payload == b"hello"

    def test_topic_wildcard_star(self):
        """Test * wildcard matching."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        received = []
        ps.subscribe("sensors/*/temperature", lambda m: received.append(m))

        ps.publish("sensors/kitchen/temperature", b"21")
        ps.publish("sensors/bedroom/temperature", b"19")
        ps.publish("sensors/kitchen/humidity", b"50")  # Should not match

        assert len(received) == 2

    def test_topic_wildcard_hash(self):
        """Test # wildcard matching."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        received = []
        ps.subscribe("sensors/#", lambda m: received.append(m))

        ps.publish("sensors/kitchen/temperature", b"21")
        ps.publish("sensors/bedroom", b"data")
        ps.publish("other/topic", b"x")  # Should not match

        assert len(received) == 2

    def test_message_deduplication(self):
        """Test that duplicate messages are ignored."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        received = []
        ps.subscribe("test", lambda m: received.append(m))

        msg = ps.publish("test", b"hello")

        # Try to handle the same message again
        result = ps.handle_publish(msg)
        assert not result  # Should be rejected as duplicate

        assert len(received) == 1

    def test_encode_decode_publish(self):
        """Test publish message encoding/decoding."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)

        msg = PubSubMessage(
            topic="test/topic",
            payload=b"test payload",
            publisher_id=my_id,
            message_id=os.urandom(16),
            timestamp=time.time(),
        )

        encoded = ps.encode_publish(msg)
        decoded = ps.decode_publish(encoded)

        assert decoded.topic == msg.topic
        assert decoded.payload == msg.payload
        assert decoded.message_id == msg.message_id

    def test_handle_remote_subscribe(self):
        """Test handling remote subscription."""
        my_id = os.urandom(16)
        ps = PubSubManager(my_id)
        peer = os.urandom(16)

        ps.handle_subscribe(peer, "events/#")

        subscribers = ps.get_subscribers("events/user/login")
        assert peer in subscribers


class TestDistributedKVStore:
    """Tests for DistributedKVStore."""

    def test_put_get(self):
        """Test basic put/get."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        assert kv.put("key1", b"value1")
        assert kv.get("key1") == b"value1"

    def test_get_missing_key(self):
        """Test getting non-existent key."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        assert kv.get("nonexistent") is None

    def test_delete(self):
        """Test deleting a key."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        kv.put("key1", b"value1")
        assert kv.delete("key1")
        assert kv.get("key1") is None

    def test_merge_newer_remote(self):
        """Test merging newer remote entry."""
        my_id = os.urandom(16)
        other_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        # Put local value
        kv.put("key1", b"local")

        # Create newer remote entry
        remote = KVEntry(
            key="key1",
            value=b"remote",
            version={other_id: 100},  # Higher version
            modified_by=other_id,
            modified_at=time.time() + 10,
        )

        assert kv.merge(remote)
        assert kv.get("key1") == b"remote"

    def test_merge_older_remote(self):
        """Test merging older remote entry."""
        my_id = os.urandom(16)
        other_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        # Put local value with version
        kv.put("key1", b"local")

        # Create older remote entry
        remote = KVEntry(
            key="key1",
            value=b"remote",
            version={other_id: 1},
            modified_by=other_id,
            modified_at=time.time() - 100,
        )

        # Local should win
        assert not kv.merge(remote)
        assert kv.get("key1") == b"local"

    def test_conflict_resolution(self):
        """Test conflict resolution (last-writer-wins)."""
        my_id = os.urandom(16)
        other_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        # Put local value
        kv.put("key1", b"local")

        # Create concurrent remote entry with later timestamp
        now = time.time()
        remote = KVEntry(
            key="key1",
            value=b"remote",
            version={other_id: 1},  # Different node, concurrent
            modified_by=other_id,
            modified_at=now + 1,  # Later
        )

        kv.merge(remote)
        assert kv.get("key1") == b"remote"

    def test_encode_decode_entry(self):
        """Test entry encoding/decoding."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        entry = KVEntry(
            key="test_key",
            value=b"test_value",
            version={my_id: 5},
            modified_by=my_id,
            modified_at=time.time(),
        )

        encoded = kv.encode_entry(entry)
        decoded = kv.decode_entry(encoded)

        assert decoded.key == entry.key
        assert decoded.value == entry.value
        assert decoded.version == entry.version
        assert decoded.modified_by == entry.modified_by

    def test_sync_entries(self):
        """Test getting entries for sync."""
        my_id = os.urandom(16)
        peer = os.urandom(16)
        kv = DistributedKVStore(my_id)

        kv.put("key1", b"value1")
        kv.put("key2", b"value2")

        kv.add_peer(peer)

        entries = kv.get_sync_entries(peer)
        assert len(entries) == 2

        # Second call should return empty (already synced)
        entries2 = kv.get_sync_entries(peer)
        assert len(entries2) == 0

    def test_keys(self):
        """Test listing keys."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        kv.put("key1", b"value1")
        kv.put("key2", b"value2")
        kv.delete("key1")

        keys = kv.keys()
        assert "key2" in keys
        assert "key1" not in keys  # Deleted

    def test_encode_decode_sync(self):
        """Test sync message encoding/decoding."""
        my_id = os.urandom(16)
        kv = DistributedKVStore(my_id)

        kv.put("key1", b"value1")
        kv.put("key2", b"value2")

        peer = os.urandom(16)
        kv.add_peer(peer)
        entries = kv.get_sync_entries(peer)

        encoded = kv.encode_sync(entries)
        decoded = kv.decode_sync(encoded)

        assert len(decoded) == 2
        assert decoded[0].key in ["key1", "key2"]
