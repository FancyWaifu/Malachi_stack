"""
Tests for malachi.protocol module.
"""

import pytest
import os
import time

from malachi.protocol import (
    MulticastManager,
    QoSScheduler,
    QoSClass,
    ConnectionManager,
    ConnectionState,
    StreamManager,
    StreamState,
    RequestResponseManager,
    MULTICAST_GROUP_PREFIX,
)


class TestMulticastManager:
    """Tests for MulticastManager."""

    def test_create_group(self):
        """Test creating a multicast group."""
        my_id = os.urandom(16)
        mgr = MulticastManager(my_id)

        group_id = mgr.create_group("test-group")

        assert group_id.startswith(MULTICAST_GROUP_PREFIX)
        assert len(group_id) == 16

    def test_join_leave_group(self):
        """Test joining and leaving groups."""
        my_id = os.urandom(16)
        mgr = MulticastManager(my_id)

        group_id = mgr.create_group("test-group")

        assert mgr.join_group(group_id)
        assert mgr.is_member(group_id)
        assert my_id in mgr.get_group_members(group_id)

        assert mgr.leave_group(group_id)
        assert not mgr.is_member(group_id)

    def test_encode_decode(self):
        """Test message encoding/decoding."""
        my_id = os.urandom(16)
        mgr = MulticastManager(my_id)

        group_id = mgr.create_group("test")
        data = b"hello multicast"

        encoded = mgr.encode_data(group_id, data)
        msg_type, decoded_group, payload = mgr.decode_message(encoded)

        assert decoded_group == group_id
        assert payload == data

    def test_stats(self):
        """Test statistics."""
        my_id = os.urandom(16)
        mgr = MulticastManager(my_id)

        group_id = mgr.create_group("test")
        mgr.join_group(group_id)

        stats = mgr.stats()
        assert stats["groups_known"] == 1
        assert stats["groups_joined"] == 1


class TestQoSScheduler:
    """Tests for QoSScheduler."""

    def test_enqueue_dequeue(self):
        """Test basic enqueue/dequeue."""
        sched = QoSScheduler()
        dest = os.urandom(16)

        sched.enqueue(b"test", priority=4, dest=dest)
        result = sched.dequeue()

        assert result is not None
        assert result[0] == b"test"
        assert result[1] == dest

    def test_priority_ordering(self):
        """Test that higher priority dequeues first."""
        sched = QoSScheduler()

        sched.enqueue(b"low", priority=0)
        sched.enqueue(b"high", priority=7)
        sched.enqueue(b"medium", priority=4)

        # Should get high first
        data, _ = sched.dequeue()
        assert data == b"high"

        data, _ = sched.dequeue()
        assert data == b"medium"

        data, _ = sched.dequeue()
        assert data == b"low"

    def test_empty_dequeue(self):
        """Test dequeue from empty scheduler."""
        sched = QoSScheduler()
        assert sched.dequeue() is None

    def test_has_pending(self):
        """Test has_pending check."""
        sched = QoSScheduler()

        assert not sched.has_pending()
        sched.enqueue(b"test")
        assert sched.has_pending()
        sched.dequeue()
        assert not sched.has_pending()

    def test_stats(self):
        """Test statistics."""
        sched = QoSScheduler()
        sched.enqueue(b"test", priority=QoSClass.CONTROL)
        sched.dequeue()

        stats = sched.stats()
        assert "class_7" in stats
        assert stats["class_7"]["packets_sent"] == 1


class TestConnectionManager:
    """Tests for ConnectionManager."""

    def test_connect(self):
        """Test initiating connection."""
        my_id = os.urandom(16)
        mgr = ConnectionManager(my_id)
        peer_id = os.urandom(16)

        conn_id = mgr.connect(peer_id)

        assert conn_id > 0
        conn = mgr.get_connection(conn_id)
        assert conn is not None
        assert conn.state == ConnectionState.SYN_SENT

    def test_accept(self):
        """Test accepting connection."""
        my_id = os.urandom(16)
        mgr = ConnectionManager(my_id)
        peer_id = os.urandom(16)

        conn_id = mgr.accept(peer_id, 12345)

        conn = mgr.get_connection(conn_id)
        assert conn.state == ConnectionState.SYN_RECEIVED
        assert conn.remote_seq == 12345

    def test_three_way_handshake(self):
        """Test full connection establishment."""
        my_id = os.urandom(16)
        mgr = ConnectionManager(my_id)
        peer_id = os.urandom(16)

        # Client sends SYN
        conn_id = mgr.connect(peer_id)

        # Simulate receiving SYN-ACK
        mgr.on_syn_ack(conn_id, 67890)

        conn = mgr.get_connection(conn_id)
        assert conn.state == ConnectionState.ESTABLISHED
        assert mgr.is_connected(peer_id)

    def test_close(self):
        """Test connection close."""
        my_id = os.urandom(16)
        mgr = ConnectionManager(my_id)
        peer_id = os.urandom(16)

        conn_id = mgr.connect(peer_id)
        mgr.on_syn_ack(conn_id, 67890)

        assert mgr.close(conn_id)
        conn = mgr.get_connection(conn_id)
        assert conn.state == ConnectionState.FIN_WAIT_1

    def test_encode_messages(self):
        """Test message encoding."""
        my_id = os.urandom(16)
        mgr = ConnectionManager(my_id)
        peer_id = os.urandom(16)

        conn_id = mgr.connect(peer_id)

        syn = mgr.encode_syn(conn_id)
        assert len(syn) > 0

        # Accept to test SYN-ACK
        mgr.on_syn_ack(conn_id, 12345)
        ack = mgr.encode_ack(conn_id)
        assert len(ack) > 0


class TestStreamManager:
    """Tests for StreamManager."""

    def test_open_stream(self):
        """Test opening a stream."""
        mgr = StreamManager()

        stream_id = mgr.open_stream(conn_id=1, is_client=True)

        assert stream_id == 1  # Client starts with odd IDs

    def test_write_read(self):
        """Test stream write/read."""
        mgr = StreamManager()
        stream_id = mgr.open_stream(conn_id=1)

        written = mgr.write(1, stream_id, b"hello")
        assert written == 5

        # Simulate receiving data
        mgr.receive_data(1, stream_id, b"world")
        data = mgr.read(1, stream_id)
        assert data == b"world"

    def test_stream_close(self):
        """Test stream close."""
        mgr = StreamManager()
        stream_id = mgr.open_stream(conn_id=1)

        mgr.close_stream(1, stream_id)

        stream = mgr._streams.get((1, stream_id))
        assert stream.state == StreamState.HALF_CLOSED_LOCAL

    def test_encode_messages(self):
        """Test message encoding."""
        mgr = StreamManager()
        stream_id = mgr.open_stream(conn_id=1)

        open_msg = mgr.encode_open(1, stream_id)
        assert len(open_msg) > 0

        data_msg = mgr.encode_data(1, stream_id, b"test")
        assert b"test" in data_msg


class TestRequestResponseManager:
    """Tests for RequestResponseManager."""

    def test_register_handler(self):
        """Test registering request handler."""
        mgr = RequestResponseManager()

        def handler(peer_id, data):
            return 200, b"ok"

        mgr.register_handler("ping", handler)
        assert "ping" in mgr._handlers

    def test_request(self):
        """Test creating a request."""
        mgr = RequestResponseManager()
        peer_id = os.urandom(16)

        req_id = mgr.request(peer_id, "test", b"data")

        assert req_id > 0
        assert req_id in mgr._pending

    def test_handle_request(self):
        """Test handling incoming request."""
        mgr = RequestResponseManager()

        def echo_handler(peer_id, data):
            return 200, data

        mgr.register_handler("echo", echo_handler)

        peer_id = os.urandom(16)
        status, response = mgr.handle_request(peer_id, 1, "echo", b"hello")

        assert status == 200
        assert response == b"hello"

    def test_handle_unknown_method(self):
        """Test handling unknown method."""
        mgr = RequestResponseManager()
        peer_id = os.urandom(16)

        status, response = mgr.handle_request(peer_id, 1, "unknown", b"")

        assert status == 404

    def test_handle_response_with_callback(self):
        """Test handling response with callback."""
        mgr = RequestResponseManager()
        peer_id = os.urandom(16)

        received = []

        def callback(data, error):
            received.append((data, error))

        req_id = mgr.request(peer_id, "test", callback=callback)
        mgr.handle_response(req_id, 200, b"response")

        assert len(received) == 1
        assert received[0][0] == b"response"
        assert received[0][1] is None

    def test_cancel(self):
        """Test cancelling request."""
        mgr = RequestResponseManager()
        peer_id = os.urandom(16)

        cancelled = []

        def callback(data, error):
            cancelled.append(error)

        req_id = mgr.request(peer_id, "test", callback=callback)
        assert mgr.cancel(req_id)

        assert len(cancelled) == 1
        assert "Cancelled" in str(cancelled[0])

    def test_encode_decode_request(self):
        """Test request encoding/decoding."""
        mgr = RequestResponseManager()

        encoded = mgr.encode_request(123, "ping", b"payload")
        req_id, method, payload = mgr.decode_request(encoded)

        assert req_id == 123
        assert method == "ping"
        assert payload == b"payload"

    def test_encode_decode_response(self):
        """Test response encoding/decoding."""
        mgr = RequestResponseManager()

        encoded = mgr.encode_response(456, 200, b"ok")
        req_id, status, payload = mgr.decode_response(encoded)

        assert req_id == 456
        assert status == 200
        assert payload == b"ok"
