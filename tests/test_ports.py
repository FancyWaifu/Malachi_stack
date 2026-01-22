"""
Tests for malachi.ports module.
"""

import pytest
import os
import threading
import time

from malachi.ports import (
    PortManager,
    PortMessage,
    allocate_ephemeral_port,
)
from malachi.exceptions import (
    PortAlreadyBoundError,
    PortNotBoundError,
    InvalidPortError,
)


class TestPortManager:
    """Tests for PortManager."""

    def test_bind_port(self):
        """Test binding a port."""
        manager = PortManager()
        manager.bind(1234)

        assert manager.is_bound(1234)

    def test_bind_duplicate(self):
        """Test binding already-bound port."""
        manager = PortManager()
        manager.bind(1234)

        with pytest.raises(PortAlreadyBoundError):
            manager.bind(1234)

    def test_bind_invalid_port(self):
        """Test binding invalid port number."""
        manager = PortManager()

        with pytest.raises(InvalidPortError):
            manager.bind(-1)

        with pytest.raises(InvalidPortError):
            manager.bind(70000)

    def test_unbind_port(self):
        """Test unbinding a port."""
        manager = PortManager()
        manager.bind(1234)
        manager.unbind(1234)

        assert not manager.is_bound(1234)

    def test_unbind_not_bound(self):
        """Test unbinding not-bound port."""
        manager = PortManager()

        with pytest.raises(PortNotBoundError):
            manager.unbind(1234)

    def test_publish_and_receive(self):
        """Test publishing and receiving messages."""
        manager = PortManager()
        manager.bind(1234)

        src_id = os.urandom(16)
        payload = b"test message"

        assert manager.publish(1234, src_id, 5678, payload)

        msg = manager.receive(1234, timeout=1.0)

        assert msg is not None
        assert msg.src_id == src_id
        assert msg.src_port == 5678
        assert msg.payload == payload

    def test_receive_timeout(self):
        """Test receive timeout."""
        manager = PortManager()
        manager.bind(1234)

        msg = manager.receive(1234, timeout=0.1)

        assert msg is None

    def test_receive_non_blocking(self):
        """Test non-blocking receive."""
        manager = PortManager()
        manager.bind(1234)

        msg = manager.receive(1234, timeout=0)

        assert msg is None

    def test_publish_no_listener(self):
        """Test publishing to unbound port."""
        manager = PortManager()

        result = manager.publish(1234, os.urandom(16), 5678, b"test")

        assert not result

    def test_list_ports(self):
        """Test listing bound ports."""
        manager = PortManager()
        manager.bind(1234)
        manager.bind(5678)

        ports = manager.list_ports()

        assert 1234 in ports
        assert 5678 in ports

    def test_queue_capacity(self):
        """Test queue capacity handling."""
        manager = PortManager()
        manager.bind(1234, capacity=2)

        src_id = os.urandom(16)

        # Fill queue
        manager.publish(1234, src_id, 1, b"msg1")
        manager.publish(1234, src_id, 2, b"msg2")
        manager.publish(1234, src_id, 3, b"msg3")  # Should evict oldest

        # Should receive msg2 and msg3 (msg1 evicted)
        msg1 = manager.receive(1234, timeout=0)
        msg2 = manager.receive(1234, timeout=0)

        assert msg1 is not None
        assert msg2 is not None
        assert manager.receive(1234, timeout=0) is None


class TestEphemeralPorts:
    """Tests for ephemeral port allocation."""

    def test_allocate_in_range(self):
        """Test ephemeral port is in valid range."""
        for _ in range(100):
            port = allocate_ephemeral_port()
            assert 49152 <= port <= 65535


class TestPortManagerConcurrency:
    """Tests for concurrent port operations."""

    def test_concurrent_publish_receive(self):
        """Test concurrent publishing and receiving."""
        manager = PortManager()
        manager.bind(1234, capacity=1000)

        received = []
        errors = []

        def publisher():
            for i in range(100):
                try:
                    manager.publish(1234, os.urandom(16), i, f"msg{i}".encode())
                except Exception as e:
                    errors.append(e)

        def receiver():
            for _ in range(100):
                try:
                    msg = manager.receive(1234, timeout=1.0)
                    if msg:
                        received.append(msg)
                except Exception as e:
                    errors.append(e)

        pub_thread = threading.Thread(target=publisher)
        recv_thread = threading.Thread(target=receiver)

        pub_thread.start()
        recv_thread.start()

        pub_thread.join()
        recv_thread.join()

        assert len(errors) == 0
        assert len(received) == 100
