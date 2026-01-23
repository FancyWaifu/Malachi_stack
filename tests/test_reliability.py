"""
Tests for malachi.reliability module.
"""

import pytest
import time
import threading

from malachi.reliability import (
    ACKManager,
    FlowController,
    CongestionController,
    KeepAliveManager,
    ReliabilityLayer,
    RTTEstimator,
    ACK_TYPE_SELECTIVE,
    ACK_TYPE_CUMULATIVE,
    CongestionState,
    INITIAL_CWND,
    DEFAULT_WINDOW_SIZE,
)


class TestRTTEstimator:
    """Tests for RTT estimation."""

    def test_initial_measurement(self):
        """Test first RTT measurement."""
        est = RTTEstimator()
        est.update(0.1)  # 100ms RTT

        assert est.has_measurement
        assert est.srtt == 0.1
        assert est.rto > 0

    def test_smoothed_update(self):
        """Test smoothed RTT updates."""
        est = RTTEstimator()
        est.update(0.1)
        est.update(0.2)
        est.update(0.15)

        # SRTT should be smoothed
        assert 0.1 < est.srtt < 0.2

    def test_backoff(self):
        """Test exponential backoff."""
        est = RTTEstimator()
        est.update(0.1)
        initial_rto = est.rto

        est.backoff()
        assert est.rto == initial_rto * 2


class TestACKManager:
    """Tests for ACK manager."""

    def test_send_assigns_sequence(self):
        """Test that send assigns sequence numbers."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        seq1 = mgr.send_reliable(peer, b"msg1")
        seq2 = mgr.send_reliable(peer, b"msg2")

        assert seq1 == 0
        assert seq2 == 1

    def test_receive_ack_selective(self):
        """Test selective ACK processing."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        seq1 = mgr.send_reliable(peer, b"msg1")
        seq2 = mgr.send_reliable(peer, b"msg2")
        seq3 = mgr.send_reliable(peer, b"msg3")

        # ACK only seq2
        mgr.receive_ack(peer, ACK_TYPE_SELECTIVE, [seq2])

        stats = mgr.stats()
        assert stats["messages_acked"] == 1
        assert stats["pending_messages"] == 2

    def test_receive_ack_cumulative(self):
        """Test cumulative ACK processing."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        mgr.send_reliable(peer, b"msg1")
        mgr.send_reliable(peer, b"msg2")
        mgr.send_reliable(peer, b"msg3")

        # Cumulative ACK up to seq 1
        mgr.receive_ack(peer, ACK_TYPE_CUMULATIVE, [1])

        stats = mgr.stats()
        assert stats["messages_acked"] == 2  # seq 0 and 1
        assert stats["pending_messages"] == 1  # seq 2 still pending

    def test_receive_data_in_order(self):
        """Test receiving data in order."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        is_dup, data, acks = mgr.receive_data(peer, 0, b"first")
        assert not is_dup
        assert data == b"first"
        assert 0 in acks

        is_dup, data, acks = mgr.receive_data(peer, 1, b"second")
        assert not is_dup
        assert data == b"second"

    def test_receive_data_out_of_order(self):
        """Test receiving data out of order."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        # Receive seq 2 first
        is_dup, data, acks = mgr.receive_data(peer, 2, b"third")
        assert not is_dup
        assert data is None  # Can't deliver yet
        assert 2 in acks

        # Receive seq 0
        is_dup, data, acks = mgr.receive_data(peer, 0, b"first")
        assert not is_dup
        assert data == b"first"

    def test_receive_data_duplicate(self):
        """Test receiving duplicate data."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        mgr.receive_data(peer, 0, b"first")
        is_dup, data, _ = mgr.receive_data(peer, 0, b"first")

        assert is_dup
        assert data is None

    def test_generate_ack(self):
        """Test ACK generation."""
        mgr = ACKManager()
        peer = b"\x00" * 16

        ack = mgr.generate_ack(peer, [1, 3, 5])

        assert ack[0] == ACK_TYPE_SELECTIVE
        assert ack[1] == 3  # count


class TestFlowController:
    """Tests for flow controller."""

    def test_initial_window(self):
        """Test initial window size."""
        fc = FlowController()
        peer = b"\x00" * 16

        window = fc.get_send_window(peer)
        assert window == DEFAULT_WINDOW_SIZE

    def test_send_reduces_window(self):
        """Test that sending reduces available window."""
        fc = FlowController()
        peer = b"\x00" * 16

        initial = fc.get_send_window(peer)
        fc.on_send(peer, 1000)

        assert fc.get_send_window(peer) == initial - 1000

    def test_ack_increases_window(self):
        """Test that ACK increases available window."""
        fc = FlowController()
        peer = b"\x00" * 16

        fc.on_send(peer, 1000)
        fc.on_ack(peer, 500)

        initial = DEFAULT_WINDOW_SIZE
        assert fc.get_send_window(peer) == initial - 500

    def test_can_send(self):
        """Test can_send check."""
        fc = FlowController(default_window=1000)
        peer = b"\x00" * 16

        assert fc.can_send(peer, 500)
        fc.on_send(peer, 800)
        assert not fc.can_send(peer, 300)

    def test_receive_window(self):
        """Test receive window tracking."""
        fc = FlowController(default_window=1000)
        peer = b"\x00" * 16

        assert fc.get_recv_window(peer) == 1000
        fc.on_receive(peer, 300)
        assert fc.get_recv_window(peer) == 700
        fc.on_consume(peer, 200)
        assert fc.get_recv_window(peer) == 900


class TestCongestionController:
    """Tests for congestion controller."""

    def test_initial_cwnd(self):
        """Test initial congestion window."""
        cc = CongestionController()
        peer = b"\x00" * 16

        cwnd = cc.get_cwnd(peer)
        assert cwnd == INITIAL_CWND

    def test_slow_start_growth(self):
        """Test slow start exponential growth."""
        cc = CongestionController()
        peer = b"\x00" * 16

        initial = cc.get_cwnd(peer)

        # ACK some bytes
        cc.on_ack(peer, 1400, 0)
        assert cc.get_cwnd(peer) > initial

    def test_timeout_resets_cwnd(self):
        """Test timeout resets cwnd."""
        cc = CongestionController()
        peer = b"\x00" * 16

        # Grow the window
        cc.on_ack(peer, 5000, 0)
        before_timeout = cc.get_cwnd(peer)

        cc.on_timeout(peer)

        assert cc.get_cwnd(peer) < before_timeout
        assert cc.get_cwnd(peer) == INITIAL_CWND

    def test_triple_dup_ack(self):
        """Test triple duplicate ACK triggers fast recovery."""
        cc = CongestionController()
        peer = b"\x00" * 16

        # ACK seq 0 multiple times
        cc.on_ack(peer, 1400, 0)
        cc.on_ack(peer, 0, 0)  # dup 1
        cc.on_ack(peer, 0, 0)  # dup 2
        cc.on_ack(peer, 0, 0)  # dup 3 - triggers fast recovery

        state = cc._get_state(peer)
        assert state.state == CongestionState.FAST_RECOVERY


class TestKeepAliveManager:
    """Tests for keep-alive manager."""

    def test_track_peer(self):
        """Test peer tracking."""
        ka = KeepAliveManager()
        peer = b"\x00" * 16

        ka.track_peer(peer)
        assert ka.is_alive(peer)

    def test_untrack_peer(self):
        """Test peer untracking."""
        ka = KeepAliveManager()
        peer = b"\x00" * 16

        ka.track_peer(peer)
        ka.untrack_peer(peer)
        assert not ka.is_alive(peer)

    def test_on_activity(self):
        """Test activity tracking."""
        ka = KeepAliveManager()
        peer = b"\x00" * 16

        ka.track_peer(peer)
        ka.on_activity(peer)

        stats = ka.stats()
        assert stats["alive_peers"] == 1


class TestReliabilityLayer:
    """Tests for integrated reliability layer."""

    def test_create_layer(self):
        """Test creating reliability layer."""
        layer = ReliabilityLayer()
        assert layer.ack_manager is not None
        assert layer.flow_controller is not None
        assert layer.congestion_controller is not None
        assert layer.keepalive_manager is not None

    def test_start_stop(self):
        """Test starting and stopping."""
        layer = ReliabilityLayer()
        layer.start()
        assert layer._running
        layer.stop()
        assert not layer._running

    def test_can_send_checks_all(self):
        """Test can_send checks all controllers."""
        layer = ReliabilityLayer()
        peer = b"\x00" * 16

        # Should be able to send initially
        assert layer.can_send(peer, 1000, 0)

    def test_stats_combined(self):
        """Test combined statistics."""
        layer = ReliabilityLayer()
        stats = layer.stats()

        assert "ack" in stats
        assert "flow" in stats
        assert "congestion" in stats
        assert "keepalive" in stats
