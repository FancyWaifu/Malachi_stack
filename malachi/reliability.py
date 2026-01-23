"""
Reliability features for Malachi protocol.

This module implements:
- ACKs and Retransmission with exponential backoff
- Flow Control with receiver-advertised window
- Congestion Control (AIMD - Additive Increase Multiplicative Decrease)
- Keep-Alive/Heartbeat mechanisms
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple, List, Callable, Any
from enum import IntEnum
from collections import deque

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# ACK/Retransmission
ACK_TYPE_SELECTIVE = 0x01  # Selective ACK (SACK)
ACK_TYPE_CUMULATIVE = 0x02  # Cumulative ACK
ACK_TYPE_NACK = 0x03  # Negative ACK

INITIAL_RTO = 1.0  # Initial retransmission timeout (seconds)
MIN_RTO = 0.2  # Minimum RTO
MAX_RTO = 60.0  # Maximum RTO
RTO_ALPHA = 0.125  # SRTT smoothing factor
RTO_BETA = 0.25  # RTTVAR smoothing factor
MAX_RETRIES = 5  # Maximum retransmission attempts

# Flow Control
DEFAULT_WINDOW_SIZE = 65535  # Default receive window (bytes)
MIN_WINDOW_SIZE = 1400  # Minimum window size (one MTU)
MAX_WINDOW_SIZE = 1048576  # Maximum window size (1MB)

# Congestion Control (AIMD)
INITIAL_CWND = 1400 * 2  # Initial congestion window (2 MTU)
MIN_CWND = 1400  # Minimum congestion window
MAX_CWND = 1048576  # Maximum congestion window
SSTHRESH_INITIAL = 65535  # Initial slow start threshold
AIMD_INCREASE = 1400  # Additive increase per RTT (1 MTU)
AIMD_DECREASE = 0.5  # Multiplicative decrease factor

# Keep-Alive
KEEPALIVE_INTERVAL = 30.0  # Send keepalive every 30 seconds
KEEPALIVE_TIMEOUT = 90.0  # Consider dead after 90 seconds
KEEPALIVE_RETRIES = 3  # Keepalive retries before declaring dead


# =============================================================================
# Message Types for Reliability
# =============================================================================

class ReliabilityMsgType(IntEnum):
    """Message types for reliability layer."""
    DATA = 0x01
    ACK = 0x02
    NACK = 0x03
    KEEPALIVE_REQ = 0x04
    KEEPALIVE_RSP = 0x05
    WINDOW_UPDATE = 0x06


# =============================================================================
# ACK and Retransmission
# =============================================================================

@dataclass
class PendingMessage:
    """A message awaiting acknowledgment."""
    seq_num: int
    data: bytes
    first_sent: float
    last_sent: float
    retries: int = 0
    acked: bool = False


@dataclass
class RTTEstimator:
    """Estimates round-trip time for a peer using Jacobson/Karels algorithm."""
    srtt: float = 0.0  # Smoothed RTT
    rttvar: float = 0.0  # RTT variance
    rto: float = INITIAL_RTO  # Retransmission timeout
    has_measurement: bool = False

    def update(self, rtt: float) -> None:
        """Update RTT estimate with a new measurement."""
        if not self.has_measurement:
            # First measurement
            self.srtt = rtt
            self.rttvar = rtt / 2
            self.has_measurement = True
        else:
            # Jacobson/Karels algorithm
            self.rttvar = (1 - RTO_BETA) * self.rttvar + RTO_BETA * abs(self.srtt - rtt)
            self.srtt = (1 - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt

        # Calculate RTO
        self.rto = self.srtt + 4 * self.rttvar
        self.rto = max(MIN_RTO, min(MAX_RTO, self.rto))

    def backoff(self) -> None:
        """Apply exponential backoff to RTO."""
        self.rto = min(MAX_RTO, self.rto * 2)


class ACKManager:
    """
    Manages acknowledgments and retransmissions.

    Supports both selective ACK (SACK) and cumulative ACK modes.
    Implements exponential backoff for retransmissions.
    """

    def __init__(self, send_callback: Optional[Callable[[bytes, bytes], None]] = None):
        """
        Initialize ACK manager.

        Args:
            send_callback: Function to call when retransmitting (peer_id, data)
        """
        self._lock = threading.RLock()
        self._send_callback = send_callback

        # Per-peer state
        self._tx_seq: Dict[bytes, int] = {}  # Next sequence number to send
        self._rx_seq: Dict[bytes, int] = {}  # Next expected sequence number
        self._pending: Dict[bytes, Dict[int, PendingMessage]] = {}  # Pending ACKs
        self._rtt: Dict[bytes, RTTEstimator] = {}  # RTT estimators
        self._out_of_order: Dict[bytes, Dict[int, bytes]] = {}  # Out-of-order received

        # Statistics
        self._stats = {
            "messages_sent": 0,
            "messages_acked": 0,
            "retransmissions": 0,
            "acks_sent": 0,
            "timeouts": 0,
        }

        # Retransmission thread
        self._running = False
        self._retx_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the retransmission thread."""
        if self._running:
            return
        self._running = True
        self._retx_thread = threading.Thread(target=self._retx_loop, daemon=True)
        self._retx_thread.start()

    def stop(self) -> None:
        """Stop the retransmission thread."""
        self._running = False
        if self._retx_thread:
            self._retx_thread.join(timeout=2.0)
            self._retx_thread = None

    def _get_rtt(self, peer_id: bytes) -> RTTEstimator:
        """Get or create RTT estimator for peer."""
        if peer_id not in self._rtt:
            self._rtt[peer_id] = RTTEstimator()
        return self._rtt[peer_id]

    def send_reliable(self, peer_id: bytes, data: bytes) -> int:
        """
        Queue a message for reliable delivery.

        Args:
            peer_id: Destination peer ID
            data: Message data

        Returns:
            Sequence number assigned to message
        """
        with self._lock:
            if peer_id not in self._tx_seq:
                self._tx_seq[peer_id] = 0
                self._pending[peer_id] = {}

            seq = self._tx_seq[peer_id]
            self._tx_seq[peer_id] = (seq + 1) & 0xFFFFFFFF

            now = time.time()
            self._pending[peer_id][seq] = PendingMessage(
                seq_num=seq,
                data=data,
                first_sent=now,
                last_sent=now,
            )
            self._stats["messages_sent"] += 1

            return seq

    def receive_ack(self, peer_id: bytes, ack_type: int, seq_nums: List[int]) -> None:
        """
        Process received acknowledgment.

        Args:
            peer_id: Peer that sent ACK
            ack_type: Type of ACK (SACK, cumulative, etc.)
            seq_nums: Acknowledged sequence numbers
        """
        with self._lock:
            if peer_id not in self._pending:
                return

            now = time.time()
            rtt_est = self._get_rtt(peer_id)
            pending = self._pending[peer_id]

            if ack_type == ACK_TYPE_CUMULATIVE:
                # Cumulative ACK - all seq_nums up to the value are acked
                if seq_nums:
                    cum_ack = seq_nums[0]
                    for seq in list(pending.keys()):
                        if seq <= cum_ack:
                            msg = pending.pop(seq)
                            if msg.retries == 0:
                                # Only update RTT for non-retransmitted packets
                                rtt_est.update(now - msg.first_sent)
                            self._stats["messages_acked"] += 1

            elif ack_type == ACK_TYPE_SELECTIVE:
                # Selective ACK - only specific seq_nums are acked
                for seq in seq_nums:
                    if seq in pending:
                        msg = pending.pop(seq)
                        if msg.retries == 0:
                            rtt_est.update(now - msg.first_sent)
                        self._stats["messages_acked"] += 1

    def receive_nack(self, peer_id: bytes, seq_nums: List[int]) -> None:
        """
        Process negative acknowledgment - immediate retransmit.

        Args:
            peer_id: Peer that sent NACK
            seq_nums: Sequence numbers to retransmit
        """
        with self._lock:
            if peer_id not in self._pending:
                return

            pending = self._pending[peer_id]
            for seq in seq_nums:
                if seq in pending:
                    self._retransmit(peer_id, pending[seq])

    def receive_data(self, peer_id: bytes, seq_num: int, data: bytes) -> Tuple[bool, Optional[bytes], List[int]]:
        """
        Process received reliable data.

        Args:
            peer_id: Sender peer ID
            seq_num: Sequence number
            data: Message data

        Returns:
            Tuple of (is_duplicate, data_if_in_order, ack_seq_nums)
        """
        with self._lock:
            if peer_id not in self._rx_seq:
                self._rx_seq[peer_id] = 0
                self._out_of_order[peer_id] = {}

            expected = self._rx_seq[peer_id]

            if seq_num < expected:
                # Duplicate - already received
                return True, None, [seq_num]

            elif seq_num == expected:
                # In order - deliver and check for buffered
                self._rx_seq[peer_id] = (expected + 1) & 0xFFFFFFFF
                ack_seqs = [seq_num]

                # Check for buffered out-of-order messages
                buffered = self._out_of_order[peer_id]
                while self._rx_seq[peer_id] in buffered:
                    next_seq = self._rx_seq[peer_id]
                    buffered.pop(next_seq)
                    ack_seqs.append(next_seq)
                    self._rx_seq[peer_id] = (next_seq + 1) & 0xFFFFFFFF

                return False, data, ack_seqs

            else:
                # Out of order - buffer it
                self._out_of_order[peer_id][seq_num] = data
                return False, None, [seq_num]

    def generate_ack(self, peer_id: bytes, seq_nums: List[int], cumulative: bool = False) -> bytes:
        """
        Generate ACK message.

        Args:
            peer_id: Peer to ACK
            seq_nums: Sequence numbers to acknowledge
            cumulative: If True, generate cumulative ACK

        Returns:
            Encoded ACK message
        """
        self._stats["acks_sent"] += 1

        ack_type = ACK_TYPE_CUMULATIVE if cumulative else ACK_TYPE_SELECTIVE
        # Format: type(1) + count(1) + seq_nums(4 each)
        data = bytes([ack_type, len(seq_nums)])
        for seq in seq_nums:
            data += seq.to_bytes(4, "big")
        return data

    def _retransmit(self, peer_id: bytes, msg: PendingMessage) -> None:
        """Retransmit a pending message."""
        if msg.retries >= MAX_RETRIES:
            # Give up
            logger.warning(f"Message {msg.seq_num} to {peer_id.hex()[:8]} failed after {MAX_RETRIES} retries")
            self._stats["timeouts"] += 1
            return

        msg.retries += 1
        msg.last_sent = time.time()
        self._stats["retransmissions"] += 1

        # Apply exponential backoff
        self._get_rtt(peer_id).backoff()

        if self._send_callback:
            self._send_callback(peer_id, msg.data)

    def _retx_loop(self) -> None:
        """Retransmission timer loop."""
        while self._running:
            time.sleep(0.1)  # Check every 100ms

            with self._lock:
                now = time.time()
                for peer_id, pending in list(self._pending.items()):
                    rtt = self._get_rtt(peer_id)
                    for seq, msg in list(pending.items()):
                        if not msg.acked and (now - msg.last_sent) > rtt.rto:
                            self._retransmit(peer_id, msg)

    def stats(self) -> Dict[str, Any]:
        """Get ACK manager statistics."""
        with self._lock:
            return {
                **self._stats,
                "pending_messages": sum(len(p) for p in self._pending.values()),
                "peers_tracked": len(self._pending),
            }


# =============================================================================
# Flow Control
# =============================================================================

@dataclass
class FlowControlState:
    """Flow control state for a peer."""
    # Receive side
    recv_window: int = DEFAULT_WINDOW_SIZE  # Our receive window
    recv_buffer_used: int = 0  # Bytes buffered

    # Send side
    peer_window: int = DEFAULT_WINDOW_SIZE  # Peer's advertised window
    bytes_in_flight: int = 0  # Unacknowledged bytes

    # Window scaling (for high-bandwidth links)
    window_scale: int = 0  # Shift count (0-14)


class FlowController:
    """
    Implements receiver-advertised window flow control.

    Prevents sender from overwhelming receiver's buffer.
    Supports window scaling for high-bandwidth networks.
    """

    def __init__(self, default_window: int = DEFAULT_WINDOW_SIZE):
        self._lock = threading.RLock()
        self._default_window = default_window
        self._peers: Dict[bytes, FlowControlState] = {}

    def _get_state(self, peer_id: bytes) -> FlowControlState:
        """Get or create flow control state for peer."""
        if peer_id not in self._peers:
            self._peers[peer_id] = FlowControlState(
                recv_window=self._default_window,
                peer_window=self._default_window,
            )
        return self._peers[peer_id]

    def get_send_window(self, peer_id: bytes) -> int:
        """
        Get available window for sending to peer.

        Args:
            peer_id: Destination peer

        Returns:
            Number of bytes we can send
        """
        with self._lock:
            state = self._get_state(peer_id)
            available = state.peer_window - state.bytes_in_flight
            return max(0, available)

    def can_send(self, peer_id: bytes, data_len: int) -> bool:
        """
        Check if we can send data of given length.

        Args:
            peer_id: Destination peer
            data_len: Length of data to send

        Returns:
            True if sending is allowed
        """
        return self.get_send_window(peer_id) >= data_len

    def on_send(self, peer_id: bytes, data_len: int) -> None:
        """
        Track sent data.

        Args:
            peer_id: Destination peer
            data_len: Bytes sent
        """
        with self._lock:
            state = self._get_state(peer_id)
            state.bytes_in_flight += data_len

    def on_ack(self, peer_id: bytes, acked_bytes: int) -> None:
        """
        Process acknowledgment - free up window space.

        Args:
            peer_id: Peer that acknowledged
            acked_bytes: Bytes acknowledged
        """
        with self._lock:
            state = self._get_state(peer_id)
            state.bytes_in_flight = max(0, state.bytes_in_flight - acked_bytes)

    def on_receive(self, peer_id: bytes, data_len: int) -> None:
        """
        Track received data in buffer.

        Args:
            peer_id: Sending peer
            data_len: Bytes received
        """
        with self._lock:
            state = self._get_state(peer_id)
            state.recv_buffer_used += data_len

    def on_consume(self, peer_id: bytes, consumed_bytes: int) -> None:
        """
        Application consumed buffered data.

        Args:
            peer_id: Associated peer
            consumed_bytes: Bytes consumed
        """
        with self._lock:
            state = self._get_state(peer_id)
            state.recv_buffer_used = max(0, state.recv_buffer_used - consumed_bytes)

    def get_recv_window(self, peer_id: bytes) -> int:
        """
        Get our receive window to advertise.

        Args:
            peer_id: Peer to report to

        Returns:
            Available receive window
        """
        with self._lock:
            state = self._get_state(peer_id)
            available = state.recv_window - state.recv_buffer_used
            return max(0, available)

    def update_peer_window(self, peer_id: bytes, window: int, scale: int = 0) -> None:
        """
        Update peer's advertised window.

        Args:
            peer_id: Peer whose window to update
            window: Advertised window value
            scale: Window scale factor
        """
        with self._lock:
            state = self._get_state(peer_id)
            state.peer_window = min(MAX_WINDOW_SIZE, window << scale)
            state.window_scale = scale

    def generate_window_update(self, peer_id: bytes) -> bytes:
        """
        Generate window update message.

        Args:
            peer_id: Peer to send update to

        Returns:
            Encoded window update
        """
        window = self.get_recv_window(peer_id)
        # Format: window(4) + scale(1)
        return window.to_bytes(4, "big") + bytes([0])

    def stats(self) -> Dict[str, Any]:
        """Get flow control statistics."""
        with self._lock:
            return {
                "peers": len(self._peers),
                "total_in_flight": sum(s.bytes_in_flight for s in self._peers.values()),
                "total_buffered": sum(s.recv_buffer_used for s in self._peers.values()),
            }


# =============================================================================
# Congestion Control (AIMD)
# =============================================================================

class CongestionState(IntEnum):
    """Congestion control states."""
    SLOW_START = 1
    CONGESTION_AVOIDANCE = 2
    FAST_RECOVERY = 3


@dataclass
class CongestionControlState:
    """Per-peer congestion control state."""
    cwnd: float = INITIAL_CWND  # Congestion window
    ssthresh: float = SSTHRESH_INITIAL  # Slow start threshold
    state: CongestionState = CongestionState.SLOW_START

    # Fast recovery
    dup_ack_count: int = 0
    last_acked_seq: int = -1

    # Statistics
    bytes_sent_this_rtt: int = 0
    rtt_start_time: float = field(default_factory=time.time)


class CongestionController:
    """
    Implements AIMD (Additive Increase Multiplicative Decrease) congestion control.

    Similar to TCP Reno with slow start, congestion avoidance, and fast recovery.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._peers: Dict[bytes, CongestionControlState] = {}
        self._stats = {
            "slow_starts": 0,
            "congestion_events": 0,
            "fast_recoveries": 0,
        }

    def _get_state(self, peer_id: bytes) -> CongestionControlState:
        """Get or create congestion state for peer."""
        if peer_id not in self._peers:
            self._peers[peer_id] = CongestionControlState()
            self._stats["slow_starts"] += 1
        return self._peers[peer_id]

    def get_cwnd(self, peer_id: bytes) -> int:
        """
        Get current congestion window.

        Args:
            peer_id: Destination peer

        Returns:
            Congestion window in bytes
        """
        with self._lock:
            state = self._get_state(peer_id)
            return int(state.cwnd)

    def can_send(self, peer_id: bytes, bytes_in_flight: int, data_len: int) -> bool:
        """
        Check if congestion window allows sending.

        Args:
            peer_id: Destination peer
            bytes_in_flight: Currently unacked bytes
            data_len: Bytes to send

        Returns:
            True if sending is allowed
        """
        cwnd = self.get_cwnd(peer_id)
        return (bytes_in_flight + data_len) <= cwnd

    def on_ack(self, peer_id: bytes, acked_bytes: int, seq_num: int) -> None:
        """
        Process acknowledgment - grow window.

        Args:
            peer_id: Peer that acknowledged
            acked_bytes: Bytes acknowledged
            seq_num: Acknowledged sequence number
        """
        with self._lock:
            state = self._get_state(peer_id)

            # Check for duplicate ACK
            if seq_num == state.last_acked_seq:
                state.dup_ack_count += 1
                if state.dup_ack_count == 3:
                    # Enter fast recovery
                    self._on_triple_dup_ack(state)
                return

            state.last_acked_seq = seq_num
            state.dup_ack_count = 0

            if state.state == CongestionState.FAST_RECOVERY:
                # Exit fast recovery
                state.cwnd = state.ssthresh
                state.state = CongestionState.CONGESTION_AVOIDANCE

            elif state.state == CongestionState.SLOW_START:
                # Exponential growth
                state.cwnd += acked_bytes
                if state.cwnd >= state.ssthresh:
                    state.state = CongestionState.CONGESTION_AVOIDANCE

            else:  # CONGESTION_AVOIDANCE
                # Additive increase: cwnd += MSS * (MSS / cwnd)
                state.cwnd += (AIMD_INCREASE * acked_bytes) / state.cwnd

            # Clamp cwnd
            state.cwnd = max(MIN_CWND, min(MAX_CWND, state.cwnd))

    def _on_triple_dup_ack(self, state: CongestionControlState) -> None:
        """Handle triple duplicate ACK - fast retransmit/recovery."""
        state.ssthresh = max(MIN_CWND, state.cwnd * AIMD_DECREASE)
        state.cwnd = state.ssthresh + 3 * AIMD_INCREASE
        state.state = CongestionState.FAST_RECOVERY
        self._stats["fast_recoveries"] += 1

    def on_timeout(self, peer_id: bytes) -> None:
        """
        Handle retransmission timeout - severe congestion.

        Args:
            peer_id: Peer that timed out
        """
        with self._lock:
            state = self._get_state(peer_id)

            # Multiplicative decrease
            state.ssthresh = max(MIN_CWND, state.cwnd * AIMD_DECREASE)
            state.cwnd = INITIAL_CWND
            state.state = CongestionState.SLOW_START
            state.dup_ack_count = 0

            self._stats["congestion_events"] += 1

    def on_loss(self, peer_id: bytes) -> None:
        """
        Handle packet loss detection (fast retransmit).

        Args:
            peer_id: Peer with loss
        """
        with self._lock:
            state = self._get_state(peer_id)

            if state.state != CongestionState.FAST_RECOVERY:
                state.ssthresh = max(MIN_CWND, state.cwnd * AIMD_DECREASE)
                state.cwnd = state.ssthresh
                self._stats["congestion_events"] += 1

    def stats(self) -> Dict[str, Any]:
        """Get congestion control statistics."""
        with self._lock:
            peer_stats = {}
            for peer_id, state in self._peers.items():
                peer_stats[peer_id.hex()[:8]] = {
                    "cwnd": int(state.cwnd),
                    "ssthresh": int(state.ssthresh),
                    "state": state.state.name,
                }
            return {
                **self._stats,
                "peers": peer_stats,
            }


# =============================================================================
# Keep-Alive / Heartbeat
# =============================================================================

@dataclass
class KeepAliveState:
    """Keep-alive state for a peer."""
    last_sent: float = 0.0
    last_received: float = 0.0
    pending_count: int = 0
    is_alive: bool = True


class KeepAliveManager:
    """
    Manages keep-alive/heartbeat messages.

    Detects dead peers and maintains connection liveness.
    """

    def __init__(
        self,
        interval: float = KEEPALIVE_INTERVAL,
        timeout: float = KEEPALIVE_TIMEOUT,
        retries: int = KEEPALIVE_RETRIES,
        send_callback: Optional[Callable[[bytes], None]] = None,
        dead_callback: Optional[Callable[[bytes], None]] = None,
    ):
        """
        Initialize keep-alive manager.

        Args:
            interval: Seconds between keep-alives
            timeout: Seconds before declaring peer dead
            retries: Keep-alive retries before dead
            send_callback: Called to send keep-alive request
            dead_callback: Called when peer declared dead
        """
        self._lock = threading.RLock()
        self._interval = interval
        self._timeout = timeout
        self._retries = retries
        self._send_callback = send_callback
        self._dead_callback = dead_callback

        self._peers: Dict[bytes, KeepAliveState] = {}

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start keep-alive thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._keepalive_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop keep-alive thread."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    def track_peer(self, peer_id: bytes) -> None:
        """
        Start tracking a peer.

        Args:
            peer_id: Peer to track
        """
        with self._lock:
            if peer_id not in self._peers:
                now = time.time()
                self._peers[peer_id] = KeepAliveState(
                    last_sent=now,
                    last_received=now,
                )

    def untrack_peer(self, peer_id: bytes) -> None:
        """
        Stop tracking a peer.

        Args:
            peer_id: Peer to untrack
        """
        with self._lock:
            self._peers.pop(peer_id, None)

    def on_activity(self, peer_id: bytes) -> None:
        """
        Record activity from peer (any message counts).

        Args:
            peer_id: Peer that was active
        """
        with self._lock:
            if peer_id in self._peers:
                state = self._peers[peer_id]
                state.last_received = time.time()
                state.pending_count = 0
                state.is_alive = True

    def on_keepalive_response(self, peer_id: bytes) -> None:
        """
        Process keep-alive response.

        Args:
            peer_id: Peer that responded
        """
        self.on_activity(peer_id)

    def is_alive(self, peer_id: bytes) -> bool:
        """
        Check if peer is considered alive.

        Args:
            peer_id: Peer to check

        Returns:
            True if peer is alive
        """
        with self._lock:
            state = self._peers.get(peer_id)
            return state.is_alive if state else False

    def _keepalive_loop(self) -> None:
        """Keep-alive timer loop."""
        while self._running:
            time.sleep(1.0)  # Check every second

            with self._lock:
                now = time.time()
                dead_peers = []

                for peer_id, state in self._peers.items():
                    # Check for timeout
                    if (now - state.last_received) > self._timeout:
                        if state.pending_count >= self._retries:
                            state.is_alive = False
                            dead_peers.append(peer_id)
                            continue

                    # Check if we need to send keep-alive
                    if (now - state.last_sent) > self._interval:
                        state.last_sent = now
                        state.pending_count += 1
                        if self._send_callback:
                            self._send_callback(peer_id)

                # Notify about dead peers
                for peer_id in dead_peers:
                    logger.warning(f"Peer {peer_id.hex()[:8]} declared dead")
                    if self._dead_callback:
                        self._dead_callback(peer_id)

    def stats(self) -> Dict[str, Any]:
        """Get keep-alive statistics."""
        with self._lock:
            alive_count = sum(1 for s in self._peers.values() if s.is_alive)
            return {
                "tracked_peers": len(self._peers),
                "alive_peers": alive_count,
                "dead_peers": len(self._peers) - alive_count,
            }


# =============================================================================
# Integrated Reliability Layer
# =============================================================================

class ReliabilityLayer:
    """
    Integrated reliability layer combining all features.

    Provides a unified interface for:
    - Reliable message delivery with ACKs
    - Flow control
    - Congestion control
    - Keep-alive management
    """

    def __init__(
        self,
        send_callback: Optional[Callable[[bytes, bytes], None]] = None,
        dead_peer_callback: Optional[Callable[[bytes], None]] = None,
    ):
        """
        Initialize reliability layer.

        Args:
            send_callback: Function to send data (peer_id, data)
            dead_peer_callback: Called when peer is declared dead
        """
        self._send_callback = send_callback

        # Components
        self.ack_manager = ACKManager(send_callback=self._retransmit)
        self.flow_controller = FlowController()
        self.congestion_controller = CongestionController()
        self.keepalive_manager = KeepAliveManager(
            send_callback=self._send_keepalive,
            dead_callback=dead_peer_callback,
        )

        self._running = False

    def start(self) -> None:
        """Start all reliability components."""
        if self._running:
            return
        self._running = True
        self.ack_manager.start()
        self.keepalive_manager.start()

    def stop(self) -> None:
        """Stop all reliability components."""
        self._running = False
        self.ack_manager.stop()
        self.keepalive_manager.stop()

    def _retransmit(self, peer_id: bytes, data: bytes) -> None:
        """Handle retransmission from ACK manager."""
        self.congestion_controller.on_loss(peer_id)
        if self._send_callback:
            self._send_callback(peer_id, data)

    def _send_keepalive(self, peer_id: bytes) -> None:
        """Send keep-alive request."""
        if self._send_callback:
            # Keepalive message: type(1)
            data = bytes([ReliabilityMsgType.KEEPALIVE_REQ])
            self._send_callback(peer_id, data)

    def can_send(self, peer_id: bytes, data_len: int, bytes_in_flight: int) -> bool:
        """
        Check if we can send data considering all limits.

        Args:
            peer_id: Destination peer
            data_len: Bytes to send
            bytes_in_flight: Currently unacked bytes

        Returns:
            True if sending is allowed
        """
        flow_ok = self.flow_controller.can_send(peer_id, data_len)
        cong_ok = self.congestion_controller.can_send(peer_id, bytes_in_flight, data_len)
        return flow_ok and cong_ok

    def send_reliable(self, peer_id: bytes, data: bytes) -> Optional[int]:
        """
        Send data reliably.

        Args:
            peer_id: Destination peer
            data: Data to send

        Returns:
            Sequence number if sent, None if blocked
        """
        state = self.flow_controller._get_state(peer_id)

        if not self.can_send(peer_id, len(data), state.bytes_in_flight):
            return None

        seq = self.ack_manager.send_reliable(peer_id, data)
        self.flow_controller.on_send(peer_id, len(data))
        self.keepalive_manager.track_peer(peer_id)

        return seq

    def on_receive(self, peer_id: bytes, data: bytes) -> Tuple[bool, Optional[bytes]]:
        """
        Process received reliable data.

        Args:
            peer_id: Sender peer ID
            data: Received data (including sequence number)

        Returns:
            Tuple of (is_duplicate, payload_if_in_order)
        """
        if len(data) < 5:
            return True, None

        msg_type = data[0]

        if msg_type == ReliabilityMsgType.KEEPALIVE_REQ:
            # Send response
            if self._send_callback:
                self._send_callback(peer_id, bytes([ReliabilityMsgType.KEEPALIVE_RSP]))
            return True, None

        elif msg_type == ReliabilityMsgType.KEEPALIVE_RSP:
            self.keepalive_manager.on_keepalive_response(peer_id)
            return True, None

        elif msg_type == ReliabilityMsgType.ACK:
            self._process_ack(peer_id, data[1:])
            return True, None

        elif msg_type == ReliabilityMsgType.WINDOW_UPDATE:
            if len(data) >= 5:
                window = int.from_bytes(data[1:5], "big")
                scale = data[5] if len(data) > 5 else 0
                self.flow_controller.update_peer_window(peer_id, window, scale)
            return True, None

        elif msg_type == ReliabilityMsgType.DATA:
            return self._process_data(peer_id, data[1:])

        return True, None

    def _process_ack(self, peer_id: bytes, data: bytes) -> None:
        """Process ACK message."""
        if len(data) < 2:
            return

        ack_type = data[0]
        count = data[1]

        if len(data) < 2 + count * 4:
            return

        seq_nums = []
        for i in range(count):
            seq = int.from_bytes(data[2 + i * 4:6 + i * 4], "big")
            seq_nums.append(seq)

        self.ack_manager.receive_ack(peer_id, ack_type, seq_nums)

        # Update flow control
        for _ in seq_nums:
            self.flow_controller.on_ack(peer_id, 1400)  # Approximate
            self.congestion_controller.on_ack(peer_id, 1400, seq_nums[-1])

        self.keepalive_manager.on_activity(peer_id)

    def _process_data(self, peer_id: bytes, data: bytes) -> Tuple[bool, Optional[bytes]]:
        """Process data message."""
        if len(data) < 4:
            return True, None

        seq_num = int.from_bytes(data[:4], "big")
        payload = data[4:]

        is_dup, result, ack_seqs = self.ack_manager.receive_data(peer_id, seq_num, payload)

        # Send ACK
        if ack_seqs and self._send_callback:
            ack_msg = bytes([ReliabilityMsgType.ACK]) + self.ack_manager.generate_ack(peer_id, ack_seqs)
            self._send_callback(peer_id, ack_msg)

        # Update flow control
        if not is_dup:
            self.flow_controller.on_receive(peer_id, len(payload))

        self.keepalive_manager.on_activity(peer_id)

        return is_dup, result

    def stats(self) -> Dict[str, Any]:
        """Get combined reliability statistics."""
        return {
            "ack": self.ack_manager.stats(),
            "flow": self.flow_controller.stats(),
            "congestion": self.congestion_controller.stats(),
            "keepalive": self.keepalive_manager.stats(),
        }
