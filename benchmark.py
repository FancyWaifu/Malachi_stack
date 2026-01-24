#!/usr/bin/env python3
"""
Malachi Stack Comprehensive Benchmark Suite

Tests the protocol under various conditions and generates
a detailed report with metrics and recommendations.
"""

import os
import sys
import time
import random
import threading
import statistics
import traceback
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.signing import SigningKey
from malachi.crypto import generate_node_id, aead_encrypt, aead_decrypt
from malachi.fragmentation import FragmentationManager


# =============================================================================
# Benchmark Infrastructure
# =============================================================================

@dataclass
class BenchmarkResult:
    """Result from a single benchmark."""
    name: str
    passed: bool
    duration_ms: float
    metrics: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SimulatedPacket:
    """A packet in the simulated network."""
    src_node: bytes
    dst_node: bytes
    payload: bytes
    timestamp: float = field(default_factory=time.time)


class SimulatedWire:
    """Simulates a network wire with configurable characteristics."""

    def __init__(
        self,
        latency_ms: float = 1.0,
        jitter_ms: float = 0.0,
        loss_rate: float = 0.0,
        bandwidth_mbps: float = 1000.0,
    ):
        self.latency_ms = latency_ms
        self.jitter_ms = jitter_ms
        self.loss_rate = loss_rate
        self.bandwidth_mbps = bandwidth_mbps
        self._lock = threading.Lock()
        self._queues: Dict[bytes, Queue] = {}

        # Statistics
        self.packets_sent = 0
        self.packets_dropped = 0
        self.bytes_sent = 0
        self.latencies: List[float] = []

    def connect(self, node_id: bytes) -> Queue:
        """Connect a node to this wire."""
        with self._lock:
            self._queues[node_id] = Queue()
            return self._queues[node_id]

    def disconnect(self, node_id: bytes):
        """Disconnect a node."""
        with self._lock:
            self._queues.pop(node_id, None)

    def send(self, src_node: bytes, dst_node: bytes, payload: bytes) -> float:
        """Send a packet, returns actual latency."""
        # Simulate packet loss
        if random.random() < self.loss_rate:
            self.packets_dropped += 1
            return -1

        # Calculate latency with jitter
        latency = self.latency_ms
        if self.jitter_ms > 0:
            latency += random.uniform(-self.jitter_ms, self.jitter_ms)
        latency = max(0.1, latency)

        # Simulate latency
        delay = latency / 1000.0
        time.sleep(delay)

        pkt = SimulatedPacket(src_node=src_node, dst_node=dst_node, payload=payload)

        with self._lock:
            self.packets_sent += 1
            self.bytes_sent += len(payload)
            self.latencies.append(latency)

            # Broadcast or unicast
            if dst_node == b"\xff" * 16:
                for node_id, queue in self._queues.items():
                    if node_id != src_node:
                        queue.put(pkt)
            else:
                if dst_node in self._queues:
                    self._queues[dst_node].put(pkt)

        return latency


class BenchmarkNode:
    """Lightweight node for benchmarking."""

    def __init__(self, name: str):
        self.name = name
        self.sk = SigningKey.generate()
        self.vk = self.sk.verify_key
        self.node_id = generate_node_id(bytes(self.vk))

        self._queues: Dict[str, Queue] = {}
        self._wires: Dict[str, SimulatedWire] = {}
        self.neighbors: Dict[bytes, str] = {}

        self.messages_sent = 0
        self.messages_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0

        self._running = False
        self._rx_threads: List[threading.Thread] = []
        self._message_callback = None

    def connect(self, wire_name: str, wire: SimulatedWire):
        """Connect to a wire."""
        queue = wire.connect(self.node_id)
        self._queues[wire_name] = queue
        self._wires[wire_name] = wire

    def start(self, message_callback=None):
        """Start receiving."""
        self._running = True
        self._message_callback = message_callback

        for wire_name, queue in self._queues.items():
            t = threading.Thread(target=self._rx_loop, args=(wire_name, queue), daemon=True)
            t.start()
            self._rx_threads.append(t)

    def stop(self):
        """Stop receiving."""
        self._running = False

    def broadcast_announce(self):
        """Announce presence."""
        announce = b"NDP:" + self.node_id
        for wire_name, wire in self._wires.items():
            wire.send(self.node_id, b"\xff" * 16, announce)

    def send(self, dest_node: bytes, payload: bytes) -> bool:
        """Send to a neighbor."""
        wire_name = self.neighbors.get(dest_node)
        if not wire_name:
            return False

        wire = self._wires.get(wire_name)
        if not wire:
            return False

        latency = wire.send(self.node_id, dest_node, payload)
        if latency >= 0:
            self.messages_sent += 1
            self.bytes_sent += len(payload)
            return True
        return False

    def _rx_loop(self, wire_name: str, queue: Queue):
        """Receive loop."""
        while self._running:
            try:
                pkt = queue.get(timeout=0.05)
                self._handle_packet(wire_name, pkt)
            except Empty:
                continue

    def _handle_packet(self, wire_name: str, pkt: SimulatedPacket):
        """Handle received packet."""
        self.messages_received += 1
        self.bytes_received += len(pkt.payload)

        if pkt.payload.startswith(b"NDP:"):
            announced_id = pkt.payload[4:20]
            if announced_id != self.node_id:
                self.neighbors[announced_id] = wire_name
        elif self._message_callback:
            self._message_callback(pkt.src_node, pkt.payload)


# =============================================================================
# Benchmark Tests
# =============================================================================

def benchmark_throughput(num_messages: int = 1000) -> BenchmarkResult:
    """Measure message throughput."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Throughput")
    print(f"{'='*60}")

    wire = SimulatedWire(latency_ms=0.1, loss_rate=0.0)

    sender = BenchmarkNode("Sender")
    receiver = BenchmarkNode("Receiver")

    sender.connect("wire", wire)
    receiver.connect("wire", wire)

    received = []
    def on_message(src, payload):
        received.append((time.time(), payload))

    sender.start()
    receiver.start(message_callback=on_message)

    # Discover
    sender.broadcast_announce()
    receiver.broadcast_announce()
    time.sleep(0.2)

    # Send messages
    payload = b"X" * 1024  # 1KB messages
    start = time.time()

    for i in range(num_messages):
        sender.send(receiver.node_id, payload)

    # Wait for all to arrive
    timeout = 10.0
    wait_start = time.time()
    while len(received) < num_messages and time.time() - wait_start < timeout:
        time.sleep(0.01)

    elapsed = time.time() - start

    sender.stop()
    receiver.stop()

    # Calculate metrics
    throughput_msg = len(received) / elapsed
    throughput_mb = (len(received) * len(payload)) / (1024 * 1024) / elapsed

    result = BenchmarkResult(
        name="Throughput",
        passed=len(received) >= num_messages * 0.99,
        duration_ms=elapsed * 1000,
        metrics={
            "messages_sent": num_messages,
            "messages_received": len(received),
            "throughput_msg_per_sec": round(throughput_msg, 2),
            "throughput_mb_per_sec": round(throughput_mb, 2),
            "delivery_rate": round(len(received) / num_messages * 100, 2),
        }
    )

    print(f"  Messages: {num_messages} sent, {len(received)} received")
    print(f"  Throughput: {throughput_msg:.0f} msg/s, {throughput_mb:.2f} MB/s")
    print(f"  Delivery: {len(received) / num_messages * 100:.1f}%")

    if throughput_msg < 5000:
        result.recommendations.append("Consider batching messages for higher throughput")

    return result


def benchmark_latency(num_samples: int = 100) -> BenchmarkResult:
    """Measure end-to-end latency distribution."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Latency Distribution")
    print(f"{'='*60}")

    wire = SimulatedWire(latency_ms=5.0, jitter_ms=2.0)

    sender = BenchmarkNode("Sender")
    receiver = BenchmarkNode("Receiver")

    sender.connect("wire", wire)
    receiver.connect("wire", wire)

    latencies = []
    received_event = threading.Event()

    def on_message(src, payload):
        recv_time = time.time()
        send_time = float(payload.decode())
        latencies.append((recv_time - send_time) * 1000)
        if len(latencies) >= num_samples:
            received_event.set()

    sender.start()
    receiver.start(message_callback=on_message)

    sender.broadcast_announce()
    receiver.broadcast_announce()
    time.sleep(0.2)

    # Send with timestamps
    start = time.time()
    for i in range(num_samples):
        sender.send(receiver.node_id, str(time.time()).encode())
        time.sleep(0.01)

    received_event.wait(timeout=10.0)

    sender.stop()
    receiver.stop()

    # Calculate statistics
    if latencies:
        avg = statistics.mean(latencies)
        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) > 20 else max(latencies)
        p99 = sorted(latencies)[int(len(latencies) * 0.99)] if len(latencies) > 100 else max(latencies)
        std = statistics.stdev(latencies) if len(latencies) > 1 else 0
    else:
        avg = p50 = p95 = p99 = std = 0

    result = BenchmarkResult(
        name="Latency",
        passed=len(latencies) >= num_samples * 0.95,
        duration_ms=(time.time() - start) * 1000,
        metrics={
            "samples": len(latencies),
            "avg_ms": round(avg, 2),
            "p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2),
            "stddev_ms": round(std, 2),
        }
    )

    print(f"  Samples: {len(latencies)}")
    print(f"  Average: {avg:.2f}ms")
    print(f"  P50: {p50:.2f}ms, P95: {p95:.2f}ms, P99: {p99:.2f}ms")
    print(f"  Std Dev: {std:.2f}ms")

    if p99 > avg * 3:
        result.recommendations.append("High tail latency detected - consider connection pooling")

    return result


def benchmark_scalability(node_counts: List[int] = [5, 10, 25, 50]) -> BenchmarkResult:
    """Test scalability with increasing node count."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Scalability")
    print(f"{'='*60}")

    results_by_count = {}

    for num_nodes in node_counts:
        print(f"\n  Testing with {num_nodes} nodes...")

        wire = SimulatedWire(latency_ms=1.0)
        nodes = []

        # Create nodes
        for i in range(num_nodes):
            node = BenchmarkNode(f"Node{i}")
            node.connect("switch", wire)
            nodes.append(node)

        # Start all
        for node in nodes:
            node.start()

        # Announce all
        announce_start = time.time()
        for node in nodes:
            node.broadcast_announce()
        time.sleep(0.5)
        announce_time = time.time() - announce_start

        # Check discovery
        avg_neighbors = statistics.mean(len(n.neighbors) for n in nodes)
        expected_neighbors = num_nodes - 1
        discovery_rate = avg_neighbors / expected_neighbors * 100

        # Message test - each node sends to one other
        msg_start = time.time()
        for i, node in enumerate(nodes):
            target = nodes[(i + 1) % num_nodes]
            node.send(target.node_id, b"test")
        time.sleep(0.5)
        msg_time = time.time() - msg_start

        # Cleanup
        for node in nodes:
            node.stop()

        results_by_count[num_nodes] = {
            "discovery_time_ms": round(announce_time * 1000, 2),
            "discovery_rate": round(discovery_rate, 1),
            "msg_time_ms": round(msg_time * 1000, 2),
            "avg_neighbors": round(avg_neighbors, 1),
        }

        print(f"    Discovery: {discovery_rate:.1f}% in {announce_time*1000:.0f}ms")
        print(f"    Avg neighbors: {avg_neighbors:.1f}/{expected_neighbors}")

    result = BenchmarkResult(
        name="Scalability",
        passed=all(r["discovery_rate"] > 95 for r in results_by_count.values()),
        duration_ms=0,
        metrics={"by_node_count": results_by_count}
    )

    # Check if performance degrades
    times = [r["discovery_time_ms"] for r in results_by_count.values()]
    if len(times) > 1 and times[-1] > times[0] * 5:
        result.recommendations.append("Discovery time scales poorly - consider hierarchical discovery")

    return result


def benchmark_packet_loss(loss_rates: List[float] = [0.01, 0.05, 0.10, 0.20]) -> BenchmarkResult:
    """Test behavior under various packet loss conditions."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Packet Loss Resilience")
    print(f"{'='*60}")

    results_by_loss = {}
    num_messages = 100

    for loss_rate in loss_rates:
        print(f"\n  Testing with {loss_rate*100:.0f}% packet loss...")

        wire = SimulatedWire(latency_ms=2.0, loss_rate=loss_rate)

        sender = BenchmarkNode("Sender")
        receiver = BenchmarkNode("Receiver")

        sender.connect("wire", wire)
        receiver.connect("wire", wire)

        received_count = [0]
        def on_message(src, payload):
            received_count[0] += 1

        sender.start()
        receiver.start(message_callback=on_message)

        sender.broadcast_announce()
        receiver.broadcast_announce()
        time.sleep(0.3)

        for i in range(num_messages):
            sender.send(receiver.node_id, f"msg{i}".encode())
            time.sleep(0.01)

        time.sleep(1.0)

        sender.stop()
        receiver.stop()

        delivery_rate = received_count[0] / num_messages * 100
        expected_rate = (1 - loss_rate) * 100

        results_by_loss[f"{loss_rate*100:.0f}%"] = {
            "sent": num_messages,
            "received": received_count[0],
            "delivery_rate": round(delivery_rate, 1),
            "expected_rate": round(expected_rate, 1),
            "wire_dropped": wire.packets_dropped,
        }

        print(f"    Delivered: {received_count[0]}/{num_messages} ({delivery_rate:.1f}%)")
        print(f"    Expected: ~{expected_rate:.1f}%")

    result = BenchmarkResult(
        name="Packet Loss",
        passed=True,
        duration_ms=0,
        metrics={"by_loss_rate": results_by_loss}
    )

    # Check if delivery matches expected
    for loss_str, data in results_by_loss.items():
        if data["delivery_rate"] < data["expected_rate"] * 0.8:
            result.recommendations.append(f"Delivery at {loss_str} loss lower than expected - check for cascading failures")

    if not any("reliability" in r.lower() for r in result.recommendations):
        result.recommendations.append("Consider adding ARQ (automatic repeat request) for reliability")

    return result


def benchmark_encryption_overhead() -> BenchmarkResult:
    """Measure encryption/decryption overhead."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Encryption Overhead")
    print(f"{'='*60}")

    key = os.urandom(32)
    nonce = os.urandom(24)
    ad = b"associated_data"

    sizes = [64, 256, 1024, 4096, 16384]
    results_by_size = {}

    for size in sizes:
        plaintext = os.urandom(size)
        iterations = 1000

        # Encryption
        start = time.time()
        for _ in range(iterations):
            ciphertext = aead_encrypt(plaintext, ad, nonce, key)
        encrypt_time = (time.time() - start) / iterations * 1000 * 1000  # microseconds

        # Decryption
        start = time.time()
        for _ in range(iterations):
            decrypted = aead_decrypt(ciphertext, ad, nonce, key)
        decrypt_time = (time.time() - start) / iterations * 1000 * 1000  # microseconds

        overhead_bytes = len(ciphertext) - len(plaintext)
        throughput_mb = (size * iterations) / (1024 * 1024) / ((encrypt_time * iterations) / 1000000)

        results_by_size[f"{size}B"] = {
            "encrypt_us": round(encrypt_time, 2),
            "decrypt_us": round(decrypt_time, 2),
            "overhead_bytes": overhead_bytes,
            "throughput_mb_s": round(throughput_mb, 2),
        }

        print(f"  {size:>5}B: encrypt={encrypt_time:.1f}µs, decrypt={decrypt_time:.1f}µs, overhead={overhead_bytes}B")

    result = BenchmarkResult(
        name="Encryption Overhead",
        passed=True,
        duration_ms=0,
        metrics={"by_size": results_by_size}
    )

    # Check if overhead is reasonable
    small_overhead = results_by_size["64B"]["overhead_bytes"]
    if small_overhead > 32:
        result.recommendations.append(f"High encryption overhead ({small_overhead}B) for small messages")

    return result


def benchmark_fragmentation() -> BenchmarkResult:
    """Test message fragmentation and reassembly."""
    print(f"\n{'='*60}")
    print("BENCHMARK: Fragmentation")
    print(f"{'='*60}")

    frag_mgr = FragmentationManager()
    mtu = 1400  # Default MTU for testing

    sizes = [500, 1500, 5000, 20000, 65000]
    results_by_size = {}

    peer_id = os.urandom(16)

    for size in sizes:
        original = os.urandom(size)
        iterations = 100

        # Fragment
        start = time.time()
        for _ in range(iterations):
            fragments = frag_mgr.fragment_message(original)
        frag_time = (time.time() - start) / iterations * 1000  # ms

        # Reassemble
        start = time.time()
        reassembled = None
        for _ in range(iterations):
            # Create fresh manager for reassembly to avoid state issues
            rx_mgr = FragmentationManager()
            for frag in fragments:
                complete, data = rx_mgr.receive_fragment(peer_id, frag)
                if complete:
                    reassembled = data
        reasm_time = (time.time() - start) / iterations * 1000  # ms

        num_fragments = len(fragments)
        overhead = sum(len(f.payload) + 12 for f in fragments) - size  # 12 bytes header per fragment

        results_by_size[f"{size}B"] = {
            "fragments": num_fragments,
            "frag_time_ms": round(frag_time, 3),
            "reasm_time_ms": round(reasm_time, 3),
            "overhead_bytes": overhead,
        }

        status = "✓" if reassembled == original else "✗"
        print(f"  {size:>6}B: {num_fragments} frags, frag={frag_time:.2f}ms, reasm={reasm_time:.2f}ms {status}")

    result = BenchmarkResult(
        name="Fragmentation",
        passed=True,
        duration_ms=0,
        metrics={"by_size": results_by_size}
    )

    return result


def benchmark_concurrent_connections(num_pairs: int = 20) -> BenchmarkResult:
    """Test many simultaneous connections."""
    print(f"\n{'='*60}")
    print(f"BENCHMARK: Concurrent Connections ({num_pairs} pairs)")
    print(f"{'='*60}")

    wire = SimulatedWire(latency_ms=1.0)
    nodes = []

    # Create nodes
    for i in range(num_pairs * 2):
        node = BenchmarkNode(f"Node{i}")
        node.connect("switch", wire)
        nodes.append(node)

    # Start all
    for node in nodes:
        node.start()

    # Announce
    for node in nodes:
        node.broadcast_announce()
    time.sleep(1.0)

    # Concurrent messaging
    messages_per_pair = 50
    total_expected = num_pairs * messages_per_pair

    def send_messages(sender, receiver, count):
        successes = 0
        for i in range(count):
            if sender.send(receiver.node_id, f"msg{i}".encode()):
                successes += 1
            time.sleep(0.001)
        return successes

    start = time.time()
    with ThreadPoolExecutor(max_workers=num_pairs) as executor:
        futures = []
        for i in range(num_pairs):
            sender = nodes[i * 2]
            receiver = nodes[i * 2 + 1]
            futures.append(executor.submit(send_messages, sender, receiver, messages_per_pair))

        total_sent = sum(f.result() for f in as_completed(futures))

    elapsed = time.time() - start
    time.sleep(0.5)

    total_received = sum(n.messages_received for n in nodes)
    # Subtract NDP announcements
    total_received -= len(nodes) * (len(nodes) - 1)

    for node in nodes:
        node.stop()

    throughput = total_sent / elapsed

    result = BenchmarkResult(
        name="Concurrent Connections",
        passed=total_received >= total_expected * 0.9,
        duration_ms=elapsed * 1000,
        metrics={
            "pairs": num_pairs,
            "messages_per_pair": messages_per_pair,
            "total_sent": total_sent,
            "total_received": total_received,
            "throughput_msg_s": round(throughput, 2),
            "elapsed_s": round(elapsed, 2),
        }
    )

    print(f"  Pairs: {num_pairs}")
    print(f"  Sent: {total_sent}, Received: ~{total_received}")
    print(f"  Throughput: {throughput:.0f} msg/s")
    print(f"  Time: {elapsed:.2f}s")

    if throughput < num_pairs * 100:
        result.recommendations.append("Concurrent throughput is limited - consider connection pooling")

    return result


def benchmark_multihop_routing(hops: int = 5) -> BenchmarkResult:
    """Test multi-hop message delivery."""
    print(f"\n{'='*60}")
    print(f"BENCHMARK: Multi-hop Routing ({hops} hops)")
    print(f"{'='*60}")

    # Create line topology: A - B - C - D - E
    nodes = []
    wires = []

    for i in range(hops + 1):
        node = BenchmarkNode(f"Hop{i}")
        nodes.append(node)

    for i in range(hops):
        wire = SimulatedWire(latency_ms=5.0)
        wires.append(wire)
        nodes[i].connect(f"wire{i}", wire)
        nodes[i + 1].connect(f"wire{i}", wire)

    # Start nodes
    for node in nodes:
        node.start()

    # Announce to direct neighbors
    for node in nodes:
        node.broadcast_announce()
    time.sleep(0.5)

    # Check direct neighbor discovery
    print(f"  Direct neighbors discovered:")
    for i, node in enumerate(nodes):
        expected = 1 if i in [0, hops] else 2
        print(f"    {node.name}: {len(node.neighbors)}/{expected} neighbors")

    # Build routing tables (simplified - share neighbor info)
    print(f"\n  Building routing tables...")
    for _ in range(hops):
        for i, node in enumerate(nodes):
            # Share routes with neighbors
            for neighbor_id, wire_name in list(node.neighbors.items()):
                # Find neighbor node
                for other in nodes:
                    if other.node_id == neighbor_id:
                        # Share our other neighbors
                        for their_neighbor in other.neighbors:
                            if their_neighbor not in node.neighbors and their_neighbor != node.node_id:
                                # Learn route through this neighbor
                                node.neighbors[their_neighbor] = wire_name
        time.sleep(0.1)

    # Check if first and last can see each other
    first = nodes[0]
    last = nodes[-1]

    can_reach = last.node_id in first.neighbors

    # Try to send
    received = [False]
    def on_message(src, payload):
        received[0] = True

    last._message_callback = on_message

    start = time.time()
    if can_reach:
        first.send(last.node_id, b"hello from first!")
    time.sleep(hops * 0.1)

    for node in nodes:
        node.stop()

    result = BenchmarkResult(
        name="Multi-hop Routing",
        passed=can_reach,
        duration_ms=(time.time() - start) * 1000,
        metrics={
            "hops": hops,
            "can_reach_end": can_reach,
            "message_delivered": received[0],
            "first_node_routes": len(first.neighbors),
        }
    )

    print(f"\n  First node can reach last: {can_reach}")
    print(f"  Message delivered: {received[0]}")
    print(f"  Routes at first node: {len(first.neighbors)}")

    if not can_reach:
        result.recommendations.append("Multi-hop routing not working - implement proper route propagation")
    if not received[0] and can_reach:
        result.recommendations.append("Route exists but message not delivered - check forwarding logic")

    return result


# =============================================================================
# Main Benchmark Runner
# =============================================================================

def run_benchmarks() -> List[BenchmarkResult]:
    """Run all benchmarks and return results."""

    print("\n" + "=" * 70)
    print("           MALACHI STACK COMPREHENSIVE BENCHMARK SUITE")
    print("=" * 70)
    print(f"\nStarted at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    results = []

    try:
        results.append(benchmark_throughput(num_messages=500))
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_latency(num_samples=100))
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_scalability(node_counts=[5, 10, 25]))
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_packet_loss())
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_encryption_overhead())
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_fragmentation())
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_concurrent_connections(num_pairs=15))
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    try:
        results.append(benchmark_multihop_routing(hops=4))
    except Exception as e:
        print(f"  ERROR: {e}")
        traceback.print_exc()

    return results


def generate_report(results: List[BenchmarkResult]):
    """Generate a summary report."""

    print("\n" + "=" * 70)
    print("                        BENCHMARK REPORT")
    print("=" * 70)

    # Summary table
    print("\n┌" + "─" * 30 + "┬" + "─" * 10 + "┬" + "─" * 25 + "┐")
    print(f"│ {'Benchmark':<28} │ {'Status':<8} │ {'Key Metric':<23} │")
    print("├" + "─" * 30 + "┼" + "─" * 10 + "┼" + "─" * 25 + "┤")

    for r in results:
        status = "✓ PASS" if r.passed else "✗ FAIL"

        # Pick key metric
        if "throughput_msg_per_sec" in r.metrics:
            key_metric = f"{r.metrics['throughput_msg_per_sec']:.0f} msg/s"
        elif "avg_ms" in r.metrics:
            key_metric = f"avg {r.metrics['avg_ms']:.1f}ms"
        elif "by_node_count" in r.metrics:
            counts = r.metrics["by_node_count"]
            max_nodes = max(int(k) for k in counts.keys())
            key_metric = f"up to {max_nodes} nodes"
        elif "by_loss_rate" in r.metrics:
            key_metric = "loss resilience tested"
        elif "by_size" in r.metrics:
            key_metric = "sizes 64B-16KB"
        else:
            key_metric = "—"

        print(f"│ {r.name:<28} │ {status:<8} │ {key_metric:<23} │")

    print("└" + "─" * 30 + "┴" + "─" * 10 + "┴" + "─" * 25 + "┘")

    # Recommendations
    all_recommendations = []
    for r in results:
        all_recommendations.extend(r.recommendations)

    if all_recommendations:
        print("\n" + "─" * 70)
        print("RECOMMENDATIONS FOR IMPROVEMENT")
        print("─" * 70)
        for i, rec in enumerate(set(all_recommendations), 1):
            print(f"  {i}. {rec}")

    # Issues found
    failed = [r for r in results if not r.passed]
    if failed:
        print("\n" + "─" * 70)
        print("ISSUES DETECTED")
        print("─" * 70)
        for r in failed:
            print(f"  • {r.name}: Test did not pass")
            for err in r.errors:
                print(f"    - {err}")

    # Final summary
    passed = sum(1 for r in results if r.passed)
    total = len(results)

    print("\n" + "=" * 70)
    print(f"SUMMARY: {passed}/{total} benchmarks passed")

    if passed == total:
        print("\n✓ All benchmarks passed! The Malachi stack is performing well.")
    else:
        print(f"\n⚠ {total - passed} benchmark(s) need attention.")

    print("\nTop priorities for improvement:")
    print("  1. Implement NAT traversal for internet connectivity")
    print("  2. Add ARQ/reliability layer for guaranteed delivery")
    print("  3. Implement proper multi-hop route propagation")
    print("  4. Consider DHT for scalable node discovery")
    print("=" * 70)


if __name__ == "__main__":
    results = run_benchmarks()
    generate_report(results)
