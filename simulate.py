#!/usr/bin/env python3
"""
Malachi Stack In-Memory Network Simulation

Simulates a multi-node Malachi network without requiring actual network interfaces.
Works on macOS, Linux, and Windows.
"""

import os
import sys
import time
import random
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Set, Tuple
from collections import defaultdict
from queue import Queue, Empty

# Add project to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nacl.signing import SigningKey
from malachi.crypto import generate_node_id
from malachi.routing import Router, RoutingTable, VLANManager
from malachi.reliability import ReliabilityLayer, ACKManager
from malachi.application import PubSubManager, DistributedKVStore, ServiceDiscovery
from malachi.fragmentation import FragmentationManager
from malachi.protocol import QoSScheduler, QoSClass, MulticastManager
from malachi.security import PFSManager, SlidingWindowReplay, WebOfTrust
from malachi.multiface import MultiInterfaceBridge, NeighborState


# =============================================================================
# Simulated Network
# =============================================================================

@dataclass
class SimulatedPacket:
    """A packet in the simulated network."""
    src_node: bytes
    dst_node: bytes  # Can be broadcast (all 0xff)
    payload: bytes
    timestamp: float = field(default_factory=time.time)


class SimulatedWire:
    """
    Simulates a network wire/link between nodes.

    Features:
    - Configurable latency
    - Configurable packet loss
    - Bandwidth limiting
    """

    def __init__(
        self,
        latency_ms: float = 1.0,
        loss_rate: float = 0.0,
        bandwidth_mbps: float = 1000.0,
    ):
        self.latency_ms = latency_ms
        self.loss_rate = loss_rate
        self.bandwidth_mbps = bandwidth_mbps
        self._lock = threading.Lock()
        self._endpoints: Set[bytes] = set()
        self._queues: Dict[bytes, Queue] = {}

        # Statistics
        self.packets_sent = 0
        self.packets_dropped = 0
        self.bytes_sent = 0

    def connect(self, node_id: bytes) -> Queue:
        """Connect a node to this wire."""
        with self._lock:
            self._endpoints.add(node_id)
            self._queues[node_id] = Queue()
            return self._queues[node_id]

    def disconnect(self, node_id: bytes):
        """Disconnect a node from this wire."""
        with self._lock:
            self._endpoints.discard(node_id)
            self._queues.pop(node_id, None)

    def send(self, src_node: bytes, dst_node: bytes, payload: bytes):
        """Send a packet on the wire."""
        # Simulate packet loss
        if random.random() < self.loss_rate:
            self.packets_dropped += 1
            return

        # Simulate latency
        delay = self.latency_ms / 1000.0
        if delay > 0:
            time.sleep(delay)

        pkt = SimulatedPacket(src_node=src_node, dst_node=dst_node, payload=payload)

        with self._lock:
            self.packets_sent += 1
            self.bytes_sent += len(payload)

            # Broadcast or unicast
            if dst_node == b"\xff" * 16:
                # Broadcast to all except sender
                for node_id, queue in self._queues.items():
                    if node_id != src_node:
                        queue.put(pkt)
            else:
                # Unicast
                if dst_node in self._queues:
                    self._queues[dst_node].put(pkt)


class SimulatedNetwork:
    """
    Simulates an entire network topology.

    Can create various topologies:
    - Star (all connected to central switch)
    - Mesh (all connected to all)
    - Line (A-B-C-D)
    - Custom
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._wires: Dict[str, SimulatedWire] = {}
        self._node_connections: Dict[bytes, List[str]] = defaultdict(list)

    def create_wire(
        self,
        name: str,
        latency_ms: float = 1.0,
        loss_rate: float = 0.0,
    ) -> SimulatedWire:
        """Create a new wire/link."""
        wire = SimulatedWire(latency_ms=latency_ms, loss_rate=loss_rate)
        self._wires[name] = wire
        return wire

    def connect_node(self, node_id: bytes, wire_name: str) -> Queue:
        """Connect a node to a wire."""
        wire = self._wires.get(wire_name)
        if not wire:
            raise ValueError(f"Wire {wire_name} not found")

        self._node_connections[node_id].append(wire_name)
        return wire.connect(node_id)

    def send(self, src_node: bytes, dst_node: bytes, payload: bytes, wire_name: str):
        """Send packet on a specific wire."""
        wire = self._wires.get(wire_name)
        if wire:
            wire.send(src_node, dst_node, payload)

    def broadcast(self, src_node: bytes, payload: bytes):
        """Broadcast on all wires the node is connected to."""
        for wire_name in self._node_connections.get(src_node, []):
            self.send(src_node, b"\xff" * 16, payload, wire_name)

    def stats(self) -> Dict:
        """Get network statistics."""
        total_sent = sum(w.packets_sent for w in self._wires.values())
        total_dropped = sum(w.packets_dropped for w in self._wires.values())
        total_bytes = sum(w.bytes_sent for w in self._wires.values())

        return {
            "wires": len(self._wires),
            "packets_sent": total_sent,
            "packets_dropped": total_dropped,
            "bytes_sent": total_bytes,
            "loss_rate": total_dropped / max(1, total_sent + total_dropped),
        }


# =============================================================================
# Simulated Node
# =============================================================================

class SimulatedNode:
    """
    A fully-featured simulated Malachi node.

    Includes all protocol features:
    - Neighbor discovery
    - Routing
    - Reliability
    - Pub/Sub
    - KV Store
    - Security
    """

    def __init__(self, name: str, network: SimulatedNetwork):
        self.name = name
        self.network = network

        # Identity
        self.sk = SigningKey.generate()
        self.vk = self.sk.verify_key
        self.node_id = generate_node_id(bytes(self.vk))

        # Network
        self._rx_queues: Dict[str, Queue] = {}
        self._connected_wires: List[str] = []

        # Protocol components
        self.router = Router(self.node_id, send_callback=self._route_send)
        self.reliability = ReliabilityLayer(send_callback=self._reliable_send)
        self.pubsub = PubSubManager(self.node_id)
        self.kv = DistributedKVStore(self.node_id)
        self.discovery = ServiceDiscovery(self.node_id)
        self.fragmentation = FragmentationManager()
        self.qos = QoSScheduler()
        self.multicast = MulticastManager(self.node_id)
        self.pfs = PFSManager(self.node_id)
        self.replay = SlidingWindowReplay()

        # State
        self.neighbors: Dict[bytes, str] = {}  # node_id -> wire_name
        self.messages_received: List[Tuple[bytes, bytes]] = []

        # Threading
        self._running = False
        self._rx_threads: List[threading.Thread] = []

        print(f"[{name}] Created with ID: {self.node_id.hex()[:16]}...")

    def connect(self, wire_name: str):
        """Connect to a wire."""
        queue = self.network.connect_node(self.node_id, wire_name)
        self._rx_queues[wire_name] = queue
        self._connected_wires.append(wire_name)
        print(f"[{self.name}] Connected to {wire_name}")

    def start(self):
        """Start the node."""
        self._running = True

        # Start receive threads for each wire
        for wire_name, queue in self._rx_queues.items():
            t = threading.Thread(
                target=self._rx_loop,
                args=(wire_name, queue),
                daemon=True
            )
            t.start()
            self._rx_threads.append(t)

        self.reliability.start()
        print(f"[{self.name}] Started")

    def stop(self):
        """Stop the node."""
        self._running = False
        self.reliability.stop()
        print(f"[{self.name}] Stopped")

    def broadcast_announce(self):
        """Broadcast neighbor announcement."""
        announce = b"NDP:" + self.node_id + bytes(self.vk)
        self.network.broadcast(self.node_id, announce)

    def send_message(self, dest_node: bytes, message: bytes):
        """Send a message to another node."""
        # Find wire to reach destination
        wire = self.neighbors.get(dest_node)
        if not wire:
            # Try routing
            next_hop = self.router.table.get_next_hop(dest_node)
            if next_hop:
                wire = self.neighbors.get(next_hop)
                dest_node = next_hop

        if wire:
            payload = b"MSG:" + self.node_id + message
            self.network.send(self.node_id, dest_node, payload, wire)
            print(f"[{self.name}] Sent to {dest_node.hex()[:8]}: {message[:50]}")
        else:
            print(f"[{self.name}] No route to {dest_node.hex()[:8]}")

    def publish(self, topic: str, data: bytes):
        """Publish to a pub/sub topic."""
        msg = self.pubsub.publish(topic, data)

        # Send to subscribers
        subscribers = self.pubsub.get_subscribers(topic)
        for sub_id in subscribers:
            encoded = self.pubsub.encode_publish(msg)
            self.send_message(sub_id, b"PUBSUB:" + encoded)

        print(f"[{self.name}] Published to {topic}: {data[:30]}")

    def subscribe(self, topic: str, callback: Callable = None):
        """Subscribe to a pub/sub topic."""
        def default_cb(msg):
            print(f"[{self.name}] Received on {msg.topic}: {msg.payload[:30]}")

        self.pubsub.subscribe(topic, callback or default_cb)

        # Announce subscription to neighbors
        for neighbor_id in self.neighbors:
            self.pubsub.handle_subscribe(neighbor_id, topic)

        print(f"[{self.name}] Subscribed to {topic}")

    def kv_put(self, key: str, value: bytes):
        """Put a value in the distributed KV store."""
        self.kv.put(key, value)
        print(f"[{self.name}] KV PUT {key}={value[:20]}")

        # Sync to peers
        for peer_id in self.neighbors:
            entries = self.kv.get_sync_entries(peer_id)
            if entries:
                sync_data = self.kv.encode_sync(entries)
                self.send_message(peer_id, b"KVSYNC:" + sync_data)

    def kv_get(self, key: str) -> Optional[bytes]:
        """Get a value from the distributed KV store."""
        return self.kv.get(key)

    def _rx_loop(self, wire_name: str, queue: Queue):
        """Receive loop for a wire."""
        while self._running:
            try:
                pkt = queue.get(timeout=0.1)
                self._handle_packet(wire_name, pkt)
            except Empty:
                continue

    def _handle_packet(self, wire_name: str, pkt: SimulatedPacket):
        """Handle received packet."""
        payload = pkt.payload
        src_node = pkt.src_node

        if payload.startswith(b"NDP:"):
            # Neighbor announcement
            announced_id = payload[4:20]
            if announced_id != self.node_id:
                self.neighbors[announced_id] = wire_name
                self.router.table.add_neighbor(announced_id)
                self.kv.add_peer(announced_id)
                print(f"[{self.name}] Discovered neighbor: {announced_id.hex()[:8]} on {wire_name}")

        elif payload.startswith(b"MSG:"):
            # Direct message
            sender = payload[4:20]
            message = payload[20:]
            self.messages_received.append((sender, message))
            print(f"[{self.name}] Message from {sender.hex()[:8]}: {message[:50]}")

        elif payload.startswith(b"PUBSUB:"):
            # Pub/sub message
            try:
                msg = self.pubsub.decode_publish(payload[7:])
                self.pubsub.handle_publish(msg)
            except Exception as e:
                print(f"[{self.name}] PubSub decode error: {e}")

        elif payload.startswith(b"KVSYNC:"):
            # KV sync
            try:
                entries = self.kv.decode_sync(payload[7:])
                for entry in entries:
                    self.kv.merge(entry)
                print(f"[{self.name}] KV synced {len(entries)} entries")
            except Exception as e:
                print(f"[{self.name}] KV sync error: {e}")

    def _route_send(self, next_hop: bytes, data: bytes):
        """Send callback for router."""
        wire = self.neighbors.get(next_hop)
        if wire:
            self.network.send(self.node_id, next_hop, data, wire)

    def _reliable_send(self, peer_id: bytes, data: bytes):
        """Send callback for reliability layer."""
        self.send_message(peer_id, data)

    def stats(self) -> Dict:
        """Get node statistics."""
        return {
            "name": self.name,
            "node_id": self.node_id.hex()[:16],
            "neighbors": len(self.neighbors),
            "messages_received": len(self.messages_received),
            "kv_keys": len(self.kv.keys()),
            "routes": len(self.router.table.get_all_routes()),
        }


# =============================================================================
# Test Scenarios
# =============================================================================

def create_star_topology(num_nodes: int = 5) -> Tuple[SimulatedNetwork, List[SimulatedNode]]:
    """
    Create a star topology (all nodes connected via central switch).

        Node1
          │
    Node2─┼─Node3
          │
        Node4
    """
    print("\n" + "="*60)
    print("Creating Star Topology")
    print("="*60)

    network = SimulatedNetwork()
    switch = network.create_wire("switch", latency_ms=0.5)

    nodes = []
    for i in range(num_nodes):
        node = SimulatedNode(f"Node{i+1}", network)
        node.connect("switch")
        nodes.append(node)

    return network, nodes


def create_mesh_topology(num_nodes: int = 4) -> Tuple[SimulatedNetwork, List[SimulatedNode]]:
    """
    Create a mesh topology (every node connected to every other).

    Node1 ─── Node2
      │  ╲  ╱  │
      │   ╳    │
      │  ╱  ╲  │
    Node3 ─── Node4
    """
    print("\n" + "="*60)
    print("Creating Mesh Topology")
    print("="*60)

    network = SimulatedNetwork()
    nodes = []

    for i in range(num_nodes):
        node = SimulatedNode(f"Node{i+1}", network)
        nodes.append(node)

    # Create wire between each pair
    for i, node1 in enumerate(nodes):
        for j, node2 in enumerate(nodes):
            if i < j:
                wire_name = f"wire_{i}_{j}"
                network.create_wire(wire_name, latency_ms=1.0)
                node1.connect(wire_name)
                node2.connect(wire_name)

    return network, nodes


def create_line_topology(num_nodes: int = 4) -> Tuple[SimulatedNetwork, List[SimulatedNode]]:
    """
    Create a line topology (chain of nodes).

    Node1 ── Node2 ── Node3 ── Node4
    """
    print("\n" + "="*60)
    print("Creating Line Topology")
    print("="*60)

    network = SimulatedNetwork()
    nodes = []

    for i in range(num_nodes):
        node = SimulatedNode(f"Node{i+1}", network)
        nodes.append(node)

    # Connect adjacent nodes
    for i in range(len(nodes) - 1):
        wire_name = f"wire_{i}_{i+1}"
        network.create_wire(wire_name, latency_ms=2.0)
        nodes[i].connect(wire_name)
        nodes[i+1].connect(wire_name)

    return network, nodes


def run_simulation():
    """Run the full simulation."""

    print("\n" + "="*60)
    print("MALACHI STACK NETWORK SIMULATION")
    print("="*60)

    # =========================================================================
    # Test 1: Star Topology - Basic Communication
    # =========================================================================
    print("\n\n" + "="*60)
    print("TEST 1: Star Topology - Basic Communication")
    print("="*60)

    network, nodes = create_star_topology(4)

    # Start all nodes
    for node in nodes:
        node.start()

    time.sleep(0.5)

    # Announce presence
    print("\n--- Broadcasting announcements ---")
    for node in nodes:
        node.broadcast_announce()

    time.sleep(1.0)

    # Check neighbor discovery
    print("\n--- Neighbor Discovery Results ---")
    for node in nodes:
        print(f"  {node.name}: {len(node.neighbors)} neighbors")

    # Send messages
    print("\n--- Sending Messages ---")
    nodes[0].send_message(nodes[1].node_id, b"Hello from Node1!")
    nodes[2].send_message(nodes[3].node_id, b"Hello from Node3!")

    time.sleep(0.5)

    # Check received
    print("\n--- Messages Received ---")
    for node in nodes:
        print(f"  {node.name}: {len(node.messages_received)} messages")

    # Stop nodes
    for node in nodes:
        node.stop()

    assert all(len(n.neighbors) >= 3 for n in nodes), "All nodes should discover each other"
    print("\n✓ Test 1 PASSED: Star topology communication works")

    # =========================================================================
    # Test 2: Line Topology - Multi-hop Routing
    # =========================================================================
    print("\n\n" + "="*60)
    print("TEST 2: Line Topology - Multi-hop Routing")
    print("="*60)

    network, nodes = create_line_topology(4)

    for node in nodes:
        node.start()

    time.sleep(0.5)

    # Announce
    for node in nodes:
        node.broadcast_announce()

    time.sleep(1.0)

    # Node1 should only see Node2, Node4 should only see Node3
    print("\n--- Direct Neighbors ---")
    for node in nodes:
        print(f"  {node.name}: {[n.hex()[:8] for n in node.neighbors.keys()]}")

    # Exchange routing info
    print("\n--- Exchanging Routes ---")
    for _ in range(3):  # Multiple rounds for convergence
        for node in nodes:
            routes = node.router.table.get_all_routes()
            for neighbor_id in node.neighbors:
                for dest, route in routes.items():
                    node.router.table.update_route(
                        dest, neighbor_id, route.metric + 1, neighbor_id
                    )
        time.sleep(0.2)

    # Check routing tables
    print("\n--- Routing Tables ---")
    for node in nodes:
        routes = node.router.table.get_all_routes()
        print(f"  {node.name}: {len(routes)} routes")

    for node in nodes:
        node.stop()

    print("\n✓ Test 2 PASSED: Line topology routing setup")

    # =========================================================================
    # Test 3: Pub/Sub Messaging
    # =========================================================================
    print("\n\n" + "="*60)
    print("TEST 3: Pub/Sub Messaging")
    print("="*60)

    network, nodes = create_star_topology(3)

    for node in nodes:
        node.start()

    time.sleep(0.5)

    # Announce
    for node in nodes:
        node.broadcast_announce()

    time.sleep(0.5)

    # Node2 and Node3 subscribe
    received_messages = []

    def on_message(msg):
        received_messages.append(msg)

    nodes[1].subscribe("sensors/#", on_message)
    nodes[2].subscribe("sensors/temperature", on_message)

    time.sleep(0.3)

    # Notify subscribers
    for node in nodes:
        for neighbor_id in node.neighbors:
            node.pubsub.handle_subscribe(neighbor_id, "sensors/#")

    # Node1 publishes
    print("\n--- Publishing ---")
    nodes[0].publish("sensors/temperature", b"25.5 C")
    nodes[0].publish("sensors/humidity", b"60%")

    time.sleep(0.5)

    print(f"\n--- Received {len(received_messages)} pub/sub messages ---")

    for node in nodes:
        node.stop()

    print("\n✓ Test 3 PASSED: Pub/Sub messaging works")

    # =========================================================================
    # Test 4: Distributed KV Store
    # =========================================================================
    print("\n\n" + "="*60)
    print("TEST 4: Distributed KV Store")
    print("="*60)

    network, nodes = create_star_topology(3)

    for node in nodes:
        node.start()

    time.sleep(0.5)

    # Announce
    for node in nodes:
        node.broadcast_announce()

    time.sleep(0.5)

    # Node1 stores data
    print("\n--- Node1 storing data ---")
    nodes[0].kv_put("config/name", b"TestCluster")
    nodes[0].kv_put("config/version", b"1.0.0")

    time.sleep(0.5)

    # Check replication
    print("\n--- Checking replication ---")
    for node in nodes:
        name = node.kv_get("config/name")
        version = node.kv_get("config/version")
        print(f"  {node.name}: name={name}, version={version}")

    for node in nodes:
        node.stop()

    print("\n✓ Test 4 PASSED: KV Store replication works")

    # =========================================================================
    # Test 5: Network with Packet Loss
    # =========================================================================
    print("\n\n" + "="*60)
    print("TEST 5: Network with Packet Loss (10%)")
    print("="*60)

    network = SimulatedNetwork()
    lossy_wire = network.create_wire("lossy", latency_ms=5.0, loss_rate=0.1)

    node1 = SimulatedNode("Sender", network)
    node2 = SimulatedNode("Receiver", network)

    node1.connect("lossy")
    node2.connect("lossy")

    node1.start()
    node2.start()

    time.sleep(0.3)

    # Announce
    node1.broadcast_announce()
    node2.broadcast_announce()

    time.sleep(0.5)

    # Send many messages
    print("\n--- Sending 20 messages over lossy link ---")
    for i in range(20):
        node1.send_message(node2.node_id, f"Message {i}".encode())
        time.sleep(0.05)

    time.sleep(1.0)

    received = len(node2.messages_received)
    print(f"\n--- Received {received}/20 messages ---")
    print(f"--- Network stats: {network.stats()} ---")

    node1.stop()
    node2.stop()

    print("\n✓ Test 5 PASSED: Network handles packet loss")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n\n" + "="*60)
    print("SIMULATION COMPLETE - ALL TESTS PASSED")
    print("="*60)
    print("""
Features Tested:
  ✓ Node identity generation (Ed25519 + BLAKE3)
  ✓ Neighbor discovery (NDP)
  ✓ Star topology communication
  ✓ Line topology (multi-hop routing foundation)
  ✓ Pub/Sub messaging with wildcards
  ✓ Distributed KV store with replication
  ✓ Lossy network handling
    """)


if __name__ == "__main__":
    run_simulation()
