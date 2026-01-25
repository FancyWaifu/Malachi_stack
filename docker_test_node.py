#!/usr/bin/env python3
"""Malachi test node for Docker network testing."""
import os
import sys
import time
import socket
import argparse
import hashlib

sys.path.insert(0, "/app")

from malachi.mesh import MeshNode, PeerInfo

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7891)
    parser.add_argument("--peer", type=str, action='append', help="Peer address ip:port (can specify multiple)")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--node-name", type=str, default="node")
    args = parser.parse_args()

    # Generate deterministic node ID from name
    node_id = hashlib.sha256(args.node_name.encode()).digest()[:16]

    print(f"[{args.node_name}] Starting MeshNode")
    print(f"[{args.node_name}] Node ID: {node_id.hex()[:16]}...")
    print(f"[{args.node_name}] Port: {args.port}")

    node = MeshNode(node_id, port=args.port)

    received_messages = []

    def on_message(src, data):
        msg = data.decode() if isinstance(data, bytes) else str(data)
        print(f"[{args.node_name}] RECEIVED from {src.hex()[:8]}: {msg[:50]}")
        received_messages.append((src, data))

    node.on_message(on_message)

    if not node.start():
        print(f"[{args.node_name}] Failed to start node")
        sys.exit(1)

    print(f"[{args.node_name}] Node started successfully")

    # Add peers if specified
    if args.peer:
        for peer_spec in args.peer:
            peer_ip, peer_port = peer_spec.split(":")
            # Generate peer ID - try to match the naming pattern
            for i in range(1, 10):
                candidate_name = f"node{i}"
                if candidate_name != args.node_name:
                    peer_id = hashlib.sha256(candidate_name.encode()).digest()[:16]
                    peer = PeerInfo(node_id=peer_id, address=(peer_ip, int(peer_port)))
                    node.dht.add_peer(peer)
                    print(f"[{args.node_name}] Added peer: {peer_ip}:{peer_port}")
                    break

    # Wait a bit then send test messages
    time.sleep(2)

    if args.peer:
        for peer in node.dht.get_all_peers():
            print(f"[{args.node_name}] Sending test message to {peer.node_id.hex()[:8]}...")
            node.send_reliable(peer.node_id, f"Hello from {args.node_name}!".encode())

    # Run for duration
    start = time.time()
    while time.time() - start < args.duration:
        time.sleep(1)
        stats = node.stats()
        print(f"[{args.node_name}] Stats: sent={stats['packets_sent']}, recv={stats['packets_received']}")

    print(f"[{args.node_name}] Total messages received: {len(received_messages)}")
    node.stop()
    print(f"[{args.node_name}] Node stopped")

    # Exit with success if received messages (or no peers expected)
    if not args.peer:
        sys.exit(0)
    sys.exit(0 if len(received_messages) > 0 else 1)

if __name__ == "__main__":
    main()
