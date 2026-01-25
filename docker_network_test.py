#!/usr/bin/env python3
"""
Malachi Docker Network Test

Creates Docker containers with isolated networks to test Malachi communication.
Uses Docker's networking to create realistic network conditions.
"""

import os
import sys
import time
import json
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import threading


# =============================================================================
# Docker Network Manager
# =============================================================================

@dataclass
class ContainerInfo:
    """Information about a Docker container."""
    name: str
    container_id: str
    ip_addr: str
    network: str


class DockerNetworkManager:
    """Manages Docker containers and networks for testing."""

    def __init__(self, prefix: str = "malachi_test"):
        self.prefix = prefix
        self.containers: Dict[str, ContainerInfo] = {}
        self.networks: List[str] = []
        self.project_dir = os.path.dirname(os.path.abspath(__file__))

    def run_cmd(self, cmd: str, check: bool = True) -> Tuple[int, str, str]:
        """Run a shell command."""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if check and result.returncode != 0:
            print(f"Command failed: {cmd}")
            print(f"  stderr: {result.stderr}")
        return result.returncode, result.stdout.strip(), result.stderr.strip()

    def check_docker(self) -> bool:
        """Check if Docker is available and running."""
        ret, _, _ = self.run_cmd("docker info", check=False)
        return ret == 0

    def create_network(self, name: str, subnet: str = "172.28.0.0/16") -> bool:
        """Create a Docker network."""
        network_name = f"{self.prefix}_{name}"

        # Remove if exists
        self.run_cmd(f"docker network rm {network_name}", check=False)

        ret, _, _ = self.run_cmd(
            f"docker network create --driver bridge --subnet={subnet} {network_name}"
        )
        if ret == 0:
            self.networks.append(network_name)
            return True
        return False

    def build_image(self) -> bool:
        """Build Docker image for Malachi testing."""
        dockerfile_content = '''
FROM python:3.10-slim

# Install dependencies and tools
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pynacl scapy blake3

# Copy project files
COPY . /app
WORKDIR /app

# Create test node script
COPY docker_test_node.py /app/docker_test_node.py

# Default command
CMD ["python3", "-c", "print('Malachi container ready')"]
'''
        dockerfile_path = os.path.join(self.project_dir, "Dockerfile.test")
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)

        print("  Building Docker image...")
        ret, _, stderr = self.run_cmd(
            f"docker build -t {self.prefix}_image -f {dockerfile_path} {self.project_dir}"
        )

        os.remove(dockerfile_path)
        return ret == 0

    def start_container(
        self,
        name: str,
        network: str,
        ip_addr: str,
        command: str = "sleep infinity"
    ) -> Optional[ContainerInfo]:
        """Start a Docker container."""
        container_name = f"{self.prefix}_{name}"
        network_name = f"{self.prefix}_{network}"

        # Remove if exists
        self.run_cmd(f"docker rm -f {container_name}", check=False)

        ret, container_id, _ = self.run_cmd(
            f"docker run -d --name {container_name} "
            f"--network {network_name} --ip {ip_addr} "
            f"--cap-add=NET_ADMIN "
            f"{self.prefix}_image {command}"
        )

        if ret == 0:
            info = ContainerInfo(
                name=container_name,
                container_id=container_id[:12],
                ip_addr=ip_addr,
                network=network_name
            )
            self.containers[name] = info
            return info
        return None

    def exec_in_container(self, name: str, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Execute a command in a container."""
        container_name = f"{self.prefix}_{name}"
        return self.run_cmd(f"docker exec {container_name} {command}", check=False)

    def stop_container(self, name: str):
        """Stop and remove a container."""
        container_name = f"{self.prefix}_{name}"
        self.run_cmd(f"docker rm -f {container_name}", check=False)
        self.containers.pop(name, None)

    def cleanup(self):
        """Clean up all containers and networks."""
        print("\nCleaning up Docker resources...")

        # Stop containers
        for name in list(self.containers.keys()):
            print(f"  Stopping container {self.prefix}_{name}...")
            self.stop_container(name)

        # Remove networks
        for network in self.networks:
            print(f"  Removing network {network}...")
            self.run_cmd(f"docker network rm {network}", check=False)

        # Remove image
        self.run_cmd(f"docker rmi {self.prefix}_image", check=False)

        print("  Cleanup complete.")


# =============================================================================
# Test Node Script
# =============================================================================

TEST_NODE_SCRIPT = '''
#!/usr/bin/env python3
"""Malachi test node for Docker network testing."""
import os
import sys
import time
import socket
import argparse

sys.path.insert(0, "/app")

from malachi.mesh import MeshNode, PeerInfo

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7891)
    parser.add_argument("--peer", type=str, help="Peer address ip:port")
    parser.add_argument("--duration", type=int, default=15)
    parser.add_argument("--node-name", type=str, default="node")
    args = parser.parse_args()

    # Generate deterministic node ID from name
    import hashlib
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

    # Add peer if specified
    if args.peer:
        peer_ip, peer_port = args.peer.split(":")
        # Generate peer ID from a known pattern
        peer_name = "node2" if args.node_name == "node1" else "node1"
        peer_id = hashlib.sha256(peer_name.encode()).digest()[:16]
        peer = PeerInfo(node_id=peer_id, address=(peer_ip, int(peer_port)))
        node.dht.add_peer(peer)
        print(f"[{args.node_name}] Added peer: {peer_ip}:{peer_port} (ID: {peer_id.hex()[:8]})")

        # Send test message
        time.sleep(1)
        print(f"[{args.node_name}] Sending test message to peer...")
        node.send_reliable(peer_id, f"Hello from {args.node_name}!".encode())

    # Run for duration
    start = time.time()
    while time.time() - start < args.duration:
        time.sleep(1)
        stats = node.stats()
        print(f"[{args.node_name}] Stats: sent={stats['packets_sent']}, recv={stats['packets_received']}")

    print(f"[{args.node_name}] Total messages received: {len(received_messages)}")
    node.stop()
    print(f"[{args.node_name}] Node stopped")

    # Exit with success if received messages
    sys.exit(0 if len(received_messages) > 0 or not args.peer else 1)

if __name__ == "__main__":
    main()
'''


# =============================================================================
# Tests
# =============================================================================

def print_header(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)


def print_result(name: str, passed: bool, details: str = ""):
    status = "PASS" if passed else "FAIL"
    mark = "✓" if passed else "✗"
    print(f"  {mark} {status}: {name}")
    if details:
        print(f"         {details}")


def test_container_connectivity(manager: DockerNetworkManager) -> bool:
    """Test basic connectivity between containers."""
    print_header("TEST 1: Container Connectivity")

    containers = list(manager.containers.keys())
    if len(containers) < 2:
        print("  Need at least 2 containers")
        return False

    results = []
    for i, c1 in enumerate(containers):
        for c2 in containers[i+1:]:
            c2_ip = manager.containers[c2].ip_addr
            ret, stdout, _ = manager.exec_in_container(c1, f"ping -c 2 -W 2 {c2_ip}")
            success = ret == 0
            results.append((f"{c1} -> {c2}", success))
            print_result(f"Ping {c1} -> {c2}", success)

    return all(r[1] for r in results)


def test_udp_communication(manager: DockerNetworkManager) -> bool:
    """Test UDP communication between containers."""
    print_header("TEST 2: UDP Communication")

    containers = list(manager.containers.keys())
    if len(containers) < 2:
        return False

    c1, c2 = containers[0], containers[1]
    c2_ip = manager.containers[c2].ip_addr

    # Start UDP server in c2
    server_cmd = '''python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9999))
sock.settimeout(10)
try:
    data, addr = sock.recvfrom(1024)
    print(f'RECEIVED: {data}')
except:
    print('TIMEOUT')
sock.close()
"'''

    client_cmd = f'''python3 -c "
import socket
import time
time.sleep(1)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'Hello UDP!', ('{c2_ip}', 9999))
print('SENT')
sock.close()
"'''

    results = {'server': False, 'client': False}

    def run_server():
        ret, stdout, _ = manager.exec_in_container(c2, server_cmd, timeout=15)
        results['server'] = 'RECEIVED' in stdout

    def run_client():
        ret, stdout, _ = manager.exec_in_container(c1, client_cmd, timeout=15)
        results['client'] = 'SENT' in stdout

    t1 = threading.Thread(target=run_server)
    t2 = threading.Thread(target=run_client)

    t1.start()
    time.sleep(0.5)
    t2.start()

    t1.join(timeout=20)
    t2.join(timeout=20)

    print_result("UDP server received", results['server'])
    print_result("UDP client sent", results['client'])

    return results['server'] and results['client']


def test_malachi_nodes(manager: DockerNetworkManager) -> bool:
    """Test Malachi mesh nodes in containers."""
    print_header("TEST 3: Malachi Mesh Nodes")

    containers = list(manager.containers.keys())
    if len(containers) < 2:
        return False

    c1, c2 = containers[0], containers[1]
    c1_ip = manager.containers[c1].ip_addr
    c2_ip = manager.containers[c2].ip_addr

    # Test script is included in the Docker image
    script_path = "/app/docker_test_node.py"

    results = {'node1': False, 'node2': False, 'received': False}
    logs = {'node1': '', 'node2': ''}

    def run_node1():
        ret, stdout, stderr = manager.exec_in_container(
            c1,
            f"python3 {script_path} --node-name node1 --port 7891 --peer {c2_ip}:7892 --duration 12",
            timeout=20
        )
        logs['node1'] = stdout + '\n' + stderr
        results['node1'] = 'Node started successfully' in stdout
        if 'RECEIVED' in stdout:
            results['received'] = True

    def run_node2():
        ret, stdout, stderr = manager.exec_in_container(
            c2,
            f"python3 {script_path} --node-name node2 --port 7892 --peer {c1_ip}:7891 --duration 12",
            timeout=20
        )
        logs['node2'] = stdout + '\n' + stderr
        results['node2'] = 'Node started successfully' in stdout
        if 'RECEIVED' in stdout:
            results['received'] = True

    print("  Starting Malachi nodes in containers...")

    t1 = threading.Thread(target=run_node1)
    t2 = threading.Thread(target=run_node2)

    t1.start()
    time.sleep(0.5)
    t2.start()

    t1.join(timeout=25)
    t2.join(timeout=25)

    print_result("Node 1 started", results['node1'])
    print_result("Node 2 started", results['node2'])
    print_result("Cross-container message exchange", results['received'])

    # Show logs if failed
    if not results['node1'] or not results['node2'] or not results['received']:
        print("\n  Node 1 log (last 500 chars):")
        print(f"  {logs['node1'][-500:]}")
        print("\n  Node 2 log (last 500 chars):")
        print(f"  {logs['node2'][-500:]}")

    return results['node1'] and results['node2'] and results['received']


def test_three_node_mesh(manager: DockerNetworkManager) -> bool:
    """Test a three-node mesh network."""
    print_header("TEST 4: Three Node Mesh")

    # Need 3 containers
    containers = list(manager.containers.keys())
    if len(containers) < 3:
        print("  Need at least 3 containers")
        return False

    c1, c2, c3 = containers[0], containers[1], containers[2]
    ips = {c: manager.containers[c].ip_addr for c in [c1, c2, c3]}

    # Each node connects to the next in a ring
    results = {'started': 0, 'received': 0}

    def run_node(name, port, peers):
        peer_args = ' '.join([f"--peer {p}" for p in peers])
        ret, stdout, _ = manager.exec_in_container(
            name,
            f"python3 /app/docker_test_node.py --node-name {name} --port {port} {peer_args} --duration 10",
            timeout=18
        )
        if 'Node started successfully' in stdout:
            results['started'] += 1
        if 'RECEIVED' in stdout:
            results['received'] += 1

    threads = [
        threading.Thread(target=run_node, args=(c1, 7891, [f"{ips[c2]}:7892"])),
        threading.Thread(target=run_node, args=(c2, 7892, [f"{ips[c1]}:7891", f"{ips[c3]}:7893"])),
        threading.Thread(target=run_node, args=(c3, 7893, [f"{ips[c2]}:7892"])),
    ]

    print("  Starting 3-node mesh...")
    for t in threads:
        t.start()
        time.sleep(0.3)

    for t in threads:
        t.join(timeout=25)

    print_result("All nodes started", results['started'] == 3, f"{results['started']}/3")
    print_result("Messages received", results['received'] >= 2, f"{results['received']} nodes received")

    return results['started'] == 3 and results['received'] >= 2


def run_all_tests():
    """Run all Docker network tests."""
    print("\n" + "=" * 70)
    print("     MALACHI DOCKER NETWORK TESTS")
    print("=" * 70)
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    manager = DockerNetworkManager()

    # Check Docker
    if not manager.check_docker():
        print("\n  ERROR: Docker is not available or not running.")
        print("  Please start Docker and try again.")
        return False

    try:
        # Setup
        print_header("SETUP: Creating Docker Network")

        print("  Creating network...")
        if not manager.create_network("mesh", "172.28.0.0/16"):
            print("  Failed to create network")
            return False

        print("  Building image...")
        if not manager.build_image():
            print("  Failed to build image")
            return False

        print("  Starting containers...")
        for i in range(3):
            name = f"node{i+1}"
            ip = f"172.28.0.{10+i}"
            info = manager.start_container(name, "mesh", ip)
            if info:
                print(f"    {name}: {ip} (container: {info.container_id})")
            else:
                print(f"    Failed to start {name}")
                return False

        time.sleep(2)  # Wait for containers to be ready

        results = []

        # Run tests
        results.append(("Container Connectivity", test_container_connectivity(manager)))
        results.append(("UDP Communication", test_udp_communication(manager)))
        results.append(("Malachi Mesh Nodes", test_malachi_nodes(manager)))
        results.append(("Three Node Mesh", test_three_node_mesh(manager)))

        # Summary
        print_header("TEST SUMMARY")

        passed = sum(1 for _, p in results if p)
        total = len(results)

        print(f"\n  Results: {passed}/{total} tests passed\n")

        for name, p in results:
            status = "✓" if p else "✗"
            print(f"  {status} {name}")

        print("\n" + "=" * 70)

        if passed == total:
            print("  ALL DOCKER NETWORK TESTS PASSED!")
        else:
            print(f"  {total - passed} test(s) failed")

        print("=" * 70 + "\n")

        return passed == total

    finally:
        manager.cleanup()


def cleanup_only():
    """Just clean up Docker resources."""
    print("Cleaning up Docker resources...")
    manager = DockerNetworkManager()

    # Remove containers
    ret, stdout, _ = manager.run_cmd("docker ps -a --format '{{.Names}}'", check=False)
    for name in stdout.split('\n'):
        if name.startswith(manager.prefix):
            print(f"  Removing container {name}")
            manager.run_cmd(f"docker rm -f {name}", check=False)

    # Remove networks
    ret, stdout, _ = manager.run_cmd("docker network ls --format '{{.Name}}'", check=False)
    for name in stdout.split('\n'):
        if name.startswith(manager.prefix):
            print(f"  Removing network {name}")
            manager.run_cmd(f"docker network rm {name}", check=False)

    # Remove image
    manager.run_cmd(f"docker rmi {manager.prefix}_image", check=False)

    print("Cleanup complete.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Malachi Docker Network Tests")
    parser.add_argument('--cleanup', action='store_true', help='Just clean up Docker resources')
    args = parser.parse_args()

    if args.cleanup:
        cleanup_only()
    else:
        success = run_all_tests()
        sys.exit(0 if success else 1)
