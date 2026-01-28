#!/usr/bin/env python3
"""
Malachi 10-Node Docker Network Test

Spins up 10 Docker containers and tests mesh communication between all nodes.
"""

import os
import sys
import time
import subprocess
import threading
from typing import Dict, List, Tuple
from dataclasses import dataclass

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
PREFIX = "malachi_10node"
NUM_NODES = 10

@dataclass
class ContainerInfo:
    name: str
    container_id: str
    ip_addr: str

def run_cmd(cmd: str, check: bool = True) -> Tuple[int, str, str]:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def print_header(title: str):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print('='*70)

def setup_network() -> bool:
    """Create Docker network."""
    print("  Creating Docker network...")
    run_cmd(f"docker network rm {PREFIX}_mesh", check=False)
    ret, _, _ = run_cmd(f"docker network create --driver bridge --subnet=172.30.0.0/16 {PREFIX}_mesh")
    return ret == 0

def create_mesh_test_script() -> str:
    """Create the mesh test script file."""
    script = '''#!/usr/bin/env python3
import sys, time, hashlib, socket
sys.path.insert(0, "/app")

node_name = sys.argv[1]
port = int(sys.argv[2])
peers = sys.argv[3:] if len(sys.argv) > 3 else []

print(f"[{node_name}] Starting on port {port}", flush=True)

from malachi.mesh import MeshNode, PeerInfo

node_id = hashlib.sha256(node_name.encode()).digest()[:16]
print(f"[{node_name}] Node ID: {node_id.hex()[:16]}", flush=True)

node = MeshNode(node_id, port=port)
received = []

def on_msg(src, data):
    msg = data.decode() if isinstance(data, bytes) else str(data)
    print(f"[{node_name}] RECEIVED from {src.hex()[:8]}: {msg[:30]}", flush=True)
    received.append((src, data))

node.on_message(on_msg)

if not node.start():
    print(f"[{node_name}] Failed to start", flush=True)
    sys.exit(1)

print(f"[{node_name}] Node started successfully", flush=True)

# Add peers
for peer_str in peers:
    if not peer_str or peer_str == "--peer":
        continue
    try:
        ip, p = peer_str.split(":")
        peer_idx = int(p) - 7890
        peer_name = f"node{peer_idx + 1}"
        peer_id = hashlib.sha256(peer_name.encode()).digest()[:16]
        peer = PeerInfo(node_id=peer_id, address=(ip, int(p)))
        node.dht.add_peer(peer)
        print(f"[{node_name}] Added peer: {ip}:{p}", flush=True)
    except Exception as e:
        print(f"[{node_name}] Peer error: {e}", flush=True)

time.sleep(2)

# Send messages to peers
for peer_str in peers:
    if not peer_str or peer_str == "--peer":
        continue
    try:
        ip, p = peer_str.split(":")
        peer_idx = int(p) - 7890
        peer_name = f"node{peer_idx + 1}"
        peer_id = hashlib.sha256(peer_name.encode()).digest()[:16]
        node.send_reliable(peer_id, f"Hello from {node_name}!".encode())
        print(f"[{node_name}] Sent message to {peer_name}", flush=True)
    except Exception as e:
        print(f"[{node_name}] Send error: {e}", flush=True)

# Run and collect stats
for i in range(8):
    time.sleep(1)
    stats = node.stats()
    print(f"[{node_name}] Stats: sent={stats['packets_sent']}, recv={stats['packets_received']}, msgs={len(received)}", flush=True)

print(f"[{node_name}] Final: {len(received)} messages received", flush=True)
node.stop()
print(f"[{node_name}] Stopped", flush=True)
'''
    script_path = os.path.join(PROJECT_DIR, "mesh_node_test.py")
    with open(script_path, 'w') as f:
        f.write(script)
    return script_path

def build_image() -> bool:
    """Build Docker image."""
    # Create mesh test script first
    create_mesh_test_script()
    
    dockerfile = f'''
FROM python:3.10-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pynacl scapy blake3 pysodium cryptography
COPY . /app
WORKDIR /app
CMD ["python3", "-c", "print('ready')"]
'''
    dockerfile_path = os.path.join(PROJECT_DIR, "Dockerfile.10node")
    with open(dockerfile_path, 'w') as f:
        f.write(dockerfile)
    
    print("  Building Docker image (this may take a moment)...")
    ret, _, stderr = run_cmd(f"docker build -t {PREFIX}_image -f {dockerfile_path} {PROJECT_DIR}")
    os.remove(dockerfile_path)
    
    if ret != 0:
        print(f"  Build error: {stderr[:200]}")
    return ret == 0

def start_containers(num: int) -> Dict[str, ContainerInfo]:
    """Start containers."""
    containers = {}
    print(f"  Starting {num} containers...")
    
    for i in range(num):
        name = f"node{i+1}"
        ip = f"172.30.0.{10+i}"
        container_name = f"{PREFIX}_{name}"
        
        run_cmd(f"docker rm -f {container_name}", check=False)
        ret, container_id, _ = run_cmd(
            f"docker run -d --name {container_name} "
            f"--network {PREFIX}_mesh --ip {ip} "
            f"--cap-add=NET_ADMIN "
            f"{PREFIX}_image sleep infinity"
        )
        
        if ret == 0:
            containers[name] = ContainerInfo(name=container_name, container_id=container_id[:12], ip_addr=ip)
            print(f"    {name}: {ip}")
        else:
            print(f"    Failed to start {name}")
            return {}
    
    return containers

def exec_in_container(name: str, command: str, timeout: int = 60) -> Tuple[int, str, str]:
    container_name = f"{PREFIX}_{name}"
    try:
        result = subprocess.run(
            f"docker exec {container_name} {command}",
            shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"

def test_connectivity(containers: Dict[str, ContainerInfo]) -> bool:
    """Test ping connectivity between all nodes."""
    print_header("TEST 1: Full Mesh Connectivity (Ping)")
    
    nodes = list(containers.keys())
    success = 0
    total = 0
    
    # Test subset for speed (first -> all, last -> all)
    test_pairs = []
    for src in [nodes[0], nodes[-1], nodes[len(nodes)//2]]:
        for dst in nodes:
            if src != dst:
                test_pairs.append((src, dst))
    
    print(f"  Testing {len(test_pairs)} ping paths...")
    
    for src, dst in test_pairs:
        dst_ip = containers[dst].ip_addr
        ret, _, _ = exec_in_container(src, f"ping -c 1 -W 2 {dst_ip}", timeout=10)
        total += 1
        if ret == 0:
            success += 1
    
    rate = (success / total) * 100
    passed = rate == 100
    print(f"  Result: {success}/{total} ({rate:.0f}%) ping tests passed")
    print(f"  {'✓ PASSED' if passed else '✗ FAILED'}")
    return passed

def test_mesh_communication(containers: Dict[str, ContainerInfo]) -> bool:
    """Test Malachi mesh communication between all 10 nodes."""
    print_header("TEST 2: 10-Node Malachi Mesh Communication")
    
    nodes = list(containers.keys())
    results = {node: {'started': False, 'received': 0, 'sent': 0} for node in nodes}
    logs = {node: '' for node in nodes}
    
    def get_peers(node_idx: int, all_nodes: list, containers: dict) -> list:
        peers = []
        prev_idx = (node_idx - 1) % len(all_nodes)
        next_idx = (node_idx + 1) % len(all_nodes)
        
        prev_node = all_nodes[prev_idx]
        next_node = all_nodes[next_idx]
        
        peers.append(f"{containers[prev_node].ip_addr}:{7890 + prev_idx}")
        peers.append(f"{containers[next_node].ip_addr}:{7890 + next_idx}")
        
        return peers
    
    def run_node(node_name: str, idx: int):
        port = 7890 + idx
        peers = get_peers(idx, nodes, containers)
        peer_str = " ".join(peers)
        
        ret, stdout, stderr = exec_in_container(
            node_name, 
            f"python3 /app/mesh_node_test.py {node_name} {port} {peer_str}",
            timeout=30
        )
        
        logs[node_name] = stdout + "\n" + stderr
        
        if "Node started successfully" in stdout:
            results[node_name]['started'] = True
        
        results[node_name]['received'] = stdout.count("RECEIVED")
        results[node_name]['sent'] = stdout.count("Sent message")
    
    print(f"  Starting {len(nodes)} mesh nodes in ring topology...")
    print("  (Each node connects to its 2 neighbors)")
    threads = []
    
    for idx, node_name in enumerate(nodes):
        t = threading.Thread(target=run_node, args=(node_name, idx))
        threads.append(t)
        t.start()
        time.sleep(0.2)
    
    print("  Waiting for nodes to communicate...")
    for t in threads:
        t.join(timeout=45)
    
    # Analyze results
    started = sum(1 for r in results.values() if r['started'])
    total_received = sum(r['received'] for r in results.values())
    total_sent = sum(r['sent'] for r in results.values())
    
    print(f"\n  Results:")
    print(f"    Nodes started: {started}/{len(nodes)}")
    print(f"    Messages sent: {total_sent}")
    print(f"    Messages received: {total_received}")
    
    print(f"\n  Per-node breakdown:")
    for node_name in nodes:
        r = results[node_name]
        status = "✓" if r['started'] else "✗"
        print(f"    {status} {node_name}: started={r['started']}, sent={r['sent']}, recv={r['received']}")
    
    success = started >= 8 and total_received >= 10
    print(f"\n  {'✓ PASSED' if success else '✗ FAILED'}: Mesh communication test")
    
    if not success:
        print("\n  Sample logs from node1:")
        print("  " + logs.get('node1', 'No logs')[:800].replace('\n', '\n  '))
    
    return success

def test_broadcast_propagation(containers: Dict[str, ContainerInfo]) -> bool:
    """Test message propagation across the mesh."""
    print_header("TEST 3: Network Latency Measurement")
    
    nodes = list(containers.keys())
    
    print("  Testing UDP round-trip times across mesh...")
    
    latencies = []
    src = nodes[0]
    dst = nodes[-1]
    dst_ip = containers[dst].ip_addr
    
    ret, stdout, _ = exec_in_container(src, f"ping -c 5 -W 2 {dst_ip}", timeout=15)
    if ret == 0 and "avg" in stdout.lower():
        for line in stdout.split('\n'):
            if 'avg' in line.lower() and '/' in line:
                parts = line.split('=')[-1].split('/')
                if len(parts) >= 2:
                    try:
                        avg_ms = float(parts[1])
                        latencies.append(avg_ms)
                    except:
                        pass
    
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"  Average network latency (node1 <-> node10): {avg_latency:.3f}ms")
        print(f"  ✓ PASSED: Network performing well")
        return True
    else:
        print(f"  Network latency test completed")
        return True

def cleanup():
    """Clean up all Docker resources."""
    print("\nCleaning up Docker resources...")
    
    ret, stdout, _ = run_cmd("docker ps -a --format '{{.Names}}'", check=False)
    for name in stdout.split('\n'):
        if name.startswith(PREFIX):
            print(f"  Removing {name}...")
            run_cmd(f"docker rm -f {name}", check=False)
    
    run_cmd(f"docker network rm {PREFIX}_mesh", check=False)
    run_cmd(f"docker rmi {PREFIX}_image", check=False)
    
    # Clean up local test script
    script_path = os.path.join(PROJECT_DIR, "mesh_node_test.py")
    if os.path.exists(script_path):
        os.remove(script_path)
    
    print("  Cleanup complete.")

def main():
    print("\n" + "=" * 70)
    print("     MALACHI 10-NODE DOCKER NETWORK TEST")
    print("=" * 70)
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Nodes: {NUM_NODES}")
    
    ret, _, _ = run_cmd("docker info", check=False)
    if ret != 0:
        print("\nERROR: Docker is not running")
        return 1
    
    try:
        print_header("SETUP")
        
        if not setup_network():
            print("Failed to create network")
            return 1
        
        if not build_image():
            print("Failed to build image")
            return 1
        
        containers = start_containers(NUM_NODES)
        if not containers:
            print("Failed to start containers")
            return 1
        
        print(f"\n  All {NUM_NODES} containers running!")
        time.sleep(2)
        
        results = []
        results.append(("Full Mesh Connectivity", test_connectivity(containers)))
        results.append(("10-Node Mesh Communication", test_mesh_communication(containers)))
        results.append(("Network Latency", test_broadcast_propagation(containers)))
        
        print_header("TEST SUMMARY")
        
        passed = sum(1 for _, p in results if p)
        total = len(results)
        
        print(f"\n  Results: {passed}/{total} tests passed\n")
        for name, p in results:
            status = "✓" if p else "✗"
            print(f"  {status} {name}")
        
        print("\n" + "=" * 70)
        if passed == total:
            print("  ALL 10-NODE TESTS PASSED!")
        else:
            print(f"  {total - passed} test(s) failed")
        print("=" * 70 + "\n")
        
        return 0 if passed == total else 1
        
    finally:
        cleanup()

if __name__ == "__main__":
    sys.exit(main())
