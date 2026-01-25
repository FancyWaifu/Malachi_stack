#!/usr/bin/env python3
"""
Malachi Virtual Network Test

Creates real virtual networks using Linux network namespaces and veth pairs,
then runs actual Malachi nodes through them.

Requires root/sudo privileges.
"""

import os
import sys
import time
import subprocess
import signal
import tempfile
import json
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
import threading


# =============================================================================
# Virtual Network Infrastructure
# =============================================================================

@dataclass
class VethPair:
    """A virtual ethernet pair."""
    name1: str
    name2: str
    ns1: str  # Namespace for end 1
    ns2: str  # Namespace for end 2


@dataclass
class NetworkNamespace:
    """A network namespace with its configuration."""
    name: str
    veth_name: str  # veth interface inside this namespace
    ip_addr: str
    mac_addr: str


class VirtualNetworkManager:
    """
    Manages virtual network infrastructure using Linux namespaces.
    """

    def __init__(self, prefix: str = "malachi"):
        self.prefix = prefix
        self.namespaces: Dict[str, NetworkNamespace] = {}
        self.veth_pairs: List[VethPair] = []
        self.bridge_name = f"{prefix}_br0"
        self._cleanup_on_exit = True

    def check_root(self) -> bool:
        """Check if running as root."""
        return os.geteuid() == 0

    def run_cmd(self, cmd: str, check: bool = True) -> Tuple[int, str, str]:
        """Run a shell command."""
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True
        )
        if check and result.returncode != 0:
            print(f"Command failed: {cmd}")
            print(f"  stderr: {result.stderr}")
        return result.returncode, result.stdout, result.stderr

    def run_in_ns(self, ns_name: str, cmd: str) -> Tuple[int, str, str]:
        """Run a command in a network namespace."""
        return self.run_cmd(f"ip netns exec {ns_name} {cmd}")

    def create_namespace(self, name: str) -> bool:
        """Create a network namespace."""
        full_name = f"{self.prefix}_{name}"
        ret, _, _ = self.run_cmd(f"ip netns add {full_name}", check=False)
        if ret == 0:
            # Bring up loopback
            self.run_in_ns(full_name, "ip link set lo up")
            return True
        return False

    def delete_namespace(self, name: str) -> bool:
        """Delete a network namespace."""
        full_name = f"{self.prefix}_{name}"
        ret, _, _ = self.run_cmd(f"ip netns delete {full_name}", check=False)
        return ret == 0

    def create_bridge(self) -> bool:
        """Create a Linux bridge to connect namespaces."""
        # Create bridge
        ret, _, _ = self.run_cmd(f"ip link add {self.bridge_name} type bridge", check=False)
        if ret != 0:
            # Bridge might already exist
            pass

        # Bring up bridge
        self.run_cmd(f"ip link set {self.bridge_name} up")
        return True

    def delete_bridge(self) -> bool:
        """Delete the bridge."""
        self.run_cmd(f"ip link set {self.bridge_name} down", check=False)
        self.run_cmd(f"ip link delete {self.bridge_name}", check=False)
        return True

    def create_veth_to_bridge(self, ns_name: str, ip_addr: str, mac_addr: str) -> Optional[NetworkNamespace]:
        """Create a veth pair connecting a namespace to the bridge."""
        full_ns = f"{self.prefix}_{ns_name}"
        veth_host = f"veth_{ns_name}_h"
        veth_ns = f"veth_{ns_name}"

        # Create veth pair
        ret, _, _ = self.run_cmd(
            f"ip link add {veth_host} type veth peer name {veth_ns}",
            check=False
        )
        if ret != 0:
            return None

        # Move one end to namespace
        self.run_cmd(f"ip link set {veth_ns} netns {full_ns}")

        # Attach host end to bridge
        self.run_cmd(f"ip link set {veth_host} master {self.bridge_name}")
        self.run_cmd(f"ip link set {veth_host} up")

        # Configure namespace end
        self.run_in_ns(full_ns, f"ip link set {veth_ns} address {mac_addr}")
        self.run_in_ns(full_ns, f"ip addr add {ip_addr}/24 dev {veth_ns}")
        self.run_in_ns(full_ns, f"ip link set {veth_ns} up")

        ns_info = NetworkNamespace(
            name=full_ns,
            veth_name=veth_ns,
            ip_addr=ip_addr,
            mac_addr=mac_addr
        )
        self.namespaces[ns_name] = ns_info

        return ns_info

    def setup_star_topology(self, num_nodes: int) -> bool:
        """
        Setup a star topology with all nodes connected to a central bridge.

        Node1 (10.99.0.1)
              │
        Node2─┼─Bridge─Node3
              │
        Node4 (10.99.0.4)
        """
        print(f"\n{'='*60}")
        print("Setting up Star Topology")
        print('='*60)

        # Create bridge
        print("  Creating bridge...")
        self.create_bridge()

        # Create namespaces and connect to bridge
        for i in range(num_nodes):
            ns_name = f"node{i+1}"
            ip_addr = f"10.99.0.{i+1}"
            mac_addr = f"02:00:00:00:00:{i+1:02x}"

            print(f"  Creating namespace {ns_name} ({ip_addr}, {mac_addr})...")
            self.create_namespace(ns_name)
            self.create_veth_to_bridge(ns_name, ip_addr, mac_addr)

        return True

    def setup_line_topology(self, num_nodes: int) -> bool:
        """
        Setup a line topology: Node1 -- Node2 -- Node3 -- Node4
        Each node only connects to its neighbors.
        """
        print(f"\n{'='*60}")
        print("Setting up Line Topology")
        print('='*60)

        # Create namespaces
        for i in range(num_nodes):
            ns_name = f"node{i+1}"
            print(f"  Creating namespace {ns_name}...")
            self.create_namespace(ns_name)

        # Create veth pairs between adjacent nodes
        for i in range(num_nodes - 1):
            ns1 = f"node{i+1}"
            ns2 = f"node{i+2}"
            full_ns1 = f"{self.prefix}_{ns1}"
            full_ns2 = f"{self.prefix}_{ns2}"

            veth1 = f"veth{i+1}to{i+2}"
            veth2 = f"veth{i+2}to{i+1}"

            print(f"  Connecting {ns1} <-> {ns2}...")

            # Create veth pair
            self.run_cmd(f"ip link add {veth1} type veth peer name {veth2}")

            # Move to namespaces
            self.run_cmd(f"ip link set {veth1} netns {full_ns1}")
            self.run_cmd(f"ip link set {veth2} netns {full_ns2}")

            # Configure IPs (subnet for each link)
            subnet = i + 1
            self.run_in_ns(full_ns1, f"ip addr add 10.99.{subnet}.1/24 dev {veth1}")
            self.run_in_ns(full_ns1, f"ip link set {veth1} up")

            self.run_in_ns(full_ns2, f"ip addr add 10.99.{subnet}.2/24 dev {veth2}")
            self.run_in_ns(full_ns2, f"ip link set {veth2} up")

            # Store namespace info
            if ns1 not in self.namespaces:
                self.namespaces[ns1] = NetworkNamespace(
                    name=full_ns1, veth_name=veth1,
                    ip_addr=f"10.99.{subnet}.1",
                    mac_addr=f"02:00:00:00:{subnet:02x}:01"
                )
            if ns2 not in self.namespaces:
                self.namespaces[ns2] = NetworkNamespace(
                    name=full_ns2, veth_name=veth2,
                    ip_addr=f"10.99.{subnet}.2",
                    mac_addr=f"02:00:00:00:{subnet:02x}:02"
                )

        return True

    def cleanup(self):
        """Clean up all virtual network infrastructure."""
        print("\nCleaning up virtual network...")

        # Delete namespaces
        for ns_name in list(self.namespaces.keys()):
            print(f"  Deleting namespace {self.prefix}_{ns_name}...")
            self.delete_namespace(ns_name)

        # Delete bridge
        print(f"  Deleting bridge {self.bridge_name}...")
        self.delete_bridge()

        # Clean up any leftover veth interfaces
        ret, stdout, _ = self.run_cmd("ip link show", check=False)
        for line in stdout.split('\n'):
            if f'veth_' in line and self.prefix in line:
                iface = line.split(':')[1].strip().split('@')[0]
                print(f"  Cleaning up interface {iface}...")
                self.run_cmd(f"ip link delete {iface}", check=False)

        self.namespaces.clear()
        self.veth_pairs.clear()

        print("  Cleanup complete.")

    def verify_connectivity(self) -> Dict[str, bool]:
        """Verify connectivity between namespaces."""
        results = {}
        ns_list = list(self.namespaces.keys())

        for i, ns1 in enumerate(ns_list):
            for ns2 in ns_list[i+1:]:
                ns1_info = self.namespaces[ns1]
                ns2_info = self.namespaces[ns2]

                # Ping from ns1 to ns2
                key = f"{ns1}->{ns2}"
                ret, _, _ = self.run_in_ns(
                    ns1_info.name,
                    f"ping -c 1 -W 1 {ns2_info.ip_addr}"
                )
                results[key] = (ret == 0)

        return results


# =============================================================================
# Malachi Node Runner
# =============================================================================

class MalachiNodeRunner:
    """Runs Malachi nodes in network namespaces."""

    def __init__(self, project_dir: str, net_manager: VirtualNetworkManager):
        self.project_dir = project_dir
        self.net_manager = net_manager
        self.processes: Dict[str, subprocess.Popen] = {}
        self.log_dir = Path(tempfile.mkdtemp(prefix="malachi_logs_"))

    def start_node(self, ns_name: str, node_script: str, extra_args: str = "") -> bool:
        """Start a Malachi node in a namespace."""
        ns_info = self.net_manager.namespaces.get(ns_name)
        if not ns_info:
            print(f"  Namespace {ns_name} not found")
            return False

        log_file = self.log_dir / f"{ns_name}.log"

        # Build command to run in namespace
        cmd = f"ip netns exec {ns_info.name} python3 {self.project_dir}/{node_script} {extra_args}"

        print(f"  Starting node in {ns_name}: {node_script}")

        with open(log_file, 'w') as log:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=log, stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )

        self.processes[ns_name] = proc
        return True

    def stop_node(self, ns_name: str):
        """Stop a Malachi node."""
        proc = self.processes.get(ns_name)
        if proc:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except:
                    pass
            del self.processes[ns_name]

    def stop_all(self):
        """Stop all nodes."""
        for ns_name in list(self.processes.keys()):
            self.stop_node(ns_name)

    def get_logs(self, ns_name: str) -> str:
        """Get logs for a node."""
        log_file = self.log_dir / f"{ns_name}.log"
        if log_file.exists():
            return log_file.read_text()
        return ""


# =============================================================================
# Test Script Generator
# =============================================================================

def create_test_node_script(project_dir: str) -> str:
    """Create a test script that runs a Malachi mesh node."""
    script_content = '''#!/usr/bin/env python3
"""Test node for virtual network testing."""
import os
import sys
import time
import socket
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from malachi.mesh import MeshNode, PeerInfo

def get_interface_info():
    """Get the first non-loopback interface info."""
    import subprocess
    result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)

    current_iface = None
    iface_info = {}

    for line in result.stdout.split('\\n'):
        if ': ' in line and not line.startswith(' '):
            parts = line.split(': ')
            if len(parts) >= 2:
                current_iface = parts[1].split('@')[0]
                iface_info[current_iface] = {'ip': None, 'mac': None}
        elif 'inet ' in line and current_iface:
            ip = line.strip().split()[1].split('/')[0]
            iface_info[current_iface]['ip'] = ip
        elif 'link/ether' in line and current_iface:
            mac = line.strip().split()[1]
            iface_info[current_iface]['mac'] = mac

    # Return first non-loopback interface
    for iface, info in iface_info.items():
        if iface != 'lo' and info['ip']:
            return iface, info['ip'], info['mac']

    return None, None, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=7891)
    parser.add_argument('--peer', type=str, help='Peer address (ip:port)')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--send-test', action='store_true')
    args = parser.parse_args()

    iface, ip, mac = get_interface_info()
    print(f"Interface: {iface}, IP: {ip}, MAC: {mac}")

    # Generate node ID from MAC
    node_id = os.urandom(16)

    print(f"Starting MeshNode on port {args.port}")
    print(f"Node ID: {node_id.hex()[:16]}...")

    node = MeshNode(node_id, port=args.port)

    received_messages = []

    def on_message(src, data):
        print(f"RECEIVED from {src.hex()[:8]}: {data[:50]}")
        received_messages.append((src, data))

    node.on_message(on_message)

    if not node.start():
        print("Failed to start node")
        sys.exit(1)

    print("Node started successfully")

    # Add peer if specified
    if args.peer:
        peer_ip, peer_port = args.peer.split(':')
        peer_id = os.urandom(16)  # We don't know the peer's real ID yet
        peer = PeerInfo(node_id=peer_id, address=(peer_ip, int(peer_port)))
        node.dht.add_peer(peer)
        print(f"Added peer: {peer_ip}:{peer_port}")

    # If send test enabled, send messages periodically
    if args.send_test and args.peer:
        peer_ip, peer_port = args.peer.split(':')
        for peer in node.dht.get_all_peers():
            print(f"Sending test message to {peer.node_id.hex()[:8]}")
            node.send_reliable(peer.node_id, f"Hello from {ip}!".encode())

    # Run for specified duration
    start = time.time()
    while time.time() - start < args.duration:
        time.sleep(1)
        stats = node.stats()
        print(f"Stats: sent={stats['packets_sent']}, recv={stats['packets_received']}, peers={stats['known_peers']}")

    print(f"Received {len(received_messages)} messages total")
    node.stop()
    print("Node stopped")

if __name__ == "__main__":
    main()
'''

    script_path = os.path.join(project_dir, "test_vnet_node.py")
    with open(script_path, 'w') as f:
        f.write(script_content)
    os.chmod(script_path, 0o755)

    return script_path


# =============================================================================
# Main Test Runner
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


def run_connectivity_test(net_manager: VirtualNetworkManager) -> bool:
    """Test basic IP connectivity between namespaces."""
    print_header("TEST 1: IP Connectivity")

    results = net_manager.verify_connectivity()

    all_passed = True
    for path, success in results.items():
        print_result(f"Ping {path}", success)
        if not success:
            all_passed = False

    return all_passed


def run_udp_test(net_manager: VirtualNetworkManager) -> bool:
    """Test UDP communication between namespaces."""
    print_header("TEST 2: UDP Communication")

    ns_list = list(net_manager.namespaces.keys())
    if len(ns_list) < 2:
        print("  Need at least 2 namespaces")
        return False

    ns1_info = net_manager.namespaces[ns_list[0]]
    ns2_info = net_manager.namespaces[ns_list[1]]

    # Start UDP listener in ns2
    listener_script = f'''
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 9999))
sock.settimeout(5)
try:
    data, addr = sock.recvfrom(1024)
    print(f"RECEIVED: {{data}}")
except socket.timeout:
    print("TIMEOUT")
sock.close()
'''

    # Start sender in ns1
    sender_script = f'''
import socket
import time
time.sleep(0.5)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b"Hello UDP!", ("{ns2_info.ip_addr}", 9999))
print("SENT")
sock.close()
'''

    # Run in parallel
    import threading
    results = {}

    def run_listener():
        ret, stdout, _ = net_manager.run_in_ns(
            ns2_info.name,
            f'python3 -c "{listener_script}"'
        )
        results['listener'] = 'RECEIVED' in stdout

    def run_sender():
        time.sleep(0.3)
        ret, stdout, _ = net_manager.run_in_ns(
            ns1_info.name,
            f'python3 -c "{sender_script}"'
        )
        results['sender'] = 'SENT' in stdout

    t1 = threading.Thread(target=run_listener)
    t2 = threading.Thread(target=run_sender)

    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    print_result("UDP send", results.get('sender', False))
    print_result("UDP receive", results.get('listener', False))

    return results.get('sender', False) and results.get('listener', False)


def run_malachi_mesh_test(net_manager: VirtualNetworkManager, project_dir: str) -> bool:
    """Test Malachi mesh nodes across namespaces."""
    print_header("TEST 3: Malachi Mesh Nodes")

    ns_list = list(net_manager.namespaces.keys())
    if len(ns_list) < 2:
        print("  Need at least 2 namespaces")
        return False

    # Create test node script
    create_test_node_script(project_dir)

    ns1_info = net_manager.namespaces[ns_list[0]]
    ns2_info = net_manager.namespaces[ns_list[1]]

    results = {'node1': False, 'node2': False, 'communication': False}
    logs = {'node1': '', 'node2': ''}

    def run_node1():
        ret, stdout, stderr = net_manager.run_in_ns(
            ns1_info.name,
            f'cd {project_dir} && python3 test_vnet_node.py --port 7891 --peer {ns2_info.ip_addr}:7892 --duration 10 --send-test 2>&1'
        )
        logs['node1'] = stdout + stderr
        results['node1'] = 'Node started successfully' in stdout
        if 'RECEIVED' in stdout:
            results['communication'] = True

    def run_node2():
        ret, stdout, stderr = net_manager.run_in_ns(
            ns2_info.name,
            f'cd {project_dir} && python3 test_vnet_node.py --port 7892 --peer {ns1_info.ip_addr}:7891 --duration 10 --send-test 2>&1'
        )
        logs['node2'] = stdout + stderr
        results['node2'] = 'Node started successfully' in stdout
        if 'RECEIVED' in stdout:
            results['communication'] = True

    t1 = threading.Thread(target=run_node1)
    t2 = threading.Thread(target=run_node2)

    print("  Starting nodes...")
    t1.start()
    time.sleep(0.5)
    t2.start()

    t1.join(timeout=20)
    t2.join(timeout=20)

    print_result("Node 1 started", results['node1'])
    print_result("Node 2 started", results['node2'])
    print_result("Cross-namespace communication", results['communication'])

    if not results['node1']:
        print(f"\n  Node 1 log:\n{logs['node1'][:500]}")
    if not results['node2']:
        print(f"\n  Node 2 log:\n{logs['node2'][:500]}")

    return results['node1'] and results['node2']


def run_all_tests():
    """Run all virtual network tests."""
    print("\n" + "=" * 70)
    print("     MALACHI VIRTUAL NETWORK TESTS")
    print("=" * 70)
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    project_dir = os.path.dirname(os.path.abspath(__file__))
    net_manager = VirtualNetworkManager("malachi_test")

    # Check root
    if not net_manager.check_root():
        print("\n  ERROR: This script requires root privileges.")
        print("  Please run with: sudo python3 virtual_network_test.py")
        return False

    try:
        # Setup network
        print_header("SETUP: Creating Virtual Network")
        net_manager.setup_star_topology(3)

        # Show network info
        print("\n  Network namespaces created:")
        for ns_name, ns_info in net_manager.namespaces.items():
            print(f"    {ns_name}: {ns_info.ip_addr} ({ns_info.mac_addr})")

        results = []

        # Run tests
        results.append(("IP Connectivity", run_connectivity_test(net_manager)))
        results.append(("UDP Communication", run_udp_test(net_manager)))
        results.append(("Malachi Mesh", run_malachi_mesh_test(net_manager, project_dir)))

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
            print("  ALL VIRTUAL NETWORK TESTS PASSED!")
        else:
            print(f"  {total - passed} test(s) failed")

        print("=" * 70 + "\n")

        return passed == total

    finally:
        # Cleanup
        net_manager.cleanup()


def cleanup_only():
    """Just clean up any leftover virtual network infrastructure."""
    print("Cleaning up any leftover virtual network infrastructure...")
    net_manager = VirtualNetworkManager("malachi_test")

    if not net_manager.check_root():
        print("Need root to clean up. Run with: sudo python3 virtual_network_test.py --cleanup")
        return

    # Delete any existing namespaces
    ret, stdout, _ = net_manager.run_cmd("ip netns list", check=False)
    for line in stdout.strip().split('\n'):
        if line and 'malachi_test' in line:
            ns_name = line.split()[0]
            print(f"  Deleting namespace {ns_name}")
            net_manager.run_cmd(f"ip netns delete {ns_name}", check=False)

    # Delete bridge
    net_manager.run_cmd(f"ip link delete {net_manager.bridge_name}", check=False)

    # Clean veth interfaces
    ret, stdout, _ = net_manager.run_cmd("ip link show", check=False)
    for line in stdout.split('\n'):
        if 'veth_' in line:
            iface = line.split(':')[1].strip().split('@')[0]
            print(f"  Deleting interface {iface}")
            net_manager.run_cmd(f"ip link delete {iface}", check=False)

    print("Cleanup complete.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Malachi Virtual Network Tests")
    parser.add_argument('--cleanup', action='store_true', help='Just clean up leftover infrastructure')
    args = parser.parse_args()

    if args.cleanup:
        cleanup_only()
    else:
        success = run_all_tests()
        sys.exit(0 if success else 1)
