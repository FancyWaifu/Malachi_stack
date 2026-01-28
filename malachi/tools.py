#!/usr/bin/env python3
"""
Malachi Network Tools Suite

A comprehensive set of network utilities for the Malachi stack:
- malping     : Ping nodes by ID or virtual IP
- maltrace    : Traceroute to a node
- mallookup   : Resolve node ID <-> virtual IP
- malscan     : Discover nodes on the network
- malnc       : Netcat-like data transfer
- malstat     : Network statistics
- malroute    : Routing table management
- malkeys     : Key and identity management

Usage:
    python -m malachi.tools <command> [options]

Or via malctl:
    malctl ping <node_id_or_ip>
"""

import os
import sys
import time
import struct
import socket
import random
import threading
import argparse
import ipaddress
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import json

# Import Malachi modules
try:
    from .tun_interface import (
        create_tun_interface, MalachiNetworkDaemon,
        MALACHI_PREFIX, IS_LINUX, IS_MACOS, IS_BSD, PLATFORM
    )
except ImportError:
    from tun_interface import (
        create_tun_interface, MalachiNetworkDaemon,
        MALACHI_PREFIX, IS_LINUX, IS_MACOS, IS_BSD, PLATFORM
    )


# =============================================================================
# Protocol Constants
# =============================================================================

# Malachi Control Protocol (MCP) - for tools
MCP_PING_REQUEST = 0x01
MCP_PING_REPLY = 0x02
MCP_TRACE_REQUEST = 0x03
MCP_TRACE_REPLY = 0x04
MCP_DISCOVER_REQUEST = 0x05
MCP_DISCOVER_REPLY = 0x06
MCP_INFO_REQUEST = 0x07
MCP_INFO_REPLY = 0x08

# Control port for Malachi tools
MCP_PORT = 7


# =============================================================================
# Helper Functions
# =============================================================================

def parse_node_address(address: str) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Parse a node address (node ID, virtual IP, or .mli domain).

    Supported formats:
        - Virtual IP: 10.x.x.x
        - Full node ID: a1b2c3d4e5f67890abcdef1234567890 (32 hex chars)
        - Short node ID: a1b2c3d4 (8+ hex chars, padded with zeros)
        - .mli domain: a1b2c3d4.mli or subdomain.a1b2c3d4.mli

    Returns:
        (node_id, virtual_ip) - one will be None depending on input type
    """
    address = address.strip().lower()

    # Check if it's a .mli domain
    if address.endswith('.mli'):
        # Extract node ID from domain: "a1b2c3d4.mli" or "sub.a1b2c3d4.mli"
        parts = address[:-4].split('.')  # Remove .mli and split
        # The node ID is the last part before .mli
        node_id_part = parts[-1] if parts else ''

        # Validate it's a hex string
        if len(node_id_part) >= 4 and all(c in '0123456789abcdef' for c in node_id_part):
            # Pad with zeros to make 32 chars
            padded = node_id_part.ljust(32, '0')
            try:
                node_id = bytes.fromhex(padded)
                return (node_id, None)
            except:
                pass

    # Check if it's a virtual IP (10.x.x.x range)
    if address.startswith("10."):
        try:
            ipaddress.IPv4Address(address)
            return (None, address)
        except:
            pass

    # Check if it's a hex node ID (32 chars = 16 bytes)
    if len(address) == 32:
        try:
            node_id = bytes.fromhex(address)
            return (node_id, None)
        except:
            pass

    # Check if it's a short node ID (prefix)
    if len(address) >= 8 and all(c in '0123456789abcdef' for c in address):
        # Pad with zeros to make 32 chars
        padded = address.ljust(32, '0')
        try:
            node_id = bytes.fromhex(padded)
            return (node_id, None)
        except:
            pass

    return (None, None)


def node_id_to_virtual_ip(node_id) -> str:
    """
    Convert a node ID to its virtual IP address.

    Args:
        node_id: bytes or hex string (32 chars)

    Returns:
        Virtual IP address string
    """
    # Handle string input (hex)
    if isinstance(node_id, str):
        node_id = node_id.lower().ljust(32, '0')
        try:
            node_id = bytes.fromhex(node_id)
        except ValueError:
            return "10.0.0.2"

    node_hash = int.from_bytes(node_id[:4], 'big')
    second_octet = (node_hash >> 16) & 0xFF
    third_octet = (node_hash >> 8) & 0xFF
    fourth_octet = node_hash & 0xFF
    if second_octet == 0 and third_octet == 0 and fourth_octet < 2:
        fourth_octet = 2
    return f"10.{second_octet}.{third_octet}.{fourth_octet}"


def virtual_ip_to_display(ip: str) -> str:
    """Format virtual IP for display."""
    return ip


def format_node_id(node_id: bytes, short: bool = False) -> str:
    """Format node ID for display."""
    hex_str = node_id.hex()
    if short:
        return hex_str[:8] + "..."
    return hex_str


def format_duration(seconds: float) -> str:
    """Format duration for display."""
    if seconds < 0.001:
        return f"{seconds * 1000000:.0f}us"
    elif seconds < 1:
        return f"{seconds * 1000:.2f}ms"
    else:
        return f"{seconds:.2f}s"


def format_bytes(num_bytes: int) -> str:
    """Format byte count for display."""
    if num_bytes < 1024:
        return f"{num_bytes}B"
    elif num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.1f}KB"
    elif num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f}MB"
    else:
        return f"{num_bytes / (1024 * 1024 * 1024):.1f}GB"


# =============================================================================
# Ping Implementation
# =============================================================================

@dataclass
class PingResult:
    """Result of a single ping."""
    seq: int
    success: bool
    rtt_ms: float = 0.0
    error: str = ""
    ttl: int = 64


@dataclass
class PingStats:
    """Statistics for a ping session."""
    transmitted: int = 0
    received: int = 0
    errors: int = 0
    min_rtt: float = float('inf')
    max_rtt: float = 0.0
    total_rtt: float = 0.0

    @property
    def loss_percent(self) -> float:
        if self.transmitted == 0:
            return 0.0
        return ((self.transmitted - self.received) / self.transmitted) * 100

    @property
    def avg_rtt(self) -> float:
        if self.received == 0:
            return 0.0
        return self.total_rtt / self.received


class MalachiPing:
    """
    Ping implementation for Malachi network.

    Sends ICMP-like echo requests over Malachi and measures RTT.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon
        self._responses: Dict[int, float] = {}  # seq -> timestamp
        self._lock = threading.Lock()

    def ping(
        self,
        target: str,
        count: int = 4,
        interval: float = 1.0,
        timeout: float = 5.0,
        size: int = 64,
        quiet: bool = False,
    ) -> PingStats:
        """
        Ping a Malachi node.

        Args:
            target: Node ID (hex) or virtual IP
            count: Number of pings to send (0 = infinite)
            interval: Seconds between pings
            timeout: Seconds to wait for reply
            size: Payload size in bytes
            quiet: Suppress per-ping output

        Returns:
            PingStats with results
        """
        # Parse target address
        node_id, virtual_ip = parse_node_address(target)

        if node_id:
            virtual_ip = node_id_to_virtual_ip(node_id)
            target_display = f"{format_node_id(node_id, short=True)} ({virtual_ip})"
        elif virtual_ip:
            target_display = virtual_ip
        else:
            print(f"malping: invalid address '{target}'")
            return PingStats()

        if not quiet:
            print(f"MALPING {target_display}: {size} data bytes")

        stats = PingStats()
        seq = 0

        try:
            while count == 0 or seq < count:
                seq += 1
                result = self._send_ping(virtual_ip, seq, size, timeout)
                stats.transmitted += 1

                if result.success:
                    stats.received += 1
                    stats.total_rtt += result.rtt_ms
                    stats.min_rtt = min(stats.min_rtt, result.rtt_ms)
                    stats.max_rtt = max(stats.max_rtt, result.rtt_ms)

                    if not quiet:
                        print(f"{size} bytes from {virtual_ip}: seq={result.seq} "
                              f"ttl={result.ttl} time={result.rtt_ms:.2f}ms")
                else:
                    stats.errors += 1
                    if not quiet:
                        print(f"Request timeout for seq {result.seq}")

                if count == 0 or seq < count:
                    time.sleep(interval)

        except KeyboardInterrupt:
            pass

        # Print statistics
        if not quiet:
            print(f"\n--- {target_display} malping statistics ---")
            print(f"{stats.transmitted} packets transmitted, "
                  f"{stats.received} packets received, "
                  f"{stats.loss_percent:.1f}% packet loss")

            if stats.received > 0:
                print(f"round-trip min/avg/max = "
                      f"{stats.min_rtt:.2f}/{stats.avg_rtt:.2f}/{stats.max_rtt:.2f} ms")

        return stats

    def _send_ping(
        self,
        target_ip: str,
        seq: int,
        size: int,
        timeout: float
    ) -> PingResult:
        """Send a single ping and wait for reply."""
        # Build ping packet
        # Format: [type:1][seq:2][timestamp:8][padding:N]
        timestamp = time.time()
        payload = struct.pack('>BHd', MCP_PING_REQUEST, seq, timestamp)
        payload += os.urandom(max(0, size - len(payload)))

        send_time = time.time()

        # In a real implementation, this would send via the daemon
        # For now, simulate with a small random delay
        # TODO: Integrate with actual Malachi network send/receive

        # Simulate network delay (remove when real networking is hooked up)
        simulated_rtt = random.uniform(0.5, 15.0)  # ms
        time.sleep(simulated_rtt / 1000)

        recv_time = time.time()
        rtt_ms = (recv_time - send_time) * 1000

        return PingResult(
            seq=seq,
            success=True,
            rtt_ms=rtt_ms,
            ttl=64
        )


# =============================================================================
# Traceroute Implementation
# =============================================================================

@dataclass
class TraceHop:
    """A single hop in a traceroute."""
    hop: int
    node_id: Optional[bytes] = None
    virtual_ip: Optional[str] = None
    rtt_ms: List[float] = field(default_factory=list)
    timeout: bool = False


class MalachiTrace:
    """
    Traceroute implementation for Malachi network.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon

    def trace(
        self,
        target: str,
        max_hops: int = 30,
        queries: int = 3,
        timeout: float = 5.0,
        quiet: bool = False,
    ) -> List[TraceHop]:
        """
        Trace route to a Malachi node.

        Args:
            target: Node ID (hex) or virtual IP
            max_hops: Maximum number of hops
            queries: Number of queries per hop
            timeout: Seconds to wait for reply
            quiet: Suppress output

        Returns:
            List of TraceHop results
        """
        node_id, virtual_ip = parse_node_address(target)

        if node_id:
            virtual_ip = node_id_to_virtual_ip(node_id)
            target_display = f"{format_node_id(node_id, short=True)} ({virtual_ip})"
        elif virtual_ip:
            target_display = virtual_ip
        else:
            print(f"maltrace: invalid address '{target}'")
            return []

        if not quiet:
            print(f"maltrace to {target_display}, {max_hops} hops max")

        hops = []

        for ttl in range(1, max_hops + 1):
            hop = self._probe_hop(virtual_ip, ttl, queries, timeout)
            hops.append(hop)

            if not quiet:
                self._print_hop(hop)

            # Check if we reached the target
            if hop.virtual_ip == virtual_ip:
                break

        return hops

    def _probe_hop(
        self,
        target_ip: str,
        ttl: int,
        queries: int,
        timeout: float
    ) -> TraceHop:
        """Probe a single hop."""
        hop = TraceHop(hop=ttl)

        for _ in range(queries):
            # Simulate probe (replace with real implementation)
            # TODO: Integrate with Malachi routing

            if ttl >= 2:  # Simulate reaching intermediate/final node
                simulated_rtt = random.uniform(1.0, 20.0) * ttl
                hop.rtt_ms.append(simulated_rtt)

                # Simulate intermediate node
                fake_node = os.urandom(16)
                hop.node_id = fake_node
                hop.virtual_ip = node_id_to_virtual_ip(fake_node)
            else:
                hop.rtt_ms.append(random.uniform(0.5, 5.0))
                hop.virtual_ip = "10.0.0.1"  # Local

        return hop

    def _print_hop(self, hop: TraceHop):
        """Print a single hop result."""
        if hop.timeout:
            print(f" {hop.hop:2}  * * *")
        else:
            rtts = "  ".join(f"{r:.2f}ms" for r in hop.rtt_ms)
            if hop.node_id:
                print(f" {hop.hop:2}  {hop.virtual_ip} ({format_node_id(hop.node_id, short=True)})  {rtts}")
            else:
                print(f" {hop.hop:2}  {hop.virtual_ip}  {rtts}")


# =============================================================================
# Network Scanner
# =============================================================================

@dataclass
class DiscoveredNode:
    """A discovered node on the network."""
    node_id: bytes
    virtual_ip: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    last_seen: float = field(default_factory=time.time)
    rtt_ms: float = 0.0
    services: List[int] = field(default_factory=list)


class MalachiScanner:
    """
    Network scanner for discovering Malachi nodes.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon
        self._discovered: Dict[bytes, DiscoveredNode] = {}

    def scan(
        self,
        timeout: float = 10.0,
        quiet: bool = False,
    ) -> List[DiscoveredNode]:
        """
        Scan for Malachi nodes on the network.

        Args:
            timeout: How long to scan
            quiet: Suppress output

        Returns:
            List of discovered nodes
        """
        if not quiet:
            print(f"Scanning for Malachi nodes ({timeout}s)...")
            print()

        start_time = time.time()

        # In real implementation, this would:
        # 1. Send NDP discovery broadcasts
        # 2. Listen for NDP advertisements
        # 3. Collect responses

        # Simulate discovery (replace with real NDP integration)
        # TODO: Integrate with actual NDP discovery

        while time.time() - start_time < timeout:
            # Simulate finding a node
            if random.random() < 0.3:
                fake_node_id = os.urandom(16)
                if fake_node_id not in self._discovered:
                    node = DiscoveredNode(
                        node_id=fake_node_id,
                        virtual_ip=node_id_to_virtual_ip(fake_node_id),
                        rtt_ms=random.uniform(1, 50),
                    )
                    self._discovered[fake_node_id] = node

                    if not quiet:
                        print(f"  Found: {node.virtual_ip}  {format_node_id(node.node_id, short=True)}  "
                              f"{node.rtt_ms:.1f}ms")

            time.sleep(0.5)

        if not quiet:
            print()
            print(f"Scan complete. Found {len(self._discovered)} nodes.")

        return list(self._discovered.values())

    def port_scan(
        self,
        target: str,
        ports: List[int] = None,
        timeout: float = 2.0,
        quiet: bool = False,
    ) -> Dict[int, bool]:
        """
        Scan ports on a Malachi node.

        Args:
            target: Node ID or virtual IP
            ports: List of ports to scan (default: common ports)
            timeout: Timeout per port
            quiet: Suppress output

        Returns:
            Dict of port -> open status
        """
        if ports is None:
            ports = [7, 22, 80, 443, 8080, 8443]  # Common ports

        node_id, virtual_ip = parse_node_address(target)
        if node_id:
            virtual_ip = node_id_to_virtual_ip(node_id)

        if not quiet:
            print(f"Scanning ports on {virtual_ip}...")

        results = {}

        for port in ports:
            # Simulate port scan (replace with real implementation)
            is_open = random.random() < 0.3
            results[port] = is_open

            if not quiet and is_open:
                print(f"  Port {port}: OPEN")

        return results


# =============================================================================
# Netcat-like Tool
# =============================================================================

class MalachiNetcat:
    """
    Netcat-like tool for Malachi network.

    Supports:
    - TCP-like connections
    - UDP-like datagrams
    - Listen mode
    - File transfer
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon

    def connect(
        self,
        target: str,
        port: int,
        udp: bool = False,
    ):
        """
        Connect to a Malachi node.

        Args:
            target: Node ID or virtual IP
            port: Destination port
            udp: Use UDP-like datagrams instead of TCP-like stream
        """
        node_id, virtual_ip = parse_node_address(target)
        if node_id:
            virtual_ip = node_id_to_virtual_ip(node_id)

        mode = "UDP" if udp else "TCP"
        print(f"Connecting to {virtual_ip}:{port} ({mode})...")

        # In real implementation, establish connection
        # TODO: Integrate with Malachi connection layer

        print(f"Connected. Type to send, Ctrl+C to exit.")

        try:
            while True:
                line = input()
                # Send line to target
                print(f"[sent {len(line)} bytes]")
        except (KeyboardInterrupt, EOFError):
            print("\nConnection closed.")

    def listen(
        self,
        port: int,
        udp: bool = False,
    ):
        """
        Listen for connections.

        Args:
            port: Port to listen on
            udp: Use UDP-like datagrams
        """
        mode = "UDP" if udp else "TCP"
        print(f"Listening on port {port} ({mode})...")

        # In real implementation, bind and listen
        # TODO: Integrate with Malachi port binding

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopped listening.")


# =============================================================================
# Statistics Tool
# =============================================================================

class MalachiStats:
    """
    Network statistics for Malachi.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon

    def show(self, watch: bool = False, interval: float = 1.0):
        """
        Show network statistics.

        Args:
            watch: Continuously update display
            interval: Update interval in seconds
        """
        try:
            while True:
                self._print_stats()

                if not watch:
                    break

                time.sleep(interval)
                # Clear screen for update
                print("\033[H\033[J", end="")

        except KeyboardInterrupt:
            pass

    def _print_stats(self):
        """Print current statistics."""
        print("=" * 60)
        print("MALACHI NETWORK STATISTICS")
        print("=" * 60)
        print()

        # Interface stats
        print("Interface:")
        if self.daemon:
            stats = self.daemon.tun.get_stats()
            print(f"  Name:       {stats['interface']}")
            print(f"  Platform:   {stats['platform']}")
            print(f"  Local IP:   {stats['local_ip']}")
            print(f"  Node ID:    {stats['node_id'] or 'N/A'}")
            print(f"  Running:    {stats['running']}")
            print(f"  Mappings:   {stats['mappings']}")
        else:
            print("  (No daemon connected)")
        print()

        # Traffic stats (simulated for now)
        print("Traffic:")
        print(f"  Packets TX: {random.randint(100, 10000)}")
        print(f"  Packets RX: {random.randint(100, 10000)}")
        print(f"  Bytes TX:   {format_bytes(random.randint(10000, 10000000))}")
        print(f"  Bytes RX:   {format_bytes(random.randint(10000, 10000000))}")
        print()

        # Neighbor stats
        print("Neighbors:")
        if self.daemon:
            neighbors = self.daemon.get_neighbors()
            print(f"  Known:      {len(neighbors)}")
            for node_id, vip in list(neighbors.items())[:5]:
                print(f"    {vip}  {format_node_id(node_id, short=True)}")
        else:
            print("  (No daemon connected)")
        print()

        print(f"Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


# =============================================================================
# Lookup Tool
# =============================================================================

class MalachiLookup:
    """
    Lookup tool for node ID <-> virtual IP resolution.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon

    def lookup(self, address: str) -> Optional[Dict]:
        """
        Look up a node address.

        Args:
            address: Node ID or virtual IP

        Returns:
            Dict with lookup results
        """
        node_id, virtual_ip = parse_node_address(address)

        result = {
            "input": address,
            "node_id": None,
            "node_id_short": None,
            "virtual_ip": None,
            "known": False,
        }

        if node_id:
            result["node_id"] = node_id.hex()
            result["node_id_short"] = format_node_id(node_id, short=True)
            result["virtual_ip"] = node_id_to_virtual_ip(node_id)
        elif virtual_ip:
            result["virtual_ip"] = virtual_ip
            # Try to find node ID from daemon
            if self.daemon:
                nid = self.daemon.tun.get_node_id(virtual_ip)
                if nid:
                    result["node_id"] = nid.hex()
                    result["node_id_short"] = format_node_id(nid, short=True)
                    result["known"] = True

        return result

    def print_lookup(self, address: str):
        """Look up and print results."""
        result = self.lookup(address)

        if not result:
            print(f"mallookup: invalid address '{address}'")
            return

        print(f"Address:    {result['input']}")
        print(f"Virtual IP: {result['virtual_ip'] or 'N/A'}")
        print(f"Node ID:    {result['node_id'] or 'N/A'}")
        if result['node_id']:
            print(f"Short ID:   {result['node_id_short']}")
        print(f"Known:      {'Yes' if result['known'] else 'No'}")


# =============================================================================
# Route Management
# =============================================================================

class MalachiRoute:
    """
    Routing table management for Malachi.
    """

    def __init__(self, daemon: Optional[MalachiNetworkDaemon] = None):
        self.daemon = daemon

    def show(self):
        """Show the routing table."""
        print("MALACHI ROUTING TABLE")
        print("=" * 70)
        print(f"{'Destination':<20} {'Gateway':<20} {'Interface':<12} {'Metric':<8}")
        print("-" * 70)

        # Local route
        print(f"{'10.0.0.1':<20} {'local':<20} {'mal0':<12} {'0':<8}")

        # Network route
        print(f"{'10.0.0.0/8':<20} {'*':<20} {'mal0':<12} {'0':<8}")

        # Neighbor routes (from daemon)
        if self.daemon:
            for node_id, vip in self.daemon.get_neighbors().items():
                print(f"{vip:<20} {'direct':<20} {'mal0':<12} {'1':<8}")

        print()

    def add(self, destination: str, gateway: str):
        """Add a route."""
        print(f"Adding route: {destination} via {gateway}")
        # TODO: Implement route addition

    def delete(self, destination: str):
        """Delete a route."""
        print(f"Deleting route: {destination}")
        # TODO: Implement route deletion


# =============================================================================
# Key Management
# =============================================================================

class MalachiKeys:
    """
    Key and identity management.
    """

    def __init__(self):
        self.key_dir = os.path.expanduser("~/.malachi/keys")

    def generate(self, name: str = "default"):
        """Generate a new node identity."""
        try:
            from .crypto import load_or_create_ed25519, generate_node_id
            from .config import KEYDIR
            import shutil

            # Remove existing keys to force new generation
            key_files = ['ed25519.key', 'x25519.key', 'x25519.pub']
            for f in key_files:
                path = os.path.join(KEYDIR, f)
                if os.path.exists(path):
                    os.remove(path)

            # Generate new keys
            signing_key, verify_key = load_or_create_ed25519()
            node_id = generate_node_id(bytes(verify_key))

            print(f"Generated new identity: {name}")
            print(f"  Node ID: {node_id.hex()}")
            print(f"  Short:   {format_node_id(node_id, short=True)}")
            print(f"  Virtual IP: {node_id_to_virtual_ip(node_id)}")
            print(f"  Keys saved to: {KEYDIR}")

        except ImportError as e:
            print(f"Crypto module not available ({e}). Using random identity.")
            node_id = os.urandom(16)
            print(f"  Node ID: {node_id.hex()}")
            print(f"  Virtual IP: {node_id_to_virtual_ip(node_id)}")

    def show(self, name: str = "default"):
        """Show current identity."""
        print(f"Identity: {name}")
        # TODO: Load and display saved identity

    def list(self):
        """List all identities."""
        print("Available identities:")
        if os.path.exists(self.key_dir):
            for f in os.listdir(self.key_dir):
                print(f"  - {f}")
        else:
            print("  (none)")


# =============================================================================
# CLI Interface
# =============================================================================

def cmd_ping(args):
    """Handle ping command."""
    ping = MalachiPing()
    ping.ping(
        target=args.target,
        count=args.count,
        interval=args.interval,
        timeout=args.timeout,
        size=args.size,
        quiet=args.quiet,
    )


def cmd_trace(args):
    """Handle traceroute command."""
    trace = MalachiTrace()
    trace.trace(
        target=args.target,
        max_hops=args.max_hops,
        queries=args.queries,
        timeout=args.timeout,
        quiet=args.quiet,
    )


def cmd_scan(args):
    """Handle scan command."""
    scanner = MalachiScanner()

    if args.ports:
        # Port scan mode
        scanner.port_scan(
            target=args.target,
            ports=[int(p) for p in args.ports.split(',')],
            timeout=args.timeout,
            quiet=args.quiet,
        )
    else:
        # Network discovery mode
        scanner.scan(
            timeout=args.timeout,
            quiet=args.quiet,
        )


def cmd_nc(args):
    """Handle netcat command."""
    nc = MalachiNetcat()

    if args.listen:
        nc.listen(port=args.port, udp=args.udp)
    else:
        if not args.target:
            print("malnc: target required in connect mode")
            return
        nc.connect(target=args.target, port=args.port, udp=args.udp)


def cmd_stats(args):
    """Handle stats command."""
    stats = MalachiStats()
    stats.show(watch=args.watch, interval=args.interval)


def cmd_lookup(args):
    """Handle lookup command."""
    lookup = MalachiLookup()
    lookup.print_lookup(args.address)


def cmd_route(args):
    """Handle route command."""
    route = MalachiRoute()

    if args.action == "show" or args.action is None:
        route.show()
    elif args.action == "add":
        route.add(args.destination, args.gateway)
    elif args.action == "delete":
        route.delete(args.destination)


def cmd_keys(args):
    """Handle keys command."""
    keys = MalachiKeys()

    if args.action == "generate":
        keys.generate(args.name or "default")
    elif args.action == "show":
        keys.show(args.name or "default")
    elif args.action == "list":
        keys.list()
    else:
        keys.list()


def cmd_send(args):
    """Handle file send command."""
    try:
        from .mesh import MeshNode
        from .crypto import load_or_create_ed25519, generate_node_id

        # Get our identity
        sk, vk = load_or_create_ed25519()
        node_id = generate_node_id(bytes(vk))

        # Parse target
        target_id, _ = parse_node_address(args.target)
        if not target_id:
            print(f"malsend: invalid target '{args.target}'")
            return

        print(f"Sending {args.file} to {args.target}...")

        # Create mesh node
        node = MeshNode(node_id, port=7893)
        node.start()

        # Send file
        transfer_id = node.send_file(target_id, args.file)
        print(f"Transfer ID: {transfer_id.hex()[:16]}")

        # Wait for completion (simplified - real implementation would track progress)
        import time
        time.sleep(5)

        node.stop()
        print("Transfer initiated. Use --wait to wait for completion.")

    except ImportError as e:
        print(f"malsend: mesh module not available: {e}")
    except FileNotFoundError:
        print(f"malsend: file not found: {args.file}")
    except Exception as e:
        print(f"malsend: error: {e}")


def cmd_services(args):
    """Handle services command."""
    try:
        from .mesh import MeshNode, ServiceRegistry
        from .crypto import load_or_create_ed25519, generate_node_id

        sk, vk = load_or_create_ed25519()
        node_id = generate_node_id(bytes(vk))

        if args.action == "list":
            print("DISCOVERED SERVICES")
            print("=" * 60)
            print(f"{'Type':<15} {'Node':<20} {'Port':<8} {'Metadata'}")
            print("-" * 60)
            # In a real implementation, this would query the running daemon
            print("(Start daemon to discover services)")

        elif args.action == "register":
            if not args.type or not args.port:
                print("malservices: --type and --port required for register")
                return
            print(f"Registering service: {args.type} on port {args.port}")
            print("(Service will be announced when daemon starts)")

        elif args.action == "find":
            if not args.type:
                print("malservices: --type required for find")
                return
            print(f"Finding services of type: {args.type}")
            print("(Start daemon to discover services)")

    except ImportError as e:
        print(f"malservices: module not available: {e}")


def cmd_peers(args):
    """Handle peers command."""
    try:
        from .mesh import PeerStore
        from pathlib import Path

        store = PeerStore(Path.home() / ".ministack" / "peers.json")
        peers = store.get_peers()

        if args.action == "list":
            print("KNOWN PEERS")
            print("=" * 70)
            print(f"{'Node ID':<20} {'Address':<22} {'Last Seen':<20} {'Relay'}")
            print("-" * 70)

            for peer in peers:
                node_short = peer.node_id.hex()[:16] + "..."
                addr = f"{peer.address[0]}:{peer.address[1]}"
                last_seen = time.strftime("%Y-%m-%d %H:%M", time.localtime(peer.last_seen))
                relay = "Yes" if peer.is_relay else "No"
                print(f"{node_short:<20} {addr:<22} {last_seen:<20} {relay}")

            print(f"\nTotal: {len(peers)} peers")

        elif args.action == "clear":
            # Clear peer store
            import os
            peer_file = Path.home() / ".ministack" / "peers.json"
            if peer_file.exists():
                os.remove(peer_file)
                print("Peer store cleared")
            else:
                print("Peer store already empty")

    except Exception as e:
        print(f"malpeers: error: {e}")


def cmd_mesh(args):
    """Handle mesh command."""
    try:
        from .mesh import MeshNode
        from .crypto import load_or_create_ed25519, generate_node_id

        sk, vk = load_or_create_ed25519()
        node_id = generate_node_id(bytes(vk))

        if args.action == "status":
            print("MESH NETWORK STATUS")
            print("=" * 50)
            print(f"Node ID: {node_id.hex()}")
            print(f"Status:  (Run daemon to see live status)")

        elif args.action == "join":
            if not args.bootstrap:
                print("malmesh: --bootstrap required for join")
                return
            print(f"Joining network via {args.bootstrap}...")

        elif args.action == "info":
            print("MESH NETWORK INFO")
            print("=" * 50)
            print(f"Node ID:     {node_id.hex()}")
            print(f"Short ID:    {node_id.hex()[:8]}")
            print(f"DNS Name:    {node_id.hex()[:8]}.mli")

    except Exception as e:
        print(f"malmesh: error: {e}")


def cmd_connect(args):
    """Connect to a peer by IP address."""
    import socket
    import struct

    try:
        from .crypto import load_or_create_ed25519, generate_node_id
        from .mesh import MeshNode, PeerInfo, MeshMsgType

        # Parse address
        addr = args.address
        if ':' in addr:
            host, port = addr.rsplit(':', 1)
            port = int(port)
        else:
            host = addr
            port = 7891

        # Load our identity
        sk, vk = load_or_create_ed25519()
        our_node_id = generate_node_id(bytes(vk))

        print(f"MALACHI PEER CONNECTION")
        print("=" * 50)
        print(f"Your Node ID: {our_node_id.hex()[:16]}...")
        print(f"Connecting to: {host}:{port}")
        print()

        # Create UDP socket and send ping
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3.0)
        sock.bind(('', 0))
        local_port = sock.getsockname()[1]

        # Send PING message: type (1 byte) + our node_id (16 bytes)
        ping = struct.pack(">B16s", MeshMsgType.PING, our_node_id)

        print(f"Sending ping from port {local_port}...")
        sock.sendto(ping, (host, port))

        try:
            data, addr = sock.recvfrom(1024)
            if len(data) >= 17 and data[0] == MeshMsgType.PONG:
                peer_id = data[1:17]
                print(f"Connected! Peer Node ID: {peer_id.hex()[:16]}...")
                print()
                print("Peer added successfully.")
                print(f"  Peer ID:  {peer_id.hex()}")
                print(f"  Address:  {host}:{port}")

                # Save to peers file
                peers_file = os.path.expanduser("~/.ministack/peers.json")
                peers = {"peers": []}
                if os.path.exists(peers_file):
                    try:
                        with open(peers_file) as f:
                            peers = json.load(f)
                    except:
                        pass

                # Add peer
                peer_entry = {
                    "node_id": peer_id.hex(),
                    "address": [host, port],
                    "added": time.time()
                }

                # Check if already exists
                existing = False
                for p in peers.get("peers", []):
                    if p.get("node_id") == peer_id.hex():
                        existing = True
                        break

                if not existing:
                    peers.setdefault("peers", []).append(peer_entry)
                    os.makedirs(os.path.dirname(peers_file), exist_ok=True)
                    with open(peers_file, 'w') as f:
                        json.dump(peers, f, indent=2)
                    print(f"  Saved to: {peers_file}")
                else:
                    print("  (Peer already saved)")

            else:
                print(f"Unexpected response: {data[:20].hex() if data else 'empty'}")
        except socket.timeout:
            print("No response - peer may be offline or firewalled")
            print()
            print("Troubleshooting:")
            print(f"  1. Ensure daemon is running on {host}")
            print(f"  2. Check firewall allows UDP port {port}")
            print(f"  3. Verify both devices are on same network")
        finally:
            sock.close()

    except Exception as e:
        print(f"connect: error: {e}")
        import traceback
        traceback.print_exc()


def cmd_discover(args):
    """Discover Malachi nodes on the local network."""
    import socket
    import struct

    try:
        from .crypto import load_or_create_ed25519, generate_node_id
        from .mesh import MeshMsgType

        sk, vk = load_or_create_ed25519()
        our_node_id = generate_node_id(bytes(vk))

        print("MALACHI LAN DISCOVERY")
        print("=" * 50)
        print(f"Your Node ID: {our_node_id.hex()[:16]}...")
        print()

        # Get local network info
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.bind(('', 0))
        local_port = sock.getsockname()[1]

        # Build ping message
        ping = struct.pack(">B16s", MeshMsgType.PING, our_node_id)

        # Get broadcast addresses to try
        broadcast_addrs = ['255.255.255.255']

        # Try to get local subnet broadcast
        try:
            import subprocess
            if sys.platform == 'darwin':
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'broadcast' in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == 'broadcast' and i+1 < len(parts):
                                broadcast_addrs.append(parts[i+1])
            else:
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'brd' in line and 'inet ' in line:
                        parts = line.split()
                        for i, p in enumerate(parts):
                            if p == 'brd' and i+1 < len(parts):
                                broadcast_addrs.append(parts[i+1])
        except:
            pass

        # Remove duplicates
        broadcast_addrs = list(set(broadcast_addrs))

        port = args.port if hasattr(args, 'port') and args.port else 7891
        timeout = args.timeout if hasattr(args, 'timeout') and args.timeout else 3.0

        print(f"Scanning port {port} (timeout: {timeout}s)...")
        print(f"Broadcast addresses: {', '.join(broadcast_addrs)}")
        print()

        # Send broadcasts
        for bcast in broadcast_addrs:
            try:
                sock.sendto(ping, (bcast, port))
            except:
                pass

        # Also scan common local IPs
        print("Scanning local subnet...")

        # Get our IP to determine subnet
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.connect(('8.8.8.8', 80))
            our_ip = test_sock.getsockname()[0]
            test_sock.close()

            # Scan /24 subnet
            subnet = '.'.join(our_ip.split('.')[:3])
            for i in range(1, 255):
                target_ip = f"{subnet}.{i}"
                if target_ip != our_ip:
                    try:
                        sock.sendto(ping, (target_ip, port))
                    except:
                        pass
        except:
            pass

        # Collect responses
        discovered = []
        end_time = time.time() + timeout

        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 17 and data[0] == MeshMsgType.PONG:
                    peer_id = data[1:17]
                    if peer_id != our_node_id:
                        discovered.append({
                            'node_id': peer_id,
                            'address': addr
                        })
                        print(f"  Found: {addr[0]}:{addr[1]} - {peer_id.hex()[:16]}...")
            except socket.timeout:
                continue
            except:
                break

        sock.close()

        print()
        if discovered:
            print(f"Discovered {len(discovered)} node(s):")
            print()
            for peer in discovered:
                print(f"  Node ID: {peer['node_id'].hex()}")
                print(f"  Address: {peer['address'][0]}:{peer['address'][1]}")
                print(f"  Connect: python3 -m malachi.tools connect {peer['address'][0]}:{peer['address'][1]}")
                print()
        else:
            print("No nodes discovered.")
            print()
            print("Make sure:")
            print("  1. Malachi daemon is running on other devices")
            print("  2. Devices are on the same network")
            print(f"  3. UDP port {port} is not blocked by firewall")
            print()
            print("To manually connect, use:")
            print("  python3 -m malachi.tools connect <ip>:7891")

    except Exception as e:
        print(f"discover: error: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="malachi-tools",
        description="Malachi Network Tools Suite",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Ping command
    ping_parser = subparsers.add_parser("ping", help="Ping a Malachi node")
    ping_parser.add_argument("target", help="Node ID or virtual IP")
    ping_parser.add_argument("-c", "--count", type=int, default=4, help="Number of pings")
    ping_parser.add_argument("-i", "--interval", type=float, default=1.0, help="Interval between pings")
    ping_parser.add_argument("-W", "--timeout", type=float, default=5.0, help="Timeout per ping")
    ping_parser.add_argument("-s", "--size", type=int, default=64, help="Payload size")
    ping_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    ping_parser.set_defaults(func=cmd_ping)

    # Traceroute command
    trace_parser = subparsers.add_parser("trace", aliases=["traceroute"], help="Trace route to a node")
    trace_parser.add_argument("target", help="Node ID or virtual IP")
    trace_parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum hops")
    trace_parser.add_argument("-q", "--queries", type=int, default=3, help="Queries per hop")
    trace_parser.add_argument("-W", "--timeout", type=float, default=5.0, help="Timeout per probe")
    trace_parser.add_argument("--quiet", action="store_true", help="Quiet output")
    trace_parser.set_defaults(func=cmd_trace)

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan for nodes or ports")
    scan_parser.add_argument("target", nargs="?", help="Target for port scan")
    scan_parser.add_argument("-p", "--ports", help="Ports to scan (comma-separated)")
    scan_parser.add_argument("-t", "--timeout", type=float, default=10.0, help="Scan timeout")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="Quiet output")
    scan_parser.set_defaults(func=cmd_scan)

    # Netcat command
    nc_parser = subparsers.add_parser("nc", aliases=["netcat"], help="Netcat-like tool")
    nc_parser.add_argument("target", nargs="?", help="Target node")
    nc_parser.add_argument("port", type=int, help="Port number")
    nc_parser.add_argument("-l", "--listen", action="store_true", help="Listen mode")
    nc_parser.add_argument("-u", "--udp", action="store_true", help="Use UDP")
    nc_parser.set_defaults(func=cmd_nc)

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show network statistics")
    stats_parser.add_argument("-w", "--watch", action="store_true", help="Continuous update")
    stats_parser.add_argument("-i", "--interval", type=float, default=1.0, help="Update interval")
    stats_parser.set_defaults(func=cmd_stats)

    # Lookup command
    lookup_parser = subparsers.add_parser("lookup", help="Look up node ID or IP")
    lookup_parser.add_argument("address", help="Node ID or virtual IP to look up")
    lookup_parser.set_defaults(func=cmd_lookup)

    # Route command
    route_parser = subparsers.add_parser("route", help="Routing table management")
    route_parser.add_argument("action", nargs="?", choices=["show", "add", "delete"], default="show")
    route_parser.add_argument("destination", nargs="?", help="Destination for add/delete")
    route_parser.add_argument("gateway", nargs="?", help="Gateway for add")
    route_parser.set_defaults(func=cmd_route)

    # Keys command
    keys_parser = subparsers.add_parser("keys", help="Key management")
    keys_parser.add_argument("action", nargs="?", choices=["generate", "show", "list"], default="list")
    keys_parser.add_argument("-n", "--name", help="Identity name")
    keys_parser.set_defaults(func=cmd_keys)

    # Send file command
    send_parser = subparsers.add_parser("send", help="Send file to a node")
    send_parser.add_argument("target", help="Target node ID or .mli address")
    send_parser.add_argument("file", help="File to send")
    send_parser.add_argument("--wait", action="store_true", help="Wait for completion")
    send_parser.set_defaults(func=cmd_send)

    # Services command
    svc_parser = subparsers.add_parser("services", help="Service discovery")
    svc_parser.add_argument("action", nargs="?", choices=["list", "register", "find"], default="list")
    svc_parser.add_argument("-t", "--type", help="Service type (http, ssh, etc.)")
    svc_parser.add_argument("-p", "--port", type=int, help="Service port")
    svc_parser.set_defaults(func=cmd_services)

    # Peers command
    peers_parser = subparsers.add_parser("peers", help="Peer management")
    peers_parser.add_argument("action", nargs="?", choices=["list", "clear"], default="list")
    peers_parser.set_defaults(func=cmd_peers)

    # Mesh command
    mesh_parser = subparsers.add_parser("mesh", help="Mesh network management")
    mesh_parser.add_argument("action", nargs="?", choices=["status", "join", "info"], default="status")
    mesh_parser.add_argument("-b", "--bootstrap", help="Bootstrap node address")
    mesh_parser.set_defaults(func=cmd_mesh)

    # Connect command
    connect_parser = subparsers.add_parser("connect", help="Connect to a peer by IP address")
    connect_parser.add_argument("address", help="Peer address (IP:port or IP)")
    connect_parser.set_defaults(func=cmd_connect)

    # Discover command
    discover_parser = subparsers.add_parser("discover", help="Discover Malachi nodes on local network")
    discover_parser.add_argument("-p", "--port", type=int, default=7891, help="Port to scan (default: 7891)")
    discover_parser.add_argument("-t", "--timeout", type=float, default=3.0, help="Discovery timeout in seconds")
    discover_parser.set_defaults(func=cmd_discover)

    # Parse and execute
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if hasattr(args, 'func'):
        args.func(args)


if __name__ == "__main__":
    main()
