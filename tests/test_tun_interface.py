#!/usr/bin/env python3
"""
Comprehensive tests for Malachi TUN interface and tools.
"""

import os
import sys
import unittest
import struct
import threading
import time

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from malachi.tun_interface import (
    # Platform detection
    PLATFORM, IS_LINUX, IS_MACOS, IS_BSD,
    # Classes
    TunInterfaceBase, LinuxTunInterface, MacOSTunInterface, BSDTunInterface,
    create_tun_interface, MalachiNetworkDaemon, MalachiSocket,
    NodeMapping,
    # Constants
    MALACHI_NETWORK, MALACHI_PREFIX,
)

from malachi.tools import (
    parse_node_address, node_id_to_virtual_ip, format_node_id,
    format_duration, format_bytes,
    MalachiPing, MalachiTrace, MalachiScanner, MalachiLookup,
    MalachiStats, MalachiRoute, MalachiKeys,
    PingResult, PingStats, TraceHop, DiscoveredNode,
)


class TestPlatformDetection(unittest.TestCase):
    """Test platform detection."""

    def test_platform_is_string(self):
        """Platform should be a lowercase string."""
        self.assertIsInstance(PLATFORM, str)
        self.assertEqual(PLATFORM, PLATFORM.lower())

    def test_exactly_one_platform_true(self):
        """Exactly one platform flag should be True (or none for unsupported)."""
        flags = [IS_LINUX, IS_MACOS, IS_BSD]
        true_count = sum(1 for f in flags if f)
        self.assertLessEqual(true_count, 1, "Multiple platform flags are True")

    def test_platform_matches_flags(self):
        """Platform string should match the True flag."""
        if IS_LINUX:
            self.assertEqual(PLATFORM, 'linux')
        elif IS_MACOS:
            self.assertEqual(PLATFORM, 'darwin')
        elif IS_BSD:
            self.assertIn(PLATFORM, ('freebsd', 'openbsd', 'netbsd', 'dragonfly'))


class TestNodeMapping(unittest.TestCase):
    """Test NodeMapping dataclass."""

    def test_create_mapping(self):
        """Create a node mapping."""
        node_id = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        mapping = NodeMapping(node_id=node_id, virtual_ip="10.144.1.2")

        self.assertEqual(mapping.node_id, node_id)
        self.assertEqual(mapping.virtual_ip, "10.144.1.2")
        self.assertFalse(mapping.is_local)
        self.assertIsInstance(mapping.last_seen, float)

    def test_local_mapping(self):
        """Create a local node mapping."""
        node_id = b'\x01' * 16
        mapping = NodeMapping(node_id=node_id, virtual_ip="10.144.0.1", is_local=True)

        self.assertTrue(mapping.is_local)


class TestNodeIdToVirtualIp(unittest.TestCase):
    """Test node ID to virtual IP conversion."""

    def test_conversion_deterministic(self):
        """Same node ID should always produce same IP."""
        node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")

        ip1 = node_id_to_virtual_ip(node_id)
        ip2 = node_id_to_virtual_ip(node_id)

        self.assertEqual(ip1, ip2)

    def test_conversion_format(self):
        """Virtual IP should be in correct format."""
        node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        ip = node_id_to_virtual_ip(node_id)

        self.assertTrue(ip.startswith("10.144."))
        parts = ip.split('.')
        self.assertEqual(len(parts), 4)
        for part in parts:
            self.assertTrue(0 <= int(part) <= 255)

    def test_conversion_known_value(self):
        """Test a known conversion."""
        # a1b2c3d4 -> third_octet = 0xc3 = 195, fourth_octet = 0xd4 = 212
        node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        ip = node_id_to_virtual_ip(node_id)

        self.assertEqual(ip, "10.144.195.212")

    def test_conversion_avoids_reserved(self):
        """Fourth octet should be >= 2 (avoiding .0 and .1)."""
        # Node ID with last byte = 0x00
        node_id = bytes.fromhex("00000000e5f67890abcdef1234567890")
        ip = node_id_to_virtual_ip(node_id)

        fourth_octet = int(ip.split('.')[-1])
        self.assertGreaterEqual(fourth_octet, 2)

    def test_different_nodes_different_ips(self):
        """Different node IDs should (usually) produce different IPs."""
        node1 = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        node2 = bytes.fromhex("11223344e5f67890abcdef1234567890")

        ip1 = node_id_to_virtual_ip(node1)
        ip2 = node_id_to_virtual_ip(node2)

        self.assertNotEqual(ip1, ip2)


class TestParseNodeAddress(unittest.TestCase):
    """Test address parsing."""

    def test_parse_virtual_ip(self):
        """Parse a virtual IP address."""
        node_id, vip = parse_node_address("10.144.45.23")

        self.assertIsNone(node_id)
        self.assertEqual(vip, "10.144.45.23")

    def test_parse_full_node_id(self):
        """Parse a full 32-char node ID."""
        node_id, vip = parse_node_address("a1b2c3d4e5f67890abcdef1234567890")

        self.assertEqual(node_id, bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890"))
        self.assertIsNone(vip)

    def test_parse_short_node_id(self):
        """Parse a short node ID prefix."""
        node_id, vip = parse_node_address("a1b2c3d4")

        self.assertIsNotNone(node_id)
        self.assertTrue(node_id.hex().startswith("a1b2c3d4"))
        self.assertIsNone(vip)

    def test_parse_invalid_address(self):
        """Invalid address returns (None, None)."""
        node_id, vip = parse_node_address("invalid")

        self.assertIsNone(node_id)
        self.assertIsNone(vip)

    def test_parse_non_malachi_ip(self):
        """Non-Malachi IP returns (None, None)."""
        node_id, vip = parse_node_address("192.168.1.1")

        self.assertIsNone(node_id)
        self.assertIsNone(vip)

    def test_parse_uppercase_node_id(self):
        """Uppercase hex should work."""
        node_id, vip = parse_node_address("A1B2C3D4E5F67890ABCDEF1234567890")

        self.assertIsNotNone(node_id)
        self.assertEqual(node_id.hex(), "a1b2c3d4e5f67890abcdef1234567890")


class TestFormatFunctions(unittest.TestCase):
    """Test formatting utilities."""

    def test_format_node_id_full(self):
        """Format full node ID."""
        node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        formatted = format_node_id(node_id, short=False)

        self.assertEqual(formatted, "a1b2c3d4e5f67890abcdef1234567890")

    def test_format_node_id_short(self):
        """Format short node ID."""
        node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        formatted = format_node_id(node_id, short=True)

        self.assertEqual(formatted, "a1b2c3d4...")

    def test_format_duration_microseconds(self):
        """Format sub-millisecond duration."""
        formatted = format_duration(0.0001)
        self.assertIn("us", formatted)

    def test_format_duration_milliseconds(self):
        """Format millisecond duration."""
        formatted = format_duration(0.005)
        self.assertIn("ms", formatted)

    def test_format_duration_seconds(self):
        """Format second duration."""
        formatted = format_duration(2.5)
        self.assertIn("s", formatted)
        self.assertNotIn("ms", formatted)

    def test_format_bytes_bytes(self):
        """Format byte count."""
        self.assertEqual(format_bytes(500), "500B")

    def test_format_bytes_kilobytes(self):
        """Format kilobyte count."""
        formatted = format_bytes(2048)
        self.assertIn("KB", formatted)

    def test_format_bytes_megabytes(self):
        """Format megabyte count."""
        formatted = format_bytes(2 * 1024 * 1024)
        self.assertIn("MB", formatted)

    def test_format_bytes_gigabytes(self):
        """Format gigabyte count."""
        formatted = format_bytes(2 * 1024 * 1024 * 1024)
        self.assertIn("GB", formatted)


class TestFactoryFunction(unittest.TestCase):
    """Test create_tun_interface factory."""

    def test_creates_correct_type(self):
        """Factory creates correct type for platform."""
        tun = create_tun_interface(node_id=b'\x01' * 16)

        if IS_LINUX:
            self.assertIsInstance(tun, LinuxTunInterface)
        elif IS_MACOS:
            self.assertIsInstance(tun, MacOSTunInterface)
        elif IS_BSD:
            self.assertIsInstance(tun, BSDTunInterface)

    def test_accepts_custom_name(self):
        """Factory accepts custom interface name."""
        tun = create_tun_interface(interface_name="test0", node_id=b'\x01' * 16)

        # Note: macOS may override the name
        self.assertIsNotNone(tun.interface_name)

    def test_accepts_node_id(self):
        """Factory accepts node ID."""
        node_id = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'
        tun = create_tun_interface(node_id=node_id)

        self.assertEqual(tun.node_id, node_id)


class TestTunInterfaceBase(unittest.TestCase):
    """Test TunInterfaceBase functionality."""

    def setUp(self):
        """Create a TUN interface for testing."""
        self.node_id = bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
        self.tun = create_tun_interface(node_id=self.node_id)

    def test_initial_state(self):
        """Check initial state."""
        # Local IP is derived from node ID: a1b2c3d4 -> 10.144.195.212
        self.assertEqual(self.tun.local_ip, "10.144.195.212")
        self.assertFalse(self.tun._running)
        self.assertIsNone(self.tun.tun_fd)

    def test_allocate_ip_new_node(self):
        """Allocate IP for a new node."""
        other_node = bytes.fromhex("11223344556677889900aabbccddeeff")
        ip = self.tun.allocate_ip(other_node)

        self.assertTrue(ip.startswith("10.144."))
        self.assertNotEqual(ip, self.tun.local_ip)  # Not our local IP

    def test_allocate_ip_same_node_twice(self):
        """Same node should get same IP."""
        other_node = bytes.fromhex("11223344556677889900aabbccddeeff")

        ip1 = self.tun.allocate_ip(other_node)
        ip2 = self.tun.allocate_ip(other_node)

        self.assertEqual(ip1, ip2)

    def test_get_node_id(self):
        """Get node ID from virtual IP."""
        other_node = bytes.fromhex("11223344556677889900aabbccddeeff")
        ip = self.tun.allocate_ip(other_node)

        retrieved = self.tun.get_node_id(ip)
        self.assertEqual(retrieved, other_node)

    def test_get_node_id_unknown(self):
        """Unknown IP returns None."""
        retrieved = self.tun.get_node_id("10.144.99.99")
        self.assertIsNone(retrieved)

    def test_get_virtual_ip(self):
        """Get virtual IP from node ID."""
        other_node = bytes.fromhex("11223344556677889900aabbccddeeff")
        allocated_ip = self.tun.allocate_ip(other_node)

        retrieved = self.tun.get_virtual_ip(other_node)
        self.assertEqual(retrieved, allocated_ip)

    def test_get_virtual_ip_unknown(self):
        """Unknown node ID returns None."""
        unknown_node = bytes.fromhex("ffffffffffffffffffffffffffffffff")
        retrieved = self.tun.get_virtual_ip(unknown_node)
        self.assertIsNone(retrieved)

    def test_set_send_callback(self):
        """Set send callback."""
        def my_callback(node_id, payload):
            pass

        self.tun.set_send_callback(my_callback)
        self.assertEqual(self.tun._send_callback, my_callback)

    def test_get_stats(self):
        """Get interface statistics."""
        stats = self.tun.get_stats()

        self.assertIn('interface', stats)
        self.assertIn('local_ip', stats)
        self.assertIn('node_id', stats)
        self.assertIn('mappings', stats)
        self.assertIn('running', stats)
        self.assertIn('platform', stats)

    def test_collision_handling(self):
        """IP collisions should be handled."""
        # Create many nodes to potentially cause collisions
        for i in range(100):
            node = bytes([i] * 16)
            ip = self.tun.allocate_ip(node)
            self.assertTrue(ip.startswith("10.144."))

        # All should have unique IPs
        all_ips = set(self.tun._reverse_mappings.values())
        self.assertEqual(len(all_ips), 100)


class TestPingStats(unittest.TestCase):
    """Test PingStats calculations."""

    def test_empty_stats(self):
        """Empty stats have correct defaults."""
        stats = PingStats()

        self.assertEqual(stats.transmitted, 0)
        self.assertEqual(stats.received, 0)
        self.assertEqual(stats.loss_percent, 0.0)
        self.assertEqual(stats.avg_rtt, 0.0)

    def test_loss_percent_calculation(self):
        """Loss percentage calculated correctly."""
        stats = PingStats(transmitted=10, received=7)

        self.assertEqual(stats.loss_percent, 30.0)

    def test_avg_rtt_calculation(self):
        """Average RTT calculated correctly."""
        stats = PingStats(received=4, total_rtt=100.0)

        self.assertEqual(stats.avg_rtt, 25.0)

    def test_full_stats(self):
        """Test with complete stats."""
        stats = PingStats(
            transmitted=5,
            received=4,
            errors=1,
            min_rtt=1.0,
            max_rtt=10.0,
            total_rtt=20.0
        )

        self.assertEqual(stats.loss_percent, 20.0)
        self.assertEqual(stats.avg_rtt, 5.0)


class TestMalachiPing(unittest.TestCase):
    """Test MalachiPing tool."""

    def test_ping_by_node_id(self):
        """Ping using node ID."""
        ping = MalachiPing()
        stats = ping.ping("a1b2c3d4e5f67890abcdef1234567890", count=2, quiet=True)

        self.assertEqual(stats.transmitted, 2)
        self.assertEqual(stats.received, 2)
        self.assertEqual(stats.loss_percent, 0.0)

    def test_ping_by_virtual_ip(self):
        """Ping using virtual IP."""
        ping = MalachiPing()
        stats = ping.ping("10.144.45.23", count=2, quiet=True)

        self.assertEqual(stats.transmitted, 2)
        self.assertEqual(stats.received, 2)

    def test_ping_by_short_id(self):
        """Ping using short node ID."""
        ping = MalachiPing()
        stats = ping.ping("a1b2c3d4", count=2, quiet=True)

        self.assertEqual(stats.transmitted, 2)

    def test_ping_invalid_target(self):
        """Ping with invalid target."""
        ping = MalachiPing()
        stats = ping.ping("invalid", count=1, quiet=True)

        self.assertEqual(stats.transmitted, 0)


class TestMalachiTrace(unittest.TestCase):
    """Test MalachiTrace tool."""

    def test_trace_by_virtual_ip(self):
        """Trace using virtual IP."""
        trace = MalachiTrace()
        hops = trace.trace("10.144.45.23", max_hops=3, quiet=True)

        self.assertGreater(len(hops), 0)
        self.assertLessEqual(len(hops), 3)

    def test_trace_by_node_id(self):
        """Trace using node ID."""
        trace = MalachiTrace()
        hops = trace.trace("a1b2c3d4e5f67890abcdef1234567890", max_hops=3, quiet=True)

        self.assertGreater(len(hops), 0)

    def test_trace_hop_structure(self):
        """Trace hops have correct structure."""
        trace = MalachiTrace()
        hops = trace.trace("10.144.45.23", max_hops=2, queries=2, quiet=True)

        for hop in hops:
            self.assertIsInstance(hop, TraceHop)
            self.assertIsInstance(hop.hop, int)
            self.assertIsInstance(hop.rtt_ms, list)


class TestMalachiLookup(unittest.TestCase):
    """Test MalachiLookup tool."""

    def test_lookup_node_id(self):
        """Look up node ID."""
        lookup = MalachiLookup()
        result = lookup.lookup("a1b2c3d4e5f67890abcdef1234567890")

        self.assertIsNotNone(result)
        self.assertEqual(result['node_id'], "a1b2c3d4e5f67890abcdef1234567890")
        self.assertEqual(result['virtual_ip'], "10.144.195.212")

    def test_lookup_virtual_ip(self):
        """Look up virtual IP."""
        lookup = MalachiLookup()
        result = lookup.lookup("10.144.45.23")

        self.assertIsNotNone(result)
        self.assertEqual(result['virtual_ip'], "10.144.45.23")

    def test_lookup_short_id(self):
        """Look up short node ID."""
        lookup = MalachiLookup()
        result = lookup.lookup("a1b2c3d4")

        self.assertIsNotNone(result)
        self.assertTrue(result['node_id'].startswith("a1b2c3d4"))


class TestMalachiScanner(unittest.TestCase):
    """Test MalachiScanner tool."""

    def test_scan_network(self):
        """Scan for nodes."""
        scanner = MalachiScanner()
        nodes = scanner.scan(timeout=1.0, quiet=True)

        self.assertIsInstance(nodes, list)
        for node in nodes:
            self.assertIsInstance(node, DiscoveredNode)
            self.assertIsNotNone(node.node_id)
            self.assertIsNotNone(node.virtual_ip)


class TestMalachiRoute(unittest.TestCase):
    """Test MalachiRoute tool."""

    def test_show_routes(self):
        """Show routing table without error."""
        route = MalachiRoute()
        # Should not raise
        route.show()


class TestMalachiStats(unittest.TestCase):
    """Test MalachiStats tool."""

    def test_show_stats(self):
        """Show stats without error."""
        stats = MalachiStats()
        # Should not raise
        stats.show(watch=False)


class TestMalachiKeys(unittest.TestCase):
    """Test MalachiKeys tool."""

    def test_list_keys(self):
        """List keys without error."""
        keys = MalachiKeys()
        # Should not raise
        keys.list()


class TestMalachiSocket(unittest.TestCase):
    """Test MalachiSocket wrapper."""

    def test_create_socket(self):
        """Create a socket."""
        # Create a mock daemon-like object
        class MockDaemon:
            class MockTun:
                def get_node_id(self, ip):
                    return bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
            tun = MockTun()
            def _send_malachi(self, node_id, payload):
                pass

        daemon = MockDaemon()
        sock = MalachiSocket(daemon)

        self.assertFalse(sock._connected)

    def test_connect_by_node_id(self):
        """Connect using node ID."""
        class MockDaemon:
            class MockTun:
                def get_node_id(self, ip):
                    return None
            tun = MockTun()
            def _send_malachi(self, node_id, payload):
                pass

        daemon = MockDaemon()
        sock = MalachiSocket(daemon)
        sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))

        self.assertTrue(sock._connected)
        self.assertEqual(sock._dest_port, 8080)

    def test_connect_by_virtual_ip(self):
        """Connect using virtual IP."""
        class MockDaemon:
            class MockTun:
                def get_node_id(self, ip):
                    return bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890")
            tun = MockTun()
            def _send_malachi(self, node_id, payload):
                pass

        daemon = MockDaemon()
        sock = MalachiSocket(daemon)
        sock.connect(("10.144.45.23", 8080))

        self.assertTrue(sock._connected)

    def test_send_data(self):
        """Send data through socket."""
        sent_data = []

        class MockDaemon:
            class MockTun:
                def get_node_id(self, ip):
                    return None
            tun = MockTun()
            def _send_malachi(self, node_id, payload):
                sent_data.append((node_id, payload))

        daemon = MockDaemon()
        sock = MalachiSocket(daemon)
        sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))

        bytes_sent = sock.send(b"Hello")

        self.assertEqual(bytes_sent, 5)
        self.assertEqual(len(sent_data), 1)

    def test_context_manager(self):
        """Socket works as context manager."""
        class MockDaemon:
            class MockTun:
                def get_node_id(self, ip):
                    return None
            tun = MockTun()
            def _send_malachi(self, node_id, payload):
                pass

        daemon = MockDaemon()

        with MalachiSocket(daemon) as sock:
            sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))
            self.assertTrue(sock._connected)

        self.assertFalse(sock._connected)


class TestNetworkConstants(unittest.TestCase):
    """Test network constants."""

    def test_malachi_network(self):
        """MALACHI_NETWORK is correct."""
        self.assertEqual(MALACHI_NETWORK, "10.144.0.0/16")

    def test_malachi_prefix(self):
        """MALACHI_PREFIX is valid."""
        import ipaddress
        self.assertIsInstance(MALACHI_PREFIX, ipaddress.IPv4Network)
        self.assertEqual(str(MALACHI_PREFIX), "10.144.0.0/16")


class TestThreadSafety(unittest.TestCase):
    """Test thread safety of TUN interface."""

    def test_concurrent_ip_allocation(self):
        """Concurrent IP allocation should be thread-safe."""
        tun = create_tun_interface(node_id=b'\x01' * 16)
        results = []
        errors = []

        def allocate_ips(start):
            try:
                for i in range(50):
                    node = bytes([start, i] + [0] * 14)
                    ip = tun.allocate_ip(node)
                    results.append((node, ip))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=allocate_ips, args=(i,))
            for i in range(4)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors occurred: {errors}")
        self.assertEqual(len(results), 200)

        # All IPs should be unique
        all_ips = [ip for _, ip in results]
        self.assertEqual(len(set(all_ips)), 200)


def run_tests():
    """Run all tests with verbose output."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    test_classes = [
        TestPlatformDetection,
        TestNodeMapping,
        TestNodeIdToVirtualIp,
        TestParseNodeAddress,
        TestFormatFunctions,
        TestFactoryFunction,
        TestTunInterfaceBase,
        TestPingStats,
        TestMalachiPing,
        TestMalachiTrace,
        TestMalachiLookup,
        TestMalachiScanner,
        TestMalachiRoute,
        TestMalachiStats,
        TestMalachiKeys,
        TestMalachiSocket,
        TestNetworkConstants,
        TestThreadSafety,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)
