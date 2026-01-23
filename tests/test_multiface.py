"""
Tests for malachi.multiface module.
"""

import pytest
import os
import time

from malachi.multiface import (
    InterfaceManager,
    InterfaceInfo,
    InterfaceType,
    InterfaceState,
    MultiInterfaceBridge,
    MultiInterfaceNeighbor,
    MultiInterfaceRoute,
    NeighborState,
    IFACE_COST_ETHERNET,
    IFACE_COST_WIFI_ADHOC,
)


class TestInterfaceInfo:
    """Tests for InterfaceInfo."""

    def test_is_up(self):
        """Test is_up method."""
        info = InterfaceInfo(
            name="eth0",
            mac=b"\x00" * 6,
            state=InterfaceState.UP,
        )
        assert info.is_up()

        info.state = InterfaceState.DOWN
        assert not info.is_up()

        info.state = InterfaceState.DEGRADED
        assert info.is_up()  # Degraded is still considered up


class TestMultiInterfaceNeighbor:
    """Tests for MultiInterfaceNeighbor."""

    def test_get_best_interface_single(self):
        """Test getting best interface with single interface."""
        neighbor = MultiInterfaceNeighbor(node_id=os.urandom(16))
        neighbor.interfaces["eth0"] = (
            b"\x00" * 6,
            time.time(),
            NeighborState.REACHABLE,
            5.0,
        )

        costs = {"eth0": IFACE_COST_ETHERNET}
        assert neighbor.get_best_interface(costs) == "eth0"

    def test_get_best_interface_prefer_lower_cost(self):
        """Test that lower cost interface is preferred."""
        neighbor = MultiInterfaceNeighbor(node_id=os.urandom(16))

        neighbor.interfaces["eth0"] = (
            b"\x00" * 6,
            time.time(),
            NeighborState.REACHABLE,
            5.0,
        )
        neighbor.interfaces["wlan0"] = (
            b"\x01" * 6,
            time.time(),
            NeighborState.REACHABLE,
            5.0,
        )

        costs = {
            "eth0": IFACE_COST_ETHERNET,  # 10
            "wlan0": IFACE_COST_WIFI_ADHOC,  # 100
        }

        assert neighbor.get_best_interface(costs) == "eth0"

    def test_get_best_interface_fallback_to_stale(self):
        """Test fallback to stale interface when no reachable."""
        neighbor = MultiInterfaceNeighbor(node_id=os.urandom(16))

        neighbor.interfaces["eth0"] = (
            b"\x00" * 6,
            time.time(),
            NeighborState.UNREACHABLE,
            5.0,
        )
        neighbor.interfaces["wlan0"] = (
            b"\x01" * 6,
            time.time(),
            NeighborState.STALE,
            5.0,
        )

        costs = {"eth0": 10, "wlan0": 100}
        assert neighbor.get_best_interface(costs) == "wlan0"

    def test_is_reachable(self):
        """Test is_reachable method."""
        neighbor = MultiInterfaceNeighbor(node_id=os.urandom(16))
        assert not neighbor.is_reachable()

        neighbor.interfaces["eth0"] = (
            b"\x00" * 6,
            time.time(),
            NeighborState.REACHABLE,
            5.0,
        )
        assert neighbor.is_reachable()

        neighbor.interfaces["eth0"] = (
            b"\x00" * 6,
            time.time(),
            NeighborState.UNREACHABLE,
            5.0,
        )
        assert not neighbor.is_reachable()


class TestMultiInterfaceRoute:
    """Tests for MultiInterfaceRoute."""

    def test_get_best_path_single(self):
        """Test getting best path with single path."""
        route = MultiInterfaceRoute(destination=os.urandom(16))
        next_hop = os.urandom(16)

        route.paths["eth0"] = (next_hop, 2, time.time())

        costs = {"eth0": 10}
        result = route.get_best_path(costs)

        assert result is not None
        assert result[0] == "eth0"
        assert result[1] == next_hop
        assert result[2] == 12  # cost + metric

    def test_get_best_path_multiple(self):
        """Test getting best path with multiple paths."""
        route = MultiInterfaceRoute(destination=os.urandom(16))
        next_hop1 = os.urandom(16)
        next_hop2 = os.urandom(16)

        route.paths["eth0"] = (next_hop1, 3, time.time())
        route.paths["wlan0"] = (next_hop2, 1, time.time())

        costs = {"eth0": 10, "wlan0": 100}

        # eth0: 10 + 3 = 13
        # wlan0: 100 + 1 = 101
        result = route.get_best_path(costs)

        assert result[0] == "eth0"
        assert result[2] == 13

    def test_get_all_paths(self):
        """Test getting all paths sorted."""
        route = MultiInterfaceRoute(destination=os.urandom(16))

        route.paths["eth0"] = (os.urandom(16), 5, time.time())
        route.paths["wlan0"] = (os.urandom(16), 2, time.time())
        route.paths["eth1"] = (os.urandom(16), 8, time.time())

        paths = route.get_all_paths()

        assert len(paths) == 3
        assert paths[0][2] == 2  # Lowest metric first
        assert paths[1][2] == 5
        assert paths[2][2] == 8


class TestMultiInterfaceBridge:
    """Tests for MultiInterfaceBridge."""

    def test_create_bridge(self):
        """Test creating a bridge."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        assert bridge._node_id == node_id
        assert len(bridge._neighbors) == 0

    def test_discover_neighbor(self):
        """Test neighbor discovery."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        peer_id = os.urandom(16)
        peer_mac = os.urandom(6)

        bridge.discover_neighbor(peer_id, "eth0", peer_mac)

        neighbor = bridge.get_neighbor(peer_id)
        assert neighbor is not None
        assert "eth0" in neighbor.interfaces
        assert neighbor.interfaces["eth0"][0] == peer_mac

    def test_discover_same_neighbor_multiple_interfaces(self):
        """Test discovering same neighbor on multiple interfaces."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        peer_id = os.urandom(16)
        eth_mac = os.urandom(6)
        wlan_mac = os.urandom(6)

        bridge.discover_neighbor(peer_id, "eth0", eth_mac)
        bridge.discover_neighbor(peer_id, "wlan0", wlan_mac)

        neighbor = bridge.get_neighbor(peer_id)
        assert neighbor is not None
        assert len(neighbor.interfaces) == 2
        assert "eth0" in neighbor.interfaces
        assert "wlan0" in neighbor.interfaces

    def test_update_route(self):
        """Test updating routing table."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        dest = os.urandom(16)
        next_hop = os.urandom(16)

        bridge.update_route(dest, "eth0", next_hop, metric=3)

        route = bridge.get_route(dest)
        assert route is not None
        assert "eth0" in route.paths
        assert route.paths["eth0"][0] == next_hop
        assert route.paths["eth0"][1] == 3

    def test_get_reachable_nodes(self):
        """Test getting reachable nodes."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        peer1 = os.urandom(16)
        peer2 = os.urandom(16)

        bridge.discover_neighbor(peer1, "eth0", os.urandom(6))
        bridge.discover_neighbor(peer2, "wlan0", os.urandom(6))

        reachable = bridge.get_reachable_nodes()
        assert peer1 in reachable
        assert peer2 in reachable

    def test_deduplication(self):
        """Test packet deduplication."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        peer_id = os.urandom(16)
        payload = b"test payload"

        # First receive
        result1 = bridge.on_packet_received("eth0", os.urandom(6), peer_id, payload)
        assert result1 is True

        # Same packet on different interface (duplicate)
        result2 = bridge.on_packet_received("wlan0", os.urandom(6), peer_id, payload)
        assert result2 is False

    def test_stats(self):
        """Test statistics."""
        node_id = os.urandom(16)
        bridge = MultiInterfaceBridge(node_id)

        peer_id = os.urandom(16)
        bridge.discover_neighbor(peer_id, "eth0", os.urandom(6))

        stats = bridge.stats()
        assert stats["neighbor_discoveries"] == 1
        assert stats["neighbors"] == 1


class TestInterfaceManager:
    """Tests for InterfaceManager - basic tests that don't require actual interfaces."""

    def test_create_manager(self):
        """Test creating interface manager."""
        mgr = InterfaceManager()
        assert len(mgr.get_all_interfaces()) == 0

    def test_get_interface_costs_empty(self):
        """Test getting costs when no interfaces."""
        mgr = InterfaceManager()
        costs = mgr.get_interface_costs()
        assert costs == {}

    def test_stats_empty(self):
        """Test statistics with no interfaces."""
        mgr = InterfaceManager()
        stats = mgr.stats()
        assert stats["active_count"] == 0
        assert stats["interfaces"] == {}
