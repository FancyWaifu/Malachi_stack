"""
Tests for malachi.routing module.
"""

import pytest
import os
import time

from malachi.routing import (
    RoutingTable,
    Router,
    VLANManager,
    RouteEntry,
    MAX_HOPS,
    DEFAULT_VLAN,
)


class TestRoutingTable:
    """Tests for RoutingTable."""

    def test_add_neighbor(self):
        """Test adding a direct neighbor."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor = os.urandom(16)

        table.add_neighbor(neighbor)

        route = table.get_route(neighbor)
        assert route is not None
        assert route.metric == 1
        assert route.is_direct

    def test_remove_neighbor(self):
        """Test removing a neighbor invalidates routes."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor = os.urandom(16)
        dest = os.urandom(16)

        table.add_neighbor(neighbor)
        table.update_route(dest, neighbor, 2, neighbor)

        table.remove_neighbor(neighbor)

        route = table.get_route(dest)
        assert route.metric == MAX_HOPS  # Unreachable

    def test_update_route_better(self):
        """Test updating with better route."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor1 = os.urandom(16)
        neighbor2 = os.urandom(16)
        dest = os.urandom(16)

        table.add_neighbor(neighbor1)
        table.add_neighbor(neighbor2)

        # Learn route via neighbor1 with metric 5
        table.update_route(dest, neighbor1, 5, neighbor1)
        assert table.get_route(dest).metric == 5

        # Better route via neighbor2 with metric 2
        table.update_route(dest, neighbor2, 2, neighbor2)
        assert table.get_route(dest).metric == 2
        assert table.get_next_hop(dest) == neighbor2

    def test_get_next_hop(self):
        """Test getting next hop."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor = os.urandom(16)
        dest = os.urandom(16)

        table.add_neighbor(neighbor)
        table.update_route(dest, neighbor, 3, neighbor)

        assert table.get_next_hop(dest) == neighbor
        assert table.get_next_hop(os.urandom(16)) is None  # Unknown dest

    def test_split_horizon(self):
        """Test split horizon with poison reverse."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor1 = os.urandom(16)
        neighbor2 = os.urandom(16)
        dest = os.urandom(16)

        table.add_neighbor(neighbor1)
        table.add_neighbor(neighbor2)
        table.update_route(dest, neighbor1, 3, neighbor1)

        # Routes for neighbor1 should poison the route learned from them
        routes1 = table.get_routes_for_neighbor(neighbor1)
        assert routes1[dest] == MAX_HOPS  # Poisoned

        # Routes for neighbor2 should include the normal metric
        routes2 = table.get_routes_for_neighbor(neighbor2)
        assert routes2[dest] == 3

    def test_stats(self):
        """Test statistics."""
        my_id = os.urandom(16)
        table = RoutingTable(my_id)
        neighbor = os.urandom(16)

        table.add_neighbor(neighbor)

        stats = table.stats()
        assert stats["total_routes"] == 1
        assert stats["reachable_destinations"] == 1
        assert stats["direct_neighbors"] == 1


class TestRouter:
    """Tests for Router."""

    def test_forward(self):
        """Test packet forwarding."""
        my_id = os.urandom(16)
        forwarded = []

        def send_cb(next_hop, data):
            forwarded.append((next_hop, data))

        router = Router(my_id, send_callback=send_cb)
        neighbor = os.urandom(16)
        dest = os.urandom(16)

        router.table.add_neighbor(neighbor)
        router.table.update_route(dest, neighbor, 2, neighbor)

        assert router.forward(my_id, dest, b"hello", ttl=5)
        assert len(forwarded) == 1
        assert forwarded[0][0] == neighbor

    def test_forward_no_route(self):
        """Test forward with no route fails."""
        my_id = os.urandom(16)
        router = Router(my_id)
        dest = os.urandom(16)

        assert not router.forward(my_id, dest, b"hello")

    def test_forward_ttl_expired(self):
        """Test forward with expired TTL fails."""
        my_id = os.urandom(16)
        router = Router(my_id)
        neighbor = os.urandom(16)
        dest = os.urandom(16)

        router.table.add_neighbor(neighbor)
        router.table.update_route(dest, neighbor, 2, neighbor)

        assert not router.forward(my_id, dest, b"hello", ttl=0)

    def test_encode_decode_forward(self):
        """Test forward packet encoding/decoding."""
        my_id = os.urandom(16)
        router = Router(my_id)
        src = os.urandom(16)
        dst = os.urandom(16)

        encoded = router.encode_forward(src, dst, 10, b"payload")
        pkt = router.decode_forward(encoded)

        assert pkt.original_src == src
        assert pkt.final_dst == dst
        assert pkt.ttl == 10
        assert pkt.payload == b"payload"

    def test_encode_decode_route_update(self):
        """Test route update encoding/decoding."""
        my_id = os.urandom(16)
        router = Router(my_id)

        routes = {
            os.urandom(16): 3,
            os.urandom(16): 5,
        }

        encoded = router.encode_route_update(routes)
        decoded = router.decode_route_update(encoded)

        assert len(decoded) == 2
        for dest, metric in routes.items():
            assert decoded[dest] == metric

    def test_process_route_update(self):
        """Test processing route update."""
        my_id = os.urandom(16)
        router = Router(my_id)
        neighbor = os.urandom(16)
        dest = os.urandom(16)

        router.table.add_neighbor(neighbor)
        router.process_route_update(neighbor, {dest: 2})

        route = router.table.get_route(dest)
        assert route is not None
        assert route.metric == 3  # 2 + 1 hop to neighbor


class TestVLANManager:
    """Tests for VLANManager."""

    def test_create_vlan(self):
        """Test creating a VLAN."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        assert mgr.create_vlan(100, "test-vlan")
        assert 100 in mgr._vlans

    def test_create_vlan_invalid_id(self):
        """Test creating VLAN with invalid ID fails."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        assert not mgr.create_vlan(0, "invalid")
        assert not mgr.create_vlan(5000, "invalid")

    def test_join_leave_vlan(self):
        """Test joining and leaving VLAN."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        mgr.create_vlan(100, "test")
        assert mgr.join_vlan(100)
        assert 100 in mgr._my_vlans

        assert mgr.leave_vlan(100)
        assert 100 not in mgr._my_vlans

    def test_cannot_leave_default_vlan(self):
        """Test cannot leave default VLAN."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        assert not mgr.leave_vlan(DEFAULT_VLAN)
        assert DEFAULT_VLAN in mgr._my_vlans

    def test_assign_port(self):
        """Test assigning peer to VLAN."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)
        peer = os.urandom(16)

        mgr.create_vlan(100, "test")
        assert mgr.assign_port(peer, 100)
        assert mgr.get_peer_vlan(peer) == 100

    def test_can_communicate_same_vlan(self):
        """Test communication allowed in same VLAN."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)
        peer1 = os.urandom(16)
        peer2 = os.urandom(16)

        mgr.create_vlan(100, "test")
        mgr.assign_port(peer1, 100)
        mgr.assign_port(peer2, 100)

        assert mgr.can_communicate(peer1, peer2)

    def test_cannot_communicate_different_vlan(self):
        """Test communication blocked between VLANs."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)
        peer1 = os.urandom(16)
        peer2 = os.urandom(16)

        mgr.create_vlan(100, "vlan1")
        mgr.create_vlan(200, "vlan2")
        mgr.assign_port(peer1, 100)
        mgr.assign_port(peer2, 200)

        assert not mgr.can_communicate(peer1, peer2)

    def test_private_vlan_isolation(self):
        """Test private VLAN isolates members."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)
        peer1 = os.urandom(16)
        peer2 = os.urandom(16)

        mgr.create_vlan(100, "private", is_private=True)
        mgr.assign_port(peer1, 100)
        mgr.assign_port(peer2, 100)

        assert not mgr.can_communicate(peer1, peer2)

    def test_encode_decode_vlan_tag(self):
        """Test VLAN tag encoding/decoding."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        tag = mgr.encode_vlan_tag(100, priority=5)
        vlan_id, priority = mgr.decode_vlan_tag(tag)

        assert vlan_id == 100
        assert priority == 5

    def test_stats(self):
        """Test statistics."""
        my_id = os.urandom(16)
        mgr = VLANManager(my_id)

        mgr.create_vlan(100, "test")
        mgr.join_vlan(100)

        stats = mgr.stats()
        assert stats["total_vlans"] == 2  # default + test
        assert 100 in stats["my_vlans"]
