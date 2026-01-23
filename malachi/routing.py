"""
Network layer features for Malachi.

This module implements:
- Multi-Hop Routing (distance-vector with split horizon)
- Network Segmentation (VLAN-like virtual networks)
"""

import time
import threading
import struct
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple, List, Callable, Any
from enum import IntEnum
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Routing
MAX_HOPS = 16  # Maximum hop count (infinity)
ROUTE_UPDATE_INTERVAL = 30.0  # Send routing updates every 30s
ROUTE_TIMEOUT = 180.0  # Route expires after 180s without update
ROUTE_GARBAGE_COLLECT = 120.0  # Remove expired routes after 120s
SPLIT_HORIZON = True  # Enable split horizon with poison reverse

# Network Segmentation
MAX_VLANS = 4096  # Maximum VLAN ID
DEFAULT_VLAN = 1  # Default VLAN


# =============================================================================
# Message Types
# =============================================================================

class RoutingMsgType(IntEnum):
    """Routing message types."""
    ROUTE_REQUEST = 0x70
    ROUTE_REPLY = 0x71
    ROUTE_UPDATE = 0x72
    ROUTE_ERROR = 0x73
    FORWARD = 0x74

    VLAN_ANNOUNCE = 0x80
    VLAN_JOIN = 0x81
    VLAN_LEAVE = 0x82


# =============================================================================
# Multi-Hop Routing
# =============================================================================

@dataclass
class RouteEntry:
    """A routing table entry."""
    destination: bytes  # Destination node ID
    next_hop: bytes  # Next hop node ID
    metric: int  # Hop count
    learned_from: bytes  # Neighbor we learned this from
    last_update: float = field(default_factory=time.time)
    is_direct: bool = False  # Direct neighbor


@dataclass
class ForwardedPacket:
    """A packet being forwarded."""
    original_src: bytes
    final_dst: bytes
    ttl: int
    payload: bytes


class RoutingTable:
    """
    Distance-vector routing table with split horizon.

    Implements RIP-like routing with triggered updates.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize routing table.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id
        self._routes: Dict[bytes, RouteEntry] = {}
        self._neighbors: Set[bytes] = set()  # Direct neighbors

        # Callbacks
        self._on_route_change: Optional[Callable[[bytes, Optional[RouteEntry]], None]] = None

    def add_neighbor(self, neighbor_id: bytes) -> None:
        """
        Add a direct neighbor.

        Args:
            neighbor_id: Neighbor's node ID
        """
        with self._lock:
            self._neighbors.add(neighbor_id)

            # Add direct route
            self._routes[neighbor_id] = RouteEntry(
                destination=neighbor_id,
                next_hop=neighbor_id,
                metric=1,
                learned_from=self._my_id,
                is_direct=True,
            )

            if self._on_route_change:
                self._on_route_change(neighbor_id, self._routes[neighbor_id])

    def remove_neighbor(self, neighbor_id: bytes) -> None:
        """
        Remove a neighbor and invalidate routes through it.

        Args:
            neighbor_id: Neighbor to remove
        """
        with self._lock:
            self._neighbors.discard(neighbor_id)

            # Invalidate routes through this neighbor
            to_invalidate = []
            for dest, route in self._routes.items():
                if route.next_hop == neighbor_id:
                    to_invalidate.append(dest)

            for dest in to_invalidate:
                route = self._routes[dest]
                route.metric = MAX_HOPS  # Mark as unreachable

                if self._on_route_change:
                    self._on_route_change(dest, route)

    def update_route(
        self,
        destination: bytes,
        next_hop: bytes,
        metric: int,
        learned_from: bytes,
    ) -> bool:
        """
        Update routing table with new information.

        Args:
            destination: Destination node
            next_hop: Next hop to reach destination
            metric: Hop count
            learned_from: Neighbor that advertised this route

        Returns:
            True if route table changed
        """
        if destination == self._my_id:
            return False  # Don't route to ourselves

        if metric >= MAX_HOPS:
            metric = MAX_HOPS  # Infinity

        with self._lock:
            existing = self._routes.get(destination)

            # Bellman-Ford: update if better or same neighbor with different metric
            should_update = False

            if existing is None:
                should_update = metric < MAX_HOPS
            elif learned_from == existing.learned_from:
                # Same source - always update (they might be withdrawing)
                should_update = True
            elif metric < existing.metric:
                # Better route
                should_update = True
            elif metric == existing.metric and time.time() - existing.last_update > 60:
                # Same metric but fresher
                should_update = True

            if should_update:
                self._routes[destination] = RouteEntry(
                    destination=destination,
                    next_hop=next_hop,
                    metric=metric,
                    learned_from=learned_from,
                )

                if self._on_route_change:
                    self._on_route_change(destination, self._routes[destination])

                return True

            return False

    def get_next_hop(self, destination: bytes) -> Optional[bytes]:
        """
        Get next hop for destination.

        Args:
            destination: Destination node

        Returns:
            Next hop node ID, or None if unreachable
        """
        with self._lock:
            route = self._routes.get(destination)
            if route and route.metric < MAX_HOPS:
                return route.next_hop
            return None

    def get_route(self, destination: bytes) -> Optional[RouteEntry]:
        """Get route entry for destination."""
        with self._lock:
            return self._routes.get(destination)

    def get_all_routes(self) -> Dict[bytes, RouteEntry]:
        """Get all routes."""
        with self._lock:
            return dict(self._routes)

    def get_routes_for_neighbor(self, neighbor_id: bytes) -> Dict[bytes, int]:
        """
        Get routes to advertise to a neighbor (split horizon).

        Args:
            neighbor_id: Neighbor to advertise to

        Returns:
            Dict of destination -> metric
        """
        with self._lock:
            routes = {}
            for dest, route in self._routes.items():
                if SPLIT_HORIZON and route.next_hop == neighbor_id:
                    # Poison reverse: advertise as unreachable
                    routes[dest] = MAX_HOPS
                else:
                    routes[dest] = route.metric

            return routes

    def expire_routes(self) -> List[bytes]:
        """
        Expire old routes.

        Returns:
            List of destinations that were removed
        """
        with self._lock:
            now = time.time()
            expired = []
            garbage = []

            for dest, route in self._routes.items():
                if route.is_direct:
                    continue  # Don't expire direct routes

                age = now - route.last_update

                if age > ROUTE_TIMEOUT and route.metric < MAX_HOPS:
                    # Mark as unreachable
                    route.metric = MAX_HOPS
                    expired.append(dest)

                elif age > ROUTE_TIMEOUT + ROUTE_GARBAGE_COLLECT:
                    # Remove entirely
                    garbage.append(dest)

            for dest in garbage:
                del self._routes[dest]

            return expired

    def stats(self) -> Dict[str, Any]:
        """Get routing statistics."""
        with self._lock:
            reachable = sum(1 for r in self._routes.values() if r.metric < MAX_HOPS)
            return {
                "total_routes": len(self._routes),
                "reachable_destinations": reachable,
                "direct_neighbors": len(self._neighbors),
            }


class Router:
    """
    Handles packet forwarding and route management.
    """

    def __init__(
        self,
        my_id: bytes,
        send_callback: Optional[Callable[[bytes, bytes], None]] = None,
    ):
        """
        Initialize router.

        Args:
            my_id: Our node ID
            send_callback: Function to send packet (next_hop, data)
        """
        self._my_id = my_id
        self._send_callback = send_callback
        self._routing_table = RoutingTable(my_id)

        # Routing daemon
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Statistics
        self._stats = {
            "packets_forwarded": 0,
            "packets_dropped_ttl": 0,
            "packets_dropped_no_route": 0,
            "route_updates_sent": 0,
            "route_updates_received": 0,
        }

    def start(self) -> None:
        """Start routing daemon."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._route_daemon, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop routing daemon."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None

    @property
    def table(self) -> RoutingTable:
        """Get routing table."""
        return self._routing_table

    def forward(
        self,
        original_src: bytes,
        final_dst: bytes,
        payload: bytes,
        ttl: int = MAX_HOPS,
    ) -> bool:
        """
        Forward a packet toward its destination.

        Args:
            original_src: Original source node
            final_dst: Final destination node
            payload: Packet payload
            ttl: Time to live (hop limit)

        Returns:
            True if forwarded successfully
        """
        if ttl <= 0:
            self._stats["packets_dropped_ttl"] += 1
            logger.debug(f"Dropped packet from {original_src.hex()[:8]}: TTL expired")
            return False

        if final_dst == self._my_id:
            # Destination is us - deliver locally (shouldn't happen in forward)
            return True

        next_hop = self._routing_table.get_next_hop(final_dst)
        if not next_hop:
            self._stats["packets_dropped_no_route"] += 1
            logger.debug(f"No route to {final_dst.hex()[:8]}")
            return False

        if self._send_callback:
            # Encode forwarded packet
            pkt = self.encode_forward(original_src, final_dst, ttl - 1, payload)
            self._send_callback(next_hop, pkt)
            self._stats["packets_forwarded"] += 1
            return True

        return False

    def receive_forward(self, data: bytes) -> Optional[ForwardedPacket]:
        """
        Process received forwarded packet.

        Args:
            data: Encoded packet

        Returns:
            ForwardedPacket if for us, None if forwarded
        """
        pkt = self.decode_forward(data)

        if pkt.final_dst == self._my_id:
            # Destination is us
            return pkt

        # Forward to next hop
        self.forward(pkt.original_src, pkt.final_dst, pkt.payload, pkt.ttl)
        return None

    def process_route_update(self, from_neighbor: bytes, updates: Dict[bytes, int]) -> None:
        """
        Process received route update.

        Args:
            from_neighbor: Neighbor that sent update
            updates: Dict of destination -> metric
        """
        self._stats["route_updates_received"] += 1

        for dest, metric in updates.items():
            # Add 1 hop for the link to this neighbor
            self._routing_table.update_route(
                destination=dest,
                next_hop=from_neighbor,
                metric=metric + 1,
                learned_from=from_neighbor,
            )

    def send_route_updates(self) -> None:
        """Send route updates to all neighbors."""
        if not self._send_callback:
            return

        for neighbor in self._routing_table._neighbors:
            routes = self._routing_table.get_routes_for_neighbor(neighbor)
            if routes:
                update = self.encode_route_update(routes)
                self._send_callback(neighbor, update)
                self._stats["route_updates_sent"] += 1

    def encode_forward(
        self,
        original_src: bytes,
        final_dst: bytes,
        ttl: int,
        payload: bytes,
    ) -> bytes:
        """Encode forwarded packet."""
        return (
            bytes([RoutingMsgType.FORWARD, ttl])
            + original_src
            + final_dst
            + payload
        )

    def decode_forward(self, data: bytes) -> ForwardedPacket:
        """Decode forwarded packet."""
        if len(data) < 34:  # type + ttl + 2 * 16-byte IDs
            raise ValueError("Packet too short")

        ttl = data[1]
        original_src = data[2:18]
        final_dst = data[18:34]
        payload = data[34:]

        return ForwardedPacket(
            original_src=original_src,
            final_dst=final_dst,
            ttl=ttl,
            payload=payload,
        )

    def encode_route_update(self, routes: Dict[bytes, int]) -> bytes:
        """Encode route update message."""
        data = bytes([RoutingMsgType.ROUTE_UPDATE, len(routes)])
        for dest, metric in routes.items():
            data += dest + bytes([metric])
        return data

    def decode_route_update(self, data: bytes) -> Dict[bytes, int]:
        """Decode route update message."""
        if len(data) < 2:
            raise ValueError("Update too short")

        count = data[1]
        routes = {}

        offset = 2
        for _ in range(count):
            if offset + 17 > len(data):
                break
            dest = data[offset:offset + 16]
            metric = data[offset + 16]
            routes[dest] = metric
            offset += 17

        return routes

    def encode_route_error(self, unreachable: bytes) -> bytes:
        """Encode route error message."""
        return bytes([RoutingMsgType.ROUTE_ERROR]) + unreachable

    def _route_daemon(self) -> None:
        """Periodic routing tasks."""
        last_update = 0.0

        while self._running:
            time.sleep(1.0)
            now = time.time()

            # Send periodic updates
            if now - last_update > ROUTE_UPDATE_INTERVAL:
                self.send_route_updates()
                last_update = now

            # Expire old routes
            expired = self._routing_table.expire_routes()
            if expired:
                # Send triggered update for expired routes
                self.send_route_updates()

    def stats(self) -> Dict[str, Any]:
        """Get router statistics."""
        return {
            **self._stats,
            "routing_table": self._routing_table.stats(),
        }


# =============================================================================
# Network Segmentation (VLANs)
# =============================================================================

@dataclass
class VLANConfig:
    """VLAN configuration."""
    vlan_id: int
    name: str
    members: Set[bytes] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)
    is_private: bool = False  # Private VLANs isolate members


class VLANManager:
    """
    Manages virtual network segmentation.

    Provides VLAN-like isolation between groups of nodes.
    """

    def __init__(self, my_id: bytes):
        """
        Initialize VLAN manager.

        Args:
            my_id: Our node ID
        """
        self._lock = threading.RLock()
        self._my_id = my_id
        self._vlans: Dict[int, VLANConfig] = {}
        self._my_vlans: Set[int] = {DEFAULT_VLAN}  # VLANs we belong to
        self._port_vlans: Dict[bytes, int] = {}  # Peer -> VLAN assignment

        # Create default VLAN
        self._vlans[DEFAULT_VLAN] = VLANConfig(
            vlan_id=DEFAULT_VLAN,
            name="default",
        )

    def create_vlan(self, vlan_id: int, name: str, is_private: bool = False) -> bool:
        """
        Create a new VLAN.

        Args:
            vlan_id: VLAN ID (1-4095)
            name: Human-readable name
            is_private: If True, isolate members from each other

        Returns:
            True if created successfully
        """
        if vlan_id < 1 or vlan_id >= MAX_VLANS:
            return False

        with self._lock:
            if vlan_id in self._vlans:
                return False

            self._vlans[vlan_id] = VLANConfig(
                vlan_id=vlan_id,
                name=name,
                is_private=is_private,
            )
            return True

    def delete_vlan(self, vlan_id: int) -> bool:
        """Delete a VLAN."""
        if vlan_id == DEFAULT_VLAN:
            return False  # Cannot delete default VLAN

        with self._lock:
            if vlan_id not in self._vlans:
                return False

            # Remove all members
            vlan = self._vlans[vlan_id]
            for peer in list(vlan.members):
                if self._port_vlans.get(peer) == vlan_id:
                    self._port_vlans[peer] = DEFAULT_VLAN

            self._my_vlans.discard(vlan_id)
            del self._vlans[vlan_id]
            return True

    def join_vlan(self, vlan_id: int) -> bool:
        """
        Join a VLAN.

        Args:
            vlan_id: VLAN to join

        Returns:
            True if joined successfully
        """
        with self._lock:
            if vlan_id not in self._vlans:
                return False

            self._vlans[vlan_id].members.add(self._my_id)
            self._my_vlans.add(vlan_id)
            return True

    def leave_vlan(self, vlan_id: int) -> bool:
        """Leave a VLAN."""
        if vlan_id == DEFAULT_VLAN:
            return False  # Cannot leave default VLAN

        with self._lock:
            if vlan_id in self._vlans:
                self._vlans[vlan_id].members.discard(self._my_id)
            self._my_vlans.discard(vlan_id)
            return True

    def assign_port(self, peer_id: bytes, vlan_id: int) -> bool:
        """
        Assign a peer to a VLAN (port-based VLAN).

        Args:
            peer_id: Peer to assign
            vlan_id: VLAN to assign to

        Returns:
            True if assigned successfully
        """
        with self._lock:
            if vlan_id not in self._vlans:
                return False

            old_vlan = self._port_vlans.get(peer_id, DEFAULT_VLAN)
            if old_vlan in self._vlans:
                self._vlans[old_vlan].members.discard(peer_id)

            self._port_vlans[peer_id] = vlan_id
            self._vlans[vlan_id].members.add(peer_id)
            return True

    def get_peer_vlan(self, peer_id: bytes) -> int:
        """Get VLAN assignment for a peer."""
        with self._lock:
            return self._port_vlans.get(peer_id, DEFAULT_VLAN)

    def can_communicate(self, peer1: bytes, peer2: bytes) -> bool:
        """
        Check if two peers can communicate.

        Args:
            peer1: First peer
            peer2: Second peer

        Returns:
            True if communication is allowed
        """
        with self._lock:
            vlan1 = self._port_vlans.get(peer1, DEFAULT_VLAN)
            vlan2 = self._port_vlans.get(peer2, DEFAULT_VLAN)

            # Must be in same VLAN
            if vlan1 != vlan2:
                return False

            # Check private VLAN isolation
            vlan = self._vlans.get(vlan1)
            if vlan and vlan.is_private:
                # In private VLAN, only communication with non-isolated ports allowed
                # For simplicity, private VLANs block all member-to-member traffic
                return False

            return True

    def filter_packet(self, src: bytes, dst: bytes, vlan_tag: Optional[int] = None) -> bool:
        """
        Check if packet should be forwarded (VLAN filtering).

        Args:
            src: Source peer
            dst: Destination peer
            vlan_tag: Optional VLAN tag in packet

        Returns:
            True if packet should be forwarded
        """
        with self._lock:
            src_vlan = self._port_vlans.get(src, DEFAULT_VLAN)

            if vlan_tag is not None:
                # Tagged packet - must match source VLAN
                if vlan_tag != src_vlan:
                    return False

            return self.can_communicate(src, dst)

    def get_vlan_members(self, vlan_id: int) -> Set[bytes]:
        """Get members of a VLAN."""
        with self._lock:
            vlan = self._vlans.get(vlan_id)
            if vlan:
                return vlan.members.copy()
            return set()

    def encode_vlan_tag(self, vlan_id: int, priority: int = 0) -> bytes:
        """
        Encode VLAN tag (similar to 802.1Q).

        Args:
            vlan_id: VLAN ID (12 bits)
            priority: Priority (3 bits)

        Returns:
            2-byte VLAN tag
        """
        # Format: PCP(3) + DEI(1) + VID(12)
        tag = ((priority & 0x7) << 13) | (vlan_id & 0xFFF)
        return struct.pack(">H", tag)

    def decode_vlan_tag(self, tag_bytes: bytes) -> Tuple[int, int]:
        """
        Decode VLAN tag.

        Returns:
            Tuple of (vlan_id, priority)
        """
        if len(tag_bytes) < 2:
            return DEFAULT_VLAN, 0

        tag = struct.unpack(">H", tag_bytes[:2])[0]
        vlan_id = tag & 0xFFF
        priority = (tag >> 13) & 0x7

        return vlan_id, priority

    def encode_announce(self) -> bytes:
        """Encode VLAN announcement."""
        with self._lock:
            data = bytes([RoutingMsgType.VLAN_ANNOUNCE, len(self._my_vlans)])
            for vlan_id in self._my_vlans:
                data += struct.pack(">H", vlan_id)
            return data

    def stats(self) -> Dict[str, Any]:
        """Get VLAN statistics."""
        with self._lock:
            vlan_info = {}
            for vlan_id, vlan in self._vlans.items():
                vlan_info[vlan_id] = {
                    "name": vlan.name,
                    "members": len(vlan.members),
                    "is_private": vlan.is_private,
                }

            return {
                "total_vlans": len(self._vlans),
                "my_vlans": list(self._my_vlans),
                "vlans": vlan_info,
            }
