"""
Multi-interface support for Malachi.

This module implements:
- Multi-interface management (wired + wireless simultaneously)
- Seamless bridging between interfaces
- Interface-aware routing with cost metrics
- Automatic failover between interfaces
- Multi-path route selection
"""

import time
import threading
import subprocess
import logging
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, List, Tuple, Callable, Any
from enum import IntEnum
from collections import defaultdict
import os

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Interface types and their base costs (lower = preferred)
IFACE_COST_LOOPBACK = 0
IFACE_COST_ETHERNET = 10
IFACE_COST_WIFI_INFRA = 50      # WiFi in infrastructure mode
IFACE_COST_WIFI_ADHOC = 100     # WiFi in IBSS/ad-hoc mode
IFACE_COST_CELLULAR = 200
IFACE_COST_UNKNOWN = 500

# Speed-based cost adjustment (subtracted from base cost)
SPEED_COST_10G = 5
SPEED_COST_1G = 4
SPEED_COST_100M = 2
SPEED_COST_10M = 0

# Interface monitoring
IFACE_CHECK_INTERVAL = 5.0      # Check interface status every 5s
IFACE_DOWN_TIMEOUT = 10.0       # Consider interface down after 10s no response

# Neighbor tracking
NEIGHBOR_TIMEOUT = 60.0         # Neighbor expires after 60s without contact
NEIGHBOR_STALE = 30.0           # Neighbor considered stale after 30s

# Deduplication
DEDUP_WINDOW = 5.0              # Deduplicate packets within 5s window
DEDUP_CACHE_SIZE = 10000        # Max entries in dedup cache


# =============================================================================
# Enums
# =============================================================================

class InterfaceType(IntEnum):
    """Network interface types."""
    UNKNOWN = 0
    LOOPBACK = 1
    ETHERNET = 2
    WIFI_INFRA = 3
    WIFI_ADHOC = 4
    WIFI_AP = 5
    CELLULAR = 6
    BRIDGE = 7
    VIRTUAL = 8


class InterfaceState(IntEnum):
    """Interface operational state."""
    DOWN = 0
    UP = 1
    DEGRADED = 2    # Up but experiencing issues


class NeighborState(IntEnum):
    """Neighbor reachability state."""
    UNKNOWN = 0
    REACHABLE = 1
    STALE = 2
    UNREACHABLE = 3


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class InterfaceInfo:
    """Information about a network interface."""
    name: str
    mac: bytes
    iface_type: InterfaceType = InterfaceType.UNKNOWN
    state: InterfaceState = InterfaceState.DOWN
    speed_mbps: int = 0
    mtu: int = 1500
    cost: int = IFACE_COST_UNKNOWN

    # Statistics
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0

    # Timestamps
    last_tx: float = 0.0
    last_rx: float = 0.0
    state_changed_at: float = field(default_factory=time.time)

    def is_up(self) -> bool:
        return self.state in (InterfaceState.UP, InterfaceState.DEGRADED)


@dataclass
class MultiInterfaceNeighbor:
    """A neighbor reachable via one or more interfaces."""
    node_id: bytes

    # Interface -> (MAC, last_seen, state, latency_ms)
    interfaces: Dict[str, Tuple[bytes, float, NeighborState, float]] = field(
        default_factory=dict
    )

    # Preferred interface (lowest cost, best latency)
    preferred_interface: Optional[str] = None

    # Crypto state (shared across interfaces)
    ed_public: Optional[bytes] = None
    session_key_tx: Optional[bytes] = None
    session_key_rx: Optional[bytes] = None

    def get_best_interface(self, interface_costs: Dict[str, int]) -> Optional[str]:
        """Get best interface to reach this neighbor."""
        reachable = [
            (iface, data) for iface, data in self.interfaces.items()
            if data[2] == NeighborState.REACHABLE
        ]

        if not reachable:
            # Fall back to stale interfaces
            reachable = [
                (iface, data) for iface, data in self.interfaces.items()
                if data[2] == NeighborState.STALE
            ]

        if not reachable:
            return None

        # Sort by: interface cost, then latency
        def sort_key(item):
            iface, data = item
            cost = interface_costs.get(iface, IFACE_COST_UNKNOWN)
            latency = data[3]
            return (cost, latency)

        reachable.sort(key=sort_key)
        return reachable[0][0]

    def is_reachable(self) -> bool:
        """Check if neighbor is reachable via any interface."""
        return any(
            data[2] in (NeighborState.REACHABLE, NeighborState.STALE)
            for data in self.interfaces.values()
        )


@dataclass
class MultiInterfaceRoute:
    """A route with multiple possible paths via different interfaces."""
    destination: bytes

    # Interface -> (next_hop, metric, last_updated)
    paths: Dict[str, Tuple[bytes, int, float]] = field(default_factory=dict)

    def get_best_path(self, interface_costs: Dict[str, int]) -> Optional[Tuple[str, bytes, int]]:
        """
        Get best path to destination.

        Returns:
            Tuple of (interface, next_hop, total_metric) or None
        """
        if not self.paths:
            return None

        best = None
        best_metric = float('inf')

        for iface, (next_hop, metric, _) in self.paths.items():
            iface_cost = interface_costs.get(iface, IFACE_COST_UNKNOWN)
            total = iface_cost + metric
            if total < best_metric:
                best_metric = total
                best = (iface, next_hop, total)

        return best

    def get_all_paths(self) -> List[Tuple[str, bytes, int]]:
        """Get all paths sorted by metric."""
        paths = [
            (iface, next_hop, metric)
            for iface, (next_hop, metric, _) in self.paths.items()
        ]
        paths.sort(key=lambda x: x[2])
        return paths


# =============================================================================
# Interface Manager
# =============================================================================

class InterfaceManager:
    """
    Manages multiple network interfaces.

    Handles interface detection, monitoring, and cost calculation.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._interfaces: Dict[str, InterfaceInfo] = {}
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None

        # Callbacks
        self._on_interface_up: Optional[Callable[[str], None]] = None
        self._on_interface_down: Optional[Callable[[str], None]] = None

    def add_interface(
        self,
        name: str,
        iface_type: Optional[InterfaceType] = None,
    ) -> bool:
        """
        Add an interface to manage.

        Args:
            name: Interface name (e.g., 'eth0', 'wlan0')
            iface_type: Optional type override

        Returns:
            True if added successfully
        """
        with self._lock:
            if name in self._interfaces:
                return True  # Already added

            # Get MAC address
            mac = self._get_mac(name)
            if not mac:
                logger.error(f"Could not get MAC for interface {name}")
                return False

            # Detect interface type if not provided
            if iface_type is None:
                iface_type = self._detect_type(name)

            # Get speed
            speed = self._get_speed(name)

            # Calculate cost
            cost = self._calculate_cost(iface_type, speed)

            # Check if up
            state = InterfaceState.UP if self._is_up(name) else InterfaceState.DOWN

            self._interfaces[name] = InterfaceInfo(
                name=name,
                mac=mac,
                iface_type=iface_type,
                state=state,
                speed_mbps=speed,
                cost=cost,
            )

            logger.info(
                f"Added interface {name}: type={iface_type.name}, "
                f"speed={speed}Mbps, cost={cost}, state={state.name}"
            )

            return True

    def remove_interface(self, name: str) -> bool:
        """Remove an interface from management."""
        with self._lock:
            if name in self._interfaces:
                del self._interfaces[name]
                return True
            return False

    def get_interface(self, name: str) -> Optional[InterfaceInfo]:
        """Get interface info."""
        with self._lock:
            return self._interfaces.get(name)

    def get_all_interfaces(self) -> Dict[str, InterfaceInfo]:
        """Get all managed interfaces."""
        with self._lock:
            return dict(self._interfaces)

    def get_active_interfaces(self) -> List[str]:
        """Get list of active (up) interface names."""
        with self._lock:
            return [
                name for name, info in self._interfaces.items()
                if info.is_up()
            ]

    def get_interface_costs(self) -> Dict[str, int]:
        """Get cost for each interface."""
        with self._lock:
            return {name: info.cost for name, info in self._interfaces.items()}

    def update_stats(self, name: str, tx: bool, bytes_count: int, error: bool = False):
        """Update interface statistics."""
        with self._lock:
            info = self._interfaces.get(name)
            if not info:
                return

            now = time.time()
            if tx:
                info.tx_packets += 1
                info.tx_bytes += bytes_count
                info.last_tx = now
                if error:
                    info.tx_errors += 1
            else:
                info.rx_packets += 1
                info.rx_bytes += bytes_count
                info.last_rx = now
                if error:
                    info.rx_errors += 1

    def start_monitoring(self) -> None:
        """Start interface monitoring thread."""
        if self._running:
            return
        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop interface monitoring."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2.0)
            self._monitor_thread = None

    def _monitor_loop(self) -> None:
        """Monitor interface states."""
        while self._running:
            time.sleep(IFACE_CHECK_INTERVAL)

            with self._lock:
                for name, info in self._interfaces.items():
                    was_up = info.is_up()
                    is_up = self._is_up(name)

                    if is_up and not was_up:
                        info.state = InterfaceState.UP
                        info.state_changed_at = time.time()
                        logger.info(f"Interface {name} came up")
                        if self._on_interface_up:
                            self._on_interface_up(name)

                    elif not is_up and was_up:
                        info.state = InterfaceState.DOWN
                        info.state_changed_at = time.time()
                        logger.warning(f"Interface {name} went down")
                        if self._on_interface_down:
                            self._on_interface_down(name)

    def _get_mac(self, name: str) -> Optional[bytes]:
        """Get MAC address of interface."""
        try:
            path = f"/sys/class/net/{name}/address"
            if os.path.exists(path):
                with open(path) as f:
                    mac_str = f.read().strip()
                return bytes.fromhex(mac_str.replace(":", ""))

            # Fallback for macOS
            result = subprocess.run(
                ["ifconfig", name],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split("\n"):
                if "ether" in line:
                    mac_str = line.split("ether")[1].strip().split()[0]
                    return bytes.fromhex(mac_str.replace(":", ""))
        except Exception as e:
            logger.debug(f"Error getting MAC for {name}: {e}")

        return None

    def _detect_type(self, name: str) -> InterfaceType:
        """Detect interface type."""
        if name.startswith("lo"):
            return InterfaceType.LOOPBACK

        if name.startswith(("eth", "en", "em")):
            return InterfaceType.ETHERNET

        if name.startswith(("wlan", "wl", "wifi")):
            # Check if in ad-hoc mode
            try:
                result = subprocess.run(
                    ["iw", name, "info"],
                    capture_output=True, text=True, timeout=5
                )
                if "type IBSS" in result.stdout or "type ibss" in result.stdout:
                    return InterfaceType.WIFI_ADHOC
                elif "type AP" in result.stdout:
                    return InterfaceType.WIFI_AP
                else:
                    return InterfaceType.WIFI_INFRA
            except Exception:
                return InterfaceType.WIFI_INFRA

        if name.startswith(("br", "bridge")):
            return InterfaceType.BRIDGE

        if name.startswith(("wwan", "rmnet", "ppp")):
            return InterfaceType.CELLULAR

        if name.startswith(("veth", "docker", "virbr", "tap", "tun")):
            return InterfaceType.VIRTUAL

        return InterfaceType.UNKNOWN

    def _get_speed(self, name: str) -> int:
        """Get interface speed in Mbps."""
        try:
            path = f"/sys/class/net/{name}/speed"
            if os.path.exists(path):
                with open(path) as f:
                    return int(f.read().strip())
        except Exception:
            pass

        # Default speeds by type
        iface_type = self._detect_type(name)
        defaults = {
            InterfaceType.ETHERNET: 1000,
            InterfaceType.WIFI_INFRA: 100,
            InterfaceType.WIFI_ADHOC: 54,
            InterfaceType.CELLULAR: 20,
        }
        return defaults.get(iface_type, 100)

    def _calculate_cost(self, iface_type: InterfaceType, speed_mbps: int) -> int:
        """Calculate interface cost based on type and speed."""
        base_costs = {
            InterfaceType.LOOPBACK: IFACE_COST_LOOPBACK,
            InterfaceType.ETHERNET: IFACE_COST_ETHERNET,
            InterfaceType.WIFI_INFRA: IFACE_COST_WIFI_INFRA,
            InterfaceType.WIFI_ADHOC: IFACE_COST_WIFI_ADHOC,
            InterfaceType.CELLULAR: IFACE_COST_CELLULAR,
            InterfaceType.BRIDGE: IFACE_COST_ETHERNET,
            InterfaceType.VIRTUAL: IFACE_COST_ETHERNET + 10,
        }

        base = base_costs.get(iface_type, IFACE_COST_UNKNOWN)

        # Adjust for speed
        if speed_mbps >= 10000:
            base -= SPEED_COST_10G
        elif speed_mbps >= 1000:
            base -= SPEED_COST_1G
        elif speed_mbps >= 100:
            base -= SPEED_COST_100M

        return max(1, base)  # Minimum cost of 1

    def _is_up(self, name: str) -> bool:
        """Check if interface is up."""
        try:
            path = f"/sys/class/net/{name}/operstate"
            if os.path.exists(path):
                with open(path) as f:
                    return f.read().strip().lower() == "up"

            # Fallback
            result = subprocess.run(
                ["ip", "link", "show", name],
                capture_output=True, text=True, timeout=5
            )
            return "state UP" in result.stdout
        except Exception:
            return False

    def stats(self) -> Dict[str, Any]:
        """Get interface manager statistics."""
        with self._lock:
            return {
                "interfaces": {
                    name: {
                        "type": info.iface_type.name,
                        "state": info.state.name,
                        "speed_mbps": info.speed_mbps,
                        "cost": info.cost,
                        "tx_packets": info.tx_packets,
                        "rx_packets": info.rx_packets,
                    }
                    for name, info in self._interfaces.items()
                },
                "active_count": len(self.get_active_interfaces()),
            }


# =============================================================================
# Multi-Interface Bridge
# =============================================================================

class MultiInterfaceBridge:
    """
    Bridges Malachi traffic across multiple network interfaces.

    Provides seamless connectivity between wired and wireless networks.
    """

    def __init__(self, node_id: bytes):
        """
        Initialize multi-interface bridge.

        Args:
            node_id: Our node ID
        """
        self._lock = threading.RLock()
        self._node_id = node_id

        # Interface management
        self.interfaces = InterfaceManager()

        # Neighbor tracking (node_id -> MultiInterfaceNeighbor)
        self._neighbors: Dict[bytes, MultiInterfaceNeighbor] = {}

        # Multi-path routing (destination -> MultiInterfaceRoute)
        self._routes: Dict[bytes, MultiInterfaceRoute] = {}

        # Packet deduplication (hash -> timestamp)
        self._dedup_cache: Dict[bytes, float] = {}

        # Per-interface send callbacks
        self._send_callbacks: Dict[str, Callable[[bytes, bytes], None]] = {}

        # Receive callback
        self._receive_callback: Optional[Callable[[str, bytes, bytes, bytes], None]] = None

        # Statistics
        self._stats = {
            "packets_bridged": 0,
            "packets_deduplicated": 0,
            "failovers": 0,
            "neighbor_discoveries": 0,
        }

        # Background tasks
        self._running = False
        self._maintenance_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the bridge."""
        if self._running:
            return

        self._running = True
        self.interfaces.start_monitoring()

        # Set up interface state callbacks
        self.interfaces._on_interface_down = self._on_interface_down
        self.interfaces._on_interface_up = self._on_interface_up

        self._maintenance_thread = threading.Thread(
            target=self._maintenance_loop, daemon=True
        )
        self._maintenance_thread.start()

        logger.info("Multi-interface bridge started")

    def stop(self) -> None:
        """Stop the bridge."""
        self._running = False
        self.interfaces.stop_monitoring()

        if self._maintenance_thread:
            self._maintenance_thread.join(timeout=2.0)
            self._maintenance_thread = None

        logger.info("Multi-interface bridge stopped")

    def add_interface(
        self,
        name: str,
        send_callback: Callable[[bytes, bytes], None],
        iface_type: Optional[InterfaceType] = None,
    ) -> bool:
        """
        Add an interface to the bridge.

        Args:
            name: Interface name
            send_callback: Function to send packet (dest_mac, data)
            iface_type: Optional type override

        Returns:
            True if added successfully
        """
        if not self.interfaces.add_interface(name, iface_type):
            return False

        with self._lock:
            self._send_callbacks[name] = send_callback

        return True

    def remove_interface(self, name: str) -> bool:
        """Remove an interface from the bridge."""
        with self._lock:
            self._send_callbacks.pop(name, None)
        return self.interfaces.remove_interface(name)

    def set_receive_callback(
        self,
        callback: Callable[[str, bytes, bytes, bytes], None]
    ) -> None:
        """
        Set callback for received packets.

        Callback args: (interface, src_mac, src_node_id, payload)
        """
        self._receive_callback = callback

    def on_packet_received(
        self,
        interface: str,
        src_mac: bytes,
        src_node_id: bytes,
        payload: bytes,
    ) -> bool:
        """
        Handle received packet from an interface.

        Args:
            interface: Interface packet arrived on
            src_mac: Source MAC address
            src_node_id: Source node ID
            payload: Packet payload

        Returns:
            True if packet was processed (not duplicate)
        """
        # Deduplication
        pkt_hash = self._hash_packet(src_node_id, payload)

        with self._lock:
            now = time.time()

            if pkt_hash in self._dedup_cache:
                # Duplicate packet (seen on another interface)
                self._stats["packets_deduplicated"] += 1
                return False

            self._dedup_cache[pkt_hash] = now

            # Update neighbor info
            self._update_neighbor(src_node_id, interface, src_mac)

            # Update interface stats
            self.interfaces.update_stats(interface, tx=False, bytes_count=len(payload))

        # Deliver to application
        if self._receive_callback:
            self._receive_callback(interface, src_mac, src_node_id, payload)

        return True

    def send(
        self,
        dest_node_id: bytes,
        payload: bytes,
        preferred_interface: Optional[str] = None,
    ) -> bool:
        """
        Send packet to a node via best available interface.

        Args:
            dest_node_id: Destination node ID
            payload: Packet payload
            preferred_interface: Optional interface preference

        Returns:
            True if sent successfully
        """
        with self._lock:
            # Get best interface for this destination
            interface, dest_mac = self._get_send_path(dest_node_id, preferred_interface)

            if not interface or not dest_mac:
                logger.debug(f"No path to {dest_node_id.hex()[:8]}")
                return False

            callback = self._send_callbacks.get(interface)
            if not callback:
                return False

        try:
            callback(dest_mac, payload)
            self.interfaces.update_stats(interface, tx=True, bytes_count=len(payload))
            return True
        except Exception as e:
            logger.error(f"Send failed on {interface}: {e}")
            self.interfaces.update_stats(interface, tx=True, bytes_count=len(payload), error=True)

            # Try failover
            return self._try_failover(dest_node_id, payload, exclude_interface=interface)

    def broadcast(self, payload: bytes, exclude_interface: Optional[str] = None) -> int:
        """
        Broadcast packet on all active interfaces.

        Args:
            payload: Packet payload
            exclude_interface: Optional interface to skip

        Returns:
            Number of interfaces packet was sent on
        """
        sent_count = 0
        broadcast_mac = b"\xff" * 6

        with self._lock:
            for interface in self.interfaces.get_active_interfaces():
                if interface == exclude_interface:
                    continue

                callback = self._send_callbacks.get(interface)
                if callback:
                    try:
                        callback(broadcast_mac, payload)
                        self.interfaces.update_stats(
                            interface, tx=True, bytes_count=len(payload)
                        )
                        sent_count += 1
                    except Exception as e:
                        logger.error(f"Broadcast failed on {interface}: {e}")

        return sent_count

    def bridge_packet(
        self,
        src_interface: str,
        src_node_id: bytes,
        dest_node_id: bytes,
        payload: bytes,
    ) -> bool:
        """
        Bridge a packet from one interface to another.

        Used for multi-hop routing across interfaces.

        Args:
            src_interface: Interface packet arrived on
            src_node_id: Original source node
            dest_node_id: Final destination node
            payload: Packet payload

        Returns:
            True if bridged successfully
        """
        with self._lock:
            # Find best interface to reach destination
            interface, dest_mac = self._get_send_path(dest_node_id)

            if not interface:
                return False

            # Don't bridge back to source interface for direct neighbors
            neighbor = self._neighbors.get(dest_node_id)
            if neighbor and src_interface in neighbor.interfaces:
                if interface == src_interface:
                    return False

            callback = self._send_callbacks.get(interface)
            if not callback:
                return False

            self._stats["packets_bridged"] += 1

        try:
            callback(dest_mac, payload)
            return True
        except Exception:
            return False

    def discover_neighbor(
        self,
        node_id: bytes,
        interface: str,
        mac: bytes,
        ed_public: Optional[bytes] = None,
    ) -> None:
        """
        Record discovered neighbor.

        Args:
            node_id: Neighbor's node ID
            interface: Interface neighbor was discovered on
            mac: Neighbor's MAC address on that interface
            ed_public: Neighbor's Ed25519 public key
        """
        with self._lock:
            if node_id not in self._neighbors:
                self._neighbors[node_id] = MultiInterfaceNeighbor(node_id=node_id)
                self._stats["neighbor_discoveries"] += 1

            neighbor = self._neighbors[node_id]

            # Update interface info
            neighbor.interfaces[interface] = (
                mac,
                time.time(),
                NeighborState.REACHABLE,
                0.0,  # Latency will be measured
            )

            if ed_public:
                neighbor.ed_public = ed_public

            # Update preferred interface
            neighbor.preferred_interface = neighbor.get_best_interface(
                self.interfaces.get_interface_costs()
            )

            # Add direct route
            if node_id not in self._routes:
                self._routes[node_id] = MultiInterfaceRoute(destination=node_id)

            self._routes[node_id].paths[interface] = (node_id, 0, time.time())

    def update_route(
        self,
        destination: bytes,
        interface: str,
        next_hop: bytes,
        metric: int,
    ) -> None:
        """
        Update routing table with new route.

        Args:
            destination: Destination node ID
            interface: Interface this route goes through
            next_hop: Next hop node ID
            metric: Route metric (hop count)
        """
        with self._lock:
            if destination not in self._routes:
                self._routes[destination] = MultiInterfaceRoute(destination=destination)

            self._routes[destination].paths[interface] = (
                next_hop, metric, time.time()
            )

    def get_neighbor(self, node_id: bytes) -> Optional[MultiInterfaceNeighbor]:
        """Get neighbor info."""
        with self._lock:
            return self._neighbors.get(node_id)

    def get_all_neighbors(self) -> Dict[bytes, MultiInterfaceNeighbor]:
        """Get all known neighbors."""
        with self._lock:
            return dict(self._neighbors)

    def get_route(self, destination: bytes) -> Optional[MultiInterfaceRoute]:
        """Get route to destination."""
        with self._lock:
            return self._routes.get(destination)

    def get_reachable_nodes(self) -> Set[bytes]:
        """Get all reachable node IDs."""
        with self._lock:
            reachable = set()

            # Direct neighbors
            for node_id, neighbor in self._neighbors.items():
                if neighbor.is_reachable():
                    reachable.add(node_id)

            # Routed destinations
            for dest, route in self._routes.items():
                if route.get_best_path(self.interfaces.get_interface_costs()):
                    reachable.add(dest)

            return reachable

    def _get_send_path(
        self,
        dest_node_id: bytes,
        preferred_interface: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[bytes]]:
        """
        Get interface and MAC to use for sending to a node.

        Returns:
            Tuple of (interface_name, dest_mac) or (None, None)
        """
        # Check if direct neighbor
        neighbor = self._neighbors.get(dest_node_id)
        if neighbor:
            if preferred_interface and preferred_interface in neighbor.interfaces:
                iface_data = neighbor.interfaces[preferred_interface]
                if iface_data[2] == NeighborState.REACHABLE:
                    return preferred_interface, iface_data[0]

            # Use best interface
            best_iface = neighbor.get_best_interface(self.interfaces.get_interface_costs())
            if best_iface:
                return best_iface, neighbor.interfaces[best_iface][0]

        # Check routing table
        route = self._routes.get(dest_node_id)
        if route:
            path = route.get_best_path(self.interfaces.get_interface_costs())
            if path:
                interface, next_hop, _ = path

                # Get MAC of next hop
                next_hop_neighbor = self._neighbors.get(next_hop)
                if next_hop_neighbor and interface in next_hop_neighbor.interfaces:
                    return interface, next_hop_neighbor.interfaces[interface][0]

        return None, None

    def _try_failover(
        self,
        dest_node_id: bytes,
        payload: bytes,
        exclude_interface: str,
    ) -> bool:
        """Try to send via alternative interface after failure."""
        with self._lock:
            neighbor = self._neighbors.get(dest_node_id)
            if not neighbor:
                return False

            # Try other interfaces
            for interface, (mac, _, state, _) in neighbor.interfaces.items():
                if interface == exclude_interface:
                    continue
                if state not in (NeighborState.REACHABLE, NeighborState.STALE):
                    continue

                callback = self._send_callbacks.get(interface)
                if not callback:
                    continue

                try:
                    callback(mac, payload)
                    self._stats["failovers"] += 1
                    logger.info(f"Failover to {interface} for {dest_node_id.hex()[:8]}")
                    return True
                except Exception:
                    continue

        return False

    def _update_neighbor(
        self,
        node_id: bytes,
        interface: str,
        mac: bytes,
    ) -> None:
        """Update neighbor state on packet received."""
        if node_id not in self._neighbors:
            self._neighbors[node_id] = MultiInterfaceNeighbor(node_id=node_id)

        neighbor = self._neighbors[node_id]

        # Get existing state
        existing = neighbor.interfaces.get(interface)
        latency = existing[3] if existing else 0.0

        neighbor.interfaces[interface] = (
            mac,
            time.time(),
            NeighborState.REACHABLE,
            latency,
        )

    def _hash_packet(self, src_node_id: bytes, payload: bytes) -> bytes:
        """Generate hash for packet deduplication."""
        import hashlib
        # Include first 32 bytes of payload for uniqueness
        data = src_node_id + payload[:32]
        return hashlib.blake2b(data, digest_size=8).digest()

    def _on_interface_down(self, interface: str) -> None:
        """Handle interface going down."""
        with self._lock:
            # Mark all neighbors on this interface as unreachable
            for neighbor in self._neighbors.values():
                if interface in neighbor.interfaces:
                    mac, _, _, latency = neighbor.interfaces[interface]
                    neighbor.interfaces[interface] = (
                        mac, time.time(), NeighborState.UNREACHABLE, latency
                    )

                    # Update preferred interface
                    neighbor.preferred_interface = neighbor.get_best_interface(
                        self.interfaces.get_interface_costs()
                    )

            # Invalidate routes via this interface
            for route in self._routes.values():
                if interface in route.paths:
                    del route.paths[interface]

    def _on_interface_up(self, interface: str) -> None:
        """Handle interface coming up."""
        # Trigger NDP on new interface (caller should handle)
        logger.info(f"Interface {interface} up - should trigger NDP")

    def _maintenance_loop(self) -> None:
        """Periodic maintenance tasks."""
        while self._running:
            time.sleep(5.0)

            now = time.time()

            with self._lock:
                # Clean dedup cache
                expired = [
                    h for h, ts in self._dedup_cache.items()
                    if now - ts > DEDUP_WINDOW
                ]
                for h in expired:
                    del self._dedup_cache[h]

                # Limit cache size
                if len(self._dedup_cache) > DEDUP_CACHE_SIZE:
                    # Remove oldest entries
                    sorted_entries = sorted(
                        self._dedup_cache.items(), key=lambda x: x[1]
                    )
                    for h, _ in sorted_entries[:len(self._dedup_cache) - DEDUP_CACHE_SIZE]:
                        del self._dedup_cache[h]

                # Update neighbor states
                for neighbor in self._neighbors.values():
                    for interface, (mac, last_seen, state, latency) in list(
                        neighbor.interfaces.items()
                    ):
                        age = now - last_seen

                        if age > NEIGHBOR_TIMEOUT:
                            neighbor.interfaces[interface] = (
                                mac, last_seen, NeighborState.UNREACHABLE, latency
                            )
                        elif age > NEIGHBOR_STALE and state == NeighborState.REACHABLE:
                            neighbor.interfaces[interface] = (
                                mac, last_seen, NeighborState.STALE, latency
                            )

                    # Update preferred interface
                    neighbor.preferred_interface = neighbor.get_best_interface(
                        self.interfaces.get_interface_costs()
                    )

    def stats(self) -> Dict[str, Any]:
        """Get bridge statistics."""
        with self._lock:
            return {
                **self._stats,
                "interfaces": self.interfaces.stats(),
                "neighbors": len(self._neighbors),
                "routes": len(self._routes),
                "dedup_cache_size": len(self._dedup_cache),
            }


# =============================================================================
# Multi-Interface NDP
# =============================================================================

class MultiInterfaceNDP:
    """
    Neighbor Discovery Protocol that runs on all interfaces.

    Coordinates NDP announcements and responses across interfaces.
    """

    def __init__(
        self,
        bridge: MultiInterfaceBridge,
        node_id: bytes,
        signing_key: Any,
        verify_key: Any,
    ):
        """
        Initialize multi-interface NDP.

        Args:
            bridge: Multi-interface bridge
            node_id: Our node ID
            signing_key: Ed25519 signing key
            verify_key: Ed25519 verify key
        """
        self._bridge = bridge
        self._node_id = node_id
        self._signing_key = signing_key
        self._verify_key = verify_key

        self._running = False
        self._announce_thread: Optional[threading.Thread] = None

        # Announcement interval
        self._announce_interval = 10.0

    def start(self) -> None:
        """Start NDP on all interfaces."""
        if self._running:
            return

        self._running = True
        self._announce_thread = threading.Thread(
            target=self._announce_loop, daemon=True
        )
        self._announce_thread.start()

    def stop(self) -> None:
        """Stop NDP."""
        self._running = False
        if self._announce_thread:
            self._announce_thread.join(timeout=2.0)
            self._announce_thread = None

    def announce_all(self) -> None:
        """Send NDP announcement on all active interfaces."""
        # Build announcement (application should provide actual encoding)
        announcement = self._build_announcement()

        # Broadcast on all interfaces
        count = self._bridge.broadcast(announcement)
        logger.debug(f"NDP announcement sent on {count} interfaces")

    def announce_on(self, interface: str) -> None:
        """Send NDP announcement on specific interface."""
        announcement = self._build_announcement()

        # Send as broadcast on specific interface
        info = self._bridge.interfaces.get_interface(interface)
        if info and info.is_up():
            callback = self._bridge._send_callbacks.get(interface)
            if callback:
                callback(b"\xff" * 6, announcement)

    def _build_announcement(self) -> bytes:
        """Build NDP announcement packet."""
        # This is a placeholder - actual implementation would use
        # the existing NDP packet format from malachi.packets
        import struct

        timestamp = int(time.time())
        data = (
            b"\x4d\x41\x4c"  # Magic "MAL"
            + b"\x01"  # NDP type
            + self._node_id
            + bytes(self._verify_key)
            + struct.pack(">I", timestamp)
        )

        # Sign it
        signature = self._signing_key.sign(data).signature

        return data + signature

    def _announce_loop(self) -> None:
        """Periodic announcement loop."""
        while self._running:
            self.announce_all()
            time.sleep(self._announce_interval)


# =============================================================================
# Convenience Functions
# =============================================================================

def create_multi_interface_node(
    node_id: bytes,
    signing_key: Any,
    verify_key: Any,
    interfaces: List[Tuple[str, Callable[[bytes, bytes], None]]],
) -> Tuple[MultiInterfaceBridge, MultiInterfaceNDP]:
    """
    Create a multi-interface Malachi node.

    Args:
        node_id: Our node ID
        signing_key: Ed25519 signing key
        verify_key: Ed25519 verify key
        interfaces: List of (interface_name, send_callback) tuples

    Returns:
        Tuple of (bridge, ndp)
    """
    bridge = MultiInterfaceBridge(node_id)

    for name, send_callback in interfaces:
        bridge.add_interface(name, send_callback)

    ndp = MultiInterfaceNDP(bridge, node_id, signing_key, verify_key)

    return bridge, ndp


def setup_adhoc_interface(interface: str, essid: str, channel: int = 1) -> bool:
    """
    Configure a wireless interface for ad-hoc (IBSS) mode.

    Args:
        interface: Interface name (e.g., 'wlan0')
        essid: Network name
        channel: WiFi channel (1-14 for 2.4GHz)

    Returns:
        True if configured successfully
    """
    try:
        # Bring interface down
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "down"],
            check=True, timeout=10
        )

        # Set type to IBSS
        subprocess.run(
            ["sudo", "iw", interface, "set", "type", "ibss"],
            check=True, timeout=10
        )

        # Bring interface up
        subprocess.run(
            ["sudo", "ip", "link", "set", interface, "up"],
            check=True, timeout=10
        )

        # Join/create IBSS network
        # Channel frequency: 2412 MHz for channel 1, +5 MHz per channel
        freq = 2412 + (channel - 1) * 5
        subprocess.run(
            ["sudo", "iw", interface, "ibss", "join", essid, str(freq)],
            check=True, timeout=10
        )

        logger.info(f"Configured {interface} for ad-hoc mode: {essid} (channel {channel})")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to configure {interface}: {e}")
        return False
    except Exception as e:
        logger.error(f"Error configuring {interface}: {e}")
        return False
