"""
LAN networking improvements for Malachi Stack.

Provides:
- Robust discovery loop with adaptive timing
- Health monitoring (RTT, packet loss, connection state)
- Interface auto-detection
- Peer expiration and cleanup
"""

from __future__ import annotations

import os
import time
import socket
import struct
import threading
import logging
import platform
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Callable
from enum import IntEnum
from collections import deque

logger = logging.getLogger(__name__)

# =============================================================================
# Platform Detection
# =============================================================================

PLATFORM = platform.system().lower()
IS_LINUX = PLATFORM == 'linux'
IS_MACOS = PLATFORM == 'darwin'
IS_BSD = PLATFORM in ('freebsd', 'openbsd', 'netbsd', 'dragonfly')

# =============================================================================
# Discovery Timing Constants (Adaptive)
# =============================================================================

DISCOVERY_MIN_INTERVAL = 2.0       # Minimum discovery interval (during active discovery)
DISCOVERY_MAX_INTERVAL = 60.0      # Maximum discovery interval (idle state)
DISCOVERY_BACKOFF_FACTOR = 1.5     # Backoff multiplier when no peers found
DISCOVERY_SPEEDUP_FACTOR = 0.5     # Speedup when new peer discovered
DISCOVERY_STABLE_PEERS = 3         # Number of stable peers to consider network stable

# =============================================================================
# Health Monitoring Constants
# =============================================================================

HEALTH_CHECK_INTERVAL = 5.0        # How often to check peer health
PING_TIMEOUT = 3.0                 # Timeout for ping responses
RTT_HISTORY_SIZE = 10              # Number of RTT samples to keep
PACKET_LOSS_WINDOW = 20            # Window for packet loss calculation
PEER_UNHEALTHY_THRESHOLD = 60.0    # Seconds without response to mark unhealthy
PEER_DEAD_THRESHOLD = 120.0        # Seconds without response to mark dead


class ConnectionState(IntEnum):
    """Peer connection state."""
    UNKNOWN = 0
    DISCOVERING = 1
    CONNECTED = 2
    UNHEALTHY = 3
    DEAD = 4


@dataclass
class PeerHealth:
    """Health information for a peer."""
    node_id: bytes
    address: Tuple[str, int]

    # Timing
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    last_ping_sent: float = 0.0
    last_pong_received: float = 0.0

    # RTT tracking
    rtt_history: deque = field(default_factory=lambda: deque(maxlen=RTT_HISTORY_SIZE))
    current_rtt_ms: float = 0.0
    min_rtt_ms: float = float('inf')
    max_rtt_ms: float = 0.0
    avg_rtt_ms: float = 0.0

    # Packet loss
    pings_sent: int = 0
    pongs_received: int = 0
    packet_loss_window: deque = field(default_factory=lambda: deque(maxlen=PACKET_LOSS_WINDOW))

    # State
    state: ConnectionState = ConnectionState.DISCOVERING

    def record_ping_sent(self):
        """Record that a ping was sent."""
        self.last_ping_sent = time.time()
        self.pings_sent += 1
        self.packet_loss_window.append(False)  # False = no response yet

    def record_pong_received(self, rtt_ms: float):
        """Record that a pong was received with RTT."""
        now = time.time()
        self.last_pong_received = now
        self.last_seen = now
        self.pongs_received += 1

        # Update RTT stats
        self.current_rtt_ms = rtt_ms
        self.rtt_history.append(rtt_ms)
        self.min_rtt_ms = min(self.min_rtt_ms, rtt_ms)
        self.max_rtt_ms = max(self.max_rtt_ms, rtt_ms)
        self.avg_rtt_ms = sum(self.rtt_history) / len(self.rtt_history)

        # Update packet loss window - mark last ping as received
        if self.packet_loss_window:
            self.packet_loss_window[-1] = True

        # Update state
        self.state = ConnectionState.CONNECTED

    @property
    def packet_loss_percent(self) -> float:
        """Calculate packet loss percentage."""
        if not self.packet_loss_window:
            return 0.0
        received = sum(1 for x in self.packet_loss_window if x)
        return 100.0 * (1 - received / len(self.packet_loss_window))

    @property
    def uptime_seconds(self) -> float:
        """How long this peer has been known."""
        return time.time() - self.first_seen

    def update_state(self):
        """Update connection state based on timing."""
        now = time.time()
        time_since_response = now - self.last_seen

        if time_since_response < HEALTH_CHECK_INTERVAL * 2:
            self.state = ConnectionState.CONNECTED
        elif time_since_response < PEER_UNHEALTHY_THRESHOLD:
            self.state = ConnectionState.UNHEALTHY
        elif time_since_response < PEER_DEAD_THRESHOLD:
            self.state = ConnectionState.DEAD
        else:
            self.state = ConnectionState.DEAD

    def is_alive(self) -> bool:
        """Check if peer is still alive."""
        return self.state in (ConnectionState.CONNECTED, ConnectionState.UNHEALTHY)

    def is_healthy(self) -> bool:
        """Check if peer is healthy."""
        return self.state == ConnectionState.CONNECTED


@dataclass
class DiscoveryStats:
    """Statistics for discovery process."""
    total_discoveries: int = 0
    total_probes_sent: int = 0
    last_probe_time: float = 0.0
    last_discovery_time: float = 0.0
    current_interval: float = DISCOVERY_MIN_INTERVAL
    peers_discovered: int = 0
    interfaces_probed: Set[str] = field(default_factory=set)


class NetworkInterface:
    """Information about a network interface."""

    def __init__(self, name: str, ip: str, mac: str, is_up: bool, is_wireless: bool):
        self.name = name
        self.ip = ip
        self.mac = mac
        self.is_up = is_up
        self.is_wireless = is_wireless
        self.last_discovery_time = 0.0
        self.peers_found = 0


def detect_network_interfaces() -> List[NetworkInterface]:
    """
    Detect available network interfaces for Malachi networking.

    Returns list of interfaces suitable for LAN discovery.
    Excludes loopback, virtual, and disconnected interfaces.
    """
    interfaces = []

    try:
        if IS_LINUX:
            interfaces = _detect_interfaces_linux()
        elif IS_MACOS:
            interfaces = _detect_interfaces_macos()
        elif IS_BSD:
            interfaces = _detect_interfaces_bsd()
        else:
            logger.warning(f"Unsupported platform: {PLATFORM}")
    except Exception as e:
        logger.error(f"Failed to detect network interfaces: {e}")

    return interfaces


def _detect_interfaces_linux() -> List[NetworkInterface]:
    """Detect interfaces on Linux using /sys/class/net."""
    interfaces = []

    try:
        net_path = '/sys/class/net'
        if not os.path.exists(net_path):
            return _detect_interfaces_fallback()

        for name in os.listdir(net_path):
            # Skip loopback and virtual interfaces
            if name == 'lo' or name.startswith('veth') or name.startswith('docker'):
                continue
            if name.startswith('br-') or name.startswith('virbr'):
                continue
            if name.startswith('mal') or name.startswith('tun') or name.startswith('tap'):
                continue

            iface_path = os.path.join(net_path, name)

            # Check if interface is up
            try:
                with open(os.path.join(iface_path, 'operstate'), 'r') as f:
                    operstate = f.read().strip()
                is_up = operstate in ('up', 'unknown')
            except:
                is_up = False

            if not is_up:
                continue

            # Get MAC address
            try:
                with open(os.path.join(iface_path, 'address'), 'r') as f:
                    mac = f.read().strip()
            except:
                mac = ''

            # Check if wireless
            is_wireless = os.path.exists(os.path.join(iface_path, 'wireless')) or \
                          os.path.exists(f'/sys/class/ieee80211/{name}')

            # Get IP address
            ip = _get_interface_ip(name)

            if ip:
                interfaces.append(NetworkInterface(
                    name=name,
                    ip=ip,
                    mac=mac,
                    is_up=is_up,
                    is_wireless=is_wireless
                ))
    except Exception as e:
        logger.debug(f"Linux interface detection error: {e}")
        return _detect_interfaces_fallback()

    return interfaces


def _detect_interfaces_macos() -> List[NetworkInterface]:
    """Detect interfaces on macOS using networksetup and ifconfig."""
    interfaces = []

    try:
        # Get list of network services
        result = subprocess.run(
            ['ifconfig', '-a'],
            capture_output=True,
            text=True,
            timeout=5
        )

        current_iface = None
        current_mac = ''
        current_ip = ''
        is_up = False
        is_wireless = False

        for line in result.stdout.split('\n'):
            if not line.startswith('\t') and ':' in line:
                # Save previous interface
                if current_iface and current_ip:
                    if not current_iface.startswith('lo') and \
                       not current_iface.startswith('utun') and \
                       not current_iface.startswith('bridge') and \
                       not current_iface.startswith('gif') and \
                       not current_iface.startswith('stf') and \
                       not current_iface.startswith('awdl'):
                        interfaces.append(NetworkInterface(
                            name=current_iface,
                            ip=current_ip,
                            mac=current_mac,
                            is_up=is_up,
                            is_wireless=is_wireless
                        ))

                # Parse new interface
                parts = line.split(':')
                current_iface = parts[0].strip()
                current_mac = ''
                current_ip = ''
                is_up = 'UP' in line
                is_wireless = current_iface.startswith('en') and current_iface != 'en0'
            elif line.strip().startswith('ether'):
                current_mac = line.strip().split()[1]
            elif line.strip().startswith('inet ') and not line.strip().startswith('inet6'):
                parts = line.strip().split()
                current_ip = parts[1]

        # Don't forget last interface
        if current_iface and current_ip:
            if not current_iface.startswith('lo') and \
               not current_iface.startswith('utun') and \
               not current_iface.startswith('bridge'):
                interfaces.append(NetworkInterface(
                    name=current_iface,
                    ip=current_ip,
                    mac=current_mac,
                    is_up=is_up,
                    is_wireless=is_wireless
                ))
    except Exception as e:
        logger.debug(f"macOS interface detection error: {e}")
        return _detect_interfaces_fallback()

    return interfaces


def _detect_interfaces_bsd() -> List[NetworkInterface]:
    """Detect interfaces on BSD systems."""
    # BSD detection is similar to macOS
    return _detect_interfaces_macos()


def _detect_interfaces_fallback() -> List[NetworkInterface]:
    """Fallback interface detection using socket."""
    interfaces = []

    try:
        import netifaces
        for iface in netifaces.interfaces():
            if iface.startswith('lo') or iface.startswith('tun') or iface.startswith('tap'):
                continue

            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip = addrs[netifaces.AF_INET][0].get('addr')
                mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', '')
                if ip and not ip.startswith('127.'):
                    interfaces.append(NetworkInterface(
                        name=iface,
                        ip=ip,
                        mac=mac,
                        is_up=True,
                        is_wireless=False
                    ))
    except ImportError:
        logger.debug("netifaces not available for fallback detection")
    except Exception as e:
        logger.debug(f"Fallback interface detection error: {e}")

    return interfaces


def _get_interface_ip(iface: str) -> Optional[str]:
    """Get IP address for an interface."""
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr', 'show', iface],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'inet ' in line:
                parts = line.strip().split()
                ip = parts[1].split('/')[0]
                if not ip.startswith('127.'):
                    return ip
    except:
        pass
    return None


class HealthMonitor:
    """
    Monitors health of discovered peers.

    Features:
    - RTT measurement via ping/pong
    - Packet loss calculation
    - Connection state tracking
    - Automatic peer expiration
    """

    def __init__(self, node_id: bytes, send_ping_func: Callable):
        self.node_id = node_id
        self._send_ping = send_ping_func

        self._peers: Dict[bytes, PeerHealth] = {}
        self._pending_pings: Dict[int, Tuple[bytes, float]] = {}  # ping_id -> (node_id, sent_time)
        self._ping_counter = 0
        self._lock = threading.Lock()

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start health monitoring."""
        self._running = True
        self._thread = threading.Thread(target=self._health_loop, daemon=True)
        self._thread.start()
        logger.info("Health monitor started")

    def stop(self):
        """Stop health monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Health monitor stopped")

    def add_peer(self, node_id: bytes, address: Tuple[str, int]) -> PeerHealth:
        """Add or update a peer for health monitoring."""
        with self._lock:
            if node_id not in self._peers:
                self._peers[node_id] = PeerHealth(node_id=node_id, address=address)
                logger.debug(f"Health monitor: added peer {node_id.hex()[:8]}")
            else:
                self._peers[node_id].address = address
                self._peers[node_id].last_seen = time.time()
            return self._peers[node_id]

    def remove_peer(self, node_id: bytes):
        """Remove a peer from health monitoring."""
        with self._lock:
            if node_id in self._peers:
                del self._peers[node_id]
                logger.debug(f"Health monitor: removed peer {node_id.hex()[:8]}")

    def get_peer_health(self, node_id: bytes) -> Optional[PeerHealth]:
        """Get health info for a peer."""
        with self._lock:
            return self._peers.get(node_id)

    def get_all_health(self) -> Dict[bytes, PeerHealth]:
        """Get health info for all peers."""
        with self._lock:
            return dict(self._peers)

    def record_pong(self, node_id: bytes, ping_id: int):
        """Record receipt of a pong."""
        with self._lock:
            if ping_id in self._pending_pings:
                expected_node, sent_time = self._pending_pings.pop(ping_id)
                if node_id == expected_node:
                    rtt_ms = (time.time() - sent_time) * 1000
                    if node_id in self._peers:
                        self._peers[node_id].record_pong_received(rtt_ms)

    def get_healthy_peers(self) -> List[PeerHealth]:
        """Get list of healthy peers."""
        with self._lock:
            return [p for p in self._peers.values() if p.is_healthy()]

    def get_alive_peers(self) -> List[PeerHealth]:
        """Get list of alive peers (including unhealthy)."""
        with self._lock:
            return [p for p in self._peers.values() if p.is_alive()]

    def _health_loop(self):
        """Main health check loop."""
        while self._running:
            try:
                self._check_peers()
                self._cleanup_expired()
            except Exception as e:
                logger.debug(f"Health check error: {e}")

            time.sleep(HEALTH_CHECK_INTERVAL)

    def _check_peers(self):
        """Send pings to all known peers."""
        with self._lock:
            peers = list(self._peers.items())

        for node_id, health in peers:
            # Update state
            health.update_state()

            # Send ping if alive
            if health.is_alive():
                self._send_health_ping(node_id, health.address)

    def _send_health_ping(self, node_id: bytes, address: Tuple[str, int]):
        """Send a health check ping."""
        with self._lock:
            self._ping_counter += 1
            ping_id = self._ping_counter
            self._pending_pings[ping_id] = (node_id, time.time())

            if node_id in self._peers:
                self._peers[node_id].record_ping_sent()

        try:
            self._send_ping(node_id, address, ping_id)
        except Exception as e:
            logger.debug(f"Failed to send health ping to {node_id.hex()[:8]}: {e}")

    def _cleanup_expired(self):
        """Remove dead peers and expired pings."""
        now = time.time()

        with self._lock:
            # Remove dead peers
            dead_peers = [
                node_id for node_id, health in self._peers.items()
                if health.state == ConnectionState.DEAD
            ]
            for node_id in dead_peers:
                del self._peers[node_id]
                logger.info(f"Removed dead peer: {node_id.hex()[:8]}")

            # Remove old pending pings (timeout)
            expired_pings = [
                ping_id for ping_id, (_, sent_time) in self._pending_pings.items()
                if now - sent_time > PING_TIMEOUT * 3
            ]
            for ping_id in expired_pings:
                del self._pending_pings[ping_id]


class DiscoveryManager:
    """
    Manages peer discovery with adaptive timing.

    Features:
    - Adaptive interval based on network conditions
    - Multi-interface support
    - Backoff when no peers found
    - Speedup when discovering new peers
    """

    def __init__(
        self,
        node_id: bytes,
        send_discover_func: Callable[[str], bool],
        interfaces: Optional[List[str]] = None
    ):
        self.node_id = node_id
        self._send_discover = send_discover_func
        self._interfaces = interfaces or []

        self.stats = DiscoveryStats()
        self._discovered_peers: Set[bytes] = set()
        self._lock = threading.Lock()

        self._running = False
        self._thread: Optional[threading.Thread] = None

    def start(self):
        """Start discovery process."""
        self._running = True

        # Auto-detect interfaces if none specified
        if not self._interfaces:
            detected = detect_network_interfaces()
            self._interfaces = [iface.name for iface in detected]
            if self._interfaces:
                logger.info(f"Auto-detected interfaces: {', '.join(self._interfaces)}")
            else:
                logger.warning("No suitable network interfaces detected")

        self._thread = threading.Thread(target=self._discovery_loop, daemon=True)
        self._thread.start()
        logger.info("Discovery manager started")

    def stop(self):
        """Stop discovery process."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        logger.info("Discovery manager stopped")

    def set_interfaces(self, interfaces: List[str]):
        """Set interfaces to use for discovery."""
        with self._lock:
            self._interfaces = interfaces
            self.stats.interfaces_probed = set(interfaces)

    def on_peer_discovered(self, node_id: bytes):
        """Called when a new peer is discovered."""
        with self._lock:
            is_new = node_id not in self._discovered_peers
            if is_new:
                self._discovered_peers.add(node_id)
                self.stats.peers_discovered = len(self._discovered_peers)
                self.stats.last_discovery_time = time.time()
                self.stats.total_discoveries += 1

                # Speed up discovery interval
                self.stats.current_interval = max(
                    DISCOVERY_MIN_INTERVAL,
                    self.stats.current_interval * DISCOVERY_SPEEDUP_FACTOR
                )
                logger.debug(f"New peer discovered, interval reduced to {self.stats.current_interval:.1f}s")

        return is_new

    def on_peer_lost(self, node_id: bytes):
        """Called when a peer is lost."""
        with self._lock:
            if node_id in self._discovered_peers:
                self._discovered_peers.discard(node_id)
                self.stats.peers_discovered = len(self._discovered_peers)

    def get_stats(self) -> DiscoveryStats:
        """Get discovery statistics."""
        with self._lock:
            return DiscoveryStats(
                total_discoveries=self.stats.total_discoveries,
                total_probes_sent=self.stats.total_probes_sent,
                last_probe_time=self.stats.last_probe_time,
                last_discovery_time=self.stats.last_discovery_time,
                current_interval=self.stats.current_interval,
                peers_discovered=self.stats.peers_discovered,
                interfaces_probed=set(self.stats.interfaces_probed)
            )

    def force_discovery(self):
        """Force immediate discovery on all interfaces."""
        logger.debug("Forcing immediate discovery")
        self._do_discovery()

    def _discovery_loop(self):
        """Main discovery loop with adaptive timing."""
        last_discovery = 0.0

        while self._running:
            now = time.time()

            with self._lock:
                interval = self.stats.current_interval
                peer_count = self.stats.peers_discovered

            # Check if it's time to discover
            if now - last_discovery >= interval:
                self._do_discovery()
                last_discovery = now

                # Adjust interval based on peer count
                with self._lock:
                    if peer_count == 0:
                        # No peers - back off
                        self.stats.current_interval = min(
                            DISCOVERY_MAX_INTERVAL,
                            self.stats.current_interval * DISCOVERY_BACKOFF_FACTOR
                        )
                    elif peer_count >= DISCOVERY_STABLE_PEERS:
                        # Stable network - slow down
                        self.stats.current_interval = min(
                            DISCOVERY_MAX_INTERVAL,
                            self.stats.current_interval * DISCOVERY_BACKOFF_FACTOR
                        )

            # Sleep for a short interval to remain responsive
            time.sleep(1.0)

    def _do_discovery(self):
        """Perform discovery on all interfaces."""
        with self._lock:
            interfaces = list(self._interfaces)

        for iface in interfaces:
            try:
                if self._send_discover(iface):
                    with self._lock:
                        self.stats.total_probes_sent += 1
                        self.stats.last_probe_time = time.time()
                        self.stats.interfaces_probed.add(iface)
            except Exception as e:
                logger.debug(f"Discovery failed on {iface}: {e}")


class LANManager:
    """
    Unified LAN networking manager.

    Combines:
    - Discovery with adaptive timing
    - Health monitoring
    - Interface auto-detection
    - Peer expiration
    """

    def __init__(
        self,
        node_id: bytes,
        send_discover_func: Callable[[str], bool],
        send_ping_func: Callable[[bytes, Tuple[str, int], int], None],
        interfaces: Optional[List[str]] = None
    ):
        self.node_id = node_id

        # Components
        self.discovery = DiscoveryManager(
            node_id=node_id,
            send_discover_func=send_discover_func,
            interfaces=interfaces
        )

        self.health = HealthMonitor(
            node_id=node_id,
            send_ping_func=send_ping_func
        )

        self._on_peer_added: Optional[Callable[[bytes, Tuple[str, int]], None]] = None
        self._on_peer_removed: Optional[Callable[[bytes], None]] = None

    def start(self):
        """Start LAN manager."""
        self.discovery.start()
        self.health.start()
        logger.info("LAN manager started")

    def stop(self):
        """Stop LAN manager."""
        self.discovery.stop()
        self.health.stop()
        logger.info("LAN manager stopped")

    def on_peer_added(self, callback: Callable[[bytes, Tuple[str, int]], None]):
        """Set callback for when peer is added."""
        self._on_peer_added = callback

    def on_peer_removed(self, callback: Callable[[bytes], None]):
        """Set callback for when peer is removed."""
        self._on_peer_removed = callback

    def peer_discovered(self, node_id: bytes, address: Tuple[str, int]):
        """Called when a peer is discovered via NDP or mesh."""
        is_new = self.discovery.on_peer_discovered(node_id)
        self.health.add_peer(node_id, address)

        if is_new and self._on_peer_added:
            self._on_peer_added(node_id, address)

    def peer_lost(self, node_id: bytes):
        """Called when a peer is lost."""
        self.discovery.on_peer_lost(node_id)
        self.health.remove_peer(node_id)

        if self._on_peer_removed:
            self._on_peer_removed(node_id)

    def pong_received(self, node_id: bytes, ping_id: int):
        """Called when a pong is received."""
        self.health.record_pong(node_id, ping_id)

    def get_status(self) -> dict:
        """
        Get comprehensive status for display.

        Returns dict with:
        - discovery: DiscoveryStats
        - interfaces: List of detected interfaces
        - peers: List of peer health info
        - summary: High-level summary
        """
        discovery_stats = self.discovery.get_stats()
        all_health = self.health.get_all_health()
        interfaces = detect_network_interfaces()

        # Build peer list
        peers = []
        for node_id, health in all_health.items():
            peers.append({
                'node_id': node_id.hex()[:16],
                'address': f"{health.address[0]}:{health.address[1]}",
                'state': health.state.name,
                'rtt_ms': round(health.avg_rtt_ms, 2),
                'packet_loss': round(health.packet_loss_percent, 1),
                'uptime': round(health.uptime_seconds, 0),
                'last_seen': round(time.time() - health.last_seen, 1),
            })

        # Build summary
        healthy_count = len([p for p in peers if p['state'] == 'CONNECTED'])
        unhealthy_count = len([p for p in peers if p['state'] == 'UNHEALTHY'])

        return {
            'discovery': {
                'total_discoveries': discovery_stats.total_discoveries,
                'probes_sent': discovery_stats.total_probes_sent,
                'current_interval': round(discovery_stats.current_interval, 1),
                'interfaces': list(discovery_stats.interfaces_probed),
            },
            'interfaces': [
                {
                    'name': iface.name,
                    'ip': iface.ip,
                    'mac': iface.mac,
                    'wireless': iface.is_wireless,
                }
                for iface in interfaces
            ],
            'peers': sorted(peers, key=lambda p: p['last_seen']),
            'summary': {
                'total_peers': len(peers),
                'healthy': healthy_count,
                'unhealthy': unhealthy_count,
                'dead': len(peers) - healthy_count - unhealthy_count,
            }
        }

    def format_status(self) -> str:
        """Format status for CLI display."""
        status = self.get_status()
        lines = []

        lines.append("=== Malachi LAN Status ===")
        lines.append("")

        # Summary
        summary = status['summary']
        lines.append(f"Peers: {summary['total_peers']} total "
                    f"({summary['healthy']} healthy, "
                    f"{summary['unhealthy']} unhealthy, "
                    f"{summary['dead']} dead)")
        lines.append("")

        # Discovery
        disc = status['discovery']
        lines.append("Discovery:")
        lines.append(f"  Interval: {disc['current_interval']}s")
        lines.append(f"  Probes sent: {disc['probes_sent']}")
        lines.append(f"  Total discoveries: {disc['total_discoveries']}")
        lines.append(f"  Interfaces: {', '.join(disc['interfaces']) or 'none'}")
        lines.append("")

        # Interfaces
        if status['interfaces']:
            lines.append("Network Interfaces:")
            for iface in status['interfaces']:
                wireless = " [wireless]" if iface['wireless'] else ""
                lines.append(f"  {iface['name']}: {iface['ip']}{wireless}")
            lines.append("")

        # Peers
        if status['peers']:
            lines.append("Peers:")
            lines.append(f"  {'Node ID':<18} {'Address':<22} {'State':<10} {'RTT':<10} {'Loss':<8}")
            lines.append("  " + "-" * 70)
            for peer in status['peers']:
                rtt = f"{peer['rtt_ms']}ms" if peer['rtt_ms'] > 0 else "-"
                loss = f"{peer['packet_loss']}%" if peer['packet_loss'] > 0 else "-"
                lines.append(f"  {peer['node_id']:<18} {peer['address']:<22} "
                           f"{peer['state']:<10} {rtt:<10} {loss:<8}")
        else:
            lines.append("No peers discovered yet.")

        return "\n".join(lines)
