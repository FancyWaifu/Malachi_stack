#!/usr/bin/env python3
"""
Malachi TUN Interface - OS-level integration.

Creates a virtual network interface (mal0) that:
- Appears in ifconfig/ip commands
- Allows applications to send to Malachi node IDs
- Integrates with standard socket API via mapped addresses

Supported Platforms:
- Linux: /dev/net/tun with TUNSETIFF ioctl
- macOS: utun via PF_SYSTEM socket
- BSD (FreeBSD/OpenBSD/NetBSD): /dev/tunX character devices

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                      Application                            │
    │                  send(10.x.x.x, data)                     │
    └───────────────────────┬─────────────────────────────────────┘
                            │
    ┌───────────────────────▼─────────────────────────────────────┐
    │                   mal0 (TUN interface)                      │
    │                    10.0.0.0/8                            │
    └───────────────────────┬─────────────────────────────────────┘
                            │
    ┌───────────────────────▼─────────────────────────────────────┐
    │                 Malachi TUN Daemon                          │
    │         Maps 10.x.x.x ←→ Malachi Node IDs                │
    │         Handles encryption, routing, discovery              │
    └───────────────────────┬─────────────────────────────────────┘
                            │
    ┌───────────────────────▼─────────────────────────────────────┐
    │              Physical Interface (eth0/wlan0)                │
    │                  Raw Ethernet Frames                        │
    └─────────────────────────────────────────────────────────────┘
"""

import os
import sys
import struct
import fcntl
import threading
import logging
import select
import ipaddress
import platform
import socket as sock_module
from abc import ABC, abstractmethod
from typing import Dict, Optional, Tuple, Callable
from dataclasses import dataclass, field
import time
import subprocess

logger = logging.getLogger(__name__)

# Try to import LAN manager
try:
    from .lan import LANManager, detect_network_interfaces
    HAS_LAN_MANAGER = True
except ImportError:
    HAS_LAN_MANAGER = False
    LANManager = None
    detect_network_interfaces = None

# =============================================================================
# Platform Detection
# =============================================================================

PLATFORM = platform.system().lower()
IS_LINUX = PLATFORM == 'linux'
IS_MACOS = PLATFORM == 'darwin'
IS_BSD = PLATFORM in ('freebsd', 'openbsd', 'netbsd', 'dragonfly')

# =============================================================================
# Platform-specific Constants
# =============================================================================

# Linux TUN/TAP constants
if IS_LINUX:
    TUNSETIFF = 0x400454ca
    TUNSETOWNER = 0x400454cc
    TUNSETGROUP = 0x400454ce
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

# macOS utun constants
if IS_MACOS:
    PF_SYSTEM = 32
    SYSPROTO_CONTROL = 2
    AF_SYS_CONTROL = 2
    CTLIOCGINFO = 0xc0644e03
    UTUN_CONTROL_NAME = b'com.apple.net.utun_control'

# BSD constants
if IS_BSD:
    # BSD uses simple /dev/tunX devices
    pass

# Malachi virtual network
MALACHI_NETWORK = "10.0.0.0/8"  # 10.x.x.x reserved for Malachi (~16.7M addresses)
MALACHI_PREFIX = ipaddress.IPv4Network(MALACHI_NETWORK)


@dataclass
class NodeMapping:
    """Maps a Malachi node ID to a virtual IP."""
    node_id: bytes
    virtual_ip: str
    last_seen: float = field(default_factory=time.time)
    is_local: bool = False


@dataclass
class RouteInfo:
    """Information about a route to a remote node."""
    dest_node_id: bytes
    dest_virtual_ip: str
    hops: list  # List of intermediate node IDs
    latency_ms: float = 0.0
    last_updated: float = field(default_factory=time.time)
    connection_type: str = "direct"  # "direct", "relay", "mesh"
    physical_interface: str = ""
    signal_quality: int = 100  # 0-100%

    @property
    def hop_count(self) -> int:
        return len(self.hops) + 1  # +1 for the destination itself

    @property
    def is_direct(self) -> bool:
        return len(self.hops) == 0


# =============================================================================
# Abstract Base Class
# =============================================================================

class TunInterfaceBase(ABC):
    """
    Abstract base class for TUN interfaces.

    Platform-specific implementations handle device creation,
    while common logic (IP mapping, packet routing) lives here.
    """

    def __init__(
        self,
        interface_name: str = "mal0",
        node_id: Optional[bytes] = None,
    ):
        self.interface_name = interface_name
        self.node_id = node_id
        self.tun_fd: Optional[int] = None

        # IP <-> Node ID mapping
        self._mappings: Dict[str, NodeMapping] = {}  # IP -> mapping
        self._reverse_mappings: Dict[bytes, str] = {}  # node_id -> IP

        # Callbacks
        self._send_callback: Optional[Callable[[bytes, bytes], None]] = None

        # Threading
        self._running = False
        self._read_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Our virtual IP - derived from node ID for consistency
        self.local_ip = self._calculate_local_ip()

    def _calculate_local_ip(self) -> str:
        """Calculate our virtual IP from node ID."""
        if self.node_id:
            # Derive IP from node ID hash (uses 3 bytes for 10.x.x.x range)
            node_hash = int.from_bytes(self.node_id[:4], 'big')
            second_octet = (node_hash >> 16) & 0xFF
            third_octet = (node_hash >> 8) & 0xFF
            fourth_octet = node_hash & 0xFF
            # Avoid .0.0.0 and .0.0.1
            if second_octet == 0 and third_octet == 0 and fourth_octet < 2:
                fourth_octet = 2
            return f"10.{second_octet}.{third_octet}.{fourth_octet}"
        else:
            # Fallback if no node ID yet
            return "10.0.0.1"

    @abstractmethod
    def create(self) -> bool:
        """Create the TUN interface. Platform-specific."""
        pass

    @abstractmethod
    def configure(self) -> bool:
        """Configure the TUN interface with IP. Platform-specific."""
        pass

    @abstractmethod
    def _read_packet(self) -> Optional[bytes]:
        """Read a packet from the TUN device. Platform-specific."""
        pass

    @abstractmethod
    def _write_packet(self, packet: bytes) -> bool:
        """Write a packet to the TUN device. Platform-specific."""
        pass

    def destroy(self):
        """Destroy the TUN interface."""
        self._running = False

        if self._read_thread:
            self._read_thread.join(timeout=2.0)

        if self.tun_fd is not None:
            try:
                if isinstance(self.tun_fd, int):
                    os.close(self.tun_fd)
                else:
                    self.tun_fd.close()
            except:
                pass
            self.tun_fd = None

        logger.info(f"Destroyed TUN interface: {self.interface_name}")

    def start(self):
        """Start reading from TUN interface."""
        if self._running or self.tun_fd is None:
            return

        self._running = True
        self._read_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._read_thread.start()
        logger.info(f"Started TUN reader for {self.interface_name}")

    def stop(self):
        """Stop reading from TUN interface."""
        self._running = False
        if self._read_thread:
            self._read_thread.join(timeout=2.0)
            self._read_thread = None

    def set_send_callback(self, callback: Callable[[bytes, bytes], None]):
        """
        Set callback for sending packets via Malachi.

        Callback args: (dest_node_id, payload)
        """
        self._send_callback = callback

    def allocate_ip(self, node_id: bytes) -> str:
        """
        Allocate a virtual IP for a node ID.

        Args:
            node_id: Malachi node ID

        Returns:
            Allocated virtual IP address
        """
        with self._lock:
            # Check if already allocated
            if node_id in self._reverse_mappings:
                return self._reverse_mappings[node_id]

            # Use hash of node ID for consistent allocation
            node_hash = int.from_bytes(node_id[:4], 'big')

            # Map to 10.x.x.x range (uses 3 bytes = ~16.7M addresses)
            second_octet = (node_hash >> 16) & 0xFF
            third_octet = (node_hash >> 8) & 0xFF
            fourth_octet = node_hash & 0xFF

            # Avoid .0.0.0 and .0.0.1 (network and gateway)
            if second_octet == 0 and third_octet == 0 and fourth_octet < 2:
                fourth_octet = 2

            ip = f"10.{second_octet}.{third_octet}.{fourth_octet}"

            # Handle collisions
            while ip in self._mappings:
                fourth_octet = (fourth_octet + 1) % 256
                if fourth_octet == 0:
                    third_octet = (third_octet + 1) % 256
                    if third_octet == 0:
                        second_octet = (second_octet + 1) % 256
                ip = f"10.{second_octet}.{third_octet}.{fourth_octet}"

            # Store mapping
            self._mappings[ip] = NodeMapping(node_id=node_id, virtual_ip=ip)
            self._reverse_mappings[node_id] = ip

            logger.debug(f"Allocated {ip} for node {node_id.hex()[:8]}")
            return ip

    def get_node_id(self, ip: str) -> Optional[bytes]:
        """Get node ID for a virtual IP."""
        mapping = self._mappings.get(ip)
        return mapping.node_id if mapping else None

    def get_virtual_ip(self, node_id: bytes) -> Optional[str]:
        """Get virtual IP for a node ID."""
        return self._reverse_mappings.get(node_id)

    def inject_packet(self, src_node_id: bytes, payload: bytes):
        """
        Inject a received Malachi packet into the TUN interface.

        This makes it appear as if the packet came from the network,
        allowing applications to receive it via standard sockets.

        Args:
            src_node_id: Source node ID
            payload: IP packet payload
        """
        if self.tun_fd is None:
            return

        try:
            # Ensure source has a virtual IP
            self.allocate_ip(src_node_id)
            self._write_packet(payload)
        except Exception as e:
            logger.error(f"Failed to inject packet: {e}")

    def _read_loop(self):
        """Read packets from TUN interface and send via Malachi."""
        while self._running:
            try:
                packet = self._read_packet()

                if packet is None or len(packet) < 20:
                    continue

                # Parse IP header
                version_ihl = packet[0]
                version = version_ihl >> 4

                if version != 4:
                    continue  # Only IPv4 for now

                # Extract destination IP
                dst_ip = ".".join(str(b) for b in packet[16:20])

                # Check if destination is in Malachi network
                if not self._is_malachi_ip(dst_ip):
                    continue

                # Look up node ID
                dest_node_id = self.get_node_id(dst_ip)

                if dest_node_id and self._send_callback:
                    self._send_callback(dest_node_id, packet)
                else:
                    logger.debug(f"No route to {dst_ip}")

            except Exception as e:
                if self._running:
                    logger.error(f"TUN read error: {e}")

    def _is_malachi_ip(self, ip: str) -> bool:
        """Check if IP is in Malachi virtual network."""
        try:
            return ipaddress.IPv4Address(ip) in MALACHI_PREFIX
        except:
            return False

    def _register_local_mapping(self):
        """Register local node ID mapping."""
        if self.node_id:
            self._mappings[self.local_ip] = NodeMapping(
                node_id=self.node_id,
                virtual_ip=self.local_ip,
                is_local=True
            )
            self._reverse_mappings[self.node_id] = self.local_ip

    def get_stats(self) -> Dict:
        """Get interface statistics."""
        return {
            "interface": self.interface_name,
            "local_ip": self.local_ip,
            "node_id": self.node_id.hex() if self.node_id else None,
            "mappings": len(self._mappings),
            "running": self._running,
            "platform": PLATFORM,
        }


# =============================================================================
# Linux Implementation
# =============================================================================

class LinuxTunInterface(TunInterfaceBase):
    """
    Linux TUN interface using /dev/net/tun.

    Requires:
    - Root or CAP_NET_ADMIN capability
    - tun kernel module loaded (modprobe tun)
    """

    def create(self) -> bool:
        """Create the TUN interface using Linux TUN/TAP driver."""
        try:
            # Open TUN device
            self.tun_fd = os.open("/dev/net/tun", os.O_RDWR)

            # Configure interface
            ifr = struct.pack('16sH', self.interface_name.encode(), IFF_TUN | IFF_NO_PI)
            fcntl.ioctl(self.tun_fd, TUNSETIFF, ifr)

            logger.info(f"Created TUN interface: {self.interface_name}")
            return True

        except FileNotFoundError:
            logger.error("TUN device not found. Is the tun module loaded?")
            logger.error("Try: sudo modprobe tun")
            return False
        except PermissionError:
            logger.error("Permission denied. Run as root or with CAP_NET_ADMIN")
            return False
        except Exception as e:
            logger.error(f"Failed to create TUN interface: {e}")
            return False

    def configure(self) -> bool:
        """Configure the TUN interface with IP address and bring it up."""
        try:
            # Assign IP address
            subprocess.run([
                "ip", "addr", "add", f"{self.local_ip}/8",
                "dev", self.interface_name
            ], check=True, capture_output=True)

            # Bring interface up
            subprocess.run([
                "ip", "link", "set", self.interface_name, "up"
            ], check=True, capture_output=True)

            # Set MTU (leave room for Malachi headers)
            subprocess.run([
                "ip", "link", "set", self.interface_name, "mtu", "1400"
            ], check=True, capture_output=True)

            logger.info(f"Configured {self.interface_name} with {self.local_ip}/8")
            self._register_local_mapping()
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure interface: {e}")
            return False
        except Exception as e:
            logger.error(f"Configuration error: {e}")
            return False

    def _read_packet(self) -> Optional[bytes]:
        """Read a packet from the TUN device."""
        try:
            readable, _, _ = select.select([self.tun_fd], [], [], 0.1)
            if not readable:
                return None
            return os.read(self.tun_fd, 65535)
        except Exception:
            return None

    def _write_packet(self, packet: bytes) -> bool:
        """Write a packet to the TUN device."""
        try:
            os.write(self.tun_fd, packet)
            return True
        except Exception as e:
            logger.error(f"Failed to write packet: {e}")
            return False


# =============================================================================
# macOS Implementation
# =============================================================================

class MacOSTunInterface(TunInterfaceBase):
    """
    macOS TUN interface using utun.

    Requires:
    - Root privileges (sudo)

    Note: macOS utun devices prepend a 4-byte protocol header to each packet.
    """

    def __init__(self, interface_name: str = "utun", node_id: Optional[bytes] = None):
        # macOS assigns utun numbers automatically
        super().__init__(interface_name, node_id)
        self._utun_unit: Optional[int] = None

    def create(self) -> bool:
        """Create the TUN interface using macOS utun."""
        try:
            # Get list of existing utun interfaces before creation
            existing_utuns = self._list_utun_interfaces()

            # Create PF_SYSTEM socket for utun control
            self.tun_fd = sock_module.socket(PF_SYSTEM, sock_module.SOCK_DGRAM, SYSPROTO_CONTROL)

            # Get the control ID for utun
            ctl_info = struct.pack('I96s', 0, UTUN_CONTROL_NAME)
            ctl_info = fcntl.ioctl(self.tun_fd.fileno(), CTLIOCGINFO, ctl_info)
            ctl_id = struct.unpack('I96s', ctl_info)[0]

            # Connect to create interface
            # Python's socket on macOS expects a tuple: (ctl_id, unit)
            # Unit 0 = let system assign the next available number
            self.tun_fd.connect((ctl_id, 0))

            # Find the newly created interface by comparing before/after
            new_utuns = self._list_utun_interfaces()
            created = set(new_utuns) - set(existing_utuns)

            if created:
                self.interface_name = sorted(created)[-1]  # Take the newest one
                # Extract unit number from name
                self._utun_unit = int(self.interface_name.replace('utun', ''))
            else:
                # Fallback: find highest numbered utun
                if new_utuns:
                    self.interface_name = sorted(new_utuns, key=lambda x: int(x.replace('utun', '')))[-1]
                    self._utun_unit = int(self.interface_name.replace('utun', ''))
                else:
                    self.interface_name = "utun0"
                    self._utun_unit = 0

            logger.info(f"Created utun interface: {self.interface_name}")
            return True

        except PermissionError:
            logger.error("Permission denied. Run with sudo")
            return False
        except Exception as e:
            logger.error(f"Failed to create utun interface: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _list_utun_interfaces(self) -> list:
        """List all current utun interfaces."""
        try:
            result = subprocess.run(
                ["ifconfig", "-l"],
                capture_output=True, text=True, check=True
            )
            interfaces = result.stdout.strip().split()
            return [i for i in interfaces if i.startswith("utun")]
        except Exception:
            return []

    def configure(self) -> bool:
        """Configure the utun interface with IP address."""
        try:
            # Assign IP address and bring up
            # macOS ifconfig syntax: ifconfig <iface> <addr> <dest> netmask <mask>
            subprocess.run([
                "ifconfig", self.interface_name,
                self.local_ip, self.local_ip,
                "netmask", "255.0.0.0",
                "mtu", "1400",
                "up"
            ], check=True, capture_output=True)

            # Add route for Malachi network
            subprocess.run([
                "route", "add", "-net", "10.0.0.0/8",
                "-interface", self.interface_name
            ], check=True, capture_output=True)

            logger.info(f"Configured {self.interface_name} with {self.local_ip}/8")
            self._register_local_mapping()
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure interface: {e.stderr.decode() if e.stderr else e}")
            return False
        except Exception as e:
            logger.error(f"Configuration error: {e}")
            return False

    def destroy(self):
        """Destroy the utun interface."""
        # Remove route first
        try:
            subprocess.run([
                "route", "delete", "-net", "10.0.0.0/8"
            ], capture_output=True)
        except:
            pass

        super().destroy()

    def _read_packet(self) -> Optional[bytes]:
        """Read a packet from the utun device."""
        try:
            readable, _, _ = select.select([self.tun_fd], [], [], 0.1)
            if not readable:
                return None

            # utun prepends 4-byte protocol info (AF_INET = 2)
            data = self.tun_fd.recv(65535)
            if len(data) <= 4:
                return None

            # Strip protocol header, return IP packet
            return data[4:]
        except Exception:
            return None

    def _write_packet(self, packet: bytes) -> bool:
        """Write a packet to the utun device."""
        try:
            # Prepend 4-byte protocol header (AF_INET = 2 for IPv4)
            header = struct.pack('>I', 2)  # AF_INET in network byte order
            self.tun_fd.send(header + packet)
            return True
        except Exception as e:
            logger.error(f"Failed to write packet: {e}")
            return False


# =============================================================================
# BSD Implementation (FreeBSD, OpenBSD, NetBSD)
# =============================================================================

class BSDTunInterface(TunInterfaceBase):
    """
    BSD TUN interface using /dev/tunX.

    Works on:
    - FreeBSD
    - OpenBSD
    - NetBSD
    - DragonFlyBSD

    Requires:
    - Root privileges
    - tun device available (/dev/tun0, /dev/tun1, etc.)
    """

    def __init__(self, interface_name: str = "tun0", node_id: Optional[bytes] = None):
        super().__init__(interface_name, node_id)
        self._tun_number: int = 0

    def create(self) -> bool:
        """Create the TUN interface using BSD /dev/tunX."""
        # Try to find an available tun device
        for i in range(16):
            tun_path = f"/dev/tun{i}"
            try:
                self.tun_fd = os.open(tun_path, os.O_RDWR)
                self._tun_number = i
                self.interface_name = f"tun{i}"
                logger.info(f"Created TUN interface: {self.interface_name}")
                return True
            except FileNotFoundError:
                continue
            except PermissionError:
                logger.error(f"Permission denied for {tun_path}. Run as root.")
                return False
            except OSError as e:
                if e.errno == 16:  # EBUSY - device in use
                    continue
                raise

        logger.error("No available tun devices found")
        return False

    def configure(self) -> bool:
        """Configure the TUN interface with IP address."""
        try:
            # Detect BSD variant for correct commands
            bsd_variant = platform.system().lower()

            if bsd_variant == 'openbsd':
                # OpenBSD uses different ifconfig syntax
                subprocess.run([
                    "ifconfig", self.interface_name,
                    "inet", self.local_ip, "255.0.0.0",
                    "mtu", "1400", "up"
                ], check=True, capture_output=True)

                # Add route
                subprocess.run([
                    "route", "add", "-inet", "10.0.0.0/8", self.local_ip
                ], check=True, capture_output=True)

            elif bsd_variant == 'netbsd':
                # NetBSD syntax
                subprocess.run([
                    "ifconfig", self.interface_name,
                    "inet", self.local_ip, "netmask", "255.0.0.0", "up"
                ], check=True, capture_output=True)

                subprocess.run([
                    "route", "add", "-net", "10.0.0.0/8", self.local_ip
                ], check=True, capture_output=True)

            else:
                # FreeBSD / DragonFlyBSD syntax
                subprocess.run([
                    "ifconfig", self.interface_name,
                    "inet", self.local_ip, "netmask", "255.0.0.0",
                    "mtu", "1400", "up"
                ], check=True, capture_output=True)

                subprocess.run([
                    "route", "add", "-net", "10.0.0.0/8", self.local_ip
                ], check=True, capture_output=True)

            logger.info(f"Configured {self.interface_name} with {self.local_ip}/8")
            self._register_local_mapping()
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to configure interface: {e}")
            return False
        except Exception as e:
            logger.error(f"Configuration error: {e}")
            return False

    def destroy(self):
        """Destroy the TUN interface."""
        # Remove route
        try:
            subprocess.run([
                "route", "delete", "-net", "10.0.0.0/8"
            ], capture_output=True)
        except:
            pass

        super().destroy()

    def _read_packet(self) -> Optional[bytes]:
        """Read a packet from the TUN device."""
        try:
            readable, _, _ = select.select([self.tun_fd], [], [], 0.1)
            if not readable:
                return None

            # BSD tun devices may prepend address family (4 bytes) depending on config
            data = os.read(self.tun_fd, 65535)

            if len(data) < 4:
                return None

            # Check if there's an address family header
            # If first byte looks like IP version (4 or 6), no header
            if (data[0] >> 4) in (4, 6):
                return data

            # Otherwise strip 4-byte header
            return data[4:]

        except Exception:
            return None

    def _write_packet(self, packet: bytes) -> bool:
        """Write a packet to the TUN device."""
        try:
            # BSD may need address family header
            # AF_INET = 2 (but in host byte order on BSD)
            header = struct.pack('@I', 2)  # Native byte order
            os.write(self.tun_fd, header + packet)
            return True
        except Exception as e:
            logger.error(f"Failed to write packet: {e}")
            return False


# =============================================================================
# Factory Function
# =============================================================================

def create_tun_interface(
    interface_name: Optional[str] = None,
    node_id: Optional[bytes] = None
) -> TunInterfaceBase:
    """
    Create a platform-appropriate TUN interface.

    Args:
        interface_name: Desired interface name (platform may override)
        node_id: Our Malachi node ID

    Returns:
        TunInterfaceBase implementation for current platform

    Raises:
        RuntimeError: If platform is not supported
    """
    if IS_LINUX:
        name = interface_name or "mal0"
        return LinuxTunInterface(name, node_id)
    elif IS_MACOS:
        name = interface_name or "utun"
        return MacOSTunInterface(name, node_id)
    elif IS_BSD:
        name = interface_name or "tun0"
        return BSDTunInterface(name, node_id)
    else:
        raise RuntimeError(f"Unsupported platform: {PLATFORM}")


# Backwards compatibility alias
MalachiTunInterface = create_tun_interface


class MalachiNetworkDaemon:
    """
    System daemon that manages Malachi networking.

    Provides:
    - TUN interface (mal0 on Linux, utunX on macOS, tunX on BSD)
    - Node ID to IP mapping
    - Automatic neighbor discovery
    - Route management

    Works on Linux, macOS, and BSD systems.
    """

    def __init__(
        self,
        physical_interface: str,
        node_id: bytes,
        signing_key=None,
        malachi_send_func: Optional[Callable[[bytes, bytes], None]] = None,
    ):
        """
        Initialize the network daemon.

        Args:
            physical_interface: Physical interface for Malachi (e.g., eth0)
            node_id: Our node ID
            signing_key: Ed25519 signing key (optional, for future use)
            malachi_send_func: Function to send packets via Malachi network
        """
        self.physical_interface = physical_interface
        self.node_id = node_id
        self.signing_key = signing_key
        self._malachi_send_func = malachi_send_func

        # Create platform-appropriate TUN interface
        self.tun = create_tun_interface(node_id=node_id)

        # State
        self._running = False
        self._neighbors: Dict[bytes, str] = {}  # node_id -> virtual_ip
        self._routes: Dict[bytes, RouteInfo] = {}  # node_id -> route info
        self._lock = threading.Lock()

        # Mesh networking node (initialized on start)
        self.mesh_node = None

        # LAN manager for discovery and health monitoring
        self.lan_manager = None

    def start(self):
        """Start the daemon."""
        logger.info(f"Starting Malachi Network Daemon on {PLATFORM}...")

        # Create TUN interface
        if not self.tun.create():
            raise RuntimeError("Failed to create TUN interface")

        if not self.tun.configure():
            self.tun.destroy()
            raise RuntimeError("Failed to configure TUN interface")

        # Set up send callback
        self.tun.set_send_callback(self._send_malachi)

        # Start TUN reader
        self.tun.start()

        self._running = True

        # Start mesh networking node
        try:
            from .mesh import MeshNode
            self.mesh_node = MeshNode(self.node_id, port=7891)
            if self.mesh_node.start():
                logger.info("Mesh networking node started")

                # Set up message handler to integrate with TUN
                def on_mesh_message(src_node: bytes, data: bytes):
                    # Deliver received mesh messages to TUN interface
                    self.on_malachi_packet(src_node, data)

                self.mesh_node.on_message(on_mesh_message)

                # Use mesh node for sending
                self._malachi_send_func = self.mesh_node.send
            else:
                logger.warning("Failed to start mesh node, continuing without mesh networking")
                self.mesh_node = None
        except ImportError as e:
            logger.warning(f"Mesh module not available: {e}")
            self.mesh_node = None
        except Exception as e:
            logger.warning(f"Failed to initialize mesh node: {e}")
            self.mesh_node = None

        # Initialize LAN manager for discovery and health monitoring
        if HAS_LAN_MANAGER and self.mesh_node:
            try:
                self.lan_manager = LANManager(
                    node_id=self.node_id,
                    send_discover_func=self._send_ndp_discover,
                    send_ping_func=self._send_health_ping,
                    interfaces=[self.physical_interface] if self.physical_interface else None
                )

                # Set up callbacks
                self.lan_manager.on_peer_added(self._on_lan_peer_added)
                self.lan_manager.on_peer_removed(self._on_lan_peer_removed)

                self.lan_manager.start()
                logger.info("LAN manager started (discovery + health monitoring)")
            except Exception as e:
                logger.warning(f"Failed to start LAN manager: {e}")
                self.lan_manager = None

        logger.info(f"Malachi daemon started on {self.tun.interface_name}")
        logger.info(f"  Platform:   {PLATFORM}")
        logger.info(f"  Node ID:    {self.node_id.hex()}")
        logger.info(f"  Virtual IP: {self.tun.local_ip}")
        if self.mesh_node:
            logger.info(f"  Mesh Port:  7891")
        if self.lan_manager:
            logger.info(f"  LAN Manager: Active")

    def stop(self):
        """Stop the daemon."""
        self._running = False

        # Stop LAN manager
        if self.lan_manager:
            try:
                self.lan_manager.stop()
                logger.info("LAN manager stopped")
            except Exception as e:
                logger.warning(f"Error stopping LAN manager: {e}")
            self.lan_manager = None

        # Stop mesh node
        if self.mesh_node:
            try:
                self.mesh_node.stop()
                logger.info("Mesh node stopped")
            except Exception as e:
                logger.warning(f"Error stopping mesh node: {e}")
            self.mesh_node = None

        self.tun.stop()
        self.tun.destroy()
        logger.info("Malachi daemon stopped")

    def set_send_function(self, func: Callable[[bytes, bytes], None]):
        """Set the function used to send packets via Malachi."""
        self._malachi_send_func = func

    def _send_ndp_discover(self, interface: str) -> bool:
        """Send NDP discover packet on interface (for LAN manager)."""
        try:
            from .discovery import NDPHandler
            from .crypto import load_or_create_ed25519, load_or_create_x25519, generate_node_id

            # Load keys
            signing_key, verify_key = load_or_create_ed25519()
            x25519_priv, x25519_pub = load_or_create_x25519()

            handler = NDPHandler(
                my_id=self.node_id,
                ed25519_sk=signing_key,
                ed25519_pub=bytes(verify_key),
                x25519_pub=x25519_pub,
                x25519_priv=x25519_priv,
            )

            return handler.send_discover(interface)
        except Exception as e:
            logger.debug(f"NDP discover failed on {interface}: {e}")
            return False

    def _send_health_ping(self, node_id: bytes, address: Tuple[str, int], ping_id: int):
        """Send health ping to a peer (for LAN manager)."""
        if self.mesh_node:
            try:
                # Use mesh node's ping mechanism with embedded ping_id
                import struct
                from .mesh import MeshMsgType
                ping_data = struct.pack(">B16sI", MeshMsgType.PING, self.node_id, ping_id)
                self.mesh_node._send_packet(address, ping_data)
            except Exception as e:
                logger.debug(f"Health ping failed to {node_id.hex()[:8]}: {e}")

    def _on_lan_peer_added(self, node_id: bytes, address: Tuple[str, int]):
        """Called when LAN manager discovers a new peer."""
        virtual_ip = self.add_neighbor(node_id)
        logger.info(f"LAN peer discovered: {node_id.hex()[:8]} -> {virtual_ip}")

    def _on_lan_peer_removed(self, node_id: bytes):
        """Called when LAN manager removes a dead peer."""
        self.remove_neighbor(node_id)
        logger.info(f"LAN peer expired: {node_id.hex()[:8]}")

    def add_neighbor(
        self,
        node_id: bytes,
        hops: list = None,
        latency_ms: float = 0.0,
        connection_type: str = "direct"
    ) -> str:
        """
        Add a discovered neighbor with route information.

        Args:
            node_id: The neighbor's node ID
            hops: List of intermediate node IDs (empty for direct connection)
            latency_ms: Measured latency to this node
            connection_type: "direct", "relay", or "mesh"

        Returns:
            Virtual IP allocated for this neighbor
        """
        with self._lock:
            if hops is None:
                hops = []

            if node_id not in self._neighbors:
                virtual_ip = self.tun.allocate_ip(node_id)
                self._neighbors[node_id] = virtual_ip
                logger.info(f"Neighbor added: {node_id.hex()[:8]} -> {virtual_ip}")
            else:
                virtual_ip = self._neighbors[node_id]

            # Update or create route info
            self._routes[node_id] = RouteInfo(
                dest_node_id=node_id,
                dest_virtual_ip=virtual_ip,
                hops=hops,
                latency_ms=latency_ms,
                connection_type=connection_type,
                physical_interface=self.physical_interface,
            )

            return virtual_ip

    def remove_neighbor(self, node_id: bytes):
        """Remove a neighbor and its route."""
        with self._lock:
            if node_id in self._neighbors:
                del self._neighbors[node_id]
            if node_id in self._routes:
                del self._routes[node_id]
            logger.info(f"Neighbor removed: {node_id.hex()[:8]}")

    def get_neighbors(self) -> Dict[bytes, str]:
        """Get all known neighbors."""
        with self._lock:
            return dict(self._neighbors)

    def get_routes(self) -> Dict[bytes, RouteInfo]:
        """Get all known routes."""
        with self._lock:
            return dict(self._routes)

    def get_route(self, node_id: bytes) -> Optional[RouteInfo]:
        """Get route info for a specific node."""
        with self._lock:
            return self._routes.get(node_id)

    def update_route(
        self,
        node_id: bytes,
        latency_ms: float = None,
        hops: list = None,
        connection_type: str = None
    ):
        """Update route information for a node."""
        with self._lock:
            if node_id in self._routes:
                route = self._routes[node_id]
                if latency_ms is not None:
                    route.latency_ms = latency_ms
                if hops is not None:
                    route.hops = hops
                if connection_type is not None:
                    route.connection_type = connection_type
                route.last_updated = time.time()

    def get_topology(self) -> dict:
        """
        Get the full network topology for visualization.

        Returns:
            Dictionary with nodes, edges, and connection info
        """
        with self._lock:
            nodes = []
            edges = []
            seen_nodes = set()

            # Add self as central node
            nodes.append({
                'id': self.node_id.hex(),
                'label': f"You\n{self.tun.local_ip}",
                'virtual_ip': self.tun.local_ip,
                'is_self': True,
                'type': 'self'
            })
            seen_nodes.add(self.node_id.hex())

            # Add neighbors from internal routes
            for node_id, route in self._routes.items():
                node_hex = node_id.hex()
                if node_hex in seen_nodes:
                    continue
                seen_nodes.add(node_hex)

                nodes.append({
                    'id': node_hex,
                    'label': f"{node_hex[:8]}\n{route.dest_virtual_ip}",
                    'virtual_ip': route.dest_virtual_ip,
                    'is_self': False,
                    'type': route.connection_type,
                    'latency_ms': route.latency_ms,
                    'hop_count': route.hop_count
                })

                if route.is_direct:
                    edges.append({
                        'from': self.node_id.hex(),
                        'to': node_hex,
                        'type': 'direct',
                        'latency_ms': route.latency_ms
                    })
                else:
                    prev_node = self.node_id.hex()
                    for hop in route.hops:
                        hop_hex = hop.hex() if isinstance(hop, bytes) else hop
                        edges.append({
                            'from': prev_node,
                            'to': hop_hex,
                            'type': 'relay'
                        })
                        prev_node = hop_hex
                    edges.append({
                        'from': prev_node,
                        'to': node_hex,
                        'type': 'relay',
                        'latency_ms': route.latency_ms
                    })

            # Also add peers from mesh node DHT
            if self.mesh_node:
                try:
                    dht_peers = self.mesh_node.dht.get_all_peers()
                    for peer in dht_peers:
                        node_hex = peer.node_id.hex()
                        if node_hex in seen_nodes:
                            continue
                        seen_nodes.add(node_hex)

                        # Calculate virtual IP from node ID
                        node_hash = int.from_bytes(peer.node_id[:4], 'big')
                        second = (node_hash >> 16) & 0xFF
                        third = (node_hash >> 8) & 0xFF
                        fourth = node_hash & 0xFF
                        if second == 0 and third == 0 and fourth < 2:
                            fourth = 2
                        virtual_ip = f"10.{second}.{third}.{fourth}"

                        nodes.append({
                            'id': node_hex,
                            'label': f"{node_hex[:8]}\n{virtual_ip}",
                            'virtual_ip': virtual_ip,
                            'is_self': False,
                            'type': 'direct' if peer.is_alive() else 'stale',
                            'latency_ms': 0,
                            'hop_count': 1
                        })

                        # Add edge from us to this peer
                        edges.append({
                            'from': self.node_id.hex(),
                            'to': node_hex,
                            'type': 'direct' if peer.is_alive() else 'stale',
                            'latency_ms': 0
                        })
                except Exception as e:
                    logger.debug(f"Error getting DHT peers for topology: {e}")

            direct_count = sum(1 for e in edges if e.get('type') == 'direct')
            relay_count = sum(1 for e in edges if e.get('type') in ('relay', 'stale'))

            return {
                'self_id': self.node_id.hex(),
                'self_ip': self.tun.local_ip,
                'nodes': nodes,
                'edges': edges,
                'total_neighbors': len(nodes) - 1,
                'direct_connections': direct_count,
                'relay_connections': relay_count
            }

    def on_malachi_packet(self, src_node_id: bytes, payload: bytes):
        """
        Handle incoming Malachi packet.

        Injects it into the TUN interface for delivery to applications.
        """
        # Ensure neighbor is registered
        self.add_neighbor(src_node_id)

        # Notify LAN manager of peer activity
        if self.lan_manager:
            # Get address from mesh node if available
            if self.mesh_node:
                peer = self.mesh_node.dht.get_peer(src_node_id)
                if peer:
                    self.lan_manager.peer_discovered(src_node_id, peer.address)

        # Inject into TUN
        self.tun.inject_packet(src_node_id, payload)

    def _send_malachi(self, dest_node_id: bytes, payload: bytes):
        """Send packet via Malachi (callback from TUN)."""
        if self._malachi_send_func:
            self._malachi_send_func(dest_node_id, payload)
        else:
            logger.debug(f"Sending {len(payload)} bytes to {dest_node_id.hex()[:8]} (no send function configured)")

    def print_status(self):
        """Print daemon status with network topology."""
        stats = self.tun.get_stats()
        topology = self.get_topology()

        print(f"\n{'='*70}")
        print("                    MALACHI NETWORK DAEMON STATUS")
        print('='*70)
        print(f"  Platform:     {stats['platform']}")
        print(f"  Interface:    {stats['interface']}")
        print(f"  Node ID:      {self.node_id.hex()}")
        print(f"  Virtual IP:   {stats['local_ip']}")
        print(f"  Running:      {stats['running']}")
        print()

        # Connection summary
        print(f"  Connections:  {topology['total_neighbors']} total")
        print(f"                {topology['direct_connections']} direct, {topology['relay_connections']} relayed")
        print()

        # Network topology visualization
        if self._routes:
            print('='*70)
            print("                       NETWORK TOPOLOGY")
            print('='*70)
            print()
            self._print_topology_tree()
            print()

            # Detailed route table
            print('-'*70)
            print("  ROUTE TABLE")
            print('-'*70)
            print(f"  {'Virtual IP':<16} {'Node ID':<18} {'Hops':<6} {'Latency':<10} {'Type':<10}")
            print(f"  {'-'*16} {'-'*18} {'-'*6} {'-'*10} {'-'*10}")

            for node_id, route in sorted(self._routes.items(), key=lambda x: x[1].hop_count):
                latency_str = f"{route.latency_ms:.1f}ms" if route.latency_ms > 0 else "N/A"
                print(f"  {route.dest_virtual_ip:<16} {node_id.hex()[:18]} {route.hop_count:<6} {latency_str:<10} {route.connection_type:<10}")

        print()

    def _print_topology_tree(self):
        """Print ASCII art network topology."""
        routes = list(self._routes.values())

        if not routes:
            print("  No connections")
            return

        # Group by connection type
        direct = [r for r in routes if r.is_direct]
        relayed = [r for r in routes if not r.is_direct]

        # Print self node at center
        self_label = f"[YOU: {self.tun.local_ip}]"
        print(f"  {' ' * 25}{self_label}")
        print(f"  {' ' * 25}{'|'}")
        print(f"  {' ' * 20}{'─' * 5}┴{'─' * 5}")

        # Print direct connections
        if direct:
            num_direct = len(direct)
            spacing = 60 // (num_direct + 1)
            line1 = "  "
            line2 = "  "
            line3 = "  "

            for i, route in enumerate(direct[:6]):  # Max 6 direct connections shown
                pos = spacing * (i + 1)
                node_label = f"{route.dest_node_id.hex()[:8]}"
                ip_label = f"{route.dest_virtual_ip}"
                latency = f"{route.latency_ms:.0f}ms" if route.latency_ms > 0 else ""

                # Build connection lines
                line1 += f"{'|':^{spacing}}"
                line2 += f"{node_label:^{spacing}}"
                line3 += f"{ip_label} {latency}".center(spacing)

            print(line1)
            print(line2)
            print(line3)

        # Print relayed connections
        if relayed:
            print()
            print(f"  {' ' * 20}Relayed connections:")
            for route in relayed[:4]:  # Max 4 relayed shown
                path_str = " → ".join([self.node_id.hex()[:6]] +
                                      [h.hex()[:6] if isinstance(h, bytes) else h[:6] for h in route.hops] +
                                      [route.dest_node_id.hex()[:6]])
                latency = f" ({route.latency_ms:.0f}ms)" if route.latency_ms > 0 else ""
                print(f"  {' ' * 22}{path_str}{latency}")
                print(f"  {' ' * 22}└─> {route.dest_virtual_ip}")

    def print_lan_status(self):
        """Print detailed LAN status with health monitoring."""
        if self.lan_manager:
            print(self.lan_manager.format_status())
        else:
            print("LAN manager not available.")
            print("Basic status:")
            self.print_status()

    def get_lan_status(self) -> dict:
        """Get LAN status as dictionary."""
        if self.lan_manager:
            return self.lan_manager.get_status()
        return {
            'discovery': {},
            'interfaces': [],
            'peers': [],
            'summary': {'total_peers': 0, 'healthy': 0, 'unhealthy': 0, 'dead': 0}
        }


# =============================================================================
# CLI Tool: malctl
# =============================================================================

def malctl_status():
    """Show Malachi network status."""
    # Detect platform-specific interface name
    if IS_MACOS:
        iface = "utunX"
        plat = "macOS"
    elif IS_BSD:
        iface = "tunX"
        plat = "BSD"
    else:
        iface = "mal0"
        plat = "Linux"

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                   MALACHI NETWORK STATUS                     ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Platform:   {plat:48}║
║  Interface:  {iface:48}║
║  Status:     UP                                              ║
║  Node ID:    a1b2c3d4e5f67890abcdef1234567890                ║
║  Virtual IP: 10.0.0.1                                      ║
║                                                              ║
║  Neighbors:  3                                               ║
║  Routes:     5                                               ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  NEIGHBOR TABLE                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Virtual IP      Node ID             Interface    Latency    ║
║  ─────────────────────────────────────────────────────────── ║
║  10.45.23.100    c3d4e5f6...         {iface:12} 2ms        ║
║  10.128.5.42    a9b8c7d6...         {iface:12} 15ms       ║
║  10.200.100.50  1a2b3c4d...         {iface:12} 3ms        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def malctl_neighbors():
    """List neighbors."""
    print("""
MALACHI NEIGHBORS
═════════════════════════════════════════════════════════════

Node ID                           Virtual IP       Interface
────────────────────────────────  ───────────────  ─────────
c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8  10.45.23.100     eth0
a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4  10.128.5.42     wlan0
1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d  10.200.100.50   eth0
""")


def malctl_help():
    """Show help."""
    # Platform-specific info
    if IS_MACOS:
        plat_info = "macOS (utun interface)"
        run_cmd = "sudo python3 -m malachi.tun_interface start"
    elif IS_BSD:
        plat_info = f"BSD ({platform.system()})"
        run_cmd = "sudo python3 -m malachi.tun_interface start"
    else:
        plat_info = "Linux (tun interface)"
        run_cmd = "sudo python3 -m malachi.tun_interface start"

    print(f"""
malctl - Malachi Network Control

PLATFORM: {plat_info}

USAGE:
    python3 -m malachi.tun_interface <command> [options]

DAEMON COMMANDS:
    start       Start the Malachi network daemon
    status      Show network status (demo)
    lan-status  Show LAN status with health monitoring
    neighbors   List discovered neighbors (demo)
    platform    Show platform support info

NETWORK TOOLS:
    ping <target>       Ping a node by ID or virtual IP
    trace <target>      Trace route to a node
    lookup <address>    Look up node ID <-> virtual IP mapping
    scan                Discover nodes on the network
    scan <target> -p    Port scan a specific node
    nc <target> <port>  Netcat-like connection tool
    nc -l <port>        Listen for connections
    stats               Show network statistics
    route               Show routing table
    keys                Manage node identities

EXAMPLES:
    # Start the daemon (required for networking)
    {run_cmd}

    # Ping by virtual IP
    python3 -m malachi.tun_interface ping 10.45.23.100

    # Ping by node ID (full or short)
    python3 -m malachi.tun_interface ping a1b2c3d4e5f67890abcdef1234567890
    python3 -m malachi.tun_interface ping a1b2c3d4

    # Continuous ping
    python3 -m malachi.tun_interface ping -c 0 10.45.23.100

    # Traceroute
    python3 -m malachi.tun_interface trace 10.200.100.50

    # Look up address
    python3 -m malachi.tun_interface lookup a1b2c3d4e5f67890

    # Scan for nodes
    python3 -m malachi.tun_interface scan

    # Port scan a node
    python3 -m malachi.tun_interface scan 10.45.23.100 -p 22,80,443

    # Connect to a node (netcat-style)
    python3 -m malachi.tun_interface nc 10.45.23.100 8080

    # Listen for connections
    python3 -m malachi.tun_interface nc -l 8080

    # Watch network stats
    python3 -m malachi.tun_interface stats -w

    # Generate new identity
    python3 -m malachi.tun_interface keys generate

PYTHON API:
    from malachi.tun_interface import MalachiSocket, MalachiNetworkDaemon

    daemon = MalachiNetworkDaemon("en0", node_id)
    daemon.start()

    sock = MalachiSocket(daemon)
    sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))
    sock.send(b"Hello Malachi!")
""")


def malctl_lan_status():
    """Show detailed LAN status with health monitoring."""
    if not HAS_LAN_MANAGER:
        print("LAN manager module not available.")
        return

    interfaces = detect_network_interfaces()

    print("=== Malachi LAN Status ===")
    print()

    # Show detected interfaces
    print("Detected Network Interfaces:")
    if interfaces:
        for iface in interfaces:
            wireless = " [wireless]" if iface.is_wireless else ""
            print(f"  {iface.name}: {iface.ip} ({iface.mac}){wireless}")
    else:
        print("  No suitable interfaces detected")
    print()

    print("Note: For full LAN status with peer health, run the daemon")
    print("      and check status via the daemon's print_lan_status() method.")
    print()

    # Show some helpful info
    print("LAN Features Available:")
    print("  - Adaptive discovery (2s-60s interval based on network activity)")
    print("  - Health monitoring (RTT, packet loss, connection state)")
    print("  - Automatic peer expiration (120s timeout)")
    print("  - Multi-interface support")


def malctl_platform():
    """Show platform support info."""
    print(f"""
MALACHI TUN INTERFACE - PLATFORM SUPPORT
========================================

Current Platform: {platform.system()} ({platform.release()})

Supported Platforms:
  [{'X' if IS_LINUX else ' '}] Linux     - /dev/net/tun (mal0 interface)
  [{'X' if IS_MACOS else ' '}] macOS     - utun socket API (utunX interface)
  [{'X' if IS_BSD else ' '}] FreeBSD   - /dev/tunX character device
  [{'X' if IS_BSD else ' '}] OpenBSD   - /dev/tunX character device
  [{'X' if IS_BSD else ' '}] NetBSD    - /dev/tunX character device
  [ ] Windows   - Not yet supported (requires WinTun)

Requirements:
  - Root/sudo privileges (or CAP_NET_ADMIN on Linux)
  - Python 3.7+

Virtual Network: 10.0.0.0/8
  - Your node:  10.0.0.1
  - Neighbors:  10.x.x.x (based on node ID hash)
""")


# =============================================================================
# User-Space Socket Wrapper
# =============================================================================

class MalachiSocket:
    """
    Drop-in replacement for socket that uses Malachi.

    Allows applications to connect using either:
    - Node ID (32-char hex string): "a1b2c3d4e5f67890abcdef1234567890"
    - Virtual IP: "10.45.23.100"

    Usage:
        # Using daemon reference
        sock = MalachiSocket(daemon)
        sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))
        sock.send(b"Hello!")
        data = sock.recv(1024)
        sock.close()

        # Or with virtual IP
        sock.connect(("10.45.23.100", 8080))
    """

    def __init__(self, daemon: MalachiNetworkDaemon):
        """
        Initialize socket.

        Args:
            daemon: Running MalachiNetworkDaemon instance
        """
        self.daemon = daemon
        self._dest_node_id: Optional[bytes] = None
        self._dest_port: int = 0
        self._local_port: int = 0
        self._connected = False
        self._recv_buffer: bytes = b""

    def connect(self, address: Tuple[str, int]):
        """
        Connect to a node by ID or virtual IP.

        Args:
            address: Tuple of (host, port) where host is node ID or virtual IP
        """
        host, port = address

        # Check if it's a node ID (32-char hex string = 16 bytes)
        if len(host) == 32 and all(c in '0123456789abcdef' for c in host.lower()):
            self._dest_node_id = bytes.fromhex(host)
        elif host.startswith("10."):
            # Virtual IP - look up node ID
            self._dest_node_id = self.daemon.tun.get_node_id(host)
            if not self._dest_node_id:
                raise ConnectionError(f"Unknown host: {host}")
        else:
            raise ValueError(f"Invalid Malachi address: {host}. Use node ID or 10.x.x.x")

        self._dest_port = port
        self._connected = True

    def bind(self, address: Tuple[str, int]):
        """Bind to a local port."""
        _, port = address
        self._local_port = port

    def send(self, data: bytes) -> int:
        """Send data to connected node."""
        if not self._connected or not self._dest_node_id:
            raise RuntimeError("Not connected")

        # Create L4-style packet with ports
        packet = struct.pack(">HH", self._local_port, self._dest_port) + data

        # Send via daemon
        self.daemon._send_malachi(self._dest_node_id, packet)
        return len(data)

    def sendto(self, data: bytes, address: Tuple[str, int]) -> int:
        """Send data to specific address (UDP-style)."""
        host, port = address

        # Resolve node ID
        if len(host) == 32 and all(c in '0123456789abcdef' for c in host.lower()):
            node_id = bytes.fromhex(host)
        elif host.startswith("10."):
            node_id = self.daemon.tun.get_node_id(host)
            if not node_id:
                raise ConnectionError(f"Unknown host: {host}")
        else:
            raise ValueError(f"Invalid Malachi address: {host}")

        packet = struct.pack(">HH", self._local_port, port) + data
        self.daemon._send_malachi(node_id, packet)
        return len(data)

    def recv(self, bufsize: int) -> bytes:
        """Receive data (blocking)."""
        # TODO: Integrate with port manager for actual receiving
        raise NotImplementedError("Use port manager for receiving")

    def recvfrom(self, bufsize: int) -> Tuple[bytes, Tuple[str, int]]:
        """Receive data with sender info."""
        # TODO: Integrate with port manager
        raise NotImplementedError("Use port manager for receiving")

    def close(self):
        """Close the socket."""
        self._dest_node_id = None
        self._connected = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def malctl_start():
    """Start the Malachi network daemon."""
    import signal

    print("Starting Malachi Network Daemon...")
    print(f"Platform: {platform.system()}")

    # Generate or load node identity
    try:
        from .crypto import load_or_create_ed25519, generate_node_id
        signing_key, verify_key = load_or_create_ed25519()
        node_id = generate_node_id(bytes(verify_key))
        print(f"Loaded node identity: {node_id.hex()}")
    except ImportError as e:
        # Fallback: generate random node ID
        import secrets
        node_id = secrets.token_bytes(16)
        signing_key = None
        print(f"Warning: crypto module not available ({e}), using random node ID")

    # Detect physical interface
    try:
        if IS_MACOS:
            result = subprocess.run(["route", "get", "default"], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'interface:' in line:
                    physical_iface = line.split(':')[1].strip()
                    break
            else:
                physical_iface = "en0"
        else:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            parts = result.stdout.split()
            physical_iface = parts[parts.index('dev') + 1] if 'dev' in parts else "eth0"
    except:
        physical_iface = "eth0"

    print(f"Physical interface: {physical_iface}")

    # Create and start daemon
    daemon = MalachiNetworkDaemon(physical_iface, node_id, signing_key)

    def signal_handler(sig, frame):
        print("\nShutting down...")
        daemon.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        daemon.start()
        daemon.print_status()

        print("\nDaemon running. Press Ctrl+C to stop.")

        # Keep running
        while True:
            time.sleep(1)

    except RuntimeError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass

    # Clean shutdown
    daemon.stop()
    print("Daemon stopped.")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    if len(sys.argv) < 2:
        malctl_help()
        sys.exit(0)

    cmd = sys.argv[1]

    # Built-in commands
    if cmd == "status":
        malctl_status()
    elif cmd == "neighbors":
        malctl_neighbors()
    elif cmd == "platform":
        malctl_platform()
    elif cmd in ("lan-status", "lan", "health"):
        malctl_lan_status()
    elif cmd == "start":
        malctl_start()
    elif cmd in ("help", "-h", "--help"):
        malctl_help()

    # Forward to tools module for network utilities
    elif cmd in ("ping", "trace", "traceroute", "scan", "nc", "netcat",
                 "stats", "lookup", "route", "keys"):
        try:
            from .tools import main as tools_main
        except ImportError:
            from tools import main as tools_main
        # Re-run with tools module
        sys.argv = ["malachi-tools"] + sys.argv[1:]
        tools_main()

    else:
        print(f"Unknown command: {cmd}")
        malctl_help()
        sys.exit(1)
