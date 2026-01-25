#!/usr/bin/env python3
"""
Malachi Ad-Hoc Network Test Script

Tests ad-hoc (IBSS) networking mode for direct peer-to-peer connections
without infrastructure (no router/access point needed).

Supports:
- Linux (using iw/ip commands)
- macOS (using networksetup/airport)

Usage:
    sudo python3 test_adhoc.py --setup          # Configure ad-hoc interface
    sudo python3 test_adhoc.py --teardown       # Restore normal WiFi
    sudo python3 test_adhoc.py --test           # Run connectivity tests
    sudo python3 test_adhoc.py --full           # Setup + test + teardown
    python3 test_adhoc.py --status              # Check current status (no sudo)
"""

import os
import sys
import time
import socket
import struct
import argparse
import subprocess
import platform
import json
import tempfile
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# =============================================================================
# Platform Detection
# =============================================================================

@dataclass
class PlatformInfo:
    """Information about the current platform."""
    os_name: str  # 'linux', 'darwin', 'windows'
    os_version: str
    is_root: bool
    wifi_interface: Optional[str]
    supports_adhoc: bool
    adhoc_method: str  # 'iw', 'airport', 'netsh', 'none'


def detect_platform() -> PlatformInfo:
    """Detect the current platform and its ad-hoc capabilities."""
    os_name = platform.system().lower()
    os_version = platform.release()
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    wifi_interface = None
    supports_adhoc = False
    adhoc_method = 'none'

    if os_name == 'linux':
        wifi_interface = _find_linux_wifi_interface()
        if wifi_interface:
            supports_adhoc = True
            adhoc_method = 'iw'

    elif os_name == 'darwin':
        wifi_interface = _find_macos_wifi_interface()
        if wifi_interface:
            supports_adhoc = True
            adhoc_method = 'airport'

    elif os_name == 'windows':
        # Windows ad-hoc is possible but complex
        adhoc_method = 'netsh'
        supports_adhoc = False  # Not implemented yet

    return PlatformInfo(
        os_name=os_name,
        os_version=os_version,
        is_root=is_root,
        wifi_interface=wifi_interface,
        supports_adhoc=supports_adhoc,
        adhoc_method=adhoc_method
    )


def _find_linux_wifi_interface() -> Optional[str]:
    """Find the primary WiFi interface on Linux."""
    try:
        # Check /sys/class/net for wireless interfaces
        net_path = Path('/sys/class/net')
        for iface in net_path.iterdir():
            wireless_path = iface / 'wireless'
            if wireless_path.exists():
                return iface.name

        # Fallback: try common names
        for name in ['wlan0', 'wlp2s0', 'wlp3s0', 'wifi0']:
            if (net_path / name).exists():
                return name

    except Exception:
        pass
    return None


def _find_macos_wifi_interface() -> Optional[str]:
    """Find the primary WiFi interface on macOS."""
    try:
        # Use networksetup to find WiFi interface
        result = subprocess.run(
            ['networksetup', '-listallhardwareports'],
            capture_output=True, text=True, timeout=10
        )

        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if 'Wi-Fi' in line or 'AirPort' in line:
                # Next line should have "Device: enX"
                if i + 1 < len(lines):
                    device_line = lines[i + 1]
                    if 'Device:' in device_line:
                        return device_line.split(':')[1].strip()

        # Fallback to common interface names
        for name in ['en0', 'en1']:
            result = subprocess.run(
                ['ifconfig', name],
                capture_output=True, text=True
            )
            if result.returncode == 0 and 'status: active' in result.stdout:
                return name

    except Exception:
        pass
    return 'en0'  # Default fallback


# =============================================================================
# Ad-Hoc Configuration
# =============================================================================

ADHOC_NETWORK_NAME = "MalachiMesh"
ADHOC_CHANNEL = 6
ADHOC_FREQUENCY = 2437  # MHz for channel 6


class AdhocConfigurator:
    """Configure ad-hoc networking for the current platform."""

    def __init__(self, platform_info: PlatformInfo):
        self.platform = platform_info
        self.original_state: Dict = {}
        self.state_file = Path(tempfile.gettempdir()) / 'malachi_adhoc_state.json'

    def save_original_state(self):
        """Save the current network state before modification."""
        state = {
            'timestamp': time.time(),
            'interface': self.platform.wifi_interface,
            'os': self.platform.os_name,
        }

        if self.platform.os_name == 'darwin':
            try:
                # Save current WiFi network
                result = subprocess.run(
                    ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'SSID:' in line and 'BSSID' not in line:
                        state['original_ssid'] = line.split(':')[1].strip()
                        break

                # Save WiFi power state
                result = subprocess.run(
                    ['networksetup', '-getairportpower', self.platform.wifi_interface],
                    capture_output=True, text=True, timeout=10
                )
                state['wifi_was_on'] = 'On' in result.stdout

            except Exception as e:
                print(f"  Warning: Could not save WiFi state: {e}")

        elif self.platform.os_name == 'linux':
            try:
                # Save current connection info
                result = subprocess.run(
                    ['iw', self.platform.wifi_interface, 'info'],
                    capture_output=True, text=True, timeout=10
                )
                state['iw_info'] = result.stdout

                # Check if connected to a network
                result = subprocess.run(
                    ['iwgetid', '-r'],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    state['original_ssid'] = result.stdout.strip()

            except Exception as e:
                print(f"  Warning: Could not save WiFi state: {e}")

        self.original_state = state

        # Save to file for recovery
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f)
        except Exception:
            pass

    def load_original_state(self) -> bool:
        """Load saved state from file."""
        try:
            if self.state_file.exists():
                with open(self.state_file) as f:
                    self.original_state = json.load(f)
                return True
        except Exception:
            pass
        return False

    def setup_adhoc(self, network_name: str = ADHOC_NETWORK_NAME,
                    channel: int = ADHOC_CHANNEL) -> bool:
        """Configure the WiFi interface for ad-hoc mode."""

        if not self.platform.is_root:
            print("ERROR: Root/sudo privileges required for ad-hoc setup")
            return False

        if not self.platform.wifi_interface:
            print("ERROR: No WiFi interface found")
            return False

        print(f"\n[Ad-Hoc Setup] Configuring {self.platform.wifi_interface}...")
        print(f"  Network: {network_name}")
        print(f"  Channel: {channel}")

        # Save current state first
        self.save_original_state()

        if self.platform.os_name == 'darwin':
            return self._setup_adhoc_macos(network_name, channel)
        elif self.platform.os_name == 'linux':
            return self._setup_adhoc_linux(network_name, channel)
        else:
            print(f"ERROR: Ad-hoc not supported on {self.platform.os_name}")
            return False

    def _setup_adhoc_macos(self, network_name: str, channel: int) -> bool:
        """Configure ad-hoc on macOS."""
        iface = self.platform.wifi_interface

        try:
            # Dissociate from current network
            print("  Disconnecting from current network...")
            subprocess.run(
                ['sudo', '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-z'],
                check=False, timeout=10
            )
            time.sleep(1)

            # Create ad-hoc network (IBSS)
            # On macOS, we use the airport utility to create a computer-to-computer network
            print(f"  Creating ad-hoc network '{network_name}'...")

            # Method 1: Use airport to create IBSS
            result = subprocess.run(
                ['sudo', '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
                 f'--ibss={network_name}', f'--channel={channel}'],
                capture_output=True, text=True, timeout=15
            )

            if result.returncode != 0:
                # Method 2: Create via networksetup (creates a hosted network)
                print("  Trying alternate method...")
                subprocess.run(
                    ['sudo', 'networksetup', '-createnetworkservice', 'MalachiAdhoc', iface],
                    check=False, timeout=10
                )

            # Assign IP address
            print("  Assigning IP address...")
            # Generate IP from hostname hash for uniqueness
            host_hash = hash(socket.gethostname()) & 0xFF
            ip_addr = f"192.168.73.{max(2, host_hash % 254)}"

            subprocess.run(
                ['sudo', 'ifconfig', iface, 'inet', ip_addr, 'netmask', '255.255.255.0'],
                check=True, timeout=10
            )

            print(f"  Assigned IP: {ip_addr}")
            print(f"\n  SUCCESS: Ad-hoc network '{network_name}' created!")
            print(f"  Other devices should join '{network_name}' on channel {channel}")

            return True

        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Command failed: {e}")
            return False
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def _setup_adhoc_linux(self, network_name: str, channel: int) -> bool:
        """Configure ad-hoc (IBSS) on Linux."""
        iface = self.platform.wifi_interface
        freq = 2412 + (channel - 1) * 5  # Calculate frequency

        try:
            # Stop NetworkManager for this interface (if running)
            print("  Stopping NetworkManager control...")
            subprocess.run(
                ['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'no'],
                check=False, timeout=10
            )
            time.sleep(0.5)

            # Bring interface down
            print("  Bringing interface down...")
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', iface, 'down'],
                check=True, timeout=10
            )

            # Set interface to IBSS mode
            print("  Setting IBSS mode...")
            subprocess.run(
                ['sudo', 'iw', iface, 'set', 'type', 'ibss'],
                check=True, timeout=10
            )

            # Bring interface up
            print("  Bringing interface up...")
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', iface, 'up'],
                check=True, timeout=10
            )
            time.sleep(0.5)

            # Join/create IBSS network
            print(f"  Joining IBSS network '{network_name}' on {freq} MHz...")
            subprocess.run(
                ['sudo', 'iw', iface, 'ibss', 'join', network_name, str(freq)],
                check=True, timeout=10
            )

            # Assign IP address
            host_hash = hash(socket.gethostname()) & 0xFF
            ip_addr = f"192.168.73.{max(2, host_hash % 254)}"

            print(f"  Assigning IP: {ip_addr}")
            subprocess.run(
                ['sudo', 'ip', 'addr', 'add', f'{ip_addr}/24', 'dev', iface],
                check=False, timeout=10  # May fail if already assigned
            )

            print(f"\n  SUCCESS: Joined IBSS network '{network_name}'!")
            return True

        except subprocess.CalledProcessError as e:
            print(f"  ERROR: Command failed: {e}")
            return False
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def teardown_adhoc(self) -> bool:
        """Restore normal WiFi configuration."""

        if not self.platform.is_root:
            print("ERROR: Root/sudo privileges required")
            return False

        # Try to load saved state
        self.load_original_state()

        print(f"\n[Ad-Hoc Teardown] Restoring {self.platform.wifi_interface}...")

        if self.platform.os_name == 'darwin':
            return self._teardown_adhoc_macos()
        elif self.platform.os_name == 'linux':
            return self._teardown_adhoc_linux()
        else:
            return False

    def _teardown_adhoc_macos(self) -> bool:
        """Restore normal WiFi on macOS."""
        iface = self.platform.wifi_interface

        try:
            # Dissociate from ad-hoc network
            print("  Leaving ad-hoc network...")
            subprocess.run(
                ['sudo', '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-z'],
                check=False, timeout=10
            )
            time.sleep(1)

            # Turn WiFi off and on to reset
            print("  Resetting WiFi...")
            subprocess.run(
                ['networksetup', '-setairportpower', iface, 'off'],
                check=False, timeout=10
            )
            time.sleep(1)
            subprocess.run(
                ['networksetup', '-setairportpower', iface, 'on'],
                check=False, timeout=10
            )
            time.sleep(2)

            # Reconnect to original network if saved
            if self.original_state.get('original_ssid'):
                ssid = self.original_state['original_ssid']
                print(f"  Reconnecting to '{ssid}'...")
                subprocess.run(
                    ['networksetup', '-setairportnetwork', iface, ssid],
                    check=False, timeout=30
                )

            print("  SUCCESS: WiFi restored")

            # Clean up state file
            if self.state_file.exists():
                self.state_file.unlink()

            return True

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def _teardown_adhoc_linux(self) -> bool:
        """Restore normal WiFi on Linux."""
        iface = self.platform.wifi_interface

        try:
            # Leave IBSS
            print("  Leaving IBSS network...")
            subprocess.run(
                ['sudo', 'iw', iface, 'ibss', 'leave'],
                check=False, timeout=10
            )

            # Bring interface down
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', iface, 'down'],
                check=False, timeout=10
            )

            # Set back to managed mode
            print("  Setting managed mode...")
            subprocess.run(
                ['sudo', 'iw', iface, 'set', 'type', 'managed'],
                check=True, timeout=10
            )

            # Bring interface up
            subprocess.run(
                ['sudo', 'ip', 'link', 'set', iface, 'up'],
                check=True, timeout=10
            )

            # Re-enable NetworkManager control
            print("  Restoring NetworkManager control...")
            subprocess.run(
                ['sudo', 'nmcli', 'device', 'set', iface, 'managed', 'yes'],
                check=False, timeout=10
            )

            # Reconnect to original network
            if self.original_state.get('original_ssid'):
                ssid = self.original_state['original_ssid']
                print(f"  Reconnecting to '{ssid}'...")
                subprocess.run(
                    ['nmcli', 'connection', 'up', ssid],
                    check=False, timeout=30
                )

            print("  SUCCESS: WiFi restored")

            # Clean up state file
            if self.state_file.exists():
                self.state_file.unlink()

            return True

        except Exception as e:
            print(f"  ERROR: {e}")
            return False

    def get_status(self) -> Dict:
        """Get current ad-hoc status."""
        status = {
            'platform': self.platform.os_name,
            'interface': self.platform.wifi_interface,
            'mode': 'unknown',
            'network': None,
            'ip_address': None,
            'is_adhoc': False,
        }

        if not self.platform.wifi_interface:
            return status

        iface = self.platform.wifi_interface

        if self.platform.os_name == 'darwin':
            try:
                result = subprocess.run(
                    ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', '-I'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'SSID:' in line and 'BSSID' not in line:
                        status['network'] = line.split(':')[1].strip()
                    if 'state:' in line:
                        status['mode'] = line.split(':')[1].strip()
                    if 'op mode:' in line:
                        mode = line.split(':')[1].strip().lower()
                        status['is_adhoc'] = 'ibss' in mode or 'adhoc' in mode

                # Get IP
                result = subprocess.run(
                    ['ifconfig', iface],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            status['ip_address'] = parts[1]
                            break

            except Exception:
                pass

        elif self.platform.os_name == 'linux':
            try:
                result = subprocess.run(
                    ['iw', iface, 'info'],
                    capture_output=True, text=True, timeout=10
                )
                status['is_adhoc'] = 'type IBSS' in result.stdout or 'type ibss' in result.stdout

                for line in result.stdout.split('\n'):
                    if 'ssid' in line.lower():
                        status['network'] = line.split()[-1]
                    if 'type' in line.lower():
                        status['mode'] = line.split()[-1]

                # Get IP
                result = subprocess.run(
                    ['ip', 'addr', 'show', iface],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            status['ip_address'] = parts[1].split('/')[0]
                            break

            except Exception:
                pass

        return status


# =============================================================================
# Connectivity Tests
# =============================================================================

def discover_adhoc_peers(timeout: float = 5.0) -> List[Dict]:
    """Discover other Malachi nodes on the ad-hoc network."""
    peers = []

    try:
        # Create broadcast socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.bind(('', 0))

        # Generate our node ID
        our_node_id = os.urandom(16)

        # Send discovery ping
        ping = struct.pack('>B16s', 0x01, our_node_id)

        # Broadcast on ad-hoc subnet
        for subnet in ['192.168.73.255', '255.255.255.255']:
            try:
                sock.sendto(ping, (subnet, 7891))
            except Exception:
                pass

        print(f"\n[Discovery] Listening for peers ({timeout}s timeout)...")

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) >= 17:
                    msg_type = data[0]
                    peer_id = data[1:17]

                    if peer_id != our_node_id:
                        peer_info = {
                            'address': addr[0],
                            'port': addr[1],
                            'node_id': peer_id.hex()[:16],
                            'msg_type': 'PONG' if msg_type == 0x02 else f'0x{msg_type:02x}'
                        }

                        # Avoid duplicates
                        if not any(p['address'] == addr[0] for p in peers):
                            peers.append(peer_info)
                            print(f"  Found: {addr[0]} - {peer_id.hex()[:16]}...")

            except socket.timeout:
                continue
            except Exception as e:
                print(f"  Error: {e}")
                break

        sock.close()

    except Exception as e:
        print(f"Discovery error: {e}")

    return peers


def test_peer_connectivity(peer_ip: str, port: int = 7891) -> Tuple[bool, float]:
    """Test connectivity to a specific peer."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)

        # Send ping
        node_id = os.urandom(16)
        ping = struct.pack('>B16s', 0x01, node_id)

        start = time.time()
        sock.sendto(ping, (peer_ip, port))

        # Wait for response
        try:
            data, addr = sock.recvfrom(1024)
            rtt = (time.time() - start) * 1000  # ms
            sock.close()
            return True, rtt
        except socket.timeout:
            sock.close()
            return False, 0.0

    except Exception as e:
        print(f"  Connection error: {e}")
        return False, 0.0


def run_adhoc_tests(configurator: AdhocConfigurator) -> bool:
    """Run ad-hoc connectivity tests."""

    print("\n" + "=" * 60)
    print("  MALACHI AD-HOC NETWORK TESTS")
    print("=" * 60)

    # Check status
    status = configurator.get_status()

    print(f"\n[Status]")
    print(f"  Platform:  {status['platform']}")
    print(f"  Interface: {status['interface']}")
    print(f"  Mode:      {status['mode']}")
    print(f"  Network:   {status['network'] or 'None'}")
    print(f"  IP:        {status['ip_address'] or 'None'}")
    print(f"  Ad-Hoc:    {'Yes' if status['is_adhoc'] else 'No'}")

    if not status['ip_address']:
        print("\n  WARNING: No IP address assigned!")
        print("  Make sure ad-hoc network is configured.")
        return False

    # Discover peers
    peers = discover_adhoc_peers(timeout=5.0)

    if not peers:
        print("\n  No peers found on ad-hoc network.")
        print("  Make sure other devices have joined the same network.")
        print(f"  Network name: {ADHOC_NETWORK_NAME}")
        print(f"  Channel: {ADHOC_CHANNEL}")
        return False

    print(f"\n[Found {len(peers)} peer(s)]")

    # Test connectivity to each peer
    print("\n[Connectivity Tests]")
    successful = 0

    for peer in peers:
        ip = peer['address']
        success, rtt = test_peer_connectivity(ip)

        if success:
            print(f"  {ip}: OK ({rtt:.1f}ms)")
            successful += 1
        else:
            print(f"  {ip}: TIMEOUT")

    # Summary
    print("\n" + "-" * 60)
    print(f"  Results: {successful}/{len(peers)} peers reachable")

    if successful == len(peers):
        print("  STATUS: ALL TESTS PASSED")
        return True
    elif successful > 0:
        print("  STATUS: PARTIAL SUCCESS")
        return True
    else:
        print("  STATUS: FAILED")
        return False


# =============================================================================
# Main
# =============================================================================

def print_banner():
    """Print the script banner."""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║           MALACHI AD-HOC NETWORK TEST SCRIPT              ║
    ╠═══════════════════════════════════════════════════════════╣
    ║  Test direct peer-to-peer networking without a router     ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(
        description="Malachi Ad-Hoc Network Test Script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 test_adhoc.py --setup        # Configure ad-hoc mode
  sudo python3 test_adhoc.py --test         # Run connectivity tests
  sudo python3 test_adhoc.py --teardown     # Restore normal WiFi
  sudo python3 test_adhoc.py --full         # Full test cycle
  python3 test_adhoc.py --status            # Check status (no sudo)
        """
    )

    parser.add_argument('--setup', action='store_true',
                       help='Configure WiFi for ad-hoc mode')
    parser.add_argument('--teardown', action='store_true',
                       help='Restore normal WiFi configuration')
    parser.add_argument('--test', action='store_true',
                       help='Run ad-hoc connectivity tests')
    parser.add_argument('--full', action='store_true',
                       help='Full cycle: setup, test, teardown')
    parser.add_argument('--status', action='store_true',
                       help='Show current network status')
    parser.add_argument('--network', type=str, default=ADHOC_NETWORK_NAME,
                       help=f'Ad-hoc network name (default: {ADHOC_NETWORK_NAME})')
    parser.add_argument('--channel', type=int, default=ADHOC_CHANNEL,
                       help=f'WiFi channel (default: {ADHOC_CHANNEL})')

    args = parser.parse_args()

    # If no action specified, show help
    if not any([args.setup, args.teardown, args.test, args.full, args.status]):
        parser.print_help()
        return 1

    print_banner()

    # Detect platform
    platform_info = detect_platform()

    print(f"[Platform Detection]")
    print(f"  OS:        {platform_info.os_name} {platform_info.os_version}")
    print(f"  Root:      {'Yes' if platform_info.is_root else 'No'}")
    print(f"  WiFi:      {platform_info.wifi_interface or 'Not found'}")
    print(f"  Ad-Hoc:    {'Supported' if platform_info.supports_adhoc else 'Not supported'}")
    print(f"  Method:    {platform_info.adhoc_method}")

    if not platform_info.supports_adhoc:
        print("\nERROR: Ad-hoc networking not supported on this platform")
        return 1

    configurator = AdhocConfigurator(platform_info)

    # Handle actions
    if args.status:
        status = configurator.get_status()
        print(f"\n[Current Status]")
        for key, value in status.items():
            print(f"  {key}: {value}")
        return 0

    if args.full:
        # Full cycle
        if not configurator.setup_adhoc(args.network, args.channel):
            return 1

        print("\nWaiting for network to stabilize...")
        time.sleep(3)

        success = run_adhoc_tests(configurator)

        print("\nRestoring normal configuration...")
        configurator.teardown_adhoc()

        return 0 if success else 1

    if args.setup:
        if not configurator.setup_adhoc(args.network, args.channel):
            return 1
        print("\nAd-hoc network configured!")
        print("Run 'python3 test_adhoc.py --test' to test connectivity")
        print("Run 'sudo python3 test_adhoc.py --teardown' to restore WiFi")
        return 0

    if args.test:
        success = run_adhoc_tests(configurator)
        return 0 if success else 1

    if args.teardown:
        if not configurator.teardown_adhoc():
            return 1
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
