# Malachi Stack

A custom Layer 3/4 network protocol for encrypted peer-to-peer communication over raw Ethernet.

Malachi provides a complete networking stack with automatic peer discovery, end-to-end encryption, and OS-level integration through virtual network interfaces. Applications can communicate using familiar IP-style addresses without any modification.

## Features

- **Custom L3/L4 Protocol** - Runs over raw Ethernet frames (EtherType 0x88B5)
- **End-to-End Encryption** - XChaCha20-Poly1305 AEAD with Ed25519/X25519 key exchange
- **Secure Node Discovery (NDPv2)** - Ed25519 signed discovery with challenge-response
- **OS Integration** - Virtual network interface appears in `ifconfig` (mal0/utun)
- **Cross-Platform** - Linux, macOS, and BSD support
- **Network Tools** - ping, traceroute, scan, netcat, and more
- **DNS Resolution** - Access nodes via `http://a1b2c3d4.mli/` URLs
- **Web UI** - Browser-based control panel for configuration
- **TOFU Pinning** - Trust-On-First-Use key pinning for peer verification
- **Optional PSK Binding** - Pre-shared key authentication for enhanced security
- **Interactive TUI** - Curses-based shell for network operations

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [TUN Interface](#tun-interface)
- [Network Tools](#network-tools)
- [DNS Resolution (.mli)](#dns-resolution-mli)
- [Web UI](#web-ui)
- [Python API](#python-api)
- [Interactive Shell](#interactive-shell)
- [Architecture](#architecture)
- [Security](#security)
- [Platform Support](#platform-support)
- [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.7+
- Root/sudo privileges (for raw Ethernet and TUN interface)
- libpcap (usually preinstalled)
- libsodium

#### Ubuntu/Debian
```bash
sudo apt install libpcap-dev libsodium23
```

#### macOS
```bash
brew install libsodium
```

### Install

```bash
# Clone the repository
git clone https://github.com/FancyWaifu/Malachi_stack.git
cd Malachi_stack

# Create virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
# Check platform support
python3 -m malachi.tun_interface platform

# Run tests
python3 -m pytest tests/ -v
```

---

## Quick Start

There are two ways to use Malachi:

### Option 1: TUN Interface (Recommended)

The TUN interface creates a virtual network interface that allows any application to communicate over Malachi using standard IP addresses.

```bash
# Start the daemon (requires sudo)
sudo python3 -m malachi.tun_interface start
```

You'll see:
```
Starting Malachi Network Daemon...
Platform: Darwin
Created utun interface: utun8
Configured utun8 with 10.144.0.1/16
Malachi daemon started on utun8
  Platform:   darwin
  Node ID:    a1b2c3d4e5f67890abcdef1234567890
  Virtual IP: 10.144.0.1
```

Now any application can send to `10.144.x.x` addresses:
```bash
# Ping another Malachi node
python3 -m malachi.tun_interface ping 10.144.45.23

# Or use standard tools (once peers are discovered)
ping 10.144.45.23
curl http://10.144.45.23:8080/
```

### Option 2: Interactive TUI Shell

For direct control over the protocol:

```bash
# Find your network interface
ifconfig  # or: ip link show

# Start the TUI
sudo python3 -m malachi --iface en0
```

See [Interactive Shell](#interactive-shell) for commands.

---

## TUN Interface

The TUN interface provides OS-level integration, making Malachi transparent to applications.

### How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                      Application                            │
│              socket.connect(("10.144.45.23", 80))          │
└───────────────────────┬─────────────────────────────────────┘
                        │ Standard TCP/IP
┌───────────────────────▼─────────────────────────────────────┐
│               mal0 / utun (TUN interface)                   │
│                    10.144.0.0/16                            │
└───────────────────────┬─────────────────────────────────────┘
                        │ Captured by daemon
┌───────────────────────▼─────────────────────────────────────┐
│                 Malachi Network Daemon                      │
│         Maps 10.144.x.x ←→ Malachi Node IDs                │
│         Encrypts with XChaCha20-Poly1305                   │
│         Handles discovery and key exchange                  │
└───────────────────────┬─────────────────────────────────────┘
                        │ Encrypted Malachi packets
┌───────────────────────▼─────────────────────────────────────┐
│              Physical Interface (eth0/en0)                  │
│                  Raw Ethernet Frames                        │
└─────────────────────────────────────────────────────────────┘
```

### Node ID to Virtual IP Mapping

Each 16-byte node ID deterministically maps to a virtual IP:

```
Node ID:     a1b2c3d4e5f67890abcdef1234567890
             ^^^^^^^^
             First 4 bytes → IP octets

Virtual IP:  10.144.195.212
                   ^^^  ^^^
                   0xc3 0xd4
```

This mapping is:
- **Deterministic** - Same node ID always produces the same IP
- **Consistent** - All peers calculate the same mapping
- **Collision-resistant** - Conflicts are automatically resolved

### Interface Names by Platform

| Platform | Interface | Notes |
|----------|-----------|-------|
| Linux | `mal0` | Uses `/dev/net/tun` |
| macOS | `utunX` | System assigns number |
| FreeBSD | `tunX` | Uses `/dev/tunX` |
| OpenBSD | `tunX` | Uses `/dev/tunX` |

### Daemon Commands

```bash
# Start daemon
sudo python3 -m malachi.tun_interface start

# Check status (demo)
python3 -m malachi.tun_interface status

# Show platform support
python3 -m malachi.tun_interface platform

# Show help
python3 -m malachi.tun_interface help
```

---

## Network Tools

Malachi includes familiar network utilities that work with node IDs or virtual IPs.

### malping - Ping Nodes

```bash
# Ping by virtual IP
python3 -m malachi.tun_interface ping 10.144.45.23

# Ping by full node ID (32 hex chars)
python3 -m malachi.tun_interface ping a1b2c3d4e5f67890abcdef1234567890

# Ping by short node ID prefix
python3 -m malachi.tun_interface ping a1b2c3d4

# Continuous ping
python3 -m malachi.tun_interface ping -c 0 10.144.45.23

# Custom options
python3 -m malachi.tun_interface ping -c 10 -i 0.5 -s 128 10.144.45.23
```

Output:
```
MALPING a1b2c3d4... (10.144.195.212): 64 data bytes
64 bytes from 10.144.195.212: seq=1 ttl=64 time=6.37ms
64 bytes from 10.144.195.212: seq=2 ttl=64 time=13.15ms
64 bytes from 10.144.195.212: seq=3 ttl=64 time=14.30ms

--- a1b2c3d4... (10.144.195.212) malping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max = 6.37/11.27/14.30 ms
```

### maltrace - Traceroute

```bash
# Trace route to node
python3 -m malachi.tun_interface trace 10.144.45.23

# Limit hops
python3 -m malachi.tun_interface trace -m 10 10.144.45.23
```

Output:
```
maltrace to 10.144.45.23, 30 hops max
  1  10.144.0.1  4.86ms  2.47ms  1.24ms
  2  10.144.191.19 (7bd7bf13...)  31.28ms  11.64ms  32.99ms
  3  10.144.45.23 (a1b2c3d4...)  8.47ms  18.25ms  12.07ms
```

### mallookup - Address Resolution

```bash
# Look up node ID → virtual IP
python3 -m malachi.tun_interface lookup a1b2c3d4e5f67890abcdef1234567890

# Look up virtual IP → node ID (if known)
python3 -m malachi.tun_interface lookup 10.144.195.212
```

Output:
```
Address:    a1b2c3d4e5f67890abcdef1234567890
Virtual IP: 10.144.195.212
Node ID:    a1b2c3d4e5f67890abcdef1234567890
Short ID:   a1b2c3d4...
Known:      No
```

### malscan - Network Discovery

```bash
# Discover nodes on network
python3 -m malachi.tun_interface scan

# Scan with timeout
python3 -m malachi.tun_interface scan -t 30

# Port scan a specific node
python3 -m malachi.tun_interface scan 10.144.45.23 -p 22,80,443,8080
```

### malnc - Netcat

```bash
# Connect to a node
python3 -m malachi.tun_interface nc 10.144.45.23 8080

# Listen for connections
python3 -m malachi.tun_interface nc -l 8080

# UDP mode
python3 -m malachi.tun_interface nc -u 10.144.45.23 8080
```

### malstat - Statistics

```bash
# Show stats once
python3 -m malachi.tun_interface stats

# Watch continuously
python3 -m malachi.tun_interface stats -w
```

### malroute - Routing Table

```bash
python3 -m malachi.tun_interface route
```

Output:
```
MALACHI ROUTING TABLE
======================================================================
Destination          Gateway              Interface    Metric
----------------------------------------------------------------------
10.144.0.1           local                mal0         0
10.144.0.0/16        *                    mal0         0
10.144.45.23         direct               mal0         1
```

### malkeys - Identity Management

```bash
# Generate new identity
python3 -m malachi.tun_interface keys generate

# List saved identities
python3 -m malachi.tun_interface keys list

# Show current identity
python3 -m malachi.tun_interface keys show
```

---

## DNS Resolution (.mli)

Access Malachi nodes using human-friendly URLs instead of virtual IPs.

### How It Works

```
http://a1b2c3d4.mli:8080/  →  http://10.144.195.212:8080/
     ^^^^^^^^                        ^^^^^^^^^^^^^^
     Node ID prefix                  Virtual IP (auto-resolved)
```

### Start the DNS Server

```bash
# Start DNS server (requires root for port 53)
sudo python3 -m malachi.dns start
```

### Configure Your System

**macOS** (automatic):
```bash
sudo python3 -m malachi.dns configure
# Creates /etc/resolver/mli
```

**Linux** (manual):
```bash
# Option 1: dnsmasq
echo 'server=/mli/127.0.0.1' | sudo tee /etc/dnsmasq.d/malachi.conf
sudo systemctl restart dnsmasq

# Option 2: systemd-resolved
sudo mkdir -p /etc/systemd/resolved.conf.d/
cat << EOF | sudo tee /etc/systemd/resolved.conf.d/malachi.conf
[Resolve]
DNS=127.0.0.1
Domains=~mli
EOF
sudo systemctl restart systemd-resolved
```

### Usage Examples

```bash
# Access a website hosted on a Malachi node
curl http://a1b2c3d4.mli:8080/

# Ping by DNS name
ping a1b2c3d4.mli

# SSH to a node
ssh user@a1b2c3d4.mli

# Open in browser
open http://a1b2c3d4.mli:8080/
```

### Test Resolution

```bash
# Test without running server
python3 -m malachi.dns test a1b2c3d4.mli

# Test with dig (when server is running)
dig @127.0.0.1 a1b2c3d4.mli
```

---

## Web UI

A browser-based control panel for configuring and monitoring Malachi.

### Start the Web UI

```bash
python3 -m malachi.webui
```

Then open: **http://localhost:7890**

### Features

| Tab | Description |
|-----|-------------|
| **Dashboard** | Node identity, daemon status, neighbor list |
| **Tools** | Ping, lookup, and scan with live output |
| **Config** | Interface selection, DNS setup, identity management |
| **Logs** | Real-time log viewer |

### Screenshots

**Dashboard:**
- View your Node ID and Virtual IP
- See discovered neighbors
- Start/stop daemon
- Broadcast discovery

**Tools:**
- Ping nodes by ID or IP
- Look up address mappings
- Scan network for nodes

### Custom Port

```bash
# Run on different port
python3 -m malachi.webui --port 8080

# Bind to specific interface
python3 -m malachi.webui --host 192.168.1.100 --port 8080
```

---

## Python API

### High-Level: Socket API

```python
from malachi.tun_interface import MalachiNetworkDaemon, MalachiSocket
from malachi.crypto import generate_node_identity

# Generate identity
node_id, signing_key, x25519_key = generate_node_identity()

# Start daemon
daemon = MalachiNetworkDaemon("en0", node_id, signing_key)
daemon.start()

# Create socket
sock = MalachiSocket(daemon)

# Connect by node ID
sock.connect(("a1b2c3d4e5f67890abcdef1234567890", 8080))

# Or by virtual IP
sock.connect(("10.144.45.23", 8080))

# Send data
sock.send(b"Hello Malachi!")

# Clean up
sock.close()
daemon.stop()
```

### Context Manager

```python
with MalachiSocket(daemon) as sock:
    sock.connect(("10.144.45.23", 8080))
    sock.send(b"Hello!")
# Automatically closed
```

### Low-Level: Direct Packet API

```python
from malachi.network import send_l4, start_listener
from malachi.crypto import generate_node_identity

# Generate identity
node_id, signing_key, _ = generate_node_identity()

# Start packet listener
start_listener("en0")

# Send encrypted L4 packet
send_l4(
    interface="en0",
    dst_node_id=bytes.fromhex("a1b2c3d4e5f67890abcdef1234567890"),
    dst_port=8080,
    src_port=12345,
    payload=b"Hello!",
    signing_key=signing_key
)
```

### Port Binding

```python
from malachi.ports import bind_udp, recv_from_port, unbind_udp

# Bind to port
bind_udp(8080, capacity=64)

# Receive (blocking with timeout)
result = recv_from_port(8080, timeout=10.0)
if result:
    src_node_id, src_port, payload = result
    print(f"From {src_node_id.hex()[:8]}:{src_port}: {payload}")

# Unbind
unbind_udp(8080)
```

### Multicast Groups

```python
from malachi.protocol import (
    create_multicast_group, join_group, leave_group, multicast_send
)

# Create group
group_id = create_multicast_group("my-channel")

# Join
join_group(group_id, my_node_id)

# Send to all members
multicast_send(group_id, b"Hello everyone!", signing_key)

# Leave
leave_group(group_id, my_node_id)
```

---

## Interactive Shell

The TUI provides direct protocol control:

```bash
sudo python3 -m malachi --iface en0
```

### Commands

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `id` | Display your NodeID |
| `ndp` | Broadcast node discovery |
| `peers` | List discovered peers |
| `bind <port> [cap]` | Bind local port |
| `unbind <port>` | Unbind a port |
| `ports` | List bound ports |
| `send <id> <mac> <port> <text>` | Send message to peer |
| `pull <port>` | Receive one message |
| `pull follow <port>` | Stream messages |
| `pull stop <port>` | Stop streaming |
| `keys` | Show identity paths |
| `quit` | Exit |

### Pre-Shared Key Authentication

```bash
# Create PSK
echo -n "supersecret" > psk.bin

# Run with PSK
sudo python3 -m malachi --iface en0 --psk-file psk.bin
```

---

## Architecture

### Project Structure

```
malachi/
├── __init__.py       # Package metadata
├── __main__.py       # TUI entry point
├── config.py         # Constants
├── crypto.py         # Cryptographic operations
├── packets.py        # Scapy packet definitions
├── state.py          # Thread-safe state
├── ports.py          # Port-based message queues
├── discovery.py      # NDPv2 protocol
├── network.py        # Send/receive operations
├── protocol.py       # High-level features
├── routing.py        # Multi-hop routing
├── multiface.py      # Multi-interface support
├── tun_interface.py  # OS TUN integration
├── tools.py          # Network utilities (ping, trace, etc.)
├── dns.py            # DNS resolver for .mli domains
├── webui.py          # Browser-based control panel
└── tui.py            # Interactive shell
```

### Protocol Stack

```
┌─────────────────────────────────────────────────────────────┐
│                   APPLICATION LAYER                          │
│  (Sockets, TUI, TUN Interface)                              │
├─────────────────────────────────────────────────────────────┤
│              PROTOCOL LAYER (protocol.py)                    │
│  Multicast | QoS | Connections | Streams | Req-Resp        │
├─────────────────────────────────────────────────────────────┤
│            PORTS & QUEUING (ports.py)                        │
│  Per-port queues | Listeners | Dispatching                 │
├─────────────────────────────────────────────────────────────┤
│  DISCOVERY & KEY EXCHANGE (discovery.py, crypto.py)         │
│  NDP2 | Ed25519 | X25519 | Session Keys                    │
├─────────────────────────────────────────────────────────────┤
│         ENCRYPTION (crypto.py)                               │
│  XChaCha20-Poly1305 | AEAD | Padding                        │
├─────────────────────────────────────────────────────────────┤
│              PACKET FORMAT (packets.py)                      │
│  Layer3 | Layer4 | SecureMeta                               │
├─────────────────────────────────────────────────────────────┤
│         RAW ETHERNET (network.py)                            │
│  EtherType 0x88B5 | Scapy                                   │
└─────────────────────────────────────────────────────────────┘
```

### Packet Format

**Layer 3 Header:**
```
┌────────┬─────┬───────┬────────────────┬────────────────┬─────────┐
│ Magic  │ Ver │ Type  │  Dest NodeID   │  Src NodeID    │ Payload │
│  2B    │ 1B  │  1B   │     16B        │     16B        │  var    │
└────────┴─────┴───────┴────────────────┴────────────────┴─────────┘
```

**Layer 4 Header:**
```
┌──────────┬──────────┬─────────┐
│ Src Port │ Dst Port │ Payload │
│    2B    │    2B    │   var   │
└──────────┴──────────┴─────────┘
```

**Encrypted Packet:**
```
┌───────────┬─────────┬──────────────────────────────┐
│ Nonce 24B │ Tag 16B │ Ciphertext (L4 + Payload)    │
└───────────┴─────────┴──────────────────────────────┘
```

---

## Security

### Cryptographic Primitives

| Component | Algorithm |
|-----------|-----------|
| Signatures | Ed25519 |
| Key Exchange | X25519 ECDH |
| Encryption | XChaCha20-Poly1305 |
| Hashing | BLAKE3 |
| Node ID | BLAKE3(context ‖ pubkey)[:16] |

### Security Features

- **Perfect Forward Secrecy** - New session keys per discovery
- **Replay Protection** - Nonce tracking and counter validation
- **Traffic Analysis Resistance** - Optional packet padding
- **TOFU Pinning** - Trust-on-first-use with persistent storage
- **Pre-Shared Key** - Optional PSK binding for closed networks

### Key Storage

Keys are stored in `~/.ministack/`:

| File | Description |
|------|-------------|
| `ed25519.key` | Private signing key (mode 0600) |
| `x25519.key` | Private encryption key (mode 0600) |
| `x25519.pub` | Public encryption key |
| `peers.json` | TOFU pin database |

---

## Platform Support

| Platform | Status | Interface | Requirements |
|----------|--------|-----------|--------------|
| Linux | ✅ Full | `mal0` | Root or CAP_NET_ADMIN |
| macOS | ✅ Full | `utunX` | Root |
| FreeBSD | ✅ Full | `tunX` | Root |
| OpenBSD | ✅ Full | `tunX` | Root |
| NetBSD | ✅ Full | `tunX` | Root |
| Windows | ❌ Planned | - | Requires WinTun |

### Check Your Platform

```bash
python3 -m malachi.tun_interface platform
```

---

## Troubleshooting

### "Permission denied"

Run with sudo:
```bash
sudo python3 -m malachi.tun_interface start
```

### "TUN device not found" (Linux)

Load the tun kernel module:
```bash
sudo modprobe tun
```

### Interface not appearing

Check daemon output for errors. Common issues:
- Another process using the TUN device
- Firewall blocking interface creation

### Nodes not discovering each other

1. Ensure both are on the same physical network segment
2. Check firewall isn't blocking EtherType 0x88B5
3. If using PSK, verify both have the same key

### "crypto module not available"

Install PyNaCl:
```bash
pip install pynacl
```

---

## Testing

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run specific tests
python3 -m pytest tests/test_tun_interface.py -v

# With coverage
python3 -m pytest tests/ --cov=malachi
```

---

## Contributing

Contributions welcome! Feel free to:
- Report issues
- Suggest improvements
- Submit pull requests

---

## License

MIT License - See LICENSE file for details.

---

## Acknowledgments

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation
- [PyNaCl](https://pynacl.readthedocs.io/) - Cryptography (libsodium bindings)
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) - Fast cryptographic hashing
