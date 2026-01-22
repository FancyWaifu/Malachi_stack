# Malachi Stack

A custom network stack in Python for learning and experimentation. It runs directly over Ethernet, performs secure node discovery, and encrypts Layer-3 and above using modern cryptography.

## Features

- **Custom L3/L4 Protocol**: Runs over raw Ethernet frames (EtherType 0x88B5)
- **Secure Node Discovery (NDPv2)**: Ed25519 signed discovery with challenge-response
- **End-to-End Encryption**: XChaCha20-Poly1305 AEAD for all data traffic
- **TOFU Pinning**: Trust-On-First-Use key pinning for peer verification
- **Optional PSK Binding**: Pre-shared key authentication for enhanced security
- **Interactive TUI**: Curses-based shell for network operations

## Architecture

```
malachi/
├── __init__.py      # Package metadata
├── __main__.py      # Entry point
├── config.py        # Constants and configuration
├── exceptions.py    # Custom exception types
├── logging_setup.py # File and TUI logging
├── crypto.py        # Cryptographic operations
├── packets.py       # Scapy packet definitions
├── state.py         # Thread-safe state management
├── ports.py         # Port-based message queues
├── discovery.py     # NDPv2 protocol
├── network.py       # Send/receive operations
└── tui.py           # Interactive shell
```

## Prerequisites

1. **Linux/macOS** with Python 3.10+ (Windows untested)
2. **Root privileges** (or CAP_NET_RAW) for raw Ethernet frames
3. **libpcap**: Usually preinstalled
   - Ubuntu: `sudo apt install libpcap-dev`
4. **libsodium**: Cryptographic library
   - Ubuntu: `sudo apt install libsodium23`
   - macOS: `brew install libsodium`

## Installation

```bash
# Clone the repository
git clone https://github.com/FancyWaifu/Malachi_stack.git
cd Malachi_stack

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Starting the Interactive Shell

```bash
# Find your network interface (e.g., en0, eth0, enp5s0)
ip link show  # Linux
ifconfig      # macOS

# Run with root privileges
sudo python3 -m malachi --iface <interface>

# Or use the convenience wrapper
sudo python3 run.py --iface <interface>
```

This generates an identity (Ed25519 + X25519 keys) stored in `~/.ministack/`.

### Command Line Options

```
--iface IFACE       Network interface (required)
--new-identity      Generate fresh identity (overwrites existing)
--psk-file PATH     PSK file for NDPv2 authentication
--no-log-file       Disable file logging
--log-level LEVEL   DEBUG, INFO, WARNING, ERROR (default: INFO)
```

### Shell Commands

Once in the TUI shell:

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `id` | Display your NodeID |
| `ndp` | Broadcast node discovery |
| `peers` | List discovered peers |
| `bind <port> [cap]` | Bind local port (default capacity: 64) |
| `unbind <port>` | Unbind a port |
| `ports` | List bound ports |
| `send <id> <mac> <port> <text>` | Send message to peer |
| `pull <port>` | Receive one message |
| `pull follow <port>` | Stream messages (tail -f style) |
| `pull stop <port>` | Stop streaming |
| `keys` | Show identity and key paths |
| `quit` | Exit |

### Pre-Shared Key (PSK) Authentication

For additional security, bind discovery to a shared secret:

```bash
# Create PSK file (base64 or raw)
echo -n "supersecret" > psk.bin

# Run with PSK
sudo python3 -m malachi --iface <interface> --psk-file psk.bin
```

Both peers must use the same PSK to discover each other.

## Cryptographic Design

| Component | Algorithm |
|-----------|-----------|
| Identity | Ed25519 signing keys |
| Key Agreement | X25519 ECDH |
| Session Keys | libsodium crypto_kx |
| Encryption | XChaCha20-Poly1305 AEAD |
| Hashing | BLAKE3 |

## Key Storage

Keys are stored in `~/.ministack/`:

| File | Description |
|------|-------------|
| `ed25519.key` | Private signing key (0600) |
| `x25519.key` | Private encryption key (0600) |
| `x25519.pub` | Public encryption key |
| `peers.json` | TOFU pin database |
| `logs/malachi.log` | Rotating log file |

## Legacy Compatibility

The original single-file version (`stack.py`) is still available for reference but the modular version in `malachi/` is recommended for new usage.

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions welcome! This is a learning project, so feel free to:
- Report issues
- Suggest improvements
- Submit pull requests
