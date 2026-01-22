"""
Configuration constants for Malachi Stack.

All protocol constants, paths, and tunable parameters are centralized here.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ---------------- Protocol Constants ----------------

ETH_TYPE = 0x88B5  # Lab-only EtherType (not IANA-registered)

# Payload types for Layer 3
PT_DATA = 1       # L3 payload = raw DATA
PT_L4_DGRAM = 2   # L3 payload = our UDP-like L4 datagram
PT_NDP = 3        # Node Discovery Protocol (ARP-like)
PT_SECURE = 4     # Encrypted L3-and-above container

# NDP operation codes
NDP_OP_DISCOVER = 1   # Broadcast "who's out there?"
NDP_OP_ADVERTISE = 2  # Unicast "I am (node_id, mac)"

# Cryptographic constants
ED25519_PUB_LEN = 32
ED25519_SIG_LEN = 64
X25519_PUB_LEN = 32
NONCE_LEN = 16
AEAD_NONCE_LEN = 24  # XChaCha20-Poly1305 nonce size
AEAD_TAG_LEN = 16    # Poly1305 tag length

# Node identity
ID_LEN = 16  # NodeID length (bytes) = BLAKE3(pubkey)[:16]
KEYCTX = b"layer3-nodeid-v1"

# Packet structure
PAYLOAD_CAP = 1400  # Per-frame payload cap (safe single-frame size)
INNER_MAGIC = b"MNi1"  # Inner packet magic for integrity checking
L3_MAGIC = b"MN"
L3_VERSION = 1

# Secure suite identifiers
SEC_SUITE_XCHACHA20POLY1305 = 1


# ---------------- NDPv2 Parameters ----------------

NDP_PROTO_VER = 2
CHALLENGE_LEN = 16
PSK_TAG_LEN = 16
CHALLENGE_TTL = 180.0  # Seconds before challenge expires
MAX_OUTSTANDING_CH = 256


# ---------------- Neighbor / Replay / Rate-limit ----------------

MAX_NEIGHBORS = 1024  # Cap neighbor entries (LRU eviction)
NEIGHBOR_TTL = 30 * 60  # Seconds; drop if not refreshed (30 min)
NONCE_CACHE_SIZE = 128  # Recent nonces kept per peer
RX_CTR_CACHE_SIZE = 1024  # Per-peer replay cache for data-plane counters

# Per-MAC rate limits (token buckets)
NDP_RL_RATE = 5.0   # Tokens per second (per requester MAC)
NDP_RL_BURST = 10.0  # Burst size

# Global rate limits
NDP_GLOBAL_RATE = 50.0   # Tokens per second (global)
NDP_GLOBAL_BURST = 200.0  # Burst size (global)

# Rate limiter eviction
RL_MAX_MACS = 10000  # Maximum number of tracked MACs before eviction
RL_EVICTION_AGE = 3600  # Evict MAC entries older than this (seconds)


# ---------------- File Paths ----------------

KEYDIR = os.path.join(os.path.expanduser("~"), ".ministack")
ED25519_PATH = os.path.join(KEYDIR, "ed25519.key")       # base64(32B Ed25519 secret)
X25519_PRIV_PATH = os.path.join(KEYDIR, "x25519.key")    # base64(32B X25519 secret)
X25519_PUB_PATH = os.path.join(KEYDIR, "x25519.pub")     # base64(32B X25519 public)
PINS_PATH = os.path.join(KEYDIR, "peers.json")           # TOFU pins
LOG_DIR = os.path.join(KEYDIR, "logs")


# ---------------- Logging Configuration ----------------

LOG_FILE = os.path.join(LOG_DIR, "malachi.log")
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB per log file
LOG_BACKUP_COUNT = 5  # Keep 5 rotated log files
LOG_QUEUE_SIZE = 10000  # Max log messages in TUI queue


@dataclass
class RuntimeConfig:
    """Runtime configuration that can be modified at startup."""

    iface: str = ""
    psk_path: Optional[str] = None
    new_identity: bool = False
    log_to_file: bool = True
    log_level: str = "INFO"

    def __post_init__(self):
        """Ensure directories exist."""
        Path(KEYDIR).mkdir(parents=True, exist_ok=True)
        if self.log_to_file:
            Path(LOG_DIR).mkdir(parents=True, exist_ok=True)


def ensure_keydir() -> None:
    """Create the key directory if it doesn't exist."""
    Path(KEYDIR).mkdir(parents=True, exist_ok=True)


def chmod600(path: str) -> None:
    """Set file permissions to 0600 (owner read/write only)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Best effort on non-POSIX filesystems
