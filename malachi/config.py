"""
Configuration constants for Malachi Stack.

All protocol constants, paths, and tunable parameters are centralized here.
"""

from __future__ import annotations

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

# Packet padding configuration
PADDING_ENABLED = True  # Enable traffic analysis protection
PADDING_BLOCK_SIZE = 64  # Pad to multiples of this size
PADDING_MIN_SIZE = 128  # Minimum padded payload size

# Protocol magic strings for signatures and associated data
NDP_SIG_PREFIX = b"MNDPv2|"  # NDP signature transcript prefix
L3_SEC_AD_PREFIX = b"MN-L3S|"  # L3 secure container associated data prefix
L4_AD_PREFIX = b"MN-L4|"  # L4 datagram associated data prefix

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
SESSION_KEY_TTL = 60 * 60  # Session keys expire after 1 hour
SESSION_KEY_REKEY_THRESHOLD = 45 * 60  # Trigger rekey warning after 45 minutes

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
CONFIG_FILE = os.path.join(KEYDIR, "config.yaml")         # YAML configuration file


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


def load_config_file(path: Optional[str] = None) -> dict:
    """
    Load configuration from YAML file.

    Args:
        path: Path to config file (defaults to CONFIG_FILE)

    Returns:
        Configuration dict (empty if file doesn't exist)
    """
    config_path = path or CONFIG_FILE

    if not os.path.exists(config_path):
        return {}

    try:
        import yaml
        with open(config_path, "r") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else {}
    except ImportError:
        return {}
    except Exception:
        return {}


def save_default_config(path: Optional[str] = None) -> bool:
    """
    Save default configuration file.

    Args:
        path: Path to config file (defaults to CONFIG_FILE)

    Returns:
        True if saved successfully
    """
    config_path = path or CONFIG_FILE

    default_config = """\
# Malachi Stack Configuration
# https://github.com/FancyWaifu/Malachi_stack

# Network interface to use
# iface: en0

# Path to pre-shared key file (optional)
# psk_file: ~/.ministack/psk.key

# Logging settings
logging:
  # Enable file logging
  to_file: true
  # Log level: DEBUG, INFO, WARNING, ERROR
  level: INFO

# Security settings
security:
  # Enable packet padding for traffic analysis resistance
  padding_enabled: true
  # Session key TTL in seconds (3600 = 1 hour)
  session_key_ttl: 3600
  # Rekey threshold in seconds (2700 = 45 minutes)
  session_key_rekey_threshold: 2700

# Network settings
network:
  # Maximum payload size per frame
  payload_cap: 1400
  # Neighbor TTL in seconds
  neighbor_ttl: 1800
"""

    try:
        import yaml
        ensure_keydir()
        with open(config_path, "w") as f:
            f.write(default_config)
        return True
    except Exception:
        return False


def apply_config_file(runtime_config: "RuntimeConfig", file_config: dict) -> None:
    """
    Apply file configuration to runtime config.

    File config values are used as defaults, CLI args take precedence.
    """
    # Network interface
    if not runtime_config.iface and "iface" in file_config:
        runtime_config.iface = file_config["iface"]

    # PSK file
    if not runtime_config.psk_path and "psk_file" in file_config:
        runtime_config.psk_path = os.path.expanduser(file_config["psk_file"])

    # Logging settings
    logging_config = file_config.get("logging", {})
    if "to_file" in logging_config:
        runtime_config.log_to_file = logging_config["to_file"]
    if "level" in logging_config:
        runtime_config.log_level = logging_config["level"]
