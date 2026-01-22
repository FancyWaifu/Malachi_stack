"""
Entry point for Malachi Stack.

Run with: python -m malachi --iface <interface>
"""

import argparse
import base64

from .config import (
    KEYDIR,
    ED25519_PATH,
    X25519_PRIV_PATH,
    X25519_PUB_PATH,
    PINS_PATH,
    RuntimeConfig,
)
from .crypto import (
    init_libsodium,
    load_or_create_ed25519,
    derive_and_store_x25519,
    generate_node_id,
    id_to_hex,
    load_psk,
)
from .logging_setup import setup_logging, log
from .state import get_pins
from .discovery import init_ndp_handler
from .network import init_network
from .tui import run_shell


def main():
    """Main entry point for Malachi Stack."""
    ap = argparse.ArgumentParser(
        description="Malachi Stack - Secure L3/L4 Network over Ethernet"
    )
    ap.add_argument(
        "--iface",
        required=True,
        help="Network interface (e.g., en0, eth0)",
    )
    ap.add_argument(
        "--new-identity",
        action="store_true",
        help="Force-generate a new Ed25519 identity (overwrites existing)",
    )
    ap.add_argument(
        "--psk-file",
        help="Path to PSK file for NDPv2 (enables PSK binding)",
    )
    ap.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable file logging",
    )
    ap.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Log level (default: INFO)",
    )
    args = ap.parse_args()

    # Initialize configuration
    config = RuntimeConfig(
        iface=args.iface,
        psk_path=args.psk_file,
        new_identity=args.new_identity,
        log_to_file=not args.no_log_file,
        log_level=args.log_level,
    )

    # Setup logging
    setup_logging(
        log_to_file=config.log_to_file,
        log_to_tui=True,
        log_level=config.log_level,
    )

    # Initialize libsodium
    init_libsodium()

    # Load or create identity
    sk, vk = load_or_create_ed25519(force_new=config.new_identity)
    my_id = generate_node_id(bytes(vk))

    # Derive X25519 keys
    x25519_priv, x25519_pub = derive_and_store_x25519(sk, vk)

    # Load PSK if provided
    psk = load_psk(config.psk_path)

    # Initialize NDP handler
    init_ndp_handler(
        my_id=my_id,
        ed25519_sk=sk,
        ed25519_pub=bytes(vk),
        x25519_pub=x25519_pub,
        x25519_priv=x25519_priv,
        psk=psk,
    )

    # Initialize network module
    init_network(my_id)

    # Load pins
    get_pins()  # Initialize pin store

    # Log startup info
    ed_pub_b64 = base64.b64encode(bytes(vk)).decode("ascii")
    x_pub_b64 = base64.b64encode(x25519_pub).decode("ascii")

    log(
        "[KEYS] Identity & encryption ready:\n"
        f"  NodeID      : {id_to_hex(my_id)}\n"
        f"  Ed25519 pub : {ed_pub_b64}\n"
        f"  X25519 pub  : {x_pub_b64}\n"
        f"  files       :\n"
        f"    {ED25519_PATH} (private, 0600)\n"
        f"    {X25519_PRIV_PATH} (private, 0600)\n"
        f"    {X25519_PUB_PATH}  (public)\n"
        f"    {PINS_PATH}  (pins)\n"
        + (
            f"  NDPv2: PSK enabled ({len(psk)} bytes)"
            if psk
            else "  NDPv2: PSK disabled; TOFU pinning active"
        )
    )

    # Run interactive shell
    try:
        run_shell(config.iface, my_id)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
