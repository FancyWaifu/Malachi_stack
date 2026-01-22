"""
Entry point for Malachi Stack.

Run with: python -m malachi --iface <interface>
"""

from __future__ import annotations

import argparse
import base64
import signal
import sys
import atexit

from .config import (
    KEYDIR,
    ED25519_PATH,
    X25519_PRIV_PATH,
    X25519_PUB_PATH,
    PINS_PATH,
    RuntimeConfig,
    load_config_file,
    apply_config_file,
    save_default_config,
    CONFIG_FILE,
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
from .state import get_pins, get_stop_flag
from .discovery import init_ndp_handler
from .network import init_network
from .tui import run_shell
from .preflight import run_preflight_checks, validate_startup
from .exceptions import InterfaceError


def _setup_signal_handlers() -> None:
    """Configure signal handlers for graceful shutdown."""
    stop_flag = get_stop_flag()

    def _shutdown_handler(signum: int, frame) -> None:
        """Handle shutdown signals."""
        sig_name = signal.Signals(signum).name if hasattr(signal, 'Signals') else str(signum)
        log(f"[SHUTDOWN] Received {sig_name}, initiating graceful shutdown...")
        stop_flag.set()

    # Register handlers for common termination signals
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # SIGHUP for reload (Unix only)
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, _shutdown_handler)


def _cleanup() -> None:
    """Cleanup function called at exit."""
    log("[CLEANUP] Malachi Stack shutting down...")


def main():
    """Main entry point for Malachi Stack."""
    ap = argparse.ArgumentParser(
        description="Malachi Stack - Secure L3/L4 Network over Ethernet"
    )
    ap.add_argument(
        "--iface",
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
    ap.add_argument(
        "--config",
        help=f"Path to config file (default: {CONFIG_FILE})",
    )
    ap.add_argument(
        "--init-config",
        action="store_true",
        help="Generate default configuration file and exit",
    )
    args = ap.parse_args()

    # Generate default config if requested
    if args.init_config:
        config_path = args.config or CONFIG_FILE
        if save_default_config(config_path):
            print(f"Default configuration saved to: {config_path}")
            sys.exit(0)
        else:
            print(f"Failed to save configuration to: {config_path}")
            sys.exit(1)

    # Load configuration file
    file_config = load_config_file(args.config)

    # Initialize configuration (CLI args take precedence over file)
    config = RuntimeConfig(
        iface=args.iface or "",
        psk_path=args.psk_file,
        new_identity=args.new_identity,
        log_to_file=not args.no_log_file,
        log_level=args.log_level,
    )

    # Apply file config as defaults
    apply_config_file(config, file_config)

    # Validate required arguments
    if not config.iface:
        ap.error("--iface is required (or set 'iface' in config file)")

    # Run pre-flight checks
    print("Running pre-flight checks...")
    try:
        validate_startup(config.iface)
        print("All pre-flight checks passed.\n")
    except InterfaceError as e:
        print(f"\nError: {e}")
        print("\nTry running with sudo or check your interface name.")
        sys.exit(1)

    # Setup logging
    setup_logging(
        log_to_file=config.log_to_file,
        log_to_tui=True,
        log_level=config.log_level,
    )

    # Setup signal handlers and cleanup
    _setup_signal_handlers()
    atexit.register(_cleanup)

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
