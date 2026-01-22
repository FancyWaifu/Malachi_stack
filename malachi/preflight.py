"""
Pre-flight checks for Malachi Stack.

Validates system requirements before starting the network stack.
"""

from __future__ import annotations

import os
import sys
import platform
from typing import List, Tuple

from .exceptions import InterfaceError


def check_interface_exists(iface: str) -> Tuple[bool, str]:
    """
    Check if the network interface exists.

    Args:
        iface: Interface name

    Returns:
        Tuple of (success, message)
    """
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        if iface in interfaces:
            return True, f"Interface '{iface}' found"
        return False, f"Interface '{iface}' not found. Available: {', '.join(interfaces)}"
    except Exception as e:
        return False, f"Failed to check interfaces: {e}"


def check_interface_mac(iface: str) -> Tuple[bool, str]:
    """
    Check if we can get the MAC address of the interface.

    Args:
        iface: Interface name

    Returns:
        Tuple of (success, message)
    """
    try:
        from scapy.all import get_if_hwaddr
        mac = get_if_hwaddr(iface)
        if mac and mac != "00:00:00:00:00:00":
            return True, f"MAC address: {mac}"
        return False, f"Interface '{iface}' has no valid MAC address"
    except Exception as e:
        return False, f"Failed to get MAC address: {e}"


def check_root_privileges() -> Tuple[bool, str]:
    """
    Check if running with sufficient privileges for raw sockets.

    Returns:
        Tuple of (success, message)
    """
    system = platform.system()

    if system == "Windows":
        # Windows requires Administrator
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                return True, "Running as Administrator"
            return False, "Raw sockets require Administrator privileges on Windows"
        except Exception:
            return True, "Cannot verify privileges (assuming sufficient)"

    elif system in ("Linux", "Darwin"):
        # Unix-like systems require root or CAP_NET_RAW
        if os.geteuid() == 0:
            return True, "Running as root"

        # Check for CAP_NET_RAW on Linux
        if system == "Linux":
            try:
                # Try to check capabilities
                import subprocess
                result = subprocess.run(
                    ["getcap", sys.executable],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if "cap_net_raw" in result.stdout.lower():
                    return True, "Python has CAP_NET_RAW capability"
            except Exception:
                pass

        return False, (
            "Raw sockets typically require root privileges. "
            "Try running with sudo, or on Linux: "
            f"sudo setcap cap_net_raw+ep {sys.executable}"
        )

    return True, f"Unknown platform '{system}', assuming sufficient privileges"


def check_scapy_available() -> Tuple[bool, str]:
    """
    Check if Scapy is properly installed and functional.

    Returns:
        Tuple of (success, message)
    """
    try:
        import scapy
        from scapy.all import Ether, sendp, sniff
        return True, f"Scapy {scapy.VERSION} available"
    except ImportError as e:
        return False, f"Scapy not installed: {e}"
    except Exception as e:
        return False, f"Scapy error: {e}"


def check_crypto_available() -> Tuple[bool, str]:
    """
    Check if cryptographic libraries are available.

    Returns:
        Tuple of (success, message)
    """
    missing = []

    try:
        import nacl
    except ImportError:
        missing.append("pynacl")

    try:
        import pysodium
    except ImportError:
        missing.append("pysodium")

    try:
        import blake3
    except ImportError:
        missing.append("blake3")

    try:
        from cryptography.hazmat.primitives.asymmetric import x25519
    except ImportError:
        missing.append("cryptography")

    if missing:
        return False, f"Missing crypto libraries: {', '.join(missing)}"
    return True, "All crypto libraries available"


def run_preflight_checks(iface: str, verbose: bool = True) -> List[Tuple[str, bool, str]]:
    """
    Run all pre-flight checks.

    Args:
        iface: Network interface to check
        verbose: Whether to print results

    Returns:
        List of (check_name, success, message) tuples
    """
    checks = [
        ("Scapy", check_scapy_available),
        ("Crypto libraries", check_crypto_available),
        ("Privileges", check_root_privileges),
        ("Interface exists", lambda: check_interface_exists(iface)),
        ("Interface MAC", lambda: check_interface_mac(iface)),
    ]

    results = []
    all_passed = True

    for name, check_fn in checks:
        success, message = check_fn()
        results.append((name, success, message))
        if not success:
            all_passed = False

        if verbose:
            status = "[OK]" if success else "[FAIL]"
            print(f"  {status} {name}: {message}")

    return results


def validate_startup(iface: str) -> None:
    """
    Validate system is ready to run Malachi Stack.

    Raises InterfaceError if any critical check fails.
    """
    results = run_preflight_checks(iface, verbose=False)
    failures = [(name, msg) for name, success, msg in results if not success]

    if failures:
        error_lines = ["Pre-flight checks failed:"]
        for name, msg in failures:
            error_lines.append(f"  - {name}: {msg}")
        raise InterfaceError("\n".join(error_lines))
