#!/usr/bin/env python3
"""
Malachi DNS Resolver

Resolves .mli domains to Malachi virtual IPs:
    http://a1b2c3d4.mli:8080/  →  10.161.195.212

Usage:
    sudo python3 -m malachi.dns start

Then access Malachi nodes via:
    curl http://a1b2c3d4.mli:8080/
    ping a1b2c3d4.mli
"""

import socket
import struct
import threading
import logging
import os
import sys
import subprocess
import platform
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# DNS constants
DNS_PORT = 53
DNS_HEADER_SIZE = 12
UPSTREAM_DNS = "8.8.8.8"  # Google DNS for non-.mli queries

# Malachi TLD
MALACHI_TLD = "mli"


@dataclass
class DNSQuestion:
    """Parsed DNS question."""
    name: str
    qtype: int
    qclass: int


@dataclass
class DNSHeader:
    """Parsed DNS header."""
    id: int
    flags: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


def node_id_to_virtual_ip(node_id_hex: str) -> Optional[str]:
    """
    Convert a node ID (hex string) to virtual IP.

    Supports full (32 char) or partial node IDs.
    """
    # Pad short IDs
    node_id_hex = node_id_hex.lower().ljust(32, '0')

    try:
        node_id = bytes.fromhex(node_id_hex)
    except ValueError:
        return None

    # Same algorithm as tun_interface.py (uses 3 bytes for 10.x.x.x range)
    node_hash = int.from_bytes(node_id[:4], 'big')
    second_octet = (node_hash >> 16) & 0xFF
    third_octet = (node_hash >> 8) & 0xFF
    fourth_octet = node_hash & 0xFF

    if second_octet == 0 and third_octet == 0 and fourth_octet < 2:
        fourth_octet = 2

    return f"10.{second_octet}.{third_octet}.{fourth_octet}"


def parse_dns_header(data: bytes) -> DNSHeader:
    """Parse DNS header from bytes."""
    fields = struct.unpack('>HHHHHH', data[:12])
    return DNSHeader(
        id=fields[0],
        flags=fields[1],
        qdcount=fields[2],
        ancount=fields[3],
        nscount=fields[4],
        arcount=fields[5]
    )


def parse_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a DNS name from the packet."""
    labels = []
    original_offset = offset
    jumped = False

    while True:
        if offset >= len(data):
            break

        length = data[offset]

        # Check for pointer (compression)
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            offset = pointer
            jumped = True
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        label = data[offset:offset + length].decode('ascii', errors='ignore')
        labels.append(label)
        offset += length

    if jumped:
        return '.'.join(labels), original_offset
    return '.'.join(labels), offset


def parse_dns_question(data: bytes, offset: int) -> Tuple[DNSQuestion, int]:
    """Parse a DNS question."""
    name, offset = parse_dns_name(data, offset)
    qtype, qclass = struct.unpack('>HH', data[offset:offset + 4])
    return DNSQuestion(name=name, qtype=qtype, qclass=qclass), offset + 4


def build_dns_response(query: bytes, question: DNSQuestion, ip: str) -> bytes:
    """Build a DNS response with an A record."""
    # Parse original header
    header = parse_dns_header(query)

    # Build response header
    # Set QR=1 (response), AA=1 (authoritative), RCODE=0 (no error)
    response_flags = 0x8400

    response_header = struct.pack(
        '>HHHHHH',
        header.id,
        response_flags,
        1,  # Questions
        1,  # Answers
        0,  # Authority
        0   # Additional
    )

    # Copy question section from original query
    # Find where question ends
    _, q_end = parse_dns_name(query, 12)
    q_end += 4  # Skip qtype and qclass
    question_section = query[12:q_end]

    # Build answer section
    # Name pointer to question name (offset 12)
    answer_name = struct.pack('>H', 0xC00C)

    # A record (type 1), IN class (1), TTL, length, IP
    ip_parts = [int(p) for p in ip.split('.')]
    answer = struct.pack(
        '>HHIH4B',
        1,      # Type A
        1,      # Class IN
        300,    # TTL (5 minutes)
        4,      # Data length
        *ip_parts
    )

    return response_header + question_section + answer_name + answer


def build_dns_nxdomain(query: bytes) -> bytes:
    """Build an NXDOMAIN response."""
    header = parse_dns_header(query)

    # QR=1, AA=1, RCODE=3 (NXDOMAIN)
    response_flags = 0x8403

    response_header = struct.pack(
        '>HHHHHH',
        header.id,
        response_flags,
        1, 0, 0, 0
    )

    # Copy question
    _, q_end = parse_dns_name(query, 12)
    q_end += 4
    question_section = query[12:q_end]

    return response_header + question_section


def forward_dns_query(query: bytes, upstream: str = UPSTREAM_DNS) -> Optional[bytes]:
    """Forward a DNS query to upstream server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.sendto(query, (upstream, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()
        return response
    except Exception as e:
        logger.error(f"Failed to forward DNS query: {e}")
        return None


class MalachiDNSServer:
    """
    DNS server that resolves .mli domains to Malachi virtual IPs.

    Examples:
        a1b2c3d4.mli        → 10.161.195.212
        a1b2c3d4e5f6.mli    → 10.161.195.212 (same, uses first 4 bytes)
        mynode.a1b2c3d4.mli → 10.161.195.212 (subdomain ignored)
    """

    def __init__(
        self,
        bind_address: str = "127.0.0.1",
        port: int = DNS_PORT,
        upstream: str = UPSTREAM_DNS
    ):
        self.bind_address = bind_address
        self.port = port
        self.upstream = upstream
        self.socket: Optional[socket.socket] = None
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Stats
        self.queries_total = 0
        self.queries_mli = 0
        self.queries_forwarded = 0

    def start(self):
        """Start the DNS server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.bind_address, self.port))
            self.socket.settimeout(1.0)

            self._running = True
            self._thread = threading.Thread(target=self._serve_loop, daemon=True)
            self._thread.start()

            logger.info(f"Malachi DNS server started on {self.bind_address}:{self.port}")
            logger.info(f"Resolving *.{MALACHI_TLD} to Malachi virtual IPs")

        except PermissionError:
            logger.error("Permission denied. DNS requires root privileges (port 53).")
            logger.error("Run with: sudo python3 -m malachi.dns start")
            raise
        except OSError as e:
            logger.error(f"Failed to bind DNS server: {e}")
            raise

    def stop(self):
        """Stop the DNS server."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        if self.socket:
            self.socket.close()
        logger.info("Malachi DNS server stopped")

    def _serve_loop(self):
        """Main server loop."""
        while self._running:
            try:
                data, addr = self.socket.recvfrom(4096)
                self._handle_query(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"DNS server error: {e}")

    def _handle_query(self, data: bytes, addr: Tuple[str, int]):
        """Handle a DNS query."""
        self.queries_total += 1

        try:
            # Parse header and question
            header = parse_dns_header(data)
            if header.qdcount < 1:
                return

            question, _ = parse_dns_question(data, DNS_HEADER_SIZE)

            logger.debug(f"DNS query from {addr}: {question.name} (type {question.qtype})")

            # Check if it's a .mli domain
            if self._is_mli_domain(question.name):
                self._handle_mli_query(data, addr, question)
            else:
                self._forward_query(data, addr)

        except Exception as e:
            logger.error(f"Error handling DNS query: {e}")

    def _is_mli_domain(self, name: str) -> bool:
        """Check if domain ends in .mli"""
        parts = name.lower().rstrip('.').split('.')
        return len(parts) >= 1 and parts[-1] == MALACHI_TLD

    def _handle_mli_query(self, data: bytes, addr: Tuple[str, int], question: DNSQuestion):
        """Handle a .mli domain query."""
        self.queries_mli += 1

        # Only handle A records
        if question.qtype != 1:
            response = build_dns_nxdomain(data)
            self.socket.sendto(response, addr)
            return

        # Extract node ID from domain
        # Format: [subdomain.]<nodeid>.mli
        parts = question.name.lower().rstrip('.').split('.')

        # Remove .mli suffix
        if parts[-1] == MALACHI_TLD:
            parts = parts[:-1]

        if not parts:
            response = build_dns_nxdomain(data)
            self.socket.sendto(response, addr)
            return

        # Last part before .mli is the node ID
        node_id_hex = parts[-1]

        # Validate it's a hex string
        if not all(c in '0123456789abcdef' for c in node_id_hex):
            response = build_dns_nxdomain(data)
            self.socket.sendto(response, addr)
            return

        # Convert to virtual IP
        virtual_ip = node_id_to_virtual_ip(node_id_hex)

        if virtual_ip:
            logger.info(f"Resolved {question.name} → {virtual_ip}")
            response = build_dns_response(data, question, virtual_ip)
        else:
            response = build_dns_nxdomain(data)

        self.socket.sendto(response, addr)

    def _forward_query(self, data: bytes, addr: Tuple[str, int]):
        """Forward non-.mli query to upstream DNS."""
        self.queries_forwarded += 1

        response = forward_dns_query(data, self.upstream)
        if response:
            self.socket.sendto(response, addr)

    def get_stats(self) -> Dict:
        """Get server statistics."""
        return {
            "bind_address": self.bind_address,
            "port": self.port,
            "upstream": self.upstream,
            "running": self._running,
            "queries_total": self.queries_total,
            "queries_mli": self.queries_mli,
            "queries_forwarded": self.queries_forwarded,
        }


def configure_system_dns(dns_ip: str = "127.0.0.1"):
    """
    Configure system to use Malachi DNS.

    Platform-specific configuration.
    """
    system = platform.system().lower()

    if system == "darwin":  # macOS
        # Create resolver directory if needed
        resolver_dir = "/etc/resolver"
        resolver_file = f"{resolver_dir}/{MALACHI_TLD}"

        try:
            os.makedirs(resolver_dir, exist_ok=True)

            with open(resolver_file, 'w') as f:
                f.write(f"nameserver {dns_ip}\n")

            logger.info(f"Created {resolver_file}")
            logger.info(f"macOS will now resolve *.{MALACHI_TLD} via Malachi DNS")
            return True

        except PermissionError:
            logger.error("Permission denied. Run with sudo.")
            return False

    elif system == "linux":
        # Option 1: systemd-resolved (modern)
        # Option 2: /etc/resolv.conf (legacy)

        logger.info("Linux DNS configuration options:")
        logger.info("")
        logger.info("Option 1: Add to /etc/hosts for specific nodes:")
        logger.info("  echo '10.161.195.212 mynode.mli' | sudo tee -a /etc/hosts")
        logger.info("")
        logger.info("Option 2: Use dnsmasq for *.mli:")
        logger.info("  echo 'server=/mli/127.0.0.1' | sudo tee /etc/dnsmasq.d/malachi.conf")
        logger.info("  sudo systemctl restart dnsmasq")
        logger.info("")
        logger.info("Option 3: Configure systemd-resolved:")
        logger.info("  sudo mkdir -p /etc/systemd/resolved.conf.d/")
        logger.info(f"  echo '[Resolve]' | sudo tee /etc/systemd/resolved.conf.d/malachi.conf")
        logger.info(f"  echo 'DNS=127.0.0.1' | sudo tee -a /etc/systemd/resolved.conf.d/malachi.conf")
        logger.info(f"  echo 'Domains=~{MALACHI_TLD}' | sudo tee -a /etc/systemd/resolved.conf.d/malachi.conf")
        logger.info("  sudo systemctl restart systemd-resolved")

        return True

    else:
        logger.warning(f"Unsupported platform for automatic DNS configuration: {system}")
        logger.info(f"Manually configure your DNS to forward *.{MALACHI_TLD} to 127.0.0.1")
        return False


def unconfigure_system_dns():
    """Remove Malachi DNS configuration."""
    system = platform.system().lower()

    if system == "darwin":
        resolver_file = f"/etc/resolver/{MALACHI_TLD}"
        try:
            if os.path.exists(resolver_file):
                os.remove(resolver_file)
                logger.info(f"Removed {resolver_file}")
            return True
        except PermissionError:
            logger.error("Permission denied. Run with sudo.")
            return False

    return True


def print_status():
    """Print DNS configuration status."""
    system = platform.system().lower()

    print(f"""
MALACHI DNS RESOLVER STATUS
{'='*50}

TLD:        .{MALACHI_TLD}
Example:    http://a1b2c3d4.{MALACHI_TLD}:8080/

Resolution:
  a1b2c3d4.{MALACHI_TLD}           → 10.161.195.212
  www.a1b2c3d4.{MALACHI_TLD}       → 10.161.195.212
  a1b2c3d4e5f67890.{MALACHI_TLD}   → 10.161.195.212

Platform: {system}
""")

    if system == "darwin":
        resolver_file = f"/etc/resolver/{MALACHI_TLD}"
        if os.path.exists(resolver_file):
            print(f"Status: CONFIGURED")
            print(f"Resolver: {resolver_file}")
        else:
            print(f"Status: NOT CONFIGURED")
            print(f"Run: sudo python3 -m malachi.dns configure")
    else:
        print(f"Status: See configuration instructions")
        print(f"Run: python3 -m malachi.dns configure")


def main():
    """CLI entry point."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(
        description=f"Malachi DNS Resolver - Resolve *.{MALACHI_TLD} domains"
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Start command
    start_parser = subparsers.add_parser("start", help="Start DNS server")
    start_parser.add_argument(
        "-b", "--bind", default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)"
    )
    start_parser.add_argument(
        "-p", "--port", type=int, default=53,
        help="Port (default: 53)"
    )
    start_parser.add_argument(
        "-u", "--upstream", default=UPSTREAM_DNS,
        help=f"Upstream DNS (default: {UPSTREAM_DNS})"
    )

    # Configure command
    subparsers.add_parser("configure", help="Configure system DNS")

    # Unconfigure command
    subparsers.add_parser("unconfigure", help="Remove DNS configuration")

    # Status command
    subparsers.add_parser("status", help="Show DNS status")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test DNS resolution")
    test_parser.add_argument("domain", help="Domain to test")

    args = parser.parse_args()

    if args.command == "start":
        server = MalachiDNSServer(
            bind_address=args.bind,
            port=args.port,
            upstream=args.upstream
        )

        try:
            server.start()
            print(f"""
Malachi DNS Server Running
{'='*40}
Bind:     {args.bind}:{args.port}
Upstream: {args.upstream}
TLD:      .{MALACHI_TLD}

Test with:
  dig @127.0.0.1 a1b2c3d4.{MALACHI_TLD}
  nslookup a1b2c3d4.{MALACHI_TLD} 127.0.0.1

Press Ctrl+C to stop...
""")
            # Keep running
            import signal
            def handler(sig, frame):
                print("\nShutting down...")
                server.stop()
                sys.exit(0)

            signal.signal(signal.SIGINT, handler)
            signal.signal(signal.SIGTERM, handler)

            while True:
                import time
                time.sleep(1)

        except PermissionError:
            sys.exit(1)
        except KeyboardInterrupt:
            server.stop()

    elif args.command == "configure":
        configure_system_dns()

    elif args.command == "unconfigure":
        unconfigure_system_dns()

    elif args.command == "status":
        print_status()

    elif args.command == "test":
        # Simple test
        domain = args.domain
        print(f"Testing resolution of: {domain}")

        if domain.endswith(f".{MALACHI_TLD}") or domain.endswith(f".{MALACHI_TLD}."):
            parts = domain.rstrip('.').split('.')
            node_id = parts[-2] if len(parts) >= 2 else parts[0]
            ip = node_id_to_virtual_ip(node_id)
            print(f"  Node ID: {node_id}")
            print(f"  Virtual IP: {ip}")
        else:
            print(f"  Not a .{MALACHI_TLD} domain")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
