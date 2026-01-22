"""
Terminal User Interface for Malachi Stack.

Provides an interactive curses-based shell for network operations.
"""

from __future__ import annotations

import os
import time
import shlex
import base64
import curses
import threading
from queue import Empty
from typing import Optional, List, Any

from nacl import signing
from scapy.all import get_if_hwaddr

from .config import (
    ED25519_PATH,
    X25519_PRIV_PATH,
    X25519_PUB_PATH,
    PINS_PATH,
    NEIGHBOR_TTL,
    NONCE_CACHE_SIZE,
)
from .crypto import id_to_hex, hex_to_id, short_id
from .state import get_neighbors, get_pins, get_stop_flag
from .ports import (
    get_port_manager,
    get_port_viewer,
    allocate_ephemeral_port,
    PortAlreadyBoundError,
    PortNotBoundError,
)
from .network import send_l4
from .discovery import get_ndp_handler
from .logging_setup import get_log_queue, log, format_block
from .exceptions import NoSessionKeyError, PayloadTooLargeError, ValidationError
from .stats import get_stats_collector
from .pcap import get_pcap_manager
from .connection import get_connection_manager


HELP_TEXT = """\
Commands:
  help
  id
  bind <port> [cap]               - bind a local port with optional capacity (default 64)
  unbind <port>
  ports                           - list bound ports & depths
  ndp                             - broadcast NDP DISCOVER
  send <dst_id_hex> <dst_mac> <dst_port> <text...>
  pull <port>                     - pop one datagram and print
  pull follow <port>              - start a live viewer (consumes messages)
  pull stop <port>                - stop the live viewer for this port
  pull list                       - list active viewers
  keys                            - show NodeID + public keys + file paths
  peers                           - list discovered peers
  stats                           - show packet/network statistics
  pcap start [name]               - start PCAP capture
  pcap stop                       - stop PCAP capture
  pcap status                     - show PCAP capture status
  conns                           - show connection states
  quit | exit
"""


def _fmt_age(seconds: float) -> str:
    """Format age in human-readable form."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m{s:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _sanitize_for_curses(text: str) -> str:
    """Sanitize string for curses display."""
    if not isinstance(text, str):
        text = str(text)
    return text.replace("\x00", r"\x00")


class CommandHandler:
    """Handles TUI commands."""

    def __init__(self, iface: str, my_id: bytes):
        self.iface = iface
        self.my_id = my_id
        self._port_manager = get_port_manager()
        self._port_viewer = get_port_viewer()
        self._ndp_handler = get_ndp_handler()

    def handle(self, line: str) -> None:
        """Process a command line."""
        parts = shlex.split(line)
        if not parts:
            return

        cmd = parts[0].lower()

        if cmd in ("quit", "exit"):
            get_stop_flag().set()
            log("[BYE] Shutting down...")
            return

        if cmd == "help":
            for ln in HELP_TEXT.splitlines():
                log(ln)
            return

        if cmd == "id":
            log(f"[ID] {id_to_hex(self.my_id)}")
            return

        if cmd == "ports":
            self._cmd_ports()
            return

        if cmd == "bind":
            self._cmd_bind(parts)
            return

        if cmd == "unbind":
            self._cmd_unbind(parts)
            return

        if cmd == "ndp":
            self._cmd_ndp()
            return

        if cmd == "pull":
            self._cmd_pull(parts)
            return

        if cmd == "send":
            self._cmd_send(parts)
            return

        if cmd == "keys":
            self._cmd_keys()
            return

        if cmd == "peers":
            self._cmd_peers()
            return

        if cmd == "stats":
            self._cmd_stats()
            return

        if cmd == "pcap":
            self._cmd_pcap(parts)
            return

        if cmd == "conns":
            self._cmd_conns()
            return

        raise ValidationError(f"Unknown command: {cmd}")

    def _cmd_ports(self) -> None:
        """List bound ports."""
        ports = self._port_manager.list_ports()
        if not ports:
            log("[PORTS] (none)")
        else:
            for port, stats in ports.items():
                log(f"[PORT] {port} depth={stats['depth']}/{stats['capacity']}")

    def _cmd_bind(self, parts: List[str]) -> None:
        """Bind a port."""
        if len(parts) < 2:
            raise ValidationError("Usage: bind <port> [capacity]")
        port = int(parts[1])
        capacity = int(parts[2]) if len(parts) >= 3 else 64
        self._port_manager.bind(port, capacity)

    def _cmd_unbind(self, parts: List[str]) -> None:
        """Unbind a port."""
        if len(parts) != 2:
            raise ValidationError("Usage: unbind <port>")
        self._port_manager.unbind(int(parts[1]))

    def _cmd_ndp(self) -> None:
        """Send NDP discover."""
        if self._ndp_handler is None:
            log("[NDP] Handler not initialized")
            return
        self._ndp_handler.send_discover(self.iface)

    def _cmd_pull(self, parts: List[str]) -> None:
        """Pull message from port or manage viewers."""
        if len(parts) == 2 and parts[1].lower() == "list":
            active = self._port_viewer.list_active()
            if not active:
                log("[VIEW] (none)")
            else:
                for port in active:
                    log(f"[VIEW] Running on port {port}")
            return

        if len(parts) == 3 and parts[1].lower() == "follow":
            port = int(parts[2])
            self._port_viewer.start(port)
            return

        if len(parts) == 3 and parts[1].lower() == "stop":
            port = int(parts[2])
            self._port_viewer.stop(port)
            return

        if len(parts) == 2:
            port = int(parts[1])
            msg = self._port_manager.receive(port, timeout=0.0)
            if msg is None:
                log(f"[PULL] port={port} (empty)")
            else:
                try:
                    text = msg.payload.decode("utf-8", "backslashreplace")
                    text = text.replace("\x00", r"\x00")
                except (UnicodeDecodeError, AttributeError):
                    text = repr(msg.payload)
                log(
                    f"[PULL] src={id_to_hex(msg.src_id)}:{msg.src_port} "
                    f"bytes={len(msg.payload)} text={text}"
                )
            return

        raise ValidationError(
            "Usage: pull <port> | pull follow <port> | pull stop <port> | pull list"
        )

    def _cmd_send(self, parts: List[str]) -> None:
        """Send message to peer."""
        if len(parts) < 5:
            raise ValidationError(
                "Usage: send <dst_id_hex> <dst_mac> <dst_port> <text...>"
            )
        dst_id = hex_to_id(parts[1])
        dst_mac = parts[2]
        dst_port = int(parts[3])
        payload = " ".join(parts[4:])
        src_port = allocate_ephemeral_port()
        send_l4(self.iface, dst_id, dst_mac, src_port, dst_port, payload)

    def _cmd_keys(self) -> None:
        """Show identity and key information."""
        try:
            ed_b64 = "(missing)"
            xpub_b64 = "(missing)"

            if os.path.exists(ED25519_PATH):
                with open(ED25519_PATH, "rb") as f:
                    raw = base64.b64decode(f.read())
                vk = signing.SigningKey(raw).verify_key
                ed_b64 = base64.b64encode(bytes(vk)).decode("ascii")

            if os.path.exists(X25519_PUB_PATH):
                with open(X25519_PUB_PATH, "rb") as f:
                    xpub_b64 = f.read().decode("ascii")

            lines = [
                f"NodeID      : {id_to_hex(self.my_id)}",
                f"Ed25519 pub : {ed_b64}",
                f"X25519 pub  : {xpub_b64}",
                f"files:",
                f"  {ED25519_PATH} (private)",
                f"  {X25519_PRIV_PATH} (private)",
                f"  {X25519_PUB_PATH}  (public)",
                f"  {PINS_PATH}  (pins)",
            ]
            log("\n".join(lines))

        except Exception as e:
            log(f"[KEYS] Error: {e!r}")

    def _cmd_stats(self) -> None:
        """Show statistics."""
        summary = get_stats_collector().format_summary()
        log(summary)

    def _cmd_pcap(self, parts: List[str]) -> None:
        """Handle PCAP capture commands."""
        if len(parts) < 2:
            raise ValidationError("Usage: pcap start [name] | pcap stop | pcap status")

        subcmd = parts[1].lower()
        pcap_mgr = get_pcap_manager()

        if subcmd == "start":
            if pcap_mgr.is_capturing():
                log("[PCAP] Capture already in progress")
                return
            name = parts[2] if len(parts) > 2 else None
            path = pcap_mgr.start_capture(name)
            log(f"[PCAP] Started capture: {path}")

        elif subcmd == "stop":
            if not pcap_mgr.is_capturing():
                log("[PCAP] No capture in progress")
                return
            stats = pcap_mgr.stop_capture()
            if "combined" in stats:
                log(f"[PCAP] Stopped. Written {stats['combined']['packets_written']} packets to {stats['combined']['path']}")
            else:
                log("[PCAP] Capture stopped")

        elif subcmd == "status":
            stats = pcap_mgr.stats()
            if stats["capturing"]:
                if "combined" in stats:
                    log(f"[PCAP] Capturing: {stats['combined']['packets_written']} packets to {stats['combined']['path']}")
                else:
                    log("[PCAP] Capturing (separate TX/RX)")
            else:
                log("[PCAP] Not capturing")

        else:
            raise ValidationError("Usage: pcap start [name] | pcap stop | pcap status")

    def _cmd_conns(self) -> None:
        """Show connection states."""
        summary = get_connection_manager().format_summary()
        log(summary)

    def _cmd_peers(self) -> None:
        """List discovered peers."""
        neighbors = get_neighbors()
        neighbors.prune_stale()
        pins = get_pins()

        items = neighbors.items()
        if not items:
            log("[PEERS] (none)")
            return

        log(
            f"[PEERS] count={len(items)} TTL={NEIGHBOR_TTL}s cache={NONCE_CACHE_SIZE}"
        )

        now = time.time()
        for nid, entry in items:
            nid_hex = id_to_hex(nid)
            mac = entry.mac
            last = _fmt_age(now - entry.last_seen)

            ed_b64 = (
                base64.b64encode(entry.ed_pub).decode("ascii")
                if entry.ed_pub
                else ""
            )
            x2_b64 = (
                base64.b64encode(entry.x25519_pub).decode("ascii")
                if entry.x25519_pub
                else ""
            )

            ed_short = (ed_b64[:8] + "...") if ed_b64 else "(unknown)"
            x2_short = (x2_b64[:8] + "...") if x2_b64 else "(unknown)"

            pinned = "yes" if pins.is_pinned(nid_hex, ed_b64) else "no"

            log(
                format_block(
                    "PEER",
                    [
                        f"id     : {nid_hex}",
                        f"mac    : {mac}",
                        f"last   : {last} ago",
                        f"pinned : {pinned}",
                        f"ed25519: {ed_short}",
                        f"x25519 : {x2_short}",
                        f"nonces : {len(entry.nonces_set)}/{NONCE_CACHE_SIZE}",
                    ],
                )
            )


def _wrap_line(text: str, width: int) -> List[str]:
    """Wrap text to fit within width."""
    if width <= 1:
        return [text]
    lines = []
    for ln in text.splitlines() or [""]:
        while len(ln) > width:
            lines.append(ln[:width])
            ln = ln[width:]
        lines.append(ln)
    return lines


def run_tui(stdscr, iface: str, my_id: bytes) -> None:
    """
    Main TUI loop.

    Args:
        stdscr: Curses standard screen
        iface: Network interface name
        my_id: Our node ID
    """
    curses.curs_set(1)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    rows, cols = stdscr.getmaxyx()
    log_h = max(3, rows - 3)
    inp_h = 3

    log_win = curses.newwin(log_h, cols, 0, 0)
    inp_win = curses.newwin(inp_h, cols, log_h, 0)
    log_win.scrollok(True)

    input_buf = ""
    log_queue = get_log_queue()
    stop_flag = get_stop_flag()
    handler = CommandHandler(iface, my_id)

    def redraw():
        # Process log messages
        try:
            while True:
                line = log_queue.get_nowait()
                for sub in _wrap_line(line, cols):
                    sub = _sanitize_for_curses(sub)
                    try:
                        log_win.addstr(sub + "\n")
                    except curses.error:
                        pass
        except Empty:
            pass
        log_win.noutrefresh()

        # Draw input area
        inp_win.erase()
        try:
            status = f"[ID {id_to_hex(my_id)}] MAC={get_if_hwaddr(iface)} iface={iface}"
            inp_win.addstr(0, 0, _sanitize_for_curses(status))
            inp_win.addstr(1, 0, _sanitize_for_curses(f"> {input_buf}"))
        except curses.error:
            pass
        inp_win.noutrefresh()
        curses.doupdate()

    log(f"[ID] my_id={id_to_hex(my_id)}")
    log("[READY] Type 'help' for commands.")

    last_draw = 0

    while not stop_flag.is_set():
        now = time.time()
        if now - last_draw > 0.05:
            redraw()
            last_draw = now

        ch = stdscr.getch()
        if ch == -1:
            time.sleep(0.01)
            continue

        if ch in (curses.KEY_ENTER, 10, 13):
            line = input_buf.strip()
            input_buf = ""
            if line:
                try:
                    handler.handle(line)
                except Exception as e:
                    log(f"[CMD ERR] {e}")

        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            input_buf = input_buf[:-1]

        elif ch == curses.KEY_RESIZE:
            rows, cols = stdscr.getmaxyx()
            log_h = max(3, rows - 3)
            log_win.resize(log_h, cols)
            inp_win.resize(3, cols)
            inp_win.mvwin(log_h, 0)

        else:
            if 0 <= ch < 256:
                input_buf += chr(ch)


def run_shell(iface: str, my_id: bytes) -> None:
    """
    Start the interactive shell.

    Spawns the listener thread and runs the TUI.
    """
    from .network import listen_loop

    # Start listener thread
    listener = threading.Thread(target=listen_loop, args=(iface,), daemon=True)
    listener.start()

    # Run TUI
    curses.wrapper(lambda stdscr: run_tui(stdscr, iface, my_id))
