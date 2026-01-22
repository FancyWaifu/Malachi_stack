"""
Port-based message queue system for Malachi Stack.

Provides UDP-like port binding and message delivery.
"""

import random
import threading
from collections import deque
from dataclasses import dataclass
from threading import Condition, RLock
from typing import Dict, Optional, Tuple

from .config import ID_LEN
from .exceptions import PortAlreadyBoundError, PortNotBoundError, InvalidPortError
from .logging_setup import log


@dataclass
class PortMessage:
    """A message received on a port."""

    src_id: bytes
    src_port: int
    payload: bytes


class PortManager:
    """
    Thread-safe port management for message queues.

    Provides bind/unbind, publish, and receive operations similar to UDP sockets.
    """

    def __init__(self):
        self._lock = RLock()
        self._ports: Dict[int, Tuple[deque, Condition]] = {}

    def bind(self, port: int, capacity: int = 64) -> None:
        """
        Bind a local port to receive messages.

        Args:
            port: Port number (0-65535)
            capacity: Maximum queue depth (oldest dropped when full)

        Raises:
            InvalidPortError: If port number is invalid
            PortAlreadyBoundError: If port is already bound
        """
        if not 0 <= port <= 65535:
            raise InvalidPortError(port)

        with self._lock:
            if port in self._ports:
                raise PortAlreadyBoundError(port)
            self._ports[port] = (deque(maxlen=capacity), Condition())
            log(f"[BIND L4] Bound port {port} (capacity={capacity})")

    def unbind(self, port: int) -> None:
        """
        Unbind a local port.

        Args:
            port: Port number to unbind

        Raises:
            PortNotBoundError: If port is not bound
        """
        with self._lock:
            if port not in self._ports:
                raise PortNotBoundError(port)
            del self._ports[port]
            log(f"[UNBIND L4] Unbound port {port}")

    def is_bound(self, port: int) -> bool:
        """Check if a port is bound."""
        with self._lock:
            return port in self._ports

    def publish(
        self,
        dst_port: int,
        src_id: bytes,
        src_port: int,
        payload: bytes,
        drop_newest: bool = False,
    ) -> bool:
        """
        Publish a message to a port queue.

        Args:
            dst_port: Destination port
            src_id: Source node ID
            src_port: Source port
            payload: Message payload
            drop_newest: If True and queue full, drop this message.
                        If False, drop oldest message.

        Returns:
            True if message was queued, False if dropped (port not bound or drop_newest)
        """
        with self._lock:
            entry = self._ports.get(dst_port)
            if entry is None:
                return False

            queue, condition = entry
            with condition:
                if drop_newest and len(queue) == queue.maxlen:
                    return False
                queue.append(PortMessage(src_id, src_port, payload))
                condition.notify()
                return True

    def receive(
        self, port: int, timeout: Optional[float] = None
    ) -> Optional[PortMessage]:
        """
        Receive a message from a port queue.

        Args:
            port: Port to receive from
            timeout: Seconds to wait (None = block forever, 0 = non-blocking)

        Returns:
            PortMessage if available, None on timeout

        Raises:
            PortNotBoundError: If port is not bound
        """
        with self._lock:
            entry = self._ports.get(port)
            if entry is None:
                raise PortNotBoundError(port)

        queue, condition = entry
        with condition:
            if not queue:
                if timeout == 0:
                    return None
                elif timeout is None:
                    while not queue:
                        condition.wait()
                else:
                    if not condition.wait(timeout=timeout) and not queue:
                        return None

            if queue:
                return queue.popleft()
            return None

    def stats(self, port: int) -> Dict[str, int]:
        """
        Get statistics for a port.

        Args:
            port: Port number

        Returns:
            Dict with 'depth' and 'capacity' keys

        Raises:
            PortNotBoundError: If port is not bound
        """
        with self._lock:
            entry = self._ports.get(port)
            if entry is None:
                raise PortNotBoundError(port)
            queue, _ = entry
            return {"depth": len(queue), "capacity": queue.maxlen or 0}

    def list_ports(self) -> Dict[int, Dict[str, int]]:
        """Get stats for all bound ports."""
        with self._lock:
            result = {}
            for port, (queue, _) in self._ports.items():
                result[port] = {"depth": len(queue), "capacity": queue.maxlen or 0}
            return result


class PortViewer:
    """
    Background viewer for port messages (like tail -f).
    """

    def __init__(self, port_manager: PortManager):
        self._port_manager = port_manager
        self._lock = RLock()
        self._viewers: Dict[int, Tuple[threading.Thread, threading.Event]] = {}

    def start(self, port: int) -> bool:
        """
        Start a viewer for a port.

        Returns True if started, False if already running or port not bound.
        """
        with self._lock:
            if port in self._viewers:
                log(f"[VIEW] Already running for port {port}")
                return False

            if not self._port_manager.is_bound(port):
                log(f"[VIEW] Port {port} is not bound")
                return False

            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._viewer_loop,
                args=(port, stop_event),
                daemon=True,
            )
            self._viewers[port] = (thread, stop_event)
            thread.start()
            return True

    def stop(self, port: int) -> bool:
        """
        Stop a viewer for a port.

        Returns True if stopped, False if not running.
        """
        with self._lock:
            entry = self._viewers.pop(port, None)
            if entry is None:
                log(f"[VIEW] No viewer for port {port}")
                return False

            thread, stop_event = entry
            stop_event.set()
            return True

    def list_active(self) -> list[int]:
        """List ports with active viewers."""
        with self._lock:
            return list(self._viewers.keys())

    def _viewer_loop(self, port: int, stop_event: threading.Event) -> None:
        """Background loop that logs received messages."""
        from .crypto import id_to_hex
        from .state import get_stop_flag

        log(f"[VIEW] Started for port {port}")
        global_stop = get_stop_flag()

        while not stop_event.is_set() and not global_stop.is_set():
            try:
                msg = self._port_manager.receive(port, timeout=0.5)
            except PortNotBoundError:
                log(f"[VIEW] Port {port} unbound, stopping")
                break

            if msg is None:
                continue

            # Sanitize payload for display
            try:
                text = msg.payload.decode("utf-8", "backslashreplace")
                text = text.replace("\x00", r"\x00")
                if len(text) > 256:
                    text = text[:256] + "..."
            except Exception:
                text = repr(msg.payload[:256])

            log(
                f"[VIEW {port}] src={id_to_hex(msg.src_id)}:{msg.src_port} "
                f"bytes={len(msg.payload)} text={text}"
            )

        log(f"[VIEW] Stopped for port {port}")


def allocate_ephemeral_port() -> int:
    """Allocate a random ephemeral port number."""
    return random.randint(49152, 65535)


# ---------------- Global Instance ----------------

_port_manager: Optional[PortManager] = None
_port_viewer: Optional[PortViewer] = None


def get_port_manager() -> PortManager:
    """Get global port manager (lazily initialized)."""
    global _port_manager
    if _port_manager is None:
        _port_manager = PortManager()
    return _port_manager


def get_port_viewer() -> PortViewer:
    """Get global port viewer (lazily initialized)."""
    global _port_viewer
    if _port_viewer is None:
        _port_viewer = PortViewer(get_port_manager())
    return _port_viewer
