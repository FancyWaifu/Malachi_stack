"""
Network send/receive operations for Malachi Stack.

Handles packet transmission and the background listener loop.
"""

from __future__ import annotations

import os
import time
import threading
from typing import Optional, Union, Any

from scapy.all import Ether, sendp, sniff, get_if_hwaddr

from .config import (
    ETH_TYPE,
    ID_LEN,
    PAYLOAD_CAP,
    PT_DATA,
    PT_L4_DGRAM,
    PT_NDP,
    PT_SECURE,
    SEC_SUITE_XCHACHA20POLY1305,
    AEAD_NONCE_LEN,
    AEAD_TAG_LEN,
    NDP_OP_DISCOVER,
    NDP_OP_ADVERTISE,
)
from .packets import (
    Layer3,
    Layer4,
    NDP2,
    SecureMeta,
    pack_inner_l4,
    pack_inner_data,
    unpack_inner,
)
from .crypto import (
    id_to_hex,
    short_id,
    aead_encrypt,
    aead_decrypt,
    l3_associated_data,
    DecryptionError,
)
from .state import get_neighbors, get_stop_flag, NonceTracker
from .ports import get_port_manager
from .discovery import get_ndp_handler
from .exceptions import (
    NoSessionKeyError,
    PayloadTooLargeError,
    PacketParseError,
)
from .logging_setup import log, format_block


# Global TX nonce prefix (set during initialization)
_tx_nonce_prefix: bytes = b""
_my_id: bytes = b""


def init_network(my_id: bytes) -> None:
    """
    Initialize network module with node identity.

    Must be called before sending packets.
    """
    global _tx_nonce_prefix, _my_id
    _tx_nonce_prefix = os.urandom(16)
    _my_id = my_id


def _next_nonce(entry) -> bytes:
    """Generate next nonce for a peer (caller must ensure thread safety)."""
    seq = entry.tx_seq
    entry.tx_seq = (seq + 1) & 0xFFFFFFFFFFFFFFFF
    return _tx_nonce_prefix + seq.to_bytes(8, "big")


def _safe_payload_preview(payload: bytes, max_len: int = 512) -> str:
    """Convert payload to safe display string."""
    try:
        text = payload.decode("utf-8", "backslashreplace")
        text = text.replace("\x00", r"\x00")
        if len(text) > max_len:
            text = text[:max_len] + "..."
        return text
    except (UnicodeDecodeError, AttributeError):
        return repr(payload[:max_len])


def send_l3_data(
    iface: str,
    dst_id: bytes,
    dst_mac: str,
    payload: Union[str, bytes],
) -> None:
    """
    Send encrypted Layer 3 data packet.

    Args:
        iface: Network interface name
        dst_id: Destination node ID
        dst_mac: Destination MAC address
        payload: Data to send (str or bytes)

    Raises:
        NoSessionKeyError: If no session key with peer
        PayloadTooLargeError: If payload too large for single frame
    """
    if isinstance(payload, str):
        payload = payload.encode()

    neighbors = get_neighbors()
    entry = neighbors.get(dst_id)

    if entry is None or entry.key_tx is None:
        raise NoSessionKeyError(id_to_hex(dst_id))

    # Check for expired keys
    if entry.keys_expired():
        entry.clear_keys()
        raise NoSessionKeyError(f"{id_to_hex(dst_id)} (keys expired, run 'ndp' to rekey)")

    # Warn if keys need rotation
    if entry.needs_rekey():
        log(f"[WARN] Session keys for {short_id(dst_id)} need rotation; run 'ndp'")

    # Build inner packet
    inner = pack_inner_data(_my_id, dst_id, payload)

    # Encrypt
    nonce = _next_nonce(entry)
    ad = l3_associated_data(SEC_SUITE_XCHACHA20POLY1305)
    ciphertext = aead_encrypt(inner, ad, nonce, entry.key_tx)

    if len(ciphertext) > PAYLOAD_CAP:
        raise PayloadTooLargeError(len(ciphertext), PAYLOAD_CAP)

    # Build frame
    my_mac = get_if_hwaddr(iface)
    frame = (
        Ether(dst=dst_mac, src=my_mac, type=ETH_TYPE)
        / Layer3(
            version=1,
            ptype=PT_SECURE,
            dst_id=b"\x00" * ID_LEN,
            src_id=b"\x00" * ID_LEN,
        )
        / SecureMeta(suite=SEC_SUITE_XCHACHA20POLY1305, nonce=nonce)
        / ciphertext
    )

    sendp(frame, iface=iface, verbose=False)
    log(
        f"[SEND L3SEC-DATA] {iface} -> {dst_mac} "
        f"dst={short_id(dst_id)} bytes={len(ciphertext)}"
    )


def send_l4(
    iface: str,
    dst_id: bytes,
    dst_mac: str,
    src_port: int,
    dst_port: int,
    payload: Union[str, bytes],
) -> None:
    """
    Send encrypted Layer 4 datagram.

    Args:
        iface: Network interface name
        dst_id: Destination node ID
        dst_mac: Destination MAC address
        src_port: Source port
        dst_port: Destination port
        payload: Data to send (str or bytes)

    Raises:
        NoSessionKeyError: If no session key with peer
        PayloadTooLargeError: If payload too large for single frame
    """
    if isinstance(payload, str):
        payload = payload.encode()

    if len(payload) > PAYLOAD_CAP:
        raise PayloadTooLargeError(len(payload), PAYLOAD_CAP)

    neighbors = get_neighbors()
    entry = neighbors.get(dst_id)

    if entry is None or entry.key_tx is None:
        raise NoSessionKeyError(id_to_hex(dst_id))

    # Check for expired keys
    if entry.keys_expired():
        entry.clear_keys()
        raise NoSessionKeyError(f"{id_to_hex(dst_id)} (keys expired, run 'ndp' to rekey)")

    # Warn if keys need rotation
    if entry.needs_rekey():
        log(f"[WARN] Session keys for {short_id(dst_id)} need rotation; run 'ndp'")

    # Build inner packet
    inner = pack_inner_l4(_my_id, dst_id, src_port, dst_port, payload)

    # Encrypt
    nonce = _next_nonce(entry)
    ad = l3_associated_data(SEC_SUITE_XCHACHA20POLY1305)
    ciphertext = aead_encrypt(inner, ad, nonce, entry.key_tx)

    if len(ciphertext) > PAYLOAD_CAP:
        raise PayloadTooLargeError(len(ciphertext), PAYLOAD_CAP)

    # Build frame
    my_mac = get_if_hwaddr(iface)
    frame = (
        Ether(dst=dst_mac, src=my_mac, type=ETH_TYPE)
        / Layer3(
            version=1,
            ptype=PT_SECURE,
            dst_id=b"\x00" * ID_LEN,
            src_id=b"\x00" * ID_LEN,
        )
        / SecureMeta(suite=SEC_SUITE_XCHACHA20POLY1305, nonce=nonce)
        / ciphertext
    )

    sendp(frame, iface=iface, verbose=False)
    log(
        f"[SEND L3SEC] {iface} -> {dst_mac} "
        f"{src_port}->{dst_port} dst={short_id(dst_id)} bytes={len(ciphertext)}"
    )


def listen_loop(iface: str) -> None:
    """
    Background packet listener.

    Handles NDP messages, encrypted packets, and legacy L4 datagrams.
    Should be run in a daemon thread.
    """
    bpf = f"ether proto 0x{ETH_TYPE:04x}"
    local_mac = get_if_hwaddr(iface).lower()
    stop_flag = get_stop_flag()
    neighbors = get_neighbors()
    port_manager = get_port_manager()

    log(f"[LISTEN] iface={iface} my_id={id_to_hex(_my_id)} filter={bpf}")

    def handle_packet(pkt):
        try:
            if not pkt.haslayer(Layer3):
                return

            l3 = pkt[Layer3]
            if l3.magic != b"MN" or l3.version != 1:
                return

            # Handle NDP
            if l3.ptype == PT_NDP and pkt.haslayer(NDP2):
                _handle_ndp(pkt, l3, local_mac, iface)
                return

            # Handle encrypted packets
            if l3.ptype == PT_SECURE and pkt.haslayer(SecureMeta):
                _handle_secure(pkt, l3, neighbors, port_manager)
                return

            # Handle legacy L4 (plaintext or optional encryption)
            if l3.ptype == PT_L4_DGRAM:
                _handle_legacy_l4(pkt, l3, neighbors, port_manager)
                return

        except Exception as e:
            log(f"[LISTEN] Handler error: {e!r}")

    while not stop_flag.is_set():
        try:
            sniff(iface=iface, filter=bpf, store=False, prn=handle_packet, timeout=2)
        except Exception as e:
            log(f"[LISTEN] Sniff error: {e!r}")
            time.sleep(0.5)


def _handle_ndp(pkt: Any, l3: Any, local_mac: str, iface: str) -> None:
    """Handle NDP messages."""
    ndp_handler = get_ndp_handler()
    if ndp_handler is None:
        return

    ndp_pkt = pkt[NDP2]
    src_mac = pkt.src.lower()

    if ndp_pkt.op == NDP_OP_DISCOVER:
        # Ignore our own DISCOVER
        if src_mac == local_mac:
            return

        ok, reason = ndp_handler.validate_and_store(ndp_pkt, l3, pkt.src, 0x01)
        if not ok:
            log(f"[NDPv2 DISCOVER drop] {reason}")
            return

        # Send ADVERTISE response
        ndp_handler.send_advertise(
            iface,
            src_mac,
            bytes(l3.src_id),
            bytes(ndp_pkt.challenge),
        )

    elif ndp_pkt.op == NDP_OP_ADVERTISE:
        # Check if addressed to us
        if bytes(l3.dst_id) != _my_id:
            return
        if src_mac == local_mac:
            return

        ok, reason = ndp_handler.validate_and_store(ndp_pkt, l3, pkt.src, 0x02)
        if not ok:
            log(f"[NDPv2 ADVERTISE drop] {reason}")
            return

        log(
            format_block(
                "NDPv2 LEARN",
                [
                    f"peer  : {id_to_hex(bytes(ndp_pkt.self_id))}",
                    f"mac   : {ndp_pkt.mac}",
                ],
            )
        )


def _handle_secure(pkt: Any, l3: Any, neighbors: Any, port_manager: Any) -> None:
    """Handle encrypted L3 packets."""
    sm = pkt[SecureMeta]

    if sm.suite != SEC_SUITE_XCHACHA20POLY1305:
        log("[L3SEC] Unsupported suite")
        return

    # Find peer by MAC
    peer_nid, entry = neighbors.find_by_mac(pkt.src)
    if entry is None or entry.key_rx is None:
        log("[L3SEC] No session key for peer MAC; drop")
        return

    nonce = bytes(sm.nonce)
    if len(nonce) != AEAD_NONCE_LEN:
        log("[L3SEC] Bad nonce length; drop")
        return

    # Extract ciphertext
    ct = getattr(sm.payload, "load", None) or bytes(sm.payload)
    if len(ct) < AEAD_TAG_LEN:
        log("[L3SEC] Ciphertext too short; drop")
        return

    # Replay check using full nonce (not just counter)
    if NonceTracker.check_nonce(entry, nonce):
        log("[L3SEC] Replay nonce; drop")
        return

    # Decrypt
    ad = l3_associated_data(sm.suite)
    try:
        inner = aead_decrypt(ct, ad, nonce, entry.key_rx)
    except DecryptionError:
        log("[L3SEC] Decrypt/auth fail; drop")
        return

    # Parse inner packet
    try:
        parsed = unpack_inner(inner)
    except PacketParseError as e:
        log(f"[L3SEC] Bad inner: {e}")
        return

    if parsed[0] == "l4":
        _, src_id, dst_id, src_port, dst_port, payload = parsed

        # Verify inner src_id matches peer
        if peer_nid is not None and src_id != peer_nid:
            log("[L3SEC] Inner src_id != pinned peer ID; drop")
            return

        if dst_id != _my_id:
            return

        ok = port_manager.publish(dst_port, src_id, src_port, payload)
        preview = _safe_payload_preview(payload)
        log(
            f"[RECV L3SEC L4] mac={pkt.src} src={short_id(src_id)} "
            f"{src_port}->{dst_port} bytes={len(payload)} text={preview}"
            + ("" if ok else " [DROP: no listener]")
        )

    elif parsed[0] == "data":
        _, src_id, dst_id, payload = parsed

        if peer_nid is not None and src_id != peer_nid:
            log("[L3SEC] Inner src_id != pinned peer ID; drop")
            return

        if dst_id != _my_id:
            return

        preview = _safe_payload_preview(payload)
        log(
            f"[RECV L3SEC DATA] mac={pkt.src} src={short_id(src_id)} "
            f"bytes={len(payload)} text={preview}"
        )


def _handle_legacy_l4(pkt: Any, l3: Any, neighbors: Any, port_manager: Any) -> None:
    """Handle legacy L4 datagrams (with optional encryption)."""
    if bytes(l3.dst_id) != _my_id:
        return

    if not pkt.haslayer(Layer4):
        return

    l4 = pkt[Layer4]
    src_id = bytes(l3.src_id)
    src_port = int(l4.src_port)
    dst_port = int(l4.dst_port)
    wire_payload = getattr(l4.payload, "load", None) or bytes(l4.payload)

    decrypted = False
    payload = wire_payload

    # Try AEAD decrypt if we have keys
    entry = neighbors.get(src_id)
    key_rx = entry.key_rx if entry else None

    if key_rx and len(wire_payload) >= AEAD_NONCE_LEN + AEAD_TAG_LEN:
        nonce = wire_payload[:AEAD_NONCE_LEN]
        ct = wire_payload[AEAD_NONCE_LEN:]
        from .crypto import l4_associated_data

        ad = l4_associated_data(src_id, bytes(l3.dst_id), src_port, dst_port)
        try:
            payload = aead_decrypt(ct, ad, nonce, key_rx)
            decrypted = True
        except DecryptionError:
            pass  # Fall back to plaintext

    ok = port_manager.publish(dst_port, src_id, src_port, payload)
    preview = _safe_payload_preview(payload)
    enc_flag = " enc" if decrypted else ""
    log(
        f"[RECV L4{enc_flag}] mac={pkt.src} src={id_to_hex(src_id)} "
        f"{src_port}->{dst_port} bytes={len(payload)} text={preview}"
        + ("" if ok else " [DROP: no listener]")
    )
