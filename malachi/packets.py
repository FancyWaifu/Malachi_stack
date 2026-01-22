"""
Packet definitions for Malachi Stack.

Defines Scapy packet structures for L3, L4, NDP, and secure containers.
"""

from __future__ import annotations

from typing import Tuple, Union

from scapy.all import Packet, bind_layers, Ether
from scapy.fields import (
    StrFixedLenField,
    ByteField,
    ShortField,
    MACField,
)

from .config import (
    ETH_TYPE,
    ID_LEN,
    ED25519_PUB_LEN,
    ED25519_SIG_LEN,
    X25519_PUB_LEN,
    NONCE_LEN,
    AEAD_NONCE_LEN,
    CHALLENGE_LEN,
    PSK_TAG_LEN,
    PT_DATA,
    PT_L4_DGRAM,
    PT_NDP,
    PT_SECURE,
    NDP_OP_DISCOVER,
    NDP_PROTO_VER,
    SEC_SUITE_XCHACHA20POLY1305,
    INNER_MAGIC,
    L3_MAGIC,
    L3_VERSION,
    NDP_SIG_PREFIX,
    PADDING_ENABLED,
)
from .exceptions import PacketParseError


class Layer3(Packet):
    """
    Layer 3 header for Malachi Stack.

    Fields:
        magic: Protocol magic bytes ("MN")
        version: Protocol version (1)
        ptype: Payload type (DATA, L4_DGRAM, NDP, SECURE)
        dst_id: Destination node ID (16 bytes)
        src_id: Source node ID (16 bytes)
    """

    name = "Layer3"
    fields_desc = [
        StrFixedLenField("magic", L3_MAGIC, 2),
        ByteField("version", L3_VERSION),
        ByteField("ptype", PT_DATA),
        StrFixedLenField("dst_id", b"\x00" * ID_LEN, ID_LEN),
        StrFixedLenField("src_id", b"\x00" * ID_LEN, ID_LEN),
    ]


class NDP2(Packet):
    """
    Node Discovery Protocol v2 packet.

    Provides secure node discovery with:
    - Ed25519 signatures
    - Challenge-response
    - Optional PSK binding
    - TOFU pinning support
    """

    name = "NDP2"
    fields_desc = [
        ByteField("op", NDP_OP_DISCOVER),
        ByteField("ver", NDP_PROTO_VER),
        StrFixedLenField("self_id", b"\x00" * ID_LEN, ID_LEN),
        MACField("mac", "00:00:00:00:00:00"),
        StrFixedLenField("ed25519_pub", b"\x00" * ED25519_PUB_LEN, ED25519_PUB_LEN),
        StrFixedLenField("x25519_pub", b"\x00" * X25519_PUB_LEN, X25519_PUB_LEN),
        StrFixedLenField("peer_id", b"\x00" * ID_LEN, ID_LEN),
        StrFixedLenField("challenge", b"\x00" * CHALLENGE_LEN, CHALLENGE_LEN),
        StrFixedLenField("nonce", b"\x00" * NONCE_LEN, NONCE_LEN),
        StrFixedLenField("psk_tag", b"\x00" * PSK_TAG_LEN, PSK_TAG_LEN),
        StrFixedLenField("sig", b"\x00" * ED25519_SIG_LEN, ED25519_SIG_LEN),
    ]


class SecureMeta(Packet):
    """
    Secure L3 container metadata.

    Contains encryption suite identifier and nonce.
    """

    name = "L3SEC"
    fields_desc = [
        ByteField("suite", SEC_SUITE_XCHACHA20POLY1305),
        StrFixedLenField("nonce", b"\x00" * AEAD_NONCE_LEN, AEAD_NONCE_LEN),
    ]


class Layer4(Packet):
    """
    Layer 4 UDP-like datagram header.

    Provides port-based message routing.
    """

    name = "Layer4"
    fields_desc = [
        ShortField("src_port", 0),
        ShortField("dst_port", 0),
    ]


# Bind layers for automatic parsing
bind_layers(Ether, Layer3, type=ETH_TYPE)
bind_layers(Layer3, NDP2, ptype=PT_NDP)
bind_layers(Layer3, SecureMeta, ptype=PT_SECURE)
bind_layers(Layer3, Layer4, ptype=PT_L4_DGRAM)


# ---------------- Inner Packet Helpers ----------------


def pack_inner_l4(
    src_id: bytes,
    dst_id: bytes,
    src_port: int,
    dst_port: int,
    payload: bytes,
) -> bytes:
    """
    Pack inner L4 datagram for encryption.

    Format: MAGIC(4) + TYPE(1) + SRC_ID(16) + DST_ID(16) + SRC_PORT(2) + DST_PORT(2) + PAYLOAD
    Payload is padded if PADDING_ENABLED is True.
    """
    from .crypto import pad_payload

    if PADDING_ENABLED:
        payload = pad_payload(payload)

    return (
        INNER_MAGIC
        + bytes([PT_L4_DGRAM])
        + src_id
        + dst_id
        + src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
        + payload
    )


def pack_inner_data(src_id: bytes, dst_id: bytes, payload: bytes) -> bytes:
    """
    Pack inner DATA packet for encryption.

    Format: MAGIC(4) + TYPE(1) + SRC_ID(16) + DST_ID(16) + PAYLOAD
    Payload is padded if PADDING_ENABLED is True.
    """
    from .crypto import pad_payload

    if PADDING_ENABLED:
        payload = pad_payload(payload)

    return INNER_MAGIC + bytes([PT_DATA]) + src_id + dst_id + payload


def unpack_inner(data: bytes) -> Tuple[str, ...]:
    """
    Unpack an inner encrypted packet.

    Args:
        data: Decrypted inner packet bytes

    Returns:
        For L4: ("l4", src_id, dst_id, src_port, dst_port, payload)
        For DATA: ("data", src_id, dst_id, payload)

    Raises:
        PacketParseError: If packet format is invalid
    """
    from .crypto import unpad_payload

    min_header = len(INNER_MAGIC) + 1 + 2 * ID_LEN

    if len(data) < min_header:
        raise PacketParseError(
            f"Inner packet too short: {len(data)} < {min_header} bytes"
        )

    if data[: len(INNER_MAGIC)] != INNER_MAGIC:
        raise PacketParseError("Invalid inner packet magic")

    ptype = data[len(INNER_MAGIC)]
    offset = len(INNER_MAGIC) + 1

    src_id = data[offset : offset + ID_LEN]
    offset += ID_LEN

    dst_id = data[offset : offset + ID_LEN]
    offset += ID_LEN

    if ptype == PT_L4_DGRAM:
        if len(data) < offset + 4:
            raise PacketParseError("Inner L4 packet too short for port fields")
        src_port = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        dst_port = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        payload = data[offset:]
        if PADDING_ENABLED:
            try:
                payload = unpad_payload(payload)
            except ValueError as e:
                raise PacketParseError(f"Invalid padding: {e}")
        return ("l4", src_id, dst_id, src_port, dst_port, payload)

    elif ptype == PT_DATA:
        payload = data[offset:]
        if PADDING_ENABLED:
            try:
                payload = unpad_payload(payload)
            except ValueError as e:
                raise PacketParseError(f"Invalid padding: {e}")
        return ("data", src_id, dst_id, payload)

    else:
        raise PacketParseError(f"Unknown inner packet type: {ptype}")


# ---------------- NDP Signature Helpers ----------------


def ndp_signature_bytes(
    op: int,
    role: int,
    self_id: bytes,
    mac_bytes: bytes,
    peer_id: bytes,
    challenge: bytes,
    ed25519_pub: bytes,
    x25519_pub: bytes,
    nonce: bytes,
    psk_tag: bytes,
) -> bytes:
    """
    Generate canonical transcript bytes for NDP signature.

    This ensures both sender and verifier compute the signature
    over the exact same data.
    """
    return (
        NDP_SIG_PREFIX
        + bytes([op])
        + bytes([role])
        + self_id
        + mac_bytes
        + peer_id
        + challenge
        + ed25519_pub
        + x25519_pub
        + nonce
        + psk_tag
    )
