"""
Tests for malachi.packets module.
"""

import pytest
import os

from malachi.packets import (
    pack_inner_l4,
    pack_inner_data,
    unpack_inner,
    Layer3,
    Layer4,
    NDP2,
    SecureMeta,
    ndp_signature_bytes,
)
from malachi.config import ID_LEN, PT_L4_DGRAM, PT_DATA


class TestInnerPackets:
    """Tests for inner packet packing/unpacking."""

    def test_pack_unpack_l4(self):
        """Test L4 packet round-trip."""
        src_id = os.urandom(ID_LEN)
        dst_id = os.urandom(ID_LEN)
        src_port = 12345
        dst_port = 54321
        payload = b"test payload data"

        packed = pack_inner_l4(src_id, dst_id, src_port, dst_port, payload)
        ptype, parsed_src, parsed_dst, parsed_sp, parsed_dp, parsed_payload = unpack_inner(packed)

        assert ptype == "l4"
        assert parsed_src == src_id
        assert parsed_dst == dst_id
        assert parsed_sp == src_port
        assert parsed_dp == dst_port
        # Payload might be padded
        assert payload in parsed_payload or parsed_payload.startswith(payload)

    def test_pack_unpack_data(self):
        """Test DATA packet round-trip."""
        src_id = os.urandom(ID_LEN)
        dst_id = os.urandom(ID_LEN)
        payload = b"raw data here"

        packed = pack_inner_data(src_id, dst_id, payload)
        ptype, parsed_src, parsed_dst, parsed_payload = unpack_inner(packed)

        assert ptype == "data"
        assert parsed_src == src_id
        assert parsed_dst == dst_id
        # Payload might be padded
        assert payload in parsed_payload or parsed_payload.startswith(payload)

    def test_unpack_too_short(self):
        """Test unpacking too-short data."""
        from malachi.exceptions import PacketParseError

        with pytest.raises(PacketParseError):
            unpack_inner(b"short")

    def test_unpack_bad_magic(self):
        """Test unpacking with bad magic bytes."""
        from malachi.exceptions import PacketParseError

        bad_packet = b"XXXX" + b"\x00" * 50

        with pytest.raises(PacketParseError):
            unpack_inner(bad_packet)


class TestScapyPackets:
    """Tests for Scapy packet structures."""

    def test_layer3_creation(self):
        """Test Layer3 packet creation."""
        pkt = Layer3(
            version=1,
            ptype=PT_L4_DGRAM,
            src_id=b"\x00" * ID_LEN,
            dst_id=b"\x00" * ID_LEN,
        )

        assert pkt.version == 1
        assert pkt.ptype == PT_L4_DGRAM

    def test_layer4_creation(self):
        """Test Layer4 packet creation."""
        pkt = Layer4(
            src_port=1234,
            dst_port=5678,
        )

        assert pkt.src_port == 1234
        assert pkt.dst_port == 5678


class TestNDPSignature:
    """Tests for NDP signature generation."""

    def test_signature_bytes_deterministic(self):
        """Test signature bytes are deterministic."""
        args = (
            1,  # op
            1,  # role
            os.urandom(ID_LEN),  # self_id
            os.urandom(6),  # mac_bytes
            os.urandom(ID_LEN),  # peer_id
            os.urandom(16),  # challenge
            os.urandom(32),  # ed25519_pub
            os.urandom(32),  # x25519_pub
            os.urandom(16),  # nonce
            os.urandom(16),  # psk_tag
        )

        result1 = ndp_signature_bytes(*args)
        result2 = ndp_signature_bytes(*args)

        assert result1 == result2

    def test_signature_bytes_different_input(self):
        """Test signature bytes differ with different input."""
        base_args = [
            1,  # op
            1,  # role
            os.urandom(ID_LEN),  # self_id
            os.urandom(6),  # mac_bytes
            os.urandom(ID_LEN),  # peer_id
            os.urandom(16),  # challenge
            os.urandom(32),  # ed25519_pub
            os.urandom(32),  # x25519_pub
            os.urandom(16),  # nonce
            os.urandom(16),  # psk_tag
        ]

        result1 = ndp_signature_bytes(*base_args)

        # Change one field
        modified_args = base_args.copy()
        modified_args[0] = 2  # Different op

        result2 = ndp_signature_bytes(*modified_args)

        assert result1 != result2
