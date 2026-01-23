"""
Tests for malachi.operations module.
"""

import pytest
import os
import time

from malachi.operations import (
    VersionNegotiator,
    ProtocolCapabilities,
    CompressionManager,
    DiagnosticsManager,
    PROTOCOL_VERSION,
    COMPRESSION_NONE,
    COMPRESSION_ZLIB,
    COMPRESSION_THRESHOLD,
)


class TestVersionNegotiator:
    """Tests for VersionNegotiator."""

    def test_get_version(self):
        """Test getting version."""
        neg = VersionNegotiator()
        assert neg.get_version() == PROTOCOL_VERSION

    def test_get_version_string(self):
        """Test version string format."""
        neg = VersionNegotiator()
        version = neg.get_version_string()
        assert "." in version

    def test_compatible_same_major(self):
        """Test compatibility with same major version."""
        neg = VersionNegotiator()
        # Same major, different minor
        assert neg.is_compatible(PROTOCOL_VERSION)
        assert neg.is_compatible((PROTOCOL_VERSION & 0xFF00) | 0x05)

    def test_incompatible_different_major(self):
        """Test incompatibility with different major version."""
        neg = VersionNegotiator()
        # Different major
        assert not neg.is_compatible(0x0200)  # Version 2.0

    def test_negotiate(self):
        """Test successful negotiation."""
        neg = VersionNegotiator()
        peer_id = os.urandom(16)

        peer_caps = ProtocolCapabilities(
            version=PROTOCOL_VERSION,
            compression=[COMPRESSION_NONE, COMPRESSION_ZLIB],
        )

        session = neg.negotiate(peer_id, peer_caps)

        assert session is not None
        assert session.peer_id == peer_id
        assert session.compression == COMPRESSION_ZLIB  # Prefer zlib

    def test_negotiate_incompatible(self):
        """Test negotiation with incompatible version."""
        neg = VersionNegotiator()
        peer_id = os.urandom(16)

        peer_caps = ProtocolCapabilities(version=0x0200)  # v2.0

        session = neg.negotiate(peer_id, peer_caps)
        assert session is None

    def test_encode_decode_capabilities(self):
        """Test capabilities encoding/decoding."""
        neg = VersionNegotiator()
        caps = ProtocolCapabilities(
            version=PROTOCOL_VERSION,
            compression=[COMPRESSION_NONE, COMPRESSION_ZLIB],
            extensions={"ext1", "ext2"},
            supports_multicast=True,
            supports_routing=True,
        )
        neg._my_caps = caps

        encoded = neg.encode_capabilities()
        decoded = neg.decode_capabilities(encoded)

        assert decoded.version == caps.version
        assert set(decoded.compression) == set(caps.compression)
        assert decoded.extensions == caps.extensions
        assert decoded.supports_multicast == caps.supports_multicast
        assert decoded.supports_routing == caps.supports_routing


class TestCompressionManager:
    """Tests for CompressionManager."""

    def test_compress_small_data_skipped(self):
        """Test that small data is not compressed."""
        mgr = CompressionManager()
        small_data = b"x" * (COMPRESSION_THRESHOLD - 1)

        compressed, algo = mgr.compress(small_data)

        assert algo == COMPRESSION_NONE
        assert compressed == small_data

    def test_compress_large_data(self):
        """Test compression of large data."""
        mgr = CompressionManager()
        # Highly compressible data
        large_data = b"x" * 1000

        compressed, algo = mgr.compress(large_data, COMPRESSION_ZLIB)

        assert algo == COMPRESSION_ZLIB
        assert len(compressed) < len(large_data)

    def test_decompress(self):
        """Test decompression."""
        mgr = CompressionManager()
        original = b"hello world " * 100

        compressed, algo = mgr.compress(original, COMPRESSION_ZLIB)
        decompressed = mgr.decompress(compressed, algo)

        assert decompressed == original

    def test_wrap_unwrap_packet(self):
        """Test packet wrapping/unwrapping."""
        mgr = CompressionManager()
        original = b"test payload " * 50

        wrapped = mgr.wrap_packet(original)
        unwrapped = mgr.unwrap_packet(wrapped)

        assert unwrapped == original

    def test_stats(self):
        """Test statistics."""
        mgr = CompressionManager()
        data = b"x" * 1000

        mgr.compress(data, COMPRESSION_ZLIB)

        stats = mgr.stats()
        assert stats["packets_compressed"] == 1
        assert stats["compression_ratio"] < 1.0


class TestDiagnosticsManager:
    """Tests for DiagnosticsManager."""

    def test_encode_decode_ping(self):
        """Test ping encoding/decoding."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)

        request = mgr.encode_ping_request(42)
        msg_type, seq, timestamp = mgr.decode_ping(request)

        assert seq == 42
        assert timestamp > 0

    def test_handle_ping_request(self):
        """Test handling ping request."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        peer = os.urandom(16)

        response = mgr.handle_ping_request(peer, 123)

        assert response is not None
        msg_type, seq, _ = mgr.decode_ping(response)
        assert seq == 123

    def test_encode_decode_trace_request(self):
        """Test trace request encoding/decoding."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        dest = os.urandom(16)

        request = mgr.encode_trace_request(99, 5, dest)
        trace_id, ttl, decoded_dest = mgr.decode_trace_request(request)

        assert trace_id == 99
        assert ttl == 5
        assert decoded_dest == dest

    def test_encode_decode_trace_response(self):
        """Test trace response encoding/decoding."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        responder = os.urandom(16)

        response = mgr.encode_trace_response(77, responder, is_destination=True)
        trace_id, decoded_responder, is_dest = mgr.decode_trace_response(response)

        assert trace_id == 77
        assert decoded_responder == responder
        assert is_dest is True

    def test_handle_trace_request_at_destination(self):
        """Test handling trace at destination."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        peer = os.urandom(16)

        response = mgr.handle_trace_request(peer, 1, 5, my_id)

        assert response is not None
        trace_id, responder, is_dest = mgr.decode_trace_response(response)
        assert responder == my_id
        assert is_dest is True

    def test_handle_trace_request_ttl_expired(self):
        """Test handling trace with expired TTL."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        peer = os.urandom(16)
        dest = os.urandom(16)

        response = mgr.handle_trace_request(peer, 1, 1, dest)

        assert response is not None
        trace_id, responder, is_dest = mgr.decode_trace_response(response)
        assert responder == my_id
        assert is_dest is False  # Not the destination, just TTL expired

    def test_stats(self):
        """Test statistics."""
        my_id = os.urandom(16)
        mgr = DiagnosticsManager(my_id)
        peer = os.urandom(16)

        mgr.handle_ping_request(peer, 1)

        stats = mgr.stats()
        assert stats["pings_received"] == 1
        assert stats["pongs_sent"] == 1
