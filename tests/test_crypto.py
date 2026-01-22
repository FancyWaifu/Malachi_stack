"""
Tests for malachi.crypto module.
"""

import pytest
import os
import tempfile
from pathlib import Path

from malachi.crypto import (
    generate_node_id,
    id_to_hex,
    hex_to_id,
    short_id,
    mac_to_bytes,
    pad_payload,
    unpad_payload,
    aead_encrypt,
    aead_decrypt,
    l3_associated_data,
    l4_associated_data,
    init_libsodium,
)
from malachi.config import ID_LEN, AEAD_NONCE_LEN


@pytest.fixture(scope="module", autouse=True)
def init_crypto():
    """Initialize libsodium before running tests."""
    init_libsodium()


class TestNodeID:
    """Tests for node ID functions."""

    def test_generate_node_id(self):
        """Test node ID generation."""
        pubkey = os.urandom(32)
        node_id = generate_node_id(pubkey)
        assert len(node_id) == ID_LEN

        # Same pubkey should produce same ID
        node_id2 = generate_node_id(pubkey)
        assert node_id == node_id2

    def test_id_to_hex(self):
        """Test node ID to hex conversion."""
        node_id = bytes(range(16))
        hex_str = id_to_hex(node_id)

        # Should have dashes
        assert "-" in hex_str

        # Should be correct length (32 hex chars + 3 dashes)
        assert len(hex_str) == 35

    def test_hex_to_id(self):
        """Test hex to node ID conversion."""
        original = bytes(range(16))
        hex_str = id_to_hex(original)

        # Should round-trip
        result = hex_to_id(hex_str)
        assert result == original

    def test_hex_to_id_no_dashes(self):
        """Test hex to node ID without dashes."""
        hex_str = "00010203040506070809101112131415"
        result = hex_to_id(hex_str)
        assert len(result) == 16

    def test_hex_to_id_bounds_check(self):
        """Test input length bounds checking."""
        # Very long input should be rejected
        with pytest.raises(ValueError):
            hex_to_id("a" * 1000)

    def test_hex_to_id_wrong_length(self):
        """Test wrong length rejection."""
        with pytest.raises(ValueError):
            hex_to_id("0011223344")

    def test_short_id(self):
        """Test short ID generation."""
        node_id = bytes(range(16))
        short = short_id(node_id)

        # Should be abbreviated
        assert "..." in short


class TestMACConversion:
    """Tests for MAC address functions."""

    def test_mac_to_bytes(self):
        """Test MAC address conversion."""
        mac_str = "aa:bb:cc:dd:ee:ff"
        result = mac_to_bytes(mac_str)

        assert len(result) == 6
        assert result == bytes([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])


class TestPadding:
    """Tests for payload padding."""

    def test_pad_unpad_roundtrip(self):
        """Test padding round-trip."""
        original = b"Hello, World!"
        padded = pad_payload(original)
        result = unpad_payload(padded)

        assert result == original

    def test_padding_alignment(self):
        """Test padding is aligned."""
        from malachi.config import PADDING_BLOCK_SIZE

        original = b"test"
        padded = pad_payload(original)

        # Should be aligned to block size
        assert len(padded) % PADDING_BLOCK_SIZE == 0

    def test_padding_minimum_size(self):
        """Test minimum padding size."""
        from malachi.config import PADDING_MIN_SIZE

        original = b"x"
        padded = pad_payload(original)

        assert len(padded) >= PADDING_MIN_SIZE

    def test_empty_payload(self):
        """Test empty payload padding."""
        original = b""
        padded = pad_payload(original)
        result = unpad_payload(padded)

        assert result == original

    def test_invalid_padding(self):
        """Test invalid padding detection."""
        # No 0x80 marker
        invalid = b"test\x00\x00\x00"

        with pytest.raises(ValueError):
            unpad_payload(invalid)


class TestAEAD:
    """Tests for AEAD encryption/decryption."""

    def test_aead_roundtrip(self):
        """Test AEAD encryption round-trip."""
        plaintext = b"Hello, encrypted world!"
        ad = b"additional data"
        nonce = os.urandom(AEAD_NONCE_LEN)
        key = os.urandom(32)

        ciphertext = aead_encrypt(plaintext, ad, nonce, key)
        result = aead_decrypt(ciphertext, ad, nonce, key)

        assert result == plaintext

    def test_aead_wrong_key(self):
        """Test decryption with wrong key."""
        from malachi.exceptions import DecryptionError

        plaintext = b"secret message"
        ad = b""
        nonce = os.urandom(AEAD_NONCE_LEN)
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        ciphertext = aead_encrypt(plaintext, ad, nonce, key1)

        with pytest.raises(DecryptionError):
            aead_decrypt(ciphertext, ad, nonce, key2)

    def test_aead_wrong_ad(self):
        """Test decryption with wrong associated data."""
        from malachi.exceptions import DecryptionError

        plaintext = b"message"
        nonce = os.urandom(AEAD_NONCE_LEN)
        key = os.urandom(32)

        ciphertext = aead_encrypt(plaintext, b"ad1", nonce, key)

        with pytest.raises(DecryptionError):
            aead_decrypt(ciphertext, b"ad2", nonce, key)


class TestAssociatedData:
    """Tests for associated data generation."""

    def test_l3_associated_data(self):
        """Test L3 associated data generation."""
        ad = l3_associated_data()

        assert isinstance(ad, bytes)
        assert len(ad) > 0

    def test_l4_associated_data(self):
        """Test L4 associated data generation."""
        src_id = bytes(range(16))
        dst_id = bytes(range(16, 32))

        ad = l4_associated_data(src_id, dst_id, 1234, 5678)

        assert isinstance(ad, bytes)
        assert src_id in ad
        assert dst_id in ad
