"""
Cryptographic operations for Malachi Stack.

Handles key management, ECDH, AEAD encryption/decryption, and signatures.
"""

import os
import base64
from pathlib import Path
from typing import Tuple, Optional

from blake3 import blake3
from nacl import signing
from cryptography.hazmat.primitives.asymmetric import x25519
import pysodium as sodium

from .config import (
    KEYDIR,
    ED25519_PATH,
    X25519_PRIV_PATH,
    X25519_PUB_PATH,
    KEYCTX,
    ID_LEN,
    AEAD_NONCE_LEN,
    SEC_SUITE_XCHACHA20POLY1305,
    ensure_keydir,
    chmod600,
)
from .exceptions import (
    KeyLoadError,
    KeyGenerationError,
    DecryptionError,
    EncryptionError,
)


def init_libsodium() -> None:
    """Initialize libsodium. Must be called before using crypto functions."""
    sodium.sodium_init()


def generate_node_id(pubkey_bytes: bytes, size: int = ID_LEN) -> bytes:
    """
    Generate a node ID from a public key.

    Args:
        pubkey_bytes: Ed25519 public key (32 bytes)
        size: Output size in bytes (default 16)

    Returns:
        Node ID derived via BLAKE3(KEYCTX + pubkey)[:size]
    """
    return blake3(KEYCTX + pubkey_bytes).digest()[:size]


def id_to_hex(node_id: bytes) -> str:
    """
    Convert node ID bytes to human-readable hex format.

    Args:
        node_id: Raw node ID bytes

    Returns:
        Formatted string like "xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx"
    """
    h = node_id.hex()
    return "-".join(h[i : i + 8] for i in range(0, len(h), 8))


def hex_to_id(hex_str: str, size: int = ID_LEN) -> bytes:
    """
    Parse a hex string into node ID bytes.

    Args:
        hex_str: Hex string (dashes optional)
        size: Expected output size in bytes

    Returns:
        Raw node ID bytes

    Raises:
        ValueError: If hex string is invalid or wrong size
    """
    hex_str = hex_str.replace("-", "").strip()
    if len(hex_str) != size * 2:
        raise ValueError(f"Expected {size * 2} hex characters, got {len(hex_str)}")
    try:
        b = bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")
    return b


def short_id(node_id: bytes) -> str:
    """
    Return a shortened node ID for display.

    Args:
        node_id: Raw node ID bytes

    Returns:
        Abbreviated hex string like "xxxxxxxx-xx...xx-xxxxxxxx"
    """
    h = id_to_hex(node_id)
    return h[:11] + "..." + h[-11:]


def mac_to_bytes(mac_str: str) -> bytes:
    """
    Convert MAC address string to bytes.

    Args:
        mac_str: MAC address like "aa:bb:cc:dd:ee:ff"

    Returns:
        6-byte MAC address
    """
    return bytes.fromhex(mac_str.replace(":", ""))


# ---------------- Ed25519 Key Management ----------------


def load_or_create_ed25519(
    force_new: bool = False,
) -> Tuple[signing.SigningKey, signing.VerifyKey]:
    """
    Load or create persistent Ed25519 identity.

    Args:
        force_new: If True, generate new identity even if one exists

    Returns:
        Tuple of (SigningKey, VerifyKey)

    Raises:
        KeyLoadError: If existing key cannot be loaded
        KeyGenerationError: If key generation fails
    """
    ensure_keydir()

    if not force_new and os.path.exists(ED25519_PATH):
        try:
            raw_b64 = Path(ED25519_PATH).read_bytes()
            raw = base64.b64decode(raw_b64)
            if len(raw) != 32:
                raise KeyLoadError(f"Invalid Ed25519 key size in {ED25519_PATH}")
            sk = signing.SigningKey(raw)
            return sk, sk.verify_key
        except Exception as e:
            raise KeyLoadError(f"Failed to load Ed25519 key: {e}")

    # Generate new identity
    try:
        sk = signing.SigningKey.generate()
        tmp_path = ED25519_PATH + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(base64.b64encode(bytes(sk)))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, ED25519_PATH)
        chmod600(ED25519_PATH)
        return sk, sk.verify_key
    except Exception as e:
        raise KeyGenerationError(f"Failed to generate Ed25519 key: {e}")


def derive_and_store_x25519(
    sk: signing.SigningKey, vk: signing.VerifyKey
) -> Tuple[bytes, bytes]:
    """
    Derive X25519 keys from Ed25519 and store them.

    Args:
        sk: Ed25519 signing key
        vk: Ed25519 verify key

    Returns:
        Tuple of (private_key_bytes, public_key_bytes)
    """
    ensure_keydir()

    # Convert Ed25519 to X25519 (Curve25519)
    xsk = sk.to_curve25519_private_key()
    xpk = vk.to_curve25519_public_key()

    # Store private key if missing
    if not os.path.exists(X25519_PRIV_PATH):
        tmp_path = X25519_PRIV_PATH + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(base64.b64encode(xsk.encode()))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, X25519_PRIV_PATH)
        chmod600(X25519_PRIV_PATH)

    # Always refresh public key
    with open(X25519_PUB_PATH, "wb") as f:
        f.write(base64.b64encode(xpk.encode()))
        f.flush()
        os.fsync(f.fileno())

    return xsk.encode(), xpk.encode()


# ---------------- ECDH Key Agreement ----------------


def ecdh_derive(peer_pub_bytes: bytes, my_priv_bytes: bytes) -> bytes:
    """
    Perform ECDH key derivation.

    Args:
        peer_pub_bytes: Peer's X25519 public key (32 bytes)
        my_priv_bytes: Our X25519 private key (32 bytes)

    Returns:
        32-byte derived key via BLAKE3
    """
    private_key = x25519.X25519PrivateKey.from_private_bytes(my_priv_bytes)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared_key = private_key.exchange(peer_public_key)
    return blake3(shared_key).digest()


def derive_session_keys(
    my_id: bytes,
    peer_id: bytes,
    my_pub: bytes,
    my_priv: bytes,
    peer_pub: bytes,
) -> Tuple[bytes, bytes]:
    """
    Derive directional session keys using libsodium crypto_kx.

    The role (client/server) is determined by NodeID ordering to ensure
    both peers derive the same keys in opposite directions.

    Args:
        my_id: Our node ID
        peer_id: Peer's node ID
        my_pub: Our X25519 public key
        my_priv: Our X25519 private key
        peer_pub: Peer's X25519 public key

    Returns:
        Tuple of (rx_key, tx_key) - 32 bytes each
    """
    i_am_client = my_id < peer_id

    if i_am_client:
        rx_key, tx_key = sodium.crypto_kx_client_session_keys(my_pub, my_priv, peer_pub)
    else:
        rx_key, tx_key = sodium.crypto_kx_server_session_keys(my_pub, my_priv, peer_pub)

    return rx_key, tx_key


# ---------------- AEAD Encryption/Decryption ----------------


def aead_encrypt(
    plaintext: bytes,
    associated_data: bytes,
    nonce: bytes,
    key: bytes,
) -> bytes:
    """
    Encrypt data using XChaCha20-Poly1305.

    Args:
        plaintext: Data to encrypt
        associated_data: Additional authenticated data
        nonce: 24-byte nonce (must be unique per key)
        key: 32-byte encryption key

    Returns:
        Ciphertext with authentication tag

    Raises:
        EncryptionError: If encryption fails
    """
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, associated_data, nonce, key
        )
    except Exception as e:
        raise EncryptionError(f"AEAD encryption failed: {e}")


def aead_decrypt(
    ciphertext: bytes,
    associated_data: bytes,
    nonce: bytes,
    key: bytes,
) -> bytes:
    """
    Decrypt data using XChaCha20-Poly1305.

    Args:
        ciphertext: Encrypted data with authentication tag
        associated_data: Additional authenticated data
        nonce: 24-byte nonce
        key: 32-byte decryption key

    Returns:
        Decrypted plaintext

    Raises:
        DecryptionError: If decryption or authentication fails
    """
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            ciphertext, associated_data, nonce, key
        )
    except Exception as e:
        raise DecryptionError(f"AEAD decryption/authentication failed: {e}")


def l3_associated_data(suite: int = SEC_SUITE_XCHACHA20POLY1305) -> bytes:
    """Generate associated data for L3 secure container."""
    return b"MN-L3S|" + bytes([suite])


def l4_associated_data(
    src_id: bytes, dst_id: bytes, src_port: int, dst_port: int
) -> bytes:
    """Generate associated data for L4 datagrams."""
    return (
        b"MN-L4|"
        + src_id
        + dst_id
        + src_port.to_bytes(2, "big")
        + dst_port.to_bytes(2, "big")
    )


# ---------------- PSK Handling ----------------


def load_psk(path: Optional[str]) -> Optional[bytes]:
    """
    Load pre-shared key from file.

    Args:
        path: Path to PSK file (base64 or raw)

    Returns:
        PSK bytes or None if not available
    """
    if not path:
        return None
    try:
        data = Path(path).read_bytes().strip()
        try:
            return base64.b64decode(data, validate=True)
        except Exception:
            return data
    except Exception:
        return None


def compute_psk_tag(
    psk: Optional[bytes], self_id: bytes, peer_id: bytes, challenge: bytes
) -> bytes:
    """
    Compute PSK tag for NDP message.

    Args:
        psk: Pre-shared key bytes (or None)
        self_id: Our node ID
        peer_id: Peer's node ID
        challenge: Challenge bytes

    Returns:
        16-byte PSK tag (zeros if no PSK)
    """
    from .config import PSK_TAG_LEN

    if psk is None:
        return b"\x00" * PSK_TAG_LEN
    return blake3(psk + self_id + peer_id + challenge).digest()[:PSK_TAG_LEN]
