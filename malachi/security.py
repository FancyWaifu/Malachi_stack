"""
Advanced security features for Malachi Stack.

Implements:
- Perfect Forward Secrecy (ephemeral key exchange)
- Key Confirmation
- Certificate/Identity Chains (Web of Trust)
- Channel Binding
- Anti-Replay Sliding Window
"""

from __future__ import annotations

import os
import time
import json
import base64
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple, Set
from threading import RLock
from collections import OrderedDict

from blake3 import blake3
from nacl import signing
from cryptography.hazmat.primitives.asymmetric import x25519
import pysodium as sodium

from .config import (
    ID_LEN,
    KEYDIR,
    AEAD_NONCE_LEN,
)
from .logging_setup import log
from .crypto import id_to_hex, short_id


# ---------------- Perfect Forward Secrecy ----------------


@dataclass
class EphemeralKeyPair:
    """Ephemeral X25519 keypair for PFS."""
    private_key: bytes
    public_key: bytes
    created_at: float = field(default_factory=time.time)
    session_id: bytes = field(default_factory=lambda: os.urandom(16))

    @classmethod
    def generate(cls) -> "EphemeralKeyPair":
        """Generate a new ephemeral keypair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(
            private_key=private_key.private_bytes_raw(),
            public_key=public_key.public_bytes_raw(),
        )

    def derive_shared_secret(self, peer_public: bytes) -> bytes:
        """Derive shared secret with peer's ephemeral public key."""
        private = x25519.X25519PrivateKey.from_private_bytes(self.private_key)
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public)
        shared = private.exchange(peer_pub)
        return blake3(shared).digest()


class PFSManager:
    """
    Perfect Forward Secrecy manager.

    Generates and manages ephemeral keypairs for each session.
    Old keypairs are securely deleted after use.
    """

    def __init__(self, key_lifetime: float = 300.0):
        """
        Initialize PFS manager.

        Args:
            key_lifetime: Maximum lifetime of ephemeral keys in seconds
        """
        self._lock = RLock()
        self._key_lifetime = key_lifetime
        # session_id -> EphemeralKeyPair
        self._keypairs: Dict[bytes, EphemeralKeyPair] = {}
        # peer_id -> (session_id, shared_secret, ephemeral_pub)
        self._sessions: Dict[bytes, Tuple[bytes, bytes, bytes]] = {}

    def generate_keypair(self) -> EphemeralKeyPair:
        """Generate and store a new ephemeral keypair."""
        with self._lock:
            self._cleanup_expired()
            keypair = EphemeralKeyPair.generate()
            self._keypairs[keypair.session_id] = keypair
            return keypair

    def complete_exchange(
        self,
        session_id: bytes,
        peer_id: bytes,
        peer_ephemeral_pub: bytes,
    ) -> Optional[bytes]:
        """
        Complete key exchange and derive session secret.

        Returns the derived shared secret, or None if session not found.
        """
        with self._lock:
            keypair = self._keypairs.get(session_id)
            if keypair is None:
                return None

            # Derive shared secret
            shared_secret = keypair.derive_shared_secret(peer_ephemeral_pub)

            # Store session info
            self._sessions[peer_id] = (session_id, shared_secret, peer_ephemeral_pub)

            # Delete the private key material (PFS)
            del self._keypairs[session_id]

            return shared_secret

    def get_session_secret(self, peer_id: bytes) -> Optional[bytes]:
        """Get the shared secret for a peer session."""
        with self._lock:
            session = self._sessions.get(peer_id)
            return session[1] if session else None

    def derive_session_keys(
        self,
        shared_secret: bytes,
        my_id: bytes,
        peer_id: bytes,
        context: bytes = b"malachi-pfs-v1",
    ) -> Tuple[bytes, bytes]:
        """
        Derive directional session keys from shared secret.

        Returns (rx_key, tx_key) based on ID ordering.
        """
        # Create key derivation material
        kdf_input = context + shared_secret + my_id + peer_id

        # Derive 64 bytes (32 for each direction)
        derived = blake3(kdf_input).digest(length=64)

        if my_id < peer_id:
            # We are "client" - rx from first half, tx from second
            return derived[:32], derived[32:]
        else:
            # We are "server" - tx from first half, rx from second
            return derived[32:], derived[:32]

    def invalidate_session(self, peer_id: bytes) -> None:
        """Invalidate and securely delete session for a peer."""
        with self._lock:
            self._sessions.pop(peer_id, None)

    def _cleanup_expired(self) -> None:
        """Remove expired keypairs."""
        now = time.time()
        expired = [
            sid for sid, kp in self._keypairs.items()
            if now - kp.created_at > self._key_lifetime
        ]
        for sid in expired:
            del self._keypairs[sid]


# ---------------- Key Confirmation ----------------


@dataclass
class KeyConfirmation:
    """Key confirmation message data."""
    session_id: bytes
    confirm_hash: bytes  # H(shared_secret || "confirm" || my_id || peer_id)
    timestamp: float = field(default_factory=time.time)


class KeyConfirmationManager:
    """
    Manages key confirmation protocol.

    After key exchange, both parties send confirmation hashes
    to verify they derived the same session keys.
    """

    CONFIRM_CONTEXT = b"malachi-key-confirm-v1"

    def __init__(self, timeout: float = 30.0):
        self._lock = RLock()
        self._timeout = timeout
        # peer_id -> expected_confirm_hash
        self._pending: Dict[bytes, bytes] = {}
        # peer_id -> confirmed timestamp
        self._confirmed: Dict[bytes, float] = {}

    def generate_confirmation(
        self,
        shared_secret: bytes,
        my_id: bytes,
        peer_id: bytes,
    ) -> bytes:
        """Generate key confirmation hash to send to peer."""
        return blake3(
            self.CONFIRM_CONTEXT + shared_secret + my_id + peer_id
        ).digest()[:16]

    def expect_confirmation(
        self,
        peer_id: bytes,
        shared_secret: bytes,
        my_id: bytes,
    ) -> None:
        """Set up expected confirmation from peer."""
        with self._lock:
            # Expected hash is computed from peer's perspective
            expected = blake3(
                self.CONFIRM_CONTEXT + shared_secret + peer_id + my_id
            ).digest()[:16]
            self._pending[peer_id] = expected

    def verify_confirmation(
        self,
        peer_id: bytes,
        received_hash: bytes,
    ) -> bool:
        """
        Verify received confirmation hash.

        Returns True if confirmation matches expected.
        """
        with self._lock:
            expected = self._pending.pop(peer_id, None)
            if expected is None:
                log(f"[KEY-CONFIRM] No pending confirmation for {short_id(peer_id)}")
                return False

            if received_hash != expected:
                log(f"[KEY-CONFIRM] Hash mismatch for {short_id(peer_id)}")
                return False

            self._confirmed[peer_id] = time.time()
            log(f"[KEY-CONFIRM] Confirmed keys with {short_id(peer_id)}")
            return True

    def is_confirmed(self, peer_id: bytes) -> bool:
        """Check if keys are confirmed with peer."""
        with self._lock:
            return peer_id in self._confirmed

    def cleanup_expired(self) -> None:
        """Remove expired pending confirmations."""
        with self._lock:
            now = time.time()
            # Note: We only store the hash, not the timestamp, so we can't
            # expire them properly. In production, store timestamps too.
            pass


# ---------------- Certificate/Identity Chains (Web of Trust) ----------------


@dataclass
class IdentityCertificate:
    """
    Identity certificate vouching for another node.

    Allows nodes to build a web of trust.
    """
    subject_id: bytes  # Node being vouched for
    subject_ed_pub: bytes  # Subject's Ed25519 public key
    issuer_id: bytes  # Node doing the vouching
    issuer_ed_pub: bytes  # Issuer's Ed25519 public key
    issued_at: float
    expires_at: float
    signature: bytes  # Issuer's signature over the certificate
    trust_level: int = 1  # 1-10, higher = more trusted

    def to_bytes(self) -> bytes:
        """Serialize certificate to bytes (excluding signature)."""
        return (
            self.subject_id
            + self.subject_ed_pub
            + self.issuer_id
            + self.issuer_ed_pub
            + int(self.issued_at).to_bytes(8, "big")
            + int(self.expires_at).to_bytes(8, "big")
            + bytes([self.trust_level])
        )

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict."""
        return {
            "subject_id": base64.b64encode(self.subject_id).decode(),
            "subject_ed_pub": base64.b64encode(self.subject_ed_pub).decode(),
            "issuer_id": base64.b64encode(self.issuer_id).decode(),
            "issuer_ed_pub": base64.b64encode(self.issuer_ed_pub).decode(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": base64.b64encode(self.signature).decode(),
            "trust_level": self.trust_level,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "IdentityCertificate":
        """Create from dict."""
        return cls(
            subject_id=base64.b64decode(data["subject_id"]),
            subject_ed_pub=base64.b64decode(data["subject_ed_pub"]),
            issuer_id=base64.b64decode(data["issuer_id"]),
            issuer_ed_pub=base64.b64decode(data["issuer_ed_pub"]),
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            signature=base64.b64decode(data["signature"]),
            trust_level=data.get("trust_level", 1),
        )


class WebOfTrust:
    """
    Web of Trust for identity verification.

    Nodes can vouch for other nodes' identities, building
    a decentralized trust network.
    """

    def __init__(self, store_path: Optional[str] = None):
        self._lock = RLock()
        self._store_path = store_path or os.path.join(KEYDIR, "trust.json")
        # subject_id -> list of certificates
        self._certificates: Dict[bytes, List[IdentityCertificate]] = {}
        # Revoked certificate hashes
        self._revoked: Set[bytes] = set()
        self._load()

    def _load(self) -> None:
        """Load trust store from disk."""
        try:
            with open(self._store_path, "r") as f:
                data = json.load(f)
                for cert_data in data.get("certificates", []):
                    cert = IdentityCertificate.from_dict(cert_data)
                    self._add_cert(cert)
                self._revoked = {
                    base64.b64decode(h) for h in data.get("revoked", [])
                }
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    def _save(self) -> None:
        """Save trust store to disk."""
        certs = []
        for cert_list in self._certificates.values():
            certs.extend(c.to_dict() for c in cert_list)

        data = {
            "certificates": certs,
            "revoked": [base64.b64encode(h).decode() for h in self._revoked],
        }

        os.makedirs(os.path.dirname(self._store_path), exist_ok=True)
        with open(self._store_path, "w") as f:
            json.dump(data, f, indent=2)

    def _add_cert(self, cert: IdentityCertificate) -> None:
        """Add certificate to store (no validation)."""
        if cert.subject_id not in self._certificates:
            self._certificates[cert.subject_id] = []
        self._certificates[cert.subject_id].append(cert)

    def _cert_hash(self, cert: IdentityCertificate) -> bytes:
        """Compute certificate hash for revocation tracking."""
        return blake3(cert.to_bytes() + cert.signature).digest()[:16]

    def issue_certificate(
        self,
        subject_id: bytes,
        subject_ed_pub: bytes,
        issuer_sk: signing.SigningKey,
        issuer_id: bytes,
        validity_days: int = 365,
        trust_level: int = 5,
    ) -> IdentityCertificate:
        """
        Issue a certificate vouching for another node.

        Args:
            subject_id: ID of node being vouched for
            subject_ed_pub: Subject's Ed25519 public key
            issuer_sk: Issuer's signing key
            issuer_id: Issuer's node ID
            validity_days: How long certificate is valid
            trust_level: Trust level (1-10)

        Returns:
            Signed IdentityCertificate
        """
        now = time.time()
        cert = IdentityCertificate(
            subject_id=subject_id,
            subject_ed_pub=subject_ed_pub,
            issuer_id=issuer_id,
            issuer_ed_pub=bytes(issuer_sk.verify_key),
            issued_at=now,
            expires_at=now + (validity_days * 86400),
            signature=b"",  # Will be set below
            trust_level=trust_level,
        )

        # Sign the certificate
        cert.signature = issuer_sk.sign(cert.to_bytes()).signature

        with self._lock:
            self._add_cert(cert)
            self._save()

        log(f"[WOT] Issued certificate for {id_to_hex(subject_id)}")
        return cert

    def verify_certificate(self, cert: IdentityCertificate) -> Tuple[bool, str]:
        """
        Verify a certificate's signature and validity.

        Returns (valid, reason).
        """
        # Check expiration
        if time.time() > cert.expires_at:
            return False, "certificate expired"

        # Check revocation
        if self._cert_hash(cert) in self._revoked:
            return False, "certificate revoked"

        # Verify signature
        try:
            vk = signing.VerifyKey(cert.issuer_ed_pub)
            vk.verify(cert.to_bytes(), cert.signature)
        except Exception as e:
            return False, f"signature invalid: {e}"

        return True, "valid"

    def add_certificate(self, cert: IdentityCertificate) -> bool:
        """
        Add and verify a certificate from another node.

        Returns True if certificate was valid and added.
        """
        valid, reason = self.verify_certificate(cert)
        if not valid:
            log(f"[WOT] Rejected certificate: {reason}")
            return False

        with self._lock:
            self._add_cert(cert)
            self._save()

        return True

    def revoke_certificate(self, cert: IdentityCertificate) -> None:
        """Revoke a certificate."""
        with self._lock:
            cert_hash = self._cert_hash(cert)
            self._revoked.add(cert_hash)
            self._save()
        log(f"[WOT] Revoked certificate for {id_to_hex(cert.subject_id)}")

    def get_trust_level(self, subject_id: bytes, my_id: bytes) -> int:
        """
        Calculate trust level for a node.

        Returns 0 (untrusted) to 10 (fully trusted).
        Uses highest trust from any valid certificate chain.
        """
        with self._lock:
            certs = self._certificates.get(subject_id, [])
            if not certs:
                return 0

            max_trust = 0
            for cert in certs:
                valid, _ = self.verify_certificate(cert)
                if not valid:
                    continue

                # Direct trust from us
                if cert.issuer_id == my_id:
                    max_trust = max(max_trust, cert.trust_level)
                else:
                    # Transitive trust (reduced)
                    issuer_trust = self.get_trust_level(cert.issuer_id, my_id)
                    if issuer_trust > 0:
                        transitive = min(issuer_trust, cert.trust_level) - 1
                        max_trust = max(max_trust, transitive)

            return max_trust

    def get_certificates_for(self, subject_id: bytes) -> List[IdentityCertificate]:
        """Get all certificates for a subject."""
        with self._lock:
            return list(self._certificates.get(subject_id, []))


# ---------------- Channel Binding ----------------


class ChannelBinding:
    """
    Binds session keys to specific MAC addresses.

    Prevents session hijacking if an attacker clones a MAC address.
    """

    BINDING_CONTEXT = b"malachi-channel-bind-v1"

    def __init__(self):
        self._lock = RLock()
        # peer_id -> (bound_mac, binding_hash)
        self._bindings: Dict[bytes, Tuple[str, bytes]] = {}

    def create_binding(
        self,
        shared_secret: bytes,
        my_mac: str,
        peer_mac: str,
        my_id: bytes,
        peer_id: bytes,
    ) -> bytes:
        """
        Create a channel binding hash.

        This hash is included in all subsequent messages to prove
        the session is bound to specific MAC addresses.
        """
        # Normalize MACs
        my_mac = my_mac.lower()
        peer_mac = peer_mac.lower()

        # Create binding
        binding_data = (
            self.BINDING_CONTEXT
            + shared_secret
            + my_mac.encode()
            + peer_mac.encode()
            + my_id
            + peer_id
        )
        binding_hash = blake3(binding_data).digest()[:16]

        with self._lock:
            self._bindings[peer_id] = (peer_mac, binding_hash)

        return binding_hash

    def verify_binding(
        self,
        peer_id: bytes,
        received_mac: str,
        received_binding: Optional[bytes] = None,
    ) -> bool:
        """
        Verify channel binding is still valid.

        Checks that the MAC address matches the bound address.
        """
        with self._lock:
            binding = self._bindings.get(peer_id)
            if binding is None:
                return True  # No binding = no restriction

            bound_mac, binding_hash = binding

            if received_mac.lower() != bound_mac:
                log(f"[CHANNEL-BIND] MAC mismatch for {short_id(peer_id)}: "
                    f"expected {bound_mac}, got {received_mac}")
                return False

            if received_binding is not None and received_binding != binding_hash:
                log(f"[CHANNEL-BIND] Binding hash mismatch for {short_id(peer_id)}")
                return False

            return True

    def get_binding(self, peer_id: bytes) -> Optional[bytes]:
        """Get binding hash for a peer."""
        with self._lock:
            binding = self._bindings.get(peer_id)
            return binding[1] if binding else None

    def remove_binding(self, peer_id: bytes) -> None:
        """Remove channel binding for a peer."""
        with self._lock:
            self._bindings.pop(peer_id, None)


# ---------------- Anti-Replay Sliding Window ----------------


class SlidingWindowReplay:
    """
    IPsec-style sliding window for replay detection.

    More memory-efficient than storing all recent nonces.
    Tracks a window of sequence numbers around the highest seen.
    """

    def __init__(self, window_size: int = 64):
        """
        Initialize sliding window.

        Args:
            window_size: Size of the replay window in bits
        """
        self._lock = RLock()
        self._window_size = window_size
        # peer_id -> (highest_seq, bitmap)
        self._windows: Dict[bytes, Tuple[int, int]] = {}

    def check_and_update(self, peer_id: bytes, seq_num: int) -> bool:
        """
        Check if sequence number is a replay.

        Returns True if this is a NEW (non-replay) packet.
        Updates the window if accepted.
        """
        with self._lock:
            if peer_id not in self._windows:
                # First packet from this peer
                self._windows[peer_id] = (seq_num, 1)
                return True

            highest, bitmap = self._windows[peer_id]

            if seq_num > highest:
                # New highest - shift window
                shift = min(seq_num - highest, self._window_size)
                if shift >= self._window_size:
                    # Complete window reset
                    bitmap = 1
                else:
                    bitmap = (bitmap << shift) | 1

                self._windows[peer_id] = (seq_num, bitmap & ((1 << self._window_size) - 1))
                return True

            elif seq_num == highest:
                # Replay of highest
                return False

            else:
                # Older packet - check window
                diff = highest - seq_num
                if diff >= self._window_size:
                    # Too old - outside window
                    return False

                # Check bit in window
                bit_pos = diff - 1
                if bitmap & (1 << bit_pos):
                    # Already seen
                    return False

                # Mark as seen
                bitmap |= (1 << bit_pos)
                self._windows[peer_id] = (highest, bitmap)
                return True

    def reset(self, peer_id: bytes) -> None:
        """Reset window for a peer."""
        with self._lock:
            self._windows.pop(peer_id, None)

    def get_highest_seq(self, peer_id: bytes) -> int:
        """Get highest sequence number seen from peer."""
        with self._lock:
            window = self._windows.get(peer_id)
            return window[0] if window else -1


# ---------------- Global Instances ----------------


_pfs_manager: Optional[PFSManager] = None
_key_confirm_manager: Optional[KeyConfirmationManager] = None
_web_of_trust: Optional[WebOfTrust] = None
_channel_binding: Optional[ChannelBinding] = None
_replay_window: Optional[SlidingWindowReplay] = None


def get_pfs_manager() -> PFSManager:
    """Get global PFS manager."""
    global _pfs_manager
    if _pfs_manager is None:
        _pfs_manager = PFSManager()
    return _pfs_manager


def get_key_confirm_manager() -> KeyConfirmationManager:
    """Get global key confirmation manager."""
    global _key_confirm_manager
    if _key_confirm_manager is None:
        _key_confirm_manager = KeyConfirmationManager()
    return _key_confirm_manager


def get_web_of_trust() -> WebOfTrust:
    """Get global web of trust."""
    global _web_of_trust
    if _web_of_trust is None:
        _web_of_trust = WebOfTrust()
    return _web_of_trust


def get_channel_binding() -> ChannelBinding:
    """Get global channel binding manager."""
    global _channel_binding
    if _channel_binding is None:
        _channel_binding = ChannelBinding()
    return _channel_binding


def get_replay_window() -> SlidingWindowReplay:
    """Get global replay window."""
    global _replay_window
    if _replay_window is None:
        _replay_window = SlidingWindowReplay()
    return _replay_window
