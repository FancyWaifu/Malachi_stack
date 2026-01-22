"""
Node Discovery Protocol (NDPv2) implementation.

Provides secure node discovery with:
- Ed25519 signed messages
- Challenge-response authentication
- Optional PSK binding
- TOFU (Trust On First Use) pinning
"""

import os
import base64
from typing import Tuple, Optional

from nacl import signing
from scapy.all import Ether, sendp, get_if_hwaddr

from .config import (
    ETH_TYPE,
    ID_LEN,
    ED25519_PUB_LEN,
    X25519_PUB_LEN,
    ED25519_SIG_LEN,
    NONCE_LEN,
    CHALLENGE_LEN,
    PSK_TAG_LEN,
    NDP_PROTO_VER,
    NDP_OP_DISCOVER,
    NDP_OP_ADVERTISE,
    PT_NDP,
)
from .packets import Layer3, NDP2, ndp_signature_bytes
from .crypto import (
    generate_node_id,
    id_to_hex,
    mac_to_bytes,
    compute_psk_tag,
    derive_session_keys,
)
from .state import (
    get_neighbors,
    get_rate_limiter,
    get_challenges,
    get_pins,
    NonceTracker,
)
from .exceptions import (
    NDPValidationError,
    ChallengeError,
    PinMismatchError,
    PSKMismatchError,
    RateLimitError,
)
from .logging_setup import log, format_block


class NDPHandler:
    """
    Handles NDP message creation and validation.
    """

    def __init__(
        self,
        my_id: bytes,
        ed25519_sk: signing.SigningKey,
        ed25519_pub: bytes,
        x25519_pub: bytes,
        x25519_priv: bytes,
        psk: Optional[bytes] = None,
    ):
        self.my_id = my_id
        self.ed25519_sk = ed25519_sk
        self.ed25519_pub = ed25519_pub
        self.x25519_pub = x25519_pub
        self.x25519_priv = x25519_priv
        self.psk = psk

        self._neighbors = get_neighbors()
        self._rate_limiter = get_rate_limiter()
        self._challenges = get_challenges()
        self._pins = get_pins()

    def send_discover(self, iface: str) -> bool:
        """
        Broadcast NDP DISCOVER message.

        Returns True if sent, False if rate-limited.
        """
        my_mac = get_if_hwaddr(iface)

        if not self._rate_limiter.allow(my_mac):
            log("[NDP RL] Budget exceeded for DISCOVER")
            return False

        mac_bytes = mac_to_bytes(my_mac)
        challenge = os.urandom(CHALLENGE_LEN)
        nonce = os.urandom(NONCE_LEN)
        op = NDP_OP_DISCOVER
        role = 0x01
        peer_id = b"\x00" * ID_LEN
        psk_tag = compute_psk_tag(self.psk, self.my_id, peer_id, challenge)

        # Sign the message
        to_sign = ndp_signature_bytes(
            op,
            role,
            self.my_id,
            mac_bytes,
            peer_id,
            challenge,
            self.ed25519_pub,
            self.x25519_pub,
            nonce,
            psk_tag,
        )
        signature = self.ed25519_sk.sign(to_sign).signature

        # Build frame
        frame = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac, type=ETH_TYPE)
            / Layer3(version=1, ptype=PT_NDP, dst_id=b"\x00" * ID_LEN, src_id=self.my_id)
            / NDP2(
                op=op,
                ver=NDP_PROTO_VER,
                self_id=self.my_id,
                mac=my_mac,
                ed25519_pub=self.ed25519_pub,
                x25519_pub=self.x25519_pub,
                peer_id=peer_id,
                challenge=challenge,
                nonce=nonce,
                psk_tag=psk_tag,
                sig=signature,
            )
        )

        sendp(frame, iface=iface, verbose=False)
        self._challenges.add(challenge)

        log(
            format_block(
                "NDPv2 PROBE",
                [
                    f"iface : {iface}",
                    f"node  : {id_to_hex(self.my_id)}",
                    f"mac   : {my_mac}",
                    "dst   : ff:ff:ff:ff:ff:ff (broadcast)",
                ],
            )
        )
        return True

    def send_advertise(
        self,
        iface: str,
        requester_mac: str,
        requester_id: bytes,
        challenge: bytes,
    ) -> bool:
        """
        Send NDP ADVERTISE message in response to DISCOVER.

        Returns True if sent, False if rate-limited.
        """
        if not self._rate_limiter.allow(requester_mac):
            log(f"[NDP RL] Rate-limited ADVERTISE to {requester_mac}")
            return False

        my_mac = get_if_hwaddr(iface)
        mac_bytes = mac_to_bytes(my_mac)
        nonce = os.urandom(NONCE_LEN)
        op = NDP_OP_ADVERTISE
        role = 0x02
        psk_tag = compute_psk_tag(self.psk, self.my_id, requester_id, challenge)

        # Sign the message
        to_sign = ndp_signature_bytes(
            op,
            role,
            self.my_id,
            mac_bytes,
            requester_id,
            challenge,
            self.ed25519_pub,
            self.x25519_pub,
            nonce,
            psk_tag,
        )
        signature = self.ed25519_sk.sign(to_sign).signature

        # Build frame
        frame = (
            Ether(dst=requester_mac, src=my_mac, type=ETH_TYPE)
            / Layer3(version=1, ptype=PT_NDP, dst_id=requester_id, src_id=self.my_id)
            / NDP2(
                op=op,
                ver=NDP_PROTO_VER,
                self_id=self.my_id,
                mac=my_mac,
                ed25519_pub=self.ed25519_pub,
                x25519_pub=self.x25519_pub,
                peer_id=requester_id,
                challenge=challenge,
                nonce=nonce,
                psk_tag=psk_tag,
                sig=signature,
            )
        )

        sendp(frame, iface=iface, verbose=False)

        log(
            format_block(
                "NDPv2 ADVERTISE",
                [
                    f"iface : {iface}",
                    f"to    : {requester_mac}",
                    f"node  : {id_to_hex(self.my_id)}",
                    f"mac   : {my_mac}",
                ],
            )
        )
        return True

    def validate_and_store(
        self,
        ndp_pkt: "NDP2",
        l3_pkt: "Layer3",
        l2_src_mac: str,
        role_expected: int,
    ) -> Tuple[bool, str]:
        """
        Validate an NDP message and store the neighbor if valid.

        Args:
            ndp_pkt: NDP2 packet
            l3_pkt: Layer3 packet
            l2_src_mac: Source MAC from Ethernet frame
            role_expected: Expected role (0x01 for DISCOVER, 0x02 for ADVERTISE)

        Returns:
            Tuple of (success, reason)
        """
        try:
            # Version check
            if ndp_pkt.ver != NDP_PROTO_VER:
                return False, "bad version"

            # Field length validation
            field_checks = [
                ("self_id", ID_LEN),
                ("ed25519_pub", ED25519_PUB_LEN),
                ("x25519_pub", X25519_PUB_LEN),
                ("peer_id", ID_LEN),
                ("challenge", CHALLENGE_LEN),
                ("nonce", NONCE_LEN),
                ("psk_tag", PSK_TAG_LEN),
                ("sig", ED25519_SIG_LEN),
            ]

            for field_name, expected_len in field_checks:
                actual_len = len(bytes(getattr(ndp_pkt, field_name)))
                if actual_len != expected_len:
                    return False, f"bad {field_name} length"

            # Extract fields
            self_id = bytes(ndp_pkt.self_id)
            mac_str = ndp_pkt.mac
            mac_bytes = mac_to_bytes(mac_str)
            peer_id = bytes(ndp_pkt.peer_id)
            challenge = bytes(ndp_pkt.challenge)
            ed_pub = bytes(ndp_pkt.ed25519_pub)
            x_pub = bytes(ndp_pkt.x25519_pub)
            nonce = bytes(ndp_pkt.nonce)
            psk_tag = bytes(ndp_pkt.psk_tag)
            signature = bytes(ndp_pkt.sig)
            op = int(ndp_pkt.op)

            # Identity verification
            if generate_node_id(ed_pub) != self_id:
                return False, "node_id mismatch with ed25519 pubkey"

            # MAC address consistency
            if mac_str.lower() != l2_src_mac.lower():
                return False, "L2 MAC mismatch"

            # L3 header consistency
            if bytes(l3_pkt.src_id) != self_id:
                return False, "L3 src_id mismatch"

            # PSK verification (if we have a PSK)
            if self.psk is not None:
                expected_tag = compute_psk_tag(self.psk, self_id, peer_id, challenge)
                if psk_tag != expected_tag:
                    return False, "PSK tag invalid"

            # Signature verification
            to_sign = ndp_signature_bytes(
                op,
                role_expected,
                self_id,
                mac_bytes,
                peer_id,
                challenge,
                ed_pub,
                x_pub,
                nonce,
                psk_tag,
            )
            try:
                signing.VerifyKey(ed_pub).verify(to_sign, signature)
            except Exception as e:
                return False, f"signature verification failed: {e}"

            # Get or create neighbor entry for nonce tracking
            entry = self._neighbors.get_or_create(self_id, mac_str, ed_pub, x_pub)

            # Replay detection
            if NonceTracker.check_nonce(entry, nonce):
                return False, "replayed nonce"

            # Role-specific checks
            if role_expected == 0x02:  # ADVERTISE
                if peer_id != self.my_id:
                    return False, "peer_id != my_id"
                if not self._challenges.consume(challenge):
                    return False, "unknown/expired challenge"

            # TOFU pinning
            ed_pub_b64 = base64.b64encode(ed_pub).decode("ascii")
            if not self._pins.check_or_set(id_to_hex(self_id), ed_pub_b64):
                return False, "TOFU pin mismatch"

            # Derive session keys
            rx_key, tx_key = derive_session_keys(
                self.my_id, self_id, self.x25519_pub, self.x25519_priv, x_pub
            )
            entry.key_rx = rx_key
            entry.key_tx = tx_key

            # Cleanup
            self._neighbors.prune_stale()
            self._challenges.prune()

            return True, "ok"

        except Exception as e:
            return False, f"validation error: {e!r}"


# ---------------- Global Handler ----------------

_ndp_handler: Optional[NDPHandler] = None


def init_ndp_handler(
    my_id: bytes,
    ed25519_sk: signing.SigningKey,
    ed25519_pub: bytes,
    x25519_pub: bytes,
    x25519_priv: bytes,
    psk: Optional[bytes] = None,
) -> NDPHandler:
    """Initialize the global NDP handler."""
    global _ndp_handler
    _ndp_handler = NDPHandler(
        my_id, ed25519_sk, ed25519_pub, x25519_pub, x25519_priv, psk
    )
    return _ndp_handler


def get_ndp_handler() -> Optional[NDPHandler]:
    """Get the global NDP handler."""
    return _ndp_handler
