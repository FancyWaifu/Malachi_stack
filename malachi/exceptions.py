"""
Custom exceptions for Malachi Stack.

Provides specific exception types for better error handling and debugging.
"""


class MalachiError(Exception):
    """Base exception for all Malachi Stack errors."""
    pass


# ---------------- Cryptographic Errors ----------------

class CryptoError(MalachiError):
    """Base class for cryptographic errors."""
    pass


class KeyLoadError(CryptoError):
    """Failed to load cryptographic key."""
    pass


class KeyGenerationError(CryptoError):
    """Failed to generate cryptographic key."""
    pass


class DecryptionError(CryptoError):
    """AEAD decryption or authentication failed."""
    pass


class EncryptionError(CryptoError):
    """Encryption operation failed."""
    pass


class SignatureError(CryptoError):
    """Signature verification failed."""
    pass


# ---------------- Protocol Errors ----------------

class ProtocolError(MalachiError):
    """Base class for protocol-related errors."""
    pass


class PacketParseError(ProtocolError):
    """Failed to parse packet structure."""
    pass


class InvalidPacketError(ProtocolError):
    """Packet validation failed."""
    pass


class ReplayError(ProtocolError):
    """Detected replay attack (duplicate nonce/counter)."""
    pass


class RateLimitError(ProtocolError):
    """Rate limit exceeded."""
    pass


# ---------------- NDP Errors ----------------

class NDPError(ProtocolError):
    """Base class for NDP-specific errors."""
    pass


class NDPValidationError(NDPError):
    """NDP message validation failed."""

    def __init__(self, message: str, reason: str = "unknown"):
        super().__init__(message)
        self.reason = reason


class ChallengeError(NDPError):
    """Challenge verification failed (unknown or expired)."""
    pass


class PinMismatchError(NDPError):
    """TOFU pin mismatch detected."""
    pass


class PSKMismatchError(NDPError):
    """Pre-shared key tag verification failed."""
    pass


# ---------------- Session Errors ----------------

class SessionError(MalachiError):
    """Base class for session-related errors."""
    pass


class NoSessionKeyError(SessionError):
    """No session key established with peer."""

    def __init__(self, peer_id_hex: str):
        super().__init__(f"No session key for peer {peer_id_hex}; run 'ndp' first")
        self.peer_id_hex = peer_id_hex


class PeerNotFoundError(SessionError):
    """Peer not found in neighbor table."""
    pass


# ---------------- Port Errors ----------------

class PortError(MalachiError):
    """Base class for port-related errors."""
    pass


class PortAlreadyBoundError(PortError):
    """Port is already bound."""

    def __init__(self, port: int):
        super().__init__(f"Port {port} is already bound")
        self.port = port


class PortNotBoundError(PortError):
    """Port is not bound."""

    def __init__(self, port: int):
        super().__init__(f"Port {port} is not bound")
        self.port = port


# ---------------- Network Errors ----------------

class NetworkError(MalachiError):
    """Base class for network-related errors."""
    pass


class PayloadTooLargeError(NetworkError):
    """Payload exceeds maximum frame size."""

    def __init__(self, size: int, max_size: int):
        super().__init__(f"Payload size {size} exceeds maximum {max_size}")
        self.size = size
        self.max_size = max_size


class InterfaceError(NetworkError):
    """Network interface error."""
    pass


# ---------------- Input Validation Errors ----------------

class ValidationError(MalachiError):
    """Input validation failed."""
    pass


class InvalidNodeIDError(ValidationError):
    """Invalid node ID format."""

    def __init__(self, value: str, expected_len: int = 16):
        super().__init__(
            f"Invalid node ID '{value}': expected {expected_len} bytes"
        )
        self.value = value
        self.expected_len = expected_len


class InvalidMACError(ValidationError):
    """Invalid MAC address format."""

    def __init__(self, value: str):
        super().__init__(f"Invalid MAC address: '{value}'")
        self.value = value


class InvalidPortError(ValidationError):
    """Invalid port number."""

    def __init__(self, port: int):
        super().__init__(f"Invalid port number: {port} (must be 0-65535)")
        self.port = port
