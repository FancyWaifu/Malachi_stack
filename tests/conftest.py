"""
Pytest configuration and fixtures for Malachi Stack tests.
"""

import pytest
import os
import sys
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def temp_keydir():
    """Create a temporary key directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def random_node_id():
    """Generate a random node ID."""
    return os.urandom(16)


@pytest.fixture
def random_mac():
    """Generate a random MAC address string."""
    mac_bytes = os.urandom(6)
    return ":".join(f"{b:02x}" for b in mac_bytes)


@pytest.fixture
def random_keypair():
    """Generate a random Ed25519 keypair."""
    from nacl import signing
    sk = signing.SigningKey.generate()
    return sk, sk.verify_key
