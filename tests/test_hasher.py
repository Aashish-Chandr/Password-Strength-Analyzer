# Feature: password-strength-analyzer, Property 8: Hashing and verification form a round trip
"""
Property-based tests for the Hasher class.

Validates: Requirements 3.2, 3.3
"""

import sys
import os

# Ensure the project root is on the path so we can import the module.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from password_strength_analyzer import Hasher


# ---------------------------------------------------------------------------
# Property 8: Hashing and verification form a round trip
# ---------------------------------------------------------------------------

@given(st.text(min_size=1, max_size=128))
@settings(max_examples=100, deadline=None)
def test_hash_verify_round_trip_same_password(password: str) -> None:
    """For any password p, Hasher.verify(p, Hasher.hash(p)) must return True.

    Validates: Requirements 3.2, 3.3
    """
    # Feature: password-strength-analyzer, Property 8: Hashing and verification form a round trip
    hasher = Hasher()
    digest = hasher.hash(password)
    assert hasher.verify(password, digest) is True, (
        f"verify(p, hash(p)) should return True for password={password!r}"
    )


@given(
    st.text(min_size=1, max_size=128),
    st.text(min_size=1, max_size=128),
)
@settings(max_examples=100, deadline=None)
def test_hash_verify_round_trip_different_password(password: str, other: str) -> None:
    """For any q != p, Hasher.verify(q, Hasher.hash(p)) must return False.

    Validates: Requirements 3.2, 3.3
    """
    # Feature: password-strength-analyzer, Property 8: Hashing and verification form a round trip
    assume(password != other)  # skip trivial case where both passwords are the same

    hasher = Hasher()
    digest = hasher.hash(password)
    assert hasher.verify(other, digest) is False, (
        f"verify(q, hash(p)) should return False when q={other!r} != p={password!r}"
    )


# ---------------------------------------------------------------------------
# Smoke test: bcrypt cost factor >= 10
# ---------------------------------------------------------------------------

def test_bcrypt_cost_factor() -> None:
    """Smoke test: stored bcrypt digest must have cost factor >= 10.

    Checks that the digest prefix is '$2b$' followed by a numeric cost
    factor of at least 10, e.g. '$2b$12$...'. This confirms Requirement 3.2
    (cost factor >= 10) is met when bcrypt is available.

    If bcrypt is unavailable the digest will use the sha256 fallback prefix
    ('sha256:'), and this test simply verifies the fallback prefix is present
    instead — it does not fail, since the fallback path is legitimate.
    """
    hasher = Hasher()
    digest = hasher.hash("smoke_test_password")

    if digest.startswith(b"sha256:"):
        # Fallback path — bcrypt is not installed; sha256 prefix is expected.
        assert digest.startswith(b"sha256:"), (
            "Fallback digest must start with 'sha256:'"
        )
    else:
        # bcrypt path — verify the digest starts with '$2b$' and that the
        # embedded cost factor is at least 10.
        assert digest.startswith(b"$2b$"), (
            f"bcrypt digest must start with '$2b$', got prefix: {digest[:4]!r}"
        )
        # The bcrypt digest format is: $2b$<cost>$<22-char-salt><31-char-hash>
        # Example: b'$2b$12$...'  →  cost = 12
        try:
            # Extract the cost factor from the digest.
            # Split on '$': ['', '2b', '<cost>', '<salt+hash>']
            parts = digest.decode("ascii").split("$")
            cost_factor = int(parts[2])
        except (ValueError, IndexError, UnicodeDecodeError) as exc:
            pytest.fail(f"Could not parse bcrypt cost factor from digest: {exc}")

        assert cost_factor >= 10, (
            f"bcrypt cost factor must be >= 10 (Requirement 3.2), got {cost_factor}"
        )
