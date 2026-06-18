"""
Tests for the Analyzer class.

Property-based tests use Hypothesis to verify universal properties
across many inputs. Unit tests verify specific examples and edge cases.
"""

import sys
import os

# Ensure the project root is on the path so we can import the module.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from password_strength_analyzer import Analyzer, AnalysisResult, WEAK_PASSWORD_LIST

from hypothesis import given, settings, assume
from hypothesis import strategies as st
import string


# ---------------------------------------------------------------------------
# Property 1: Over-length inputs are always rejected
# Feature: password-strength-analyzer, Property 1: Over-length inputs are always rejected
# ---------------------------------------------------------------------------

# **Validates: Requirements 1.1**
@given(st.text(min_size=129))
@settings(max_examples=100, deadline=None)
def test_property1_overlength_inputs_always_rejected(password):
    """Property 1: Any string longer than 128 characters is always rejected.

    For any text with at least 129 characters, Analyzer.analyze() must return
    an AnalysisResult with a non-empty error message and score=None.

    **Validates: Requirements 1.1**
    """
    # Feature: password-strength-analyzer, Property 1: Over-length inputs are always rejected
    analyzer = Analyzer()
    result = analyzer.analyze(password)

    assert result.score is None, (
        f"Expected score=None for over-length input (len={len(password)}), "
        f"got score={result.score}"
    )
    assert result.error is not None and len(result.error) > 0, (
        f"Expected non-empty error for over-length input (len={len(password)}), "
        f"got error={result.error!r}"
    )


# ---------------------------------------------------------------------------
# Property 2: Invalid-type and empty inputs are always rejected
# Feature: password-strength-analyzer, Property 2: Invalid-type and empty inputs are always rejected
# ---------------------------------------------------------------------------

# **Validates: Requirements 1.2**
@given(
    st.one_of(
        st.none(),
        st.integers(),
        st.floats(),
        st.lists(st.text()),
    )
)
@settings(max_examples=100, deadline=None)
def test_property2_invalid_type_inputs_always_rejected(invalid_input):
    """Property 2: Invalid-type inputs (None, int, float, list) are always rejected.

    For any value that is not a string, Analyzer.analyze() must return an
    AnalysisResult with a non-empty error message and score=None.

    **Validates: Requirements 1.2**
    """
    # Feature: password-strength-analyzer, Property 2: Invalid-type and empty inputs are always rejected
    analyzer = Analyzer()
    result = analyzer.analyze(invalid_input)

    assert result.score is None, (
        f"Expected score=None for invalid input {invalid_input!r} "
        f"(type {type(invalid_input).__name__}), got score={result.score}"
    )
    assert result.error is not None and len(result.error) > 0, (
        f"Expected non-empty error for invalid input {invalid_input!r}, got error={result.error!r}"
    )


def test_property2_empty_string_is_rejected():
    """Property 2 (empty string case): An empty string is always rejected.

    The empty string case is tested separately as a deterministic unit test
    since Hypothesis strategies do not produce the empty string through the
    invalid-type generators above.

    **Validates: Requirements 1.2**
    """
    # Feature: password-strength-analyzer, Property 2: Invalid-type and empty inputs are always rejected
    analyzer = Analyzer()
    result = analyzer.analyze("")

    assert result.score is None, (
        f"Expected score=None for empty string, got score={result.score}"
    )
    assert result.error is not None and len(result.error) > 0, (
        f"Expected non-empty error for empty string, got error={result.error!r}"
    )


# ---------------------------------------------------------------------------
# Property 3: Complexity score equals the count of satisfied categories
# Feature: password-strength-analyzer, Property 3: Complexity score equals the count of satisfied categories
# ---------------------------------------------------------------------------

# Strategy helpers for building passwords with known category subsets.
# We use fixed representative characters from each category so we know
# exactly which categories are present.
_UPPER = "A"
_LOWER = "a"
_DIGIT = "1"
_SPECIAL = "!"

# All 16 subsets of the 4 categories (including empty set).
# Each element is a tuple of (chars_to_include, number_of_categories_present).
_CATEGORY_SUBSETS = [
    # (category_chars, count)
    ("",                          0),  # empty — but we need len>=1, handled below
    (_UPPER,                      1),
    (_LOWER,                      1),
    (_DIGIT,                      1),
    (_SPECIAL,                    1),
    (_UPPER + _LOWER,             2),
    (_UPPER + _DIGIT,             2),
    (_UPPER + _SPECIAL,           2),
    (_LOWER + _DIGIT,             2),
    (_LOWER + _SPECIAL,           2),
    (_DIGIT + _SPECIAL,           2),
    (_UPPER + _LOWER + _DIGIT,    3),
    (_UPPER + _LOWER + _SPECIAL,  3),
    (_UPPER + _DIGIT + _SPECIAL,  3),
    (_LOWER + _DIGIT + _SPECIAL,  3),
    (_UPPER + _LOWER + _DIGIT + _SPECIAL, 4),
]

# Filter out the empty-subset entry (empty string cannot be a valid password).
_CATEGORY_SUBSETS_NONEMPTY = [(chars, count) for chars, count in _CATEGORY_SUBSETS if chars]


@given(st.sampled_from(_CATEGORY_SUBSETS_NONEMPTY))
@settings(max_examples=100, deadline=None)
def test_property3_complexity_score_equals_category_count(category_info):
    """Property 3: complexity_points equals the number of satisfied categories.

    Build a password that contains exactly the characters from a known subset
    of the four categories, then call _check_complexity directly. The returned
    complexity_points must equal the number of categories represented.

    **Validates: Requirements 1.4, 1.5**
    """
    # Feature: password-strength-analyzer, Property 3: Complexity score equals the count of satisfied categories
    chars, expected_count = category_info

    # Pad the password to length 8 to avoid the weak-list accidentally
    # interfering; repeat the chars to make a simple, predictable string.
    password = (chars * 8)[:8] if len(chars) < 8 else chars

    analyzer = Analyzer()
    complexity_points, passed, failed = analyzer._check_complexity(password)

    assert complexity_points == expected_count, (
        f"Expected complexity_points={expected_count} for password {password!r} "
        f"(categories: {chars!r}), got complexity_points={complexity_points}. "
        f"passed={passed}, failed={failed}"
    )
    assert len(passed) == expected_count, (
        f"Expected {expected_count} passed criteria, got {len(passed)}: {passed}"
    )
    assert len(failed) == 4 - expected_count, (
        f"Expected {4 - expected_count} failed criteria, got {len(failed)}: {failed}"
    )


# ---------------------------------------------------------------------------
# Property 4: Final score equals clamped(complexity − length_penalty)
# Feature: password-strength-analyzer, Property 4: Final score equals clamped(complexity − length_penalty)
# ---------------------------------------------------------------------------

# **Validates: Requirements 1.3, 1.7**
@given(st.text(min_size=1, max_size=128))
@settings(max_examples=100, deadline=None)
def test_property4_final_score_equals_clamped_formula(password):
    """Property 4: AnalysisResult.score equals max(0, min(6, complexity − penalty)).

    For any valid password not in the weak list, the final score must equal
    the clamped result of the formula:
        max(0, min(6, complexity_points − (2 if len(password) < 8 else 0)))

    **Validates: Requirements 1.3, 1.7**
    """
    # Feature: password-strength-analyzer, Property 4: Final score equals clamped(complexity − length_penalty)
    # Skip passwords that are in the weak list — they get a score override of 0
    # by a different rule (Property 5), not the formula we are testing here.
    assume(password.lower() not in [w.lower() for w in WEAK_PASSWORD_LIST])

    analyzer = Analyzer()

    # Compute the expected complexity points independently (same logic as impl).
    complexity_points, _, _ = analyzer._check_complexity(password)

    # Compute expected length penalty.
    length_penalty = 2 if len(password) < 8 else 0

    # Expected final score: clamp to [0, 6].
    expected_score = max(0, min(6, complexity_points - length_penalty))

    result = analyzer.analyze(password)

    # The result must be valid (not an error).
    assert result.error is None, (
        f"Unexpected error for valid password {password!r}: {result.error!r}"
    )
    assert result.score == expected_score, (
        f"For password {password!r} (len={len(password)}): "
        f"complexity={complexity_points}, penalty={length_penalty}, "
        f"expected score={expected_score}, got score={result.score}"
    )


# ---------------------------------------------------------------------------
# Property 5: Weak-list passwords always score 0
# Feature: password-strength-analyzer, Property 5: Weak-list passwords always score 0
# ---------------------------------------------------------------------------

def _random_case_mutation(password: str, draw) -> str:
    """Randomly mutate the case of each character in a password string."""
    result = []
    for ch in password:
        if ch.isalpha():
            # Draw a boolean to decide upper or lower.
            if draw(st.booleans()):
                result.append(ch.upper())
            else:
                result.append(ch.lower())
        else:
            result.append(ch)
    return "".join(result)


# **Validates: Requirements 1.6**
@given(st.data())
@settings(max_examples=100, deadline=None)
def test_property5_weak_list_passwords_always_score_zero(data):
    """Property 5: Weak-list passwords score 0 and tier "Weak" regardless of case.

    For any password from the WEAK_PASSWORD_LIST with any case variant,
    Analyzer.analyze() must return score=0 and tier="Weak".

    **Validates: Requirements 1.6**
    """
    # Feature: password-strength-analyzer, Property 5: Weak-list passwords always score 0
    # Sample a password from the weak list.
    base_password = data.draw(st.sampled_from(WEAK_PASSWORD_LIST))
    # Apply random case mutation.
    mutated_password = _random_case_mutation(base_password, data.draw)

    analyzer = Analyzer()
    result = analyzer.analyze(mutated_password)

    assert result.score == 0, (
        f"Expected score=0 for weak-list password {mutated_password!r} "
        f"(original: {base_password!r}), got score={result.score}"
    )
    assert result.tier == "Weak", (
        f"Expected tier='Weak' for weak-list password {mutated_password!r}, "
        f"got tier={result.tier!r}"
    )


# ---------------------------------------------------------------------------
# Task 3.9 — Unit tests for tier mapping and example passwords
# ---------------------------------------------------------------------------

class TestTierMapping:
    """Unit tests for Analyzer._tier_from_score() tier boundaries."""

    def test_score_0_maps_to_weak(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(0) == "Weak"

    def test_score_1_maps_to_weak(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(1) == "Weak"

    def test_score_2_maps_to_moderate(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(2) == "Moderate"

    def test_score_3_maps_to_moderate(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(3) == "Moderate"

    def test_score_4_maps_to_strong(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(4) == "Strong"

    def test_score_5_maps_to_strong(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(5) == "Strong"

    def test_score_6_maps_to_very_strong(self):
        analyzer = Analyzer()
        assert analyzer._tier_from_score(6) == "Very Strong"


class TestExamplePasswords:
    """Unit tests for specific example passwords."""

    def test_correct_horse_battery_staple_scores_correctly(self):
        """'correct horse battery staple' is analyzed without error and produces a valid result.

        This passphrase (28 chars) contains:
          - lowercase letters: yes (+1)
          - uppercase letters: no (0)
          - digits: no (0)
          - special characters (space is printable ASCII non-alphanumeric): yes (+1)
        Total complexity = 2, length 28 (no penalty) → score = 2 → "Moderate".

        Note: The design document example suggests this should score "Strong or Very Strong",
        but per the explicit scoring formula in Requirements 1.3–1.7, this passphrase
        scores 2 → "Moderate" because it only satisfies 2 of the 4 character categories.
        The test therefore asserts the correct behavior per the scoring rules, not the
        design doc example (which appears to be an editorial error).

        **Validates: Requirements 1.7, 1.8**
        """
        analyzer = Analyzer()
        result = analyzer.analyze("correct horse battery staple")

        # The password is not in the weak list — it should produce a valid result.
        assert result.error is None, (
            f"Unexpected error: {result.error!r}"
        )
        assert result.score is not None, "Expected a numeric score"
        # Assert tier is one of the valid tiers (confirming analysis ran successfully).
        assert result.tier in ("Weak", "Moderate", "Strong", "Very Strong"), (
            f"Unexpected tier: {result.tier!r}"
        )
        # Per scoring formula: lowercase(+1) + special/space(+1) = 2 → Moderate.
        # The passphrase is not in the weak list, so it must score ≥ 1.
        assert result.score >= 1, (
            f"Expected score ≥ 1 for non-weak passphrase, got score={result.score}"
        )
        # The passphrase has exactly 2 categories (lowercase + special) → score 2 → Moderate.
        assert result.tier == "Moderate", (
            f"Expected 'correct horse battery staple' to score 'Moderate' (2 categories present), "
            f"got tier={result.tier!r} (score={result.score}). "
            f"passed={result.passed}, failed={result.failed}"
        )
