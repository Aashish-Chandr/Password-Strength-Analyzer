"""
Password Strength Analyzer
==========================
A production-ready Python tool that evaluates password strength, suggests
cryptographically secure alternatives, and prevents password reuse via a
bcrypt-hashed history store backed by SQLite.

Modules (classes) contained in this file:
  - Analyzer       — scores and classifies password strength
  - Generator      — produces cryptographically secure password suggestions
  - Hasher         — hashes and verifies passwords using bcrypt (or sha256 fallback)
  - Password_Store — persists hashed password history for anti-reuse checking

Entry points:
  - main()         — orchestrates a complete demonstration
  - __main__ block — prints an educational breakdown when run directly
"""

import string
import os
import sys
import sqlite3
import warnings
import collections
import dataclasses
import re
import secrets  # cryptographically secure random source for password generation

# ---------------------------------------------------------------------------
# Optional bcrypt import — falls back to hashlib.sha256 when unavailable.
# ---------------------------------------------------------------------------
try:
    import bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    import hashlib  # used by the sha256 fallback path
    _BCRYPT_AVAILABLE = False
    warnings.warn(
        "bcrypt is not installed. Falling back to hashlib.sha256 for password "
        "hashing. Install bcrypt for production use: pip install bcrypt",
        stacklevel=1,
    )
    sys.stderr.write(
        "[WARNING] bcrypt unavailable — using hashlib.sha256 fallback. "
        "This is less secure than bcrypt for password storage.\n"
    )

# Make hashlib available for the fallback path regardless of import order.
# If bcrypt IS available we still import hashlib because it may be needed by
# verify() when it encounters a digest created under the fallback.
try:
    import hashlib  # noqa: F811 — safe re-import when bcrypt is present
except ImportError:  # pragma: no cover — hashlib is always in the stdlib
    pass


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

WEAK_PASSWORD_LIST: list[str] = [
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "monkey",
    "1234567890",
    "iloveyou",
    "admin",
    "welcome",
    "login",
    "passw0rd",
    "master",
]
"""A curated list of commonly used, easily guessable passwords (lowercase).

Any candidate password that matches an entry here (case-insensitive) receives
a Strength_Score of 0, overriding all complexity and length scoring.
"""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AnalysisResult:
    """Returned by Analyzer.analyze() for every evaluation attempt.

    Fields
    ------
    score : int | None
        Integer in 0–6 after clamping.  ``None`` when the input is invalid.
    tier : str | None
        Human-readable strength tier ("Weak" / "Moderate" / "Strong" /
        "Very Strong").  ``None`` when the input is invalid.
    passed : list[str]
        Criteria that were satisfied by the candidate password.
    failed : list[str]
        Criteria that were NOT satisfied by the candidate password.
    error : str | None
        Set to a descriptive message when the input is invalid; ``None``
        when the analysis completed successfully.
    """

    score: int | None = None
    tier: str | None = None
    passed: list[str] = dataclasses.field(default_factory=list)
    failed: list[str] = dataclasses.field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------

class Password_StoreError(Exception):
    """Raised when the Password_Store backend is unavailable or fails.

    Examples of conditions that trigger this error:
    - SQLite database file cannot be opened or created.
    - A query fails during ``check_reuse()`` or ``store()``.

    Callers (e.g., ``main()``) should catch this exception and return an error
    result without accepting or rejecting the candidate password.
    """


# ---------------------------------------------------------------------------
# Hasher — cryptographic hashing and verification
# ---------------------------------------------------------------------------

class Hasher:
    """Hashes and verifies passwords using bcrypt (or sha256 fallback).

    Primary path uses bcrypt — the industry-standard adaptive hashing
    algorithm designed specifically for password storage.  It is intentionally
    slow (configurable via a cost/work factor) to resist brute-force and
    dictionary attacks, and it embeds a unique per-password salt so that
    identical passwords produce different digests.

    Fallback path uses hashlib.sha256 + a random 16-byte salt when bcrypt is
    not installed.  While sha256 is a cryptographically secure hash function,
    it is NOT designed for password hashing — it is orders of magnitude faster
    than bcrypt, making brute-force attacks far more feasible.  The fallback
    is provided solely for environments where bcrypt cannot be installed;
    bcrypt should always be preferred for production use.

    The fallback digest format is:
        b"sha256:<16-byte-hex-salt>:<32-byte-hex-digest>"

    The "sha256:" prefix allows verify() to detect which path produced the
    digest and dispatch to the correct verification logic without ambiguity.
    """

    # Cost factor for bcrypt.  NIST and OWASP recommend ≥ 10; 12 is a
    # reasonable default that balances security and latency (~300 ms on
    # modern hardware).  Increase this value as hardware gets faster.
    BCRYPT_ROUNDS: int = 12

    def hash(self, password: str) -> bytes:
        """Hash *password* and return the stored digest bytes.

        Parameters
        ----------
        password : str
            The plain-text password to hash.  It is encoded to UTF-8 bytes
            before processing and is never stored or logged.

        Returns
        -------
        bytes
            - **bcrypt path**: the raw bcrypt digest (includes embedded salt
              and cost factor, e.g. ``b"$2b$12$..."``) — 60 bytes.
            - **fallback path**: ``b"sha256:<hex-salt>:<hex-digest>"`` — a
              structured ASCII representation containing a 32-char hex salt
              (16 bytes → 32 hex chars) and a 64-char hex digest (32 bytes →
              64 hex chars).

        Security note
        -------------
        bcrypt is preferred because:
        1. Its cost factor makes each hash intentionally slow, resisting
           GPU-accelerated brute-force attacks.
        2. The salt is automatically generated and embedded in the output,
           ensuring different digests for identical passwords.
        sha256 lacks the adaptive cost factor — a single modern GPU can
        compute *billions* of sha256 hashes per second.
        """
        if _BCRYPT_AVAILABLE:
            # bcrypt.hashpw expects bytes; encode the password to UTF-8.
            # The salt is generated internally by bcrypt.gensalt() and
            # embedded in the returned digest — callers never see the raw salt.
            #
            # bcrypt has a 72-byte input limit. To safely handle passwords whose
            # UTF-8 encoding exceeds 72 bytes (possible with multi-byte Unicode
            # characters), we pre-hash the password with SHA-256 before passing
            # it to bcrypt. SHA-256 produces a 32-byte digest — well within the
            # bcrypt limit — while preserving the uniqueness of each password.
            # verify() must apply the same pre-hashing step for correctness.
            password_bytes = password.encode("utf-8")
            # Pre-hash with SHA-256 to stay within bcrypt's 72-byte limit and
            # to support arbitrarily long passwords without silent truncation.
            password_bytes = hashlib.sha256(password_bytes).digest()
            salt = bcrypt.gensalt(rounds=self.BCRYPT_ROUNDS)
            return bcrypt.hashpw(password_bytes, salt)
        else:
            # ---------------------------------------------------------------
            # sha256 FALLBACK PATH
            # ---------------------------------------------------------------
            # bcrypt is unavailable (ImportError at module load).  We fall
            # back to a manually salted sha256 digest.  This is significantly
            # weaker than bcrypt for password storage — see class docstring.
            #
            # A fresh 16-byte cryptographically random salt is generated for
            # every call, ensuring different digests for identical passwords
            # (prevents rainbow-table attacks even against sha256).
            salt = os.urandom(16)  # 16 bytes = 128 bits of random salt

            # Prepend the salt to the password bytes before hashing so that
            # the salt is incorporated into the digest (H(salt || password)).
            digest = hashlib.sha256(salt + password.encode("utf-8")).digest()

            # Encode both salt and digest as hex strings for safe storage.
            # Format: b"sha256:<32-char-hex-salt>:<64-char-hex-digest>"
            # The "sha256:" prefix is the discriminator used by verify() to
            # identify this as a fallback digest rather than a bcrypt digest.
            return b"sha256:" + salt.hex().encode() + b":" + digest.hex().encode()

    def verify(self, password: str, digest: bytes) -> bool:
        """Verify *password* against a previously stored *digest*.

        Dispatches to the correct verification path based on the digest
        prefix:
        - ``b"sha256:"`` prefix → fallback sha256 verification path.
        - Anything else (e.g. ``b"$2b$"`` bcrypt prefix) → bcrypt path.

        Parameters
        ----------
        password : str
            The plain-text candidate password to check.
        digest : bytes
            The stored hash bytes produced by a prior call to ``hash()``.

        Returns
        -------
        bool
            ``True``  — *password* matches the stored digest.
            ``False`` — *password* does not match (wrong password).

        Security note
        -------------
        The bcrypt path uses ``bcrypt.checkpw`` which performs a
        constant-time comparison internally, making it resistant to
        timing side-channel attacks.  The fallback sha256 path uses
        ``hmac.compare_digest`` for the same reason.
        """
        if digest.startswith(b"sha256:"):
            # ---------------------------------------------------------------
            # sha256 FALLBACK VERIFICATION PATH
            # ---------------------------------------------------------------
            # The digest was produced by hash() under the fallback path.
            # Reconstruct the expected digest by:
            #   1. Extracting the hex-encoded salt from the stored value.
            #   2. Decoding it back to raw bytes.
            #   3. Re-computing sha256(salt || password).
            #   4. Comparing the result to the stored digest using a
            #      constant-time comparison to prevent timing attacks.
            #
            # Format: b"sha256:<hex-salt>:<hex-digest>"
            try:
                # Split on ":" — expect exactly 3 parts after the prefix.
                # Example: b"sha256:aabbcc...:<hex-digest>"
                parts = digest.split(b":")
                if len(parts) != 3:
                    # Malformed fallback digest — cannot verify safely.
                    return False
                # parts[0] = b"sha256", parts[1] = hex salt, parts[2] = hex digest
                stored_salt = bytes.fromhex(parts[1].decode())
                stored_hex_digest = parts[2].decode()

                # Re-compute the digest using the extracted salt.
                candidate_digest = hashlib.sha256(
                    stored_salt + password.encode("utf-8")
                ).hexdigest()

                # Constant-time comparison — avoids timing side-channel leaks.
                import hmac
                return hmac.compare_digest(candidate_digest, stored_hex_digest)
            except (ValueError, AttributeError):
                # Decoding or format error — treat as non-matching.
                return False
        else:
            # ---------------------------------------------------------------
            # bcrypt PRIMARY VERIFICATION PATH
            # ---------------------------------------------------------------
            # bcrypt.checkpw encodes the password, extracts the embedded salt
            # from the digest, recomputes the hash, and compares in constant
            # time — all in a single call.  No manual salt handling needed.
            #
            # Apply the same SHA-256 pre-hash that hash() uses so that the
            # comparison is against the correct pre-hashed bytes.
            try:
                password_bytes = hashlib.sha256(password.encode("utf-8")).digest()
                return bcrypt.checkpw(password_bytes, digest)
            except Exception:
                # Guard against malformed digests or unexpected bcrypt errors.
                return False


# ---------------------------------------------------------------------------
# Analyzer — password strength evaluation
# ---------------------------------------------------------------------------

class Analyzer:
    """Evaluates the strength of a candidate password.

    The evaluation pipeline is:
      1. Validate input (type, emptiness, length) → return error result early.
      2. Check the weak-password list (case-insensitive) → override score to 0.
      3. Score complexity (0–4 points, one per satisfied category).
      4. Apply length penalty (−2 if len < 8).
      5. Clamp the score to [0, 6].
      6. Map the score to a named tier.

    This class is intentionally side-effect-free: it reads no external state
    beyond the weak_list injected at construction time, so it can be imported
    and tested in isolation.
    """

    def __init__(self, weak_list: list[str] | None = None) -> None:
        """Initialise the Analyzer with an optional weak-password list.

        Parameters
        ----------
        weak_list : list[str] | None
            A list of commonly-used weak passwords (lowercase).  When ``None``
            the module-level ``WEAK_PASSWORD_LIST`` is used.  Accepting this
            as a constructor parameter allows callers to inject custom lists
            without modifying global state, which is important for testing.
        """
        # Use the caller-supplied list, or fall back to the module constant.
        # Storing a reference (not a copy) is intentional — the caller is
        # responsible for not mutating the list after construction.
        self._weak_list: list[str] = weak_list if weak_list is not None else WEAK_PASSWORD_LIST

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, password) -> AnalysisResult:
        """Evaluate the strength of *password* and return an AnalysisResult.

        This is the primary entry point for strength evaluation.  Input
        validation is performed first so that malformed or dangerous inputs
        are rejected before any scoring logic runs — this is a defence-in-
        depth measure: processing untrusted input as little as possible
        reduces the attack surface.

        The scoring pipeline (for valid inputs) is:
          1. Weak-list override — if matched, return score=0, tier="Weak".
          2. Complexity points — 0–4 based on character categories present.
          3. Length penalty   — subtract 2 if len(password) < 8.
          4. Clamp            — max(0, min(6, score)).
          5. Tier mapping     — map score to named tier string.

        Parameters
        ----------
        password : any
            The candidate password to evaluate.  Expected to be a non-empty
            ``str`` of at most 128 characters; anything else returns an error
            result with ``score=None``.

        Returns
        -------
        AnalysisResult
            - On invalid input: ``error`` is set, ``score`` and ``tier``
              are ``None``.
            - On valid input: ``score`` ∈ [0, 6], ``tier`` is one of
              "Weak" / "Moderate" / "Strong" / "Very Strong", ``error``
              is ``None``.
        """
        # ------------------------------------------------------------------
        # Guard 1 — Reject None input.
        #
        # Security rationale: a None value indicates the caller did not
        # provide a password at all.  Scoring None would raise an exception
        # deeper in the pipeline; rejecting it here gives a clean, actionable
        # error message and prevents unexpected code paths from executing.
        # ------------------------------------------------------------------
        if password is None:
            return AnalysisResult(
                score=None,
                tier=None,
                passed=[],
                failed=[],
                error="Invalid input: password must be a non-empty string",
            )

        # ------------------------------------------------------------------
        # Guard 2 — Reject non-string types.
        #
        # Security rationale: type confusion bugs are a common source of
        # security vulnerabilities.  Ensuring the input is a str before any
        # string operations prevents implicit coercions that could bypass
        # length checks or pattern matching (e.g., an integer would have a
        # different concept of "length").  We report the actual type to help
        # callers diagnose integration mistakes quickly.
        # ------------------------------------------------------------------
        if not isinstance(password, str):
            # Include the actual type name so the caller knows exactly what
            # they passed — e.g., "expected string, got int" rather than a
            # generic message.
            actual_type = type(password).__name__
            return AnalysisResult(
                score=None,
                tier=None,
                passed=[],
                failed=[],
                error=f"Invalid input: expected string, got {actual_type}",
            )

        # ------------------------------------------------------------------
        # Guard 3 — Reject empty strings.
        #
        # Security rationale: an empty password has no entropy whatsoever.
        # There is no meaningful strength score to assign, and allowing an
        # empty string through could interact unexpectedly with downstream
        # systems (e.g., a bcrypt hash of "" is a valid, storable value).
        # ------------------------------------------------------------------
        if len(password) == 0:
            return AnalysisResult(
                score=None,
                tier=None,
                passed=[],
                failed=[],
                error="Invalid input: password must be a non-empty string",
            )

        # ------------------------------------------------------------------
        # Guard 4 — Reject over-length inputs (> 128 characters).
        #
        # Security rationale: bcrypt silently truncates inputs longer than
        # 72 bytes on some implementations, meaning two different long
        # passwords could produce the same hash — a critical security flaw.
        # Capping input at 128 characters prevents that silent truncation,
        # and also protects against algorithmic-complexity denial-of-service
        # attacks that use extremely long strings to exhaust CPU/memory in
        # regex or iteration-based checks performed later in the pipeline.
        # ------------------------------------------------------------------
        if len(password) > 128:
            return AnalysisResult(
                score=None,
                tier=None,
                passed=[],
                failed=[],
                error="Invalid input: password exceeds maximum length of 128 characters",
            )

        # ------------------------------------------------------------------
        # Scoring pipeline — Step 1: Weak-list override.
        #
        # If the password matches any entry in the weak list (case-insensitive),
        # immediately return score=0 and tier="Weak" without any further
        # complexity or length calculation.  This is an unconditional override:
        # even a password like "PASSWORD123!" (which would score 4 on
        # complexity) must be rejected if it appears in the weak list verbatim.
        # ------------------------------------------------------------------
        if self._check_weak_list(password):
            # Weak-list match: override all scoring, return score 0 and "Weak"
            # tier regardless of complexity or length.
            return AnalysisResult(
                score=0,
                tier="Weak",
                passed=[],
                failed=["Not in common password list"],
                error=None,
            )

        # ------------------------------------------------------------------
        # Scoring pipeline — Step 2: Complexity points (0–4).
        #
        # One point is awarded per character category present in the password:
        # uppercase letters, lowercase letters, digits, and special characters.
        # The _check_complexity helper encapsulates this logic and returns
        # human-readable passed/failed lists for inclusion in the result.
        # ------------------------------------------------------------------
        complexity_points, passed, failed = self._check_complexity(password)

        # ------------------------------------------------------------------
        # Scoring pipeline — Step 3: Length penalty.
        #
        # Passwords shorter than 8 characters are penalised by subtracting 2
        # from the complexity score.  Short passwords are easier to brute-force
        # regardless of character variety, so the penalty ensures they cannot
        # reach the upper tiers without adequate length.
        # _check_length returns a (penalty, message) tuple; the message
        # (if not None) is appended to the failed list for user feedback.
        # ------------------------------------------------------------------
        length_penalty, length_message = self._check_length(password)
        if length_message is not None:
            # Include the length failure in the human-readable breakdown.
            failed.append(length_message)

        # ------------------------------------------------------------------
        # Scoring pipeline — Step 4: Compute and clamp the final score.
        #
        # Formula: score = complexity_points - length_penalty
        # Clamp to [0, 6]: max(0, min(6, score))
        #   - max(0, ...) prevents negative scores when a short password with
        #     low complexity would otherwise go below zero.
        #   - min(6, ...) caps the score at 6 even though the current
        #     maximum complexity is 4 (future-proofs the formula).
        # ------------------------------------------------------------------
        raw_score = complexity_points - length_penalty  # apply length penalty
        score = max(0, min(6, raw_score))               # clamp to [0, 6]

        # ------------------------------------------------------------------
        # Scoring pipeline — Step 5: Tier mapping.
        #
        # Map the clamped integer score to a human-readable tier name.
        # _tier_from_score is implemented here as a temporary stub that will
        # be replaced when task 3.3 merges the full tier-mapping method.
        # ------------------------------------------------------------------
        tier = self._tier_from_score(score)

        return AnalysisResult(
            score=score,
            tier=tier,
            passed=passed,
            failed=failed,
            error=None,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_weak_list(self, password: str) -> bool:
        """Return True if *password* matches any entry in the weak-password list.

        The comparison is case-insensitive: "Password123" and "password123"
        are treated as identical for the purposes of this check.  This prevents
        trivial case-manipulation bypasses (e.g., "QWERTY" must be caught even
        though the list stores "qwerty").

        Parameters
        ----------
        password : str
            A validated non-empty string (type and length checks have already
            been applied by the caller, ``analyze()``).

        Returns
        -------
        bool
            ``True`` if a case-insensitive match is found; ``False`` otherwise.
        """
        # Convert to lowercase once and compare against the already-lowercase
        # weak list entries.  The list is typically short (< 100 entries) so
        # a linear scan is acceptable and avoids the overhead of building a set
        # on every call.
        return password.lower() in self._weak_list

    def _check_complexity(self, password: str) -> tuple[int, list[str], list[str]]:
        """Score password complexity by testing four character categories.

        One point is awarded for each of the following categories present in
        *password*:
          1. At least one uppercase ASCII letter (A–Z).
          2. At least one lowercase ASCII letter (a–z).
          3. At least one decimal digit (0–9).
          4. At least one special character (any printable ASCII char that is
             neither a letter nor a digit — defined as any char in
             ``string.punctuation`` or equivalently any char NOT in
             ``string.ascii_letters + string.digits``).

        Parameters
        ----------
        password : str
            A validated non-empty string.

        Returns
        -------
        tuple[int, list[str], list[str]]
            (complexity_points, passed_criteria, failed_criteria)
            - ``complexity_points``: integer in [0, 4].
            - ``passed_criteria``:  human-readable list of satisfied categories.
            - ``failed_criteria``:  human-readable list of missing categories.
        """
        # Build the set of special characters per Requirement 1.9: any printable
        # ASCII character that is neither a letter (a–z, A–Z) nor a digit (0–9).
        # This includes space (ord 32) and all punctuation/symbols in the
        # printable ASCII range (ordinals 32–126), which is broader than
        # string.punctuation (which excludes space).
        special_chars: frozenset[str] = frozenset(
            ch for ch in (chr(i) for i in range(32, 127))
            if not ch.isalpha() and not ch.isdigit()
        )

        passed: list[str] = []
        failed: list[str] = []
        points: int = 0

        # Category 1 — Uppercase letters (A–Z)
        if any(c.isupper() for c in password):
            points += 1
            passed.append("Contains uppercase letter")
        else:
            failed.append("Missing uppercase letter")

        # Category 2 — Lowercase letters (a–z)
        if any(c.islower() for c in password):
            points += 1
            passed.append("Contains lowercase letter")
        else:
            failed.append("Missing lowercase letter")

        # Category 3 — Digits (0–9)
        if any(c.isdigit() for c in password):
            points += 1
            passed.append("Contains digit")
        else:
            failed.append("Missing digit")

        # Category 4 — Special characters (printable ASCII non-alphanumeric)
        # A special character is any printable ASCII char NOT in a–z, A–Z, 0–9.
        # string.punctuation covers exactly this set for printable ASCII.
        if any(c in special_chars for c in password):
            points += 1
            passed.append("Contains special character")
        else:
            failed.append("Missing special character")

        return points, passed, failed

    def _check_length(self, password: str) -> tuple[int, str | None]:
        """Return a length penalty and optional failure message for *password*.

        Passwords shorter than 8 characters incur a penalty of 2 points,
        which is subtracted from the complexity score in the main scoring
        pipeline.  This reflects the requirement that short passwords are
        fundamentally weaker regardless of their character variety.

        Parameters
        ----------
        password : str
            A validated non-empty string.

        Returns
        -------
        tuple[int, str | None]
            (penalty, message)
            - ``penalty``: 2 if ``len(password) < 8``, else 0.
            - ``message``: a human-readable description of the failure when
              the penalty applies; ``None`` when no penalty is applied.
        """
        if len(password) < 8:
            # Length is below the 8-character minimum — apply the penalty and
            # return a descriptive message so the caller can include it in the
            # AnalysisResult.failed list for user-facing feedback.
            return 2, "Password is too short (minimum 8 characters)"
        # Length is adequate — no penalty, no message.
        return 0, None

    def _tier_from_score(self, score: int) -> str:
        """Map a clamped integer score (0–6) to a named strength tier.

        This is a temporary stub implementation that will be replaced when
        task 3.3 merges the full _tier_from_score method.  The mapping is:
            0–1 → "Weak"
            2–3 → "Moderate"
            4–5 → "Strong"
              6 → "Very Strong"

        Parameters
        ----------
        score : int
            A clamped integer in the range [0, 6].

        Returns
        -------
        str
            One of "Weak", "Moderate", "Strong", "Very Strong".
        """
        # Simple threshold-based mapping — the boundaries are defined by
        # Requirement 1.8 and the score-to-tier table in the design document.
        if score <= 1:
            return "Weak"
        elif score <= 3:
            return "Moderate"
        elif score <= 5:
            return "Strong"
        else:  # score == 6
            return "Very Strong"


# ---------------------------------------------------------------------------
# Password_Store — hashed password history for anti-reuse checking
# ---------------------------------------------------------------------------

class Password_Store:
    """Persists hashed password history to prevent reuse.

    Supports two storage backends, selected at construction time:

    - **In-memory mode** (``db_path=None``): a ``collections.deque(maxlen=10)``
      that automatically evicts the oldest entry when the cap is reached.
      Data is lost when the process exits.

    - **SQLite mode** (``db_path=":memory:"`` or a file path): an SQLite
      connection that persists digests in the ``password_history`` table.
      ``":memory:"`` keeps the data within the session; a file path persists
      it across process restarts.

    In both modes, passwords are **never** stored as plain text — only the
    bcrypt (or sha256 fallback) digest produced by ``Hasher.hash()`` is
    ever written to the store.  This means a breach of the store reveals
    only hashed values, which are computationally infeasible to reverse.

    Class constant
    --------------
    MAX_HISTORY : int
        Maximum number of digests retained.  Matches the ``deque(maxlen=10)``
        cap and the SQLite LRU-eviction threshold.
    """

    MAX_HISTORY: int = 10

    def __init__(self, db_path: str | None = None) -> None:
        """Initialise the Password_Store in in-memory or SQLite mode.

        Parameters
        ----------
        db_path : str | None
            - ``None`` (default): use a ``collections.deque`` — lightweight,
              no I/O, suitable for short-lived sessions or testing.
            - ``":memory:"``: open an SQLite in-memory database; data persists
              for the lifetime of the connection object.
            - Any other string: treated as a filesystem path; SQLite creates
              or opens the file at that location.

        Raises
        ------
        Password_StoreError
            When ``db_path`` is not ``None`` and the SQLite connection or
            table-creation step fails (e.g., permission denied, corrupt file).
            Wraps the underlying ``sqlite3.OperationalError`` to give callers
            a single exception type to handle.

        Security note
        -------------
        Plain text is NEVER stored here.  ``self._hasher.hash()`` is called
        in ``store()`` before any write, so only an opaque bcrypt (or sha256
        fallback) digest ever reaches the backend.  Even if an attacker reads
        the raw store, they cannot recover the original passwords without
        reversing a one-way hash function — computationally infeasible with a
        correctly tuned bcrypt cost factor.
        """
        # Delegate all hashing and verification operations to a Hasher
        # instance.  Password_Store intentionally does NOT implement its own
        # hashing logic — this separation of concerns means the hashing
        # algorithm can be upgraded (e.g., to Argon2) without touching the
        # storage layer.
        self._hasher: Hasher = Hasher()

        if db_path is None:
            # ------------------------------------------------------------------
            # In-memory mode — use a bounded deque.
            #
            # collections.deque(maxlen=10) automatically drops the leftmost
            # (oldest) item when a new item is appended and the deque is full.
            # This gives O(1) LRU eviction with zero extra code, and no
            # external dependencies.
            #
            # _conn is set to None to signal "not using SQLite" in other methods.
            # ------------------------------------------------------------------
            self._history: collections.deque[bytes] = collections.deque(maxlen=self.MAX_HISTORY)
            self._conn: sqlite3.Connection | None = None
        else:
            # ------------------------------------------------------------------
            # SQLite mode — db_path is either ":memory:" or a file path.
            #
            # sqlite3.connect() is called inside a try/except so that any
            # OperationalError (e.g., directory missing, no write permission,
            # corrupt database file) is translated into a Password_StoreError
            # with a descriptive message.  This keeps the exception surface
            # uniform for callers — they only ever need to catch
            # Password_StoreError, not sqlite3-specific exceptions.
            # ------------------------------------------------------------------
            try:
                # check_same_thread=False is intentionally NOT set here; default
                # (True) is safer for single-threaded usage.  Multi-threaded
                # callers should manage their own connection pooling.
                self._conn = sqlite3.connect(db_path)

                # Create the password_history table if it does not already exist.
                # The digest column is BLOB (raw bytes) — never TEXT — to avoid
                # any accidental encoding that could corrupt binary hash data.
                # created_at records when the digest was inserted, which supports
                # LRU ordering via the auto-increment primary key (MIN(id) = oldest).
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS password_history (
                        id         INTEGER PRIMARY KEY AUTOINCREMENT,
                        digest     BLOB    NOT NULL,
                        created_at TEXT    NOT NULL DEFAULT (datetime('now'))
                    );
                    """
                )
                self._conn.commit()

                # _history is unused in SQLite mode; set to None for safety so
                # that any accidental deque access in other methods raises
                # AttributeError rather than silently operating on stale data.
                self._history = None  # type: ignore[assignment]

            except sqlite3.OperationalError as exc:
                # Re-raise as Password_StoreError so callers have a single,
                # stable exception type to handle.  Include the original error
                # message to aid debugging without exposing internal SQLite
                # implementation details in stack traces.
                raise Password_StoreError(
                    f"Failed to initialise Password_Store backend at {db_path!r}: {exc}"
                ) from exc

    def check_reuse(self, password: str) -> bool:
        """Check whether *password* matches any stored digest.

        Iterates all stored bcrypt (or fallback sha256) digests and calls
        ``self._hasher.verify(password, digest)`` for each one.  Returns
        ``True`` on the first match so we stop as soon as we find a hit —
        there is no need to scan the rest of the history.  Returns ``False``
        if the password does not match any stored digest.

        bcrypt verification semantics
        -----------------------------
        ``Hasher.verify()`` calls ``bcrypt.checkpw(candidate, stored_digest)``.
        bcrypt extracts the embedded salt from *stored_digest* (the salt is
        baked into the bcrypt output string), re-hashes the candidate with
        that same salt, and then compares the two outputs in constant time.
        This means: (a) each stored digest carries its own unique salt, so
        identical passwords stored at different times produce different digests,
        and (b) we cannot compare digests directly — we MUST call verify() for
        every comparison; a raw equality check would almost always return False
        even for matching passwords because the salts differ.

        Parameters
        ----------
        password : str
            The plain-text candidate password to check against stored history.

        Returns
        -------
        bool
            ``True`` — the password was found in the history (previously used).
            ``False`` — the password was not found (not previously used).

        Raises
        ------
        Password_StoreError
            On any backend failure (SQLite query error).  In-memory (deque)
            mode does not perform I/O, so it cannot raise this exception.
        """
        if self._conn is None:
            # ------------------------------------------------------------------
            # In-memory (deque) mode
            #
            # Iterate the deque directly — it contains raw digest bytes in
            # insertion order (oldest → newest).  We check every entry because
            # bcrypt digests cannot be compared as plain bytes (each has a
            # unique embedded salt), so verify() is the only correct comparison.
            # ------------------------------------------------------------------
            for digest in self._history:
                if self._hasher.verify(password, digest):
                    # Match found — password was previously used.
                    return True
            # No match after checking all stored digests.
            return False
        else:
            # ------------------------------------------------------------------
            # SQLite mode
            #
            # Fetch all stored digest blobs from the password_history table.
            # We SELECT only the digest column — we never need the id or
            # created_at for verification purposes.  Iterating the rows one at
            # a time means we stop the Python loop on the first match; however,
            # all rows are still fetched from SQLite into memory by fetchall().
            # For a history cap of 10 this is negligible.
            # ------------------------------------------------------------------
            try:
                cursor = self._conn.execute(
                    "SELECT digest FROM password_history ORDER BY id ASC"
                )
                rows = cursor.fetchall()
            except sqlite3.OperationalError as exc:
                # Translate SQLite-specific errors into the stable
                # Password_StoreError interface that callers expect.
                raise Password_StoreError(
                    f"check_reuse() query failed: {exc}"
                ) from exc

            for (digest,) in rows:
                # digest is fetched as bytes (BLOB column) — pass directly to
                # Hasher.verify() which handles both bcrypt and sha256 prefixes.
                if self._hasher.verify(password, digest):
                    return True
            return False

    def store(self, password: str) -> None:
        """Hash *password* and add the digest to the history store.

        Calls ``self._hasher.hash(password)`` to obtain a bcrypt (or fallback
        sha256) digest — the plain-text password is NEVER written to the
        backend.  If the store is already at capacity (``MAX_HISTORY``), the
        oldest entry is evicted before the new digest is inserted (LRU policy).

        LRU eviction strategy
        ---------------------
        *In-memory mode*: ``collections.deque(maxlen=10)`` handles eviction
        automatically.  When ``deque.append()`` is called on a full deque,
        Python drops the leftmost (oldest) element before adding the new one.
        This is O(1) and requires no explicit eviction logic in this method.

        *SQLite mode*: rows are ordered by the auto-increment ``id`` column —
        a higher id means a more recent insertion, so the row with ``MIN(id)``
        is always the oldest.  When the current count reaches ``MAX_HISTORY``,
        we issue::

            DELETE FROM password_history
             WHERE id = (SELECT MIN(id) FROM password_history)

        before the INSERT.  The subquery executes as a single atomic operation
        inside the same transaction, ensuring the cap is never exceeded even
        under concurrent access within the same connection.

        Parameters
        ----------
        password : str
            The plain-text password to hash and persist.  Never stored as-is.

        Raises
        ------
        Password_StoreError
            On any backend failure (SQLite query or commit error).
        """
        # Hash the password first — this is a pure CPU operation and does not
        # touch the backend.  Doing it outside the try/except keeps the
        # exception semantics clean: a Hasher error would propagate as-is,
        # while only genuine backend errors become Password_StoreError.
        digest: bytes = self._hasher.hash(password)

        if self._conn is None:
            # ------------------------------------------------------------------
            # In-memory (deque) mode
            #
            # deque(maxlen=10) auto-evicts the oldest (leftmost) element when
            # it is full and a new element is appended — no manual eviction
            # needed.  This is the LRU strategy described in Requirement 3.5.
            # No exception handling is needed here because deque.append()
            # cannot fail under normal conditions.
            # ------------------------------------------------------------------
            self._history.append(digest)
        else:
            # ------------------------------------------------------------------
            # SQLite mode
            #
            # Step 1: Count current entries.
            # Step 2: If at cap, DELETE the oldest row (LRU eviction).
            # Step 3: INSERT the new digest.
            # Step 4: COMMIT so the changes are durable.
            #
            # All three DML statements execute within an implicit transaction;
            # sqlite3's default isolation ensures they are atomic from the
            # perspective of this connection.
            # ------------------------------------------------------------------
            try:
                # Count how many digests are currently stored.
                cursor = self._conn.execute(
                    "SELECT COUNT(*) FROM password_history"
                )
                (count,) = cursor.fetchone()

                if count >= self.MAX_HISTORY:
                    # LRU eviction: remove the row with the smallest id value,
                    # which corresponds to the oldest insertion.
                    # The subquery SELECT MIN(id) identifies the target row;
                    # the outer DELETE removes exactly that one row, keeping the
                    # cap invariant: after this DELETE the table has count-1
                    # rows, and the subsequent INSERT brings it back to count.
                    self._conn.execute(
                        "DELETE FROM password_history "
                        "WHERE id = (SELECT MIN(id) FROM password_history)"
                    )

                # Insert the new digest as a BLOB — never as TEXT — to avoid
                # any character-encoding transformation that could corrupt the
                # binary bcrypt or sha256 digest bytes.
                self._conn.execute(
                    "INSERT INTO password_history (digest) VALUES (?)",
                    (digest,),
                )
                self._conn.commit()

            except sqlite3.OperationalError as exc:
                # Roll back any partial changes and raise Password_StoreError
                # so callers have a single, stable exception type to handle.
                try:
                    self._conn.rollback()
                except Exception:
                    pass  # Ignore rollback errors — the original error is more important.
                raise Password_StoreError(
                    f"store() failed: {exc}"
                ) from exc
