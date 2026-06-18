# Implementation Plan: Password Strength Analyzer

## Overview

Implement the Password Strength Analyzer as a single Python script (`password_strength_analyzer.py`) containing four cooperating classes — `Analyzer`, `Generator`, `Hasher`, and `Password_Store` — plus a `main()` entry point and an educational `__main__` block. The implementation follows the design document exactly, using Python's `secrets` module for generation, `bcrypt` for hashing (with a `hashlib.sha256` fallback), and SQLite for optional persistence.

## Tasks

- [x] 1. Set up project structure and shared foundations
  - Create `password_strength_analyzer.py` at the project root with module-level docstring
  - Add top-level imports: `import string, os, sys, sqlite3, warnings, collections, dataclasses, re` and the conditional `bcrypt` import wrapped in a `try/except ImportError`
  - Define the `WEAK_PASSWORD_LIST` constant (at least 10 common weak passwords, lowercase)
  - Define the `AnalysisResult` dataclass with fields `score: int | None`, `tier: str | None`, `passed: list[str]`, `failed: list[str]`, `error: str | None`
  - Define the `Password_StoreError` exception class
  - Create `tests/` directory with empty `__init__.py`
  - _Requirements: 1.1–1.9, 5.1, 5.5_

- [x] 2. Implement the `Hasher` class
  - [x] 2.1 Implement `Hasher.hash()` and `Hasher.verify()` with bcrypt primary path
    - Implement `hash(password: str) -> bytes` using `bcrypt.hashpw` with `BCRYPT_ROUNDS = 12`
    - Implement `verify(password: str, digest: bytes) -> bool` using `bcrypt.checkpw`
    - Add inline comments explaining the one-way property, salting, and cost factor
    - _Requirements: 3.2, 4.1, 4.2_

  - [x] 2.2 Implement `Hasher` fallback path for missing `bcrypt`
    - In the `try/except ImportError` block at module top, set a flag `_BCRYPT_AVAILABLE`
    - In `hash()`: when `_BCRYPT_AVAILABLE` is False, generate a 16-byte salt via `os.urandom(16)`, compute `hashlib.sha256(salt + password.encode()).digest()`, return `b"sha256:" + salt.hex().encode() + b":" + digest.hex().encode()`
    - In `verify()`: detect the `b"sha256:"` prefix and dispatch to the fallback verification path
    - Emit `warnings.warn(...)` or write to `sys.stderr` once at module load when bcrypt is absent
    - Add inline comments on the fallback format explaining why bcrypt is preferred
    - _Requirements: 3.2, 5.6, 4.1_

  - [x] 2.3 Write property test for hash/verify round trip (Property 8)
    - **Property 8: Hashing and verification form a round trip**
    - **Validates: Requirements 3.2, 3.3**
    - File: `tests/test_hasher.py`
    - Use `@given(st.text(min_size=1, max_size=128))` — for any password `p`, `Hasher.verify(p, Hasher.hash(p))` must return `True`
    - Also assert `Hasher.verify(q, Hasher.hash(p))` returns `False` for any `q != p`
    - Include smoke test asserting bcrypt cost factor ≥ 10 from the stored digest prefix

- [ ] 3. Implement the `Analyzer` class
  - [x] 3.1 Implement input validation in `Analyzer.analyze()`
    - Return `AnalysisResult(error=...)` with `score=None` for `None` input, empty string, non-string types, and strings longer than 128 characters
    - Use exact error message strings from the design's error-handling table
    - Add inline comments explaining each validation guard and its security rationale
    - _Requirements: 1.1, 1.2, 4.1_

  - [x] 3.2 Implement weak-list check and complexity scoring in `Analyzer`
    - Implement `_check_weak_list(password)` — case-insensitive match against `WEAK_PASSWORD_LIST`; return `True` if matched
    - Implement `_check_complexity(password)` — return a tuple `(points: int, passed: list[str], failed: list[str])` by testing each of the four categories (uppercase, lowercase, digit, special character)
    - Implement `_check_length(password)` — return `(penalty: int, message: str | None)` where penalty is 2 if `len(password) < 8` else 0
    - Wire all three helpers into `analyze()` using the scoring pipeline: weak-list override → complexity → length penalty → clamp → tier mapping
    - Add inline comments on the scoring formula and the clamp operation
    - _Requirements: 1.3, 1.4, 1.5, 1.6, 1.7, 1.9, 4.1_

  - [x] 3.3 Implement tier mapping in `Analyzer`
    - Implement `_tier_from_score(score: int) -> str` mapping 0–1 → "Weak", 2–3 → "Moderate", 4–5 → "Strong", 6 → "Very Strong"
    - _Requirements: 1.8_

  - [-] 3.4 Write property test for over-length input rejection (Property 1)
    - **Property 1: Over-length inputs are always rejected**
    - **Validates: Requirements 1.1**
    - File: `tests/test_analyzer.py`
    - Use `@given(st.text(min_size=129))` — assert `result.error` is non-empty and `result.score is None`

  - [-] 3.5 Write property test for invalid-type and empty input rejection (Property 2)
    - **Property 2: Invalid-type and empty inputs are always rejected**
    - **Validates: Requirements 1.2**
    - File: `tests/test_analyzer.py`
    - Use `@given(st.one_of(st.none(), st.integers(), st.floats(), st.lists(st.text())))` plus the empty string case — assert `result.error` is non-empty and `result.score is None`

  - [-] 3.6 Write property test for complexity score equals category count (Property 3)
    - **Property 3: Complexity score equals the count of satisfied categories**
    - **Validates: Requirements 1.4, 1.5**
    - File: `tests/test_analyzer.py`
    - Build passwords with a known subset of the four categories; assert `complexity_points == len(categories_present)`

  - [-] 3.7 Write property test for final score formula (Property 4)
    - **Property 4: Final score equals clamped(complexity − length_penalty)**
    - **Validates: Requirements 1.3, 1.7**
    - File: `tests/test_analyzer.py`
    - For valid passwords not in the weak list, compute expected score with the formula `max(0, min(6, complexity − (2 if len(p) < 8 else 0)))` and assert equality

  - [-] 3.8 Write property test for weak-list passwords always score 0 (Property 5)
    - **Property 5: Weak-list passwords always score 0**
    - **Validates: Requirements 1.6**
    - File: `tests/test_analyzer.py`
    - Use `@given(st.sampled_from(WEAK_PASSWORD_LIST))` with random case mutation; assert `score == 0` and `tier == "Weak"`

  - [-] 3.9 Write unit tests for `Analyzer` tier mapping and example passwords
    - Assert score 0 → "Weak", 1 → "Weak", 2 → "Moderate", 3 → "Moderate", 4 → "Strong", 5 → "Strong", 6 → "Very Strong"
    - Assert `analyze("correct horse battery staple")` returns a "Strong" or "Very Strong" tier
    - _Requirements: 1.7, 1.8_

- [~] 4. Checkpoint — Ensure all Analyzer and Hasher tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement the `Password_Store` class
  - [~] 5.1 Implement `Password_Store.__init__()` with in-memory and SQLite modes
    - Accept `db_path: str | None = None`; when `None`, initialize a `collections.deque(maxlen=10)` for in-memory mode
    - When `db_path` is `":memory:"` or a file path, open a SQLite connection, create the `password_history` table if not exists, and store the connection
    - Catch `sqlite3.OperationalError` in `__init__`; raise `Password_StoreError` on failure
    - Store a `self._hasher = Hasher()` instance for delegation
    - Add inline comments explaining why plain text is never stored
    - _Requirements: 3.1, 3.2, 3.7, 4.2_

  - [~] 5.2 Implement `Password_Store.check_reuse()` and `Password_Store.store()`
    - `check_reuse(password)`: iterate stored digests and call `self._hasher.verify(password, digest)` for each; return `True` on first match, `False` if none match; wrap SQLite calls in try/except and raise `Password_StoreError` on failure
    - `store(password)`: call `self._hasher.hash(password)` to get a digest; in SQLite mode, check count and run the LRU DELETE before INSERT if at cap; in deque mode, append (deque auto-evicts); wrap in try/except and raise `Password_StoreError` on failure
    - Add inline comments on both methods explaining the bcrypt verification semantics and the LRU eviction strategy
    - _Requirements: 3.1, 3.3, 3.4, 3.5, 3.6, 4.2_

  - [~] 5.3 Write property test for no plain text in store (Property 7)
    - **Property 7: Stored passwords are never retrievable as plain text**
    - **Validates: Requirements 3.1**
    - File: `tests/test_store.py`
    - Use `@given(st.text(min_size=1, max_size=128))` — after `store(p)`, read raw deque entries or SQLite `digest` column values; assert none equal `p` or `p.encode()`

  - [~] 5.4 Write property test for hash/verify round trip via store (Property 8 — store path)
    - **Property 8: check_reuse returns True after store (store/check_reuse round trip)**
    - **Validates: Requirements 3.2, 3.3**
    - File: `tests/test_store.py`
    - For any password `p`, after `store(p)`, assert `check_reuse(p)` is `True` and `check_reuse(q)` for any distinct `q` is `False`

  - [~] 5.5 Write property test for history cap and LRU eviction (Property 9)
    - **Property 9: History cap is enforced with LRU eviction**
    - **Validates: Requirements 3.5**
    - File: `tests/test_store.py`
    - Use `@given(st.lists(st.text(min_size=1, max_size=64), min_size=11, max_size=30, unique=True))` — store all; assert total entries ≤ 10; assert first `len(seq) − 10` passwords are not recognized; assert last 10 are all recognized

  - [~] 5.6 Write unit tests for `Password_Store` modes and error handling
    - Test `Password_Store()` (in-memory deque) and `Password_Store(":memory:")` (SQLite in-memory) instantiation
    - Mock SQLite to raise `OperationalError`; assert `Password_StoreError` is raised
    - _Requirements: 3.7, 3.8_

- [~] 6. Checkpoint — Ensure all Password_Store tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 7. Implement the `Generator` class
  - [~] 7.1 Implement `Generator._build_password()` and `Generator.generate_suggestions()`
    - Implement `_build_password(length: int = 20) -> str`: seed with one `secrets.choice` character from each of the four required category subsets (4 guaranteed chars), fill remaining slots from the full printable-ASCII alphabet via `secrets.choice`, shuffle using `secrets.SystemRandom().shuffle`, return as string
    - Implement `generate_suggestions(n: int = 3) -> list[str]`: call `_build_password()` for each slot, apply one-retry weak-list check via `_passes_weak_check()`, collect and return exactly `n` strings
    - Implement `_passes_weak_check(password: str) -> bool` — case-insensitive check against `WEAK_PASSWORD_LIST`
    - Add inline comments explaining the use of `secrets` for cryptographic security
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 4.1_

  - [~] 7.2 Write property test for generator output validity (Property 6)
    - **Property 6: Generator always returns exactly 3 valid suggestions**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.6**
    - File: `tests/test_generator.py`
    - Call `generate_suggestions()` at least 100 times; assert each call returns exactly 3 strings; for each string assert length ∈ [16, 128] and all four complexity categories are present

  - [~] 7.3 Write unit tests for `Generator` edge cases
    - Assert suggested passwords are not equal to any entry in `WEAK_PASSWORD_LIST`
    - Assert two calls to `generate_suggestions()` return different passwords (probabilistic)
    - _Requirements: 2.4, 2.5_

- [ ] 8. Implement `main()` and the `__main__` educational block
  - [~] 8.1 Implement `main()` orchestration function
    - Implement the three-step flow: (1) `Analyzer.analyze(password)` → print strength label and breakdown, (2) `Password_Store.check_reuse(password)` → print reuse status, (3) if tier is Weak or Moderate call `Generator.generate_suggestions()` → print 3 alternatives
    - If password is Strong or Very Strong and not reused, call `Password_Store.store(password)` and print acceptance confirmation
    - Catch `Password_StoreError` and return an error result without accepting or rejecting the candidate
    - _Requirements: 5.2, 5.3, 5.4_

  - [~] 8.2 Implement the `__main__` educational breakdown block
    - Print a "Complexity Scoring" section (≥ 2 sentences on 4-category check, length penalty, and weak-list override) with a visible heading underline
    - Print a "Why Hashing" section (≥ 2 sentences on ≥ 2 plain-text storage risks and how hashing mitigates them) with a heading underline
    - Print a "How bcrypt Works" section covering salting, cost factor, and one-way property (≥ 2 sentences each sub-topic) with a heading underline
    - Format all headings using `===` or `---` underlines for terminal readability without ANSI colour
    - _Requirements: 4.3, 4.4_

  - [~] 8.3 Write integration tests for `main()` and educational output
    - Capture stdout from the `__main__` block; assert three section headings ("Complexity Scoring", "Why Hashing", "How bcrypt Works") are present
    - Call `main()` with a Strong password that is not previously used; assert `store()` is called and acceptance message appears in stdout
    - Simulate reuse: store a password, call `main()` with same password; assert reuse error in stdout
    - File: `tests/test_integration.py`
    - _Requirements: 3.4, 4.3, 4.4, 5.2, 5.3, 5.4_

  - [~] 8.4 Write unit tests for import isolation and bcrypt fallback
    - Import `Analyzer` alone; assert no stdout output, no exceptions, `WEAK_PASSWORD_LIST` is accessible
    - Mock the `bcrypt` import to raise `ImportError`; re-import `Hasher`; assert `hashlib` fallback is used and a warning is emitted to stderr
    - File: `tests/test_integration.py`
    - _Requirements: 5.1, 5.6_

- [~] 9. Final checkpoint — Ensure all tests pass
  - Run the full test suite; ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- All property-based tests use the `hypothesis` library (`pip install hypothesis`) with `@given` and `settings(max_examples=100)` minimum
- Checkpoints (tasks 4, 6, 9) are validation gates — do not advance past them with failing tests
- The entire system lives in a single file `password_strength_analyzer.py`; tests live under `tests/`
- bcrypt fallback digest format: `b"sha256:<16-byte-hex-salt>:<32-byte-hex-digest>"` — the `"sha256:"` prefix enables correct dispatch in `verify()`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["2.1", "2.2"] },
    { "id": 2, "tasks": ["2.3", "3.1"] },
    { "id": 3, "tasks": ["3.2", "3.3"] },
    { "id": 4, "tasks": ["3.4", "3.5", "3.6", "3.7", "3.8", "3.9"] },
    { "id": 5, "tasks": ["5.1"] },
    { "id": 6, "tasks": ["5.2"] },
    { "id": 7, "tasks": ["5.3", "5.4", "5.5", "5.6", "7.1"] },
    { "id": 8, "tasks": ["7.2", "7.3", "8.1"] },
    { "id": 9, "tasks": ["8.2"] },
    { "id": 10, "tasks": ["8.3", "8.4"] }
  ]
}
```
