# Requirements Document

## Introduction

The Password Strength Analyzer is a production-ready Python tool that evaluates the strength of user-provided passwords, suggests secure alternatives when a password is weak, and prevents password reuse through a hashed-password store backed by SQLite. It also provides an educational breakdown of how its logic works. The system is intended to be modular, well-documented, and suitable for embedding in larger applications or running as a standalone script.

## Glossary

- **Analyzer**: The core evaluation module responsible for scoring and classifying password strength.
- **Generator**: The module responsible for producing cryptographically secure password suggestions.
- **Password_Store**: The SQLite-backed (or in-memory) persistence layer that stores hashed passwords to prevent reuse.
- **Hasher**: The cryptographic hashing utility that transforms plain-text passwords into secure digests before storage.
- **Weak_Password_List**: A curated list of commonly used, easily guessable passwords (e.g., "password123", "123456", "qwerty").
- **Strength_Score**: A numeric or categorical rating (e.g., Weak / Moderate / Strong / Very Strong) assigned to a password by the Analyzer.
- **Special_Character**: Any printable ASCII character that is not alphanumeric (e.g., `!`, `@`, `#`, `$`, `%`).
- **Round_Trip**: The property that hashing a password and then verifying that same password against its stored hash returns a truthy result.

---

## Requirements

### Requirement 1: Password Strength Evaluation

**User Story:** As a user, I want my password evaluated against clear, objective criteria, so that I know whether my password is strong enough to use safely.

#### Acceptance Criteria

1. THE Analyzer SHALL accept a string input representing the candidate password of at most 128 characters; inputs longer than 128 characters SHALL be rejected with an error message before scoring.
2. WHEN the candidate password is null, empty, or non-string, THE Analyzer SHALL return an error result with a message indicating invalid input, without assigning any Strength_Score.
3. WHEN the candidate password has fewer than 8 characters, THE Analyzer SHALL deduct 2 points from the Strength_Score and include a descriptive message stating the minimum length requirement.
4. WHEN the candidate password contains at least one uppercase letter, at least one lowercase letter, at least one digit, and at least one Special_Character, THE Analyzer SHALL award 4 complexity points (1 point per satisfied category).
5. WHEN any of the four character categories (uppercase, lowercase, digit, Special_Character) is missing from the candidate password, THE Analyzer SHALL award 1 complexity point per satisfied category and 0 points per missing category, yielding a complexity score between 0 and 3 inclusive.
6. WHEN the candidate password exactly matches any entry in the Weak_Password_List (case-insensitive), THE Analyzer SHALL assign a Strength_Score of 0, overriding all other scoring criteria.
7. THE Analyzer SHALL return a Strength_Score (integer in the range 0–6) and a human-readable breakdown listing which criteria passed and which failed. The score is computed as: complexity points (0–4) minus the length penalty (2 if length < 8, else 0), clamped to a minimum of 0 and maximum of 6.
8. THE Analyzer SHALL classify the final Strength_Score into one of four named tiers: score 0–1 = Weak, score 2–3 = Moderate, score 4–5 = Strong, score 6 = Very Strong.
9. FOR the purposes of this Requirement, a Special_Character is any printable ASCII character that is neither a letter (a–z, A–Z) nor a digit (0–9), including but not limited to: `!`, `@`, `#`, `$`, `%`, `^`, `&`, `*`, `(`, `)`, `-`, `_`, `+`, `=`, `[`, `]`, `{`, `}`, `;`, `'`, `:`, `"`, `,`, `.`, `<`, `>`, `/`, `?`, `\`, `|`, `` ` ``, `~`.

---

### Requirement 2: Secure Password Generation

**User Story:** As a user, I want the tool to suggest a stronger password when mine is weak, so that I can immediately adopt a more secure credential without having to invent one myself.

#### Acceptance Criteria

1. WHEN the Analyzer returns a Strength_Score classified as Weak or Moderate, THE Generator SHALL produce exactly 3 suggested passwords.
2. THE Generator SHALL produce suggested passwords that are at least 16 characters and at most 128 characters in length.
3. THE Generator SHALL ensure every suggested password contains at least one uppercase letter, at least one lowercase letter, at least one digit, and at least one Special_Character.
4. THE Generator SHALL use a cryptographically secure random source (e.g., Python's `secrets` module) to construct suggested passwords.
5. IF the Generator produces a suggested password that matches any entry in the Weak_Password_List, THEN THE Generator SHALL discard that suggestion and generate one replacement attempt using the same generation process (satisfying criteria 2–3); if the replacement also matches the Weak_Password_List, THE Generator SHALL return the replacement as-is without a further Weak_Password_List check.
6. THE Generator SHALL return the suggested passwords as a list of exactly 3 strings, each independently satisfying criteria 2–3.

---

### Requirement 3: Anti-Reuse Database Integration

**User Story:** As a user, I want the system to remember passwords I have previously used, so that I cannot accidentally reuse an old password that may have been compromised.

#### Acceptance Criteria

1. THE Password_Store SHALL persist previously accepted passwords as hashed digests, never as plain text.
2. THE Hasher SHALL use bcrypt or hashlib (SHA-256 minimum) to produce the stored digest.
3. WHEN a candidate password is submitted for reuse checking, THE Password_Store SHALL compare the candidate's hash against all stored digests and return a boolean result.
4. WHEN the candidate password matches any stored digest, THE Analyzer SHALL report the password as previously used and refuse to accept it.
5. WHEN a new password is accepted (not previously used and strength is Strong or Very Strong), THE Password_Store SHALL store its hashed digest.
6. THE Password_Store SHALL support both a SQLite file-backed mode and an in-memory mode selectable at initialization, defaulting to in-memory for testing environments.
7. FOR ALL candidate passwords, hashing the same password twice with the same parameters SHALL produce a digest that verifies successfully against the original stored digest (round-trip property).

---

### Requirement 4: Educational Breakdown Output

**User Story:** As a developer or learner, I want a clear explanation of how the tool works, so that I can understand the security reasoning behind each design decision.

#### Acceptance Criteria

1. THE Analyzer SHALL include inline code comments on every non-trivial function explaining its purpose, inputs, outputs, and any security considerations.
2. THE Password_Store SHALL include inline code comments explaining why plain-text storage is avoided and how the chosen hash function operates.
3. WHEN the script is executed directly (i.e., `__name__ == "__main__"`), THE system SHALL print a structured educational breakdown covering:
   a. How the password complexity scoring logic works, step by step.
   b. Why hashing is preferred over plain-text storage for passwords.
   c. How the chosen cryptographic hash function (bcrypt or SHA-256) works at a conceptual level.
4. THE educational breakdown SHALL be formatted in clearly separated sections with headings so it is readable in a terminal.

---

### Requirement 5: Modular Code Structure and Runnable Script

**User Story:** As a developer, I want the code organized into well-defined modules or classes, so that individual components can be tested, reused, or replaced independently.

#### Acceptance Criteria

1. THE system SHALL organize the Analyzer, Generator, Password_Store, and Hasher into separate, independently importable Python classes or modules.
2. THE system SHALL include a `main()` function that orchestrates a complete demonstration: accepting a sample password, evaluating it, checking for reuse, optionally generating alternatives, and printing results.
3. WHEN `main()` is called, THE system SHALL determine password strength dynamically from the actual input and demonstrate the full evaluation flow.
4. WHEN `main()` is called with a Strong password (whether previously seen or not), THE system SHALL store the hash and confirm acceptance.
5. THE system SHALL be runnable as a single Python script with no external dependencies beyond the Python standard library and `bcrypt` (if chosen), installable via `pip`.
6. IF `bcrypt` is not installed, THEN THE system SHALL fall back to `hashlib.sha256` with a per-password salt and log a warning to stderr.
