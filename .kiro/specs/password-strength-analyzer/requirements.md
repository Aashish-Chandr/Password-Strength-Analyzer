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
2. THE Hasher SHALL use bcrypt with a cost factor of at least 10 to produce stored digests.
3. WHEN a candidate password is submitted for reuse checking, THE Password_Store SHALL use bcrypt verification semantics to compare the candidate against each stored digest and return a boolean indicating whether a match was found.
4. WHEN the candidate password matches any stored digest, THE Password_Store SHALL return a result explicitly indicating the password was previously used, and THE Analyzer SHALL refuse to accept it.
5. THE Password_Store SHALL maintain a history of at most 10 stored digests per user context; WHEN a new digest must be added and the store already holds 10 entries, THE Password_Store SHALL evict the oldest digest (LRU order) before inserting the new one.
6. WHEN a new password is accepted (not previously used and strength is Strong or Very Strong), THE Password_Store SHALL store its hashed digest, subject to the cap in criterion 5.
7. THE Password_Store SHALL accept an explicit parameter at initialization to select SQLite file-backed mode or in-memory mode, defaulting to in-memory mode when no parameter is provided.
8. WHEN the Password_Store is unavailable (e.g., SQLite connection failure), THE Analyzer SHALL return an error result without accepting or rejecting the candidate password.

---

### Requirement 4: Educational Breakdown Output

**User Story:** As a developer or learner, I want a clear explanation of how the tool works, so that I can understand the security reasoning behind each design decision.

#### Acceptance Criteria

1. THE Analyzer SHALL include inline code comments on every function that has a non-obvious purpose, side effect, or security implication (i.e., any function beyond a simple getter or setter), explaining its purpose, inputs, outputs, and any security considerations.
2. THE Password_Store SHALL include inline code comments on every storage and retrieval function explaining why plain-text storage is avoided and how bcrypt operates on that code path.
3. WHEN the script is executed directly (i.e., `__name__ == "__main__"`), THE system SHALL print a structured educational breakdown that includes:
   a. A "Complexity Scoring" section explaining the 4-category complexity check, the length penalty, and the Weak_Password_List override — with at least 2 sentences each.
   b. A "Why Hashing" section explaining at least two concrete risks of plain-text password storage and how hashing mitigates them — with at least 2 sentences.
   c. A "How bcrypt Works" section covering salting, the cost factor, and the one-way property — with at least 2 sentences each sub-topic.
4. THE educational breakdown SHALL be formatted with a visible heading line (e.g., `===` or `---` underlines) before each named section so that sections are visually distinct in a terminal without ANSI colour support.

---

### Requirement 5: Modular Code Structure and Runnable Script

**User Story:** As a developer, I want the code organized into well-defined modules or classes, so that individual components can be tested, reused, or replaced independently.

#### Acceptance Criteria

1. THE system SHALL organize the Analyzer, Generator, Password_Store, and Hasher into separate Python classes or modules such that each can be imported without importing or executing the others.
2. THE system SHALL include a `main()` function that orchestrates a complete demonstration, printing to stdout: the evaluated strength label, the reuse check status, any generated alternative passwords (when applicable), and a hash acceptance or rejection confirmation.
3. WHEN `main()` is called, THE system SHALL perform these three steps in order: (1) assess password strength using the Analyzer, (2) check for reuse using the Password_Store, and (3) conditionally invoke the Generator if the strength tier is Weak or Moderate.
4. WHEN `main()` is called with a Strong or Very Strong password that is not previously used, THE system SHALL store its hash and print a message to stdout indicating the password was accepted and stored.
5. THE system SHALL be runnable as a single Python script with no external dependencies beyond the Python standard library and `bcrypt`, installable via `pip install bcrypt`.
6. IF `bcrypt` is not installed, THEN THE system SHALL fall back to `hashlib.sha256` with a per-password salt and log a warning to stderr.
