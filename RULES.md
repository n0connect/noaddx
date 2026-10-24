# SECURITY & RELIABILITY RULES - MANDATORY COMPLIANCE

## SCOPE
This document defines absolute requirements for all code in this project.
Every rule is MANDATORY unless explicitly marked as recommended.
Exception requests require written justification and approval before implementation.

---

## 1. CRYPTOGRAPHY

### 1.1 Library Requirements
- C/C++ projects must use OpenSSL 3.x in FIPS 140-3 mode.
- Rust projects must use OpenSSL-sys binding OR ring OR RustCrypto with documented audit and formal verification.
- Go projects must use crypto/* standard library packages. OpenSSL via CGO bindings may be used only when required functionality is unavailable in crypto/* and other Go standard implementations.

### 1.2 Key Management
- Keys must never be hardcoded in source code.
- Keys must never be committed to version control.
- Plaintext keys in memory must exist only for operation duration.
- Key cleanup must use explicit_bzero or SecureZeroMemory or zeroize before deallocation.
- Key derivation must use PBKDF2 with minimum 100,000 iterations OR Argon2id.

### 1.3 Random Number Generation
- Random number generation must use cryptographically secure PRNG from OpenSSL RAND_bytes or getrandom or platform CSPRNG.
- Seed failure must cause immediate program abort.

### 1.4 Algorithm Whitelist
- Symmetric encryption must use AES-256-GCM.
- Hashing must use SHA-256 OR SHA-384 OR SHA-512.
- Asymmetric cryptography must use RSA-4096 OR Ed25519.
- Key exchange must use ECDH with P-256 OR P-384 OR X25519.

---

## 2. RECURSION

### 2.1 Depth Control
- Recursive functions must define maximum depth.
- Every recursive call must include explicit depth counter parameter.
- Every recursive call must validate depth counter before recursing.
- Depth limit exceeded must return error.
- Stack size must be statically calculable as frame_size multiplied by maximum depth.

### 2.2 Control Flow
- goto statements are prohibited.

---

## 3. MEMORY MANAGEMENT

### 3.1 Dynamic Allocation Validation
- Dynamic memory allocation must pass type validation.
- Dynamic memory allocation must pass range validation with defined MIN and MAX bounds.
- Dynamic memory allocation must pass whitelist validation (Ignore this rule if language is RUST).
- All three validations must succeed before allocation proceeds.

### 3.2 Allocation Limits
- Single memory allocation must not exceed 100 megabytes default limit. Fixed compile-time limits may be defined per project requirements.
- Total heap memory budget must be defined at system initialization.
- Zero-size allocations are prohibited.
- Size multiplication for allocations must use checked arithmetic to prevent overflow.

### 3.3 Deallocation
- Memory deallocation must be guaranteed at scope exit using RAII or defer or finally constructs.
- Sensitive data must be zeroized before deallocation.
- Pointers must be set to NULL or Option::None after deallocation.
- Memory leak detection must run in CI pipeline.

### 3.4 Buffer Operations
- Buffer operations must use bounds-checked functions.
- Unchecked buffer functions are prohibited including but not limited to: strcpy, sprintf, gets, strcat, scanf, vsprintf, strtok. Bounds-checked alternatives must be used: strncpy_s, snprintf, fgets, strtok_r.
- Buffer reads and writes must perform bounds check before operation.
- Buffer protocols must use length-prefix format with size field preceding data.

---

## 4. CONCURRENCY

### 4.1 Shared State Protection
- Shared memory regions must be protected by mutex or read-write lock.
- Lock acquisition timeout must return error.
- Mutex poison condition must cause immediate program abort.

### 4.2 Lock Ordering
- Global lock hierarchy must be defined and documented.
- Lock acquisition must proceed from lowest priority to highest priority.
- Lock release must follow LIFO stack discipline.

### 4.3 Atomic Operations
- Flag updates must use atomic operations.
- Atomic operations must use minimum Acquire-Release memory ordering, SeqCst preferred.
- State machine transitions must be explicitly documented.

### 4.4 Thread Management
- Thread creation must define resource limits including stack size.
- Thread panic must be handled by supervisor pattern with recovery or abort decision.
- Race condition detection must run in CI pipeline using ThreadSanitizer or Loom.

---

## 5. INPUT VALIDATION

### 5.1 Triple Validation Gate
- Input validation must perform type check.
- Input validation must perform range check with MIN and MAX bounds.
- Input validation must perform whitelist check.
- All three validation checks must pass before input is processed.
- Validation failure must reject input and log event.

### 5.2 Numeric Operations
- Integer arithmetic must use checked operations to prevent overflow and underflow.
- Floating point operations must validate is_finite before use.
- Type conversions must use explicit checked conversion.

### 5.3 String and Buffer Validation
- String length must be validated within range of 1 to MAX_STRING_LEN.
- String encoding must be validated as UTF-8.
- C strings must have null termination explicitly checked.

### 5.4 Whitelist Principle
- Input validation must use whitelist approach.
- Blacklist-based validation is prohibited.

---

## 6. ERROR HANDLING

### 6.1 Error Propagation
- Functions that can fail must return Result type or error indicator.
- Error return values must be checked by caller.
- unwrap and expect functions are prohibited in production code.
- Silent error dropping is prohibited.
- Error chain must preserve root cause through propagation.

### 6.2 Panic Policy
- Recoverable errors must return error value and allow caller to decide recovery strategy.
- Unrecoverable errors including assertion failures and logic errors must panic and abort when no viable recovery mechanism exists.
- System must implement graceful degradation where possible before resorting to abort.

### 6.3 Error Logging
- Error logging must include stack trace and context.
- Error logs must not contain personally identifiable information.

---

## 7. CODE STRUCTURE

### 7.1 Function Complexity
- Functions must implement single responsibility.
- Cyclomatic complexity should not exceed 10. Complex state machines may reach 15 with documented justification.
- Functions should not exceed 90 lines. Functions containing only data initialization or linear switch-case may reach 150 lines with written justification.

### 7.2 Naming Conventions
- Public API identifiers must use camelCase except Rust which uses snake_case.
- Internal module identifiers must use snake_case.
- Constants must use SCREAMING_SNAKE_CASE.
- Abstraction layer depth must be indicated by underscore prefix count.

### 7.3 Comments
- Comment blocks should be concise and typically not exceed 3 lines. Complex algorithms, safety-critical sections, and FFI boundaries may have longer documentation when necessary.
- Comments must explain why not what.

### 7.4 Modularity
- System architecture must be modular.
- Hardcoded values are prohibited except as named constants.
- Code duplication must be eliminated through modularization.

---

## 8. ITERATION

### 8.1 Loop Bounds
- Loops must define MAX_ITERATIONS as compile-time constant.
- Loops must maintain explicit iteration counter.
- Loops must check counter against MAX_ITERATIONS within loop body.
- Infinite loops are prohibited.

---

## 9. SCOPE AND POINTERS

### 9.1 Variable Scope
- Variables must use most restrictive scope possible, local scope preferred.

### 9.2 Pointer Safety
- Pointer dereference must be preceded by NULL or nil check.
- Rust code must use Option and Result types for nullable values.
- C++ code must prefer smart pointers over raw pointers.
- Raw pointers are restricted to FFI boundaries only.

---

## 10. COMPILER REQUIREMENTS

### 10.1 Warnings
- Compiler warnings must be treated as errors.
- Build configuration must enable warnings-as-errors flag.

### 10.2 Return Values
- Function return values must be checked.
- Unused variables are prohibited.
- Dead code is prohibited.

---

## 11. TESTING AND VERIFICATION

### 11.1 Dependency Security
- Dependency vulnerability scanning must run daily.
- Software Bill of Materials must be generated.
- Dependency checksums must be verified.
- Dependency versions must be pinned in lockfile.
- Dependencies without updates for 2 years must be replaced.

---

## 12. LOGGING

### 12.1 Sensitive Data
- Logs must not contain cryptographic keys.
- Logs must not contain passwords.
- Logs must not contain authentication tokens.
- Logs must not contain personally identifiable information.
- User identifiers must be hashed with SHA-256 and salt before logging.

### 12.2 Log Injection Prevention
- Log messages must strip newline characters from user input.
- Logs must use structured format such as JSON or key-value pairs.
- Format strings must not include untrusted input.

### 12.3 Log Levels
- ERROR level must be used for unrecoverable conditions with full context.
- WARN level must be used for suspicious activity.
- INFO level must be used for state transitions.
- DEBUG level must be used in development builds only.

---

## 13. DEPENDENCIES

### 13.1 Dependency Limits
- Direct dependencies should not exceed 20 without written justification.
- Transitive dependencies must be audited.
- Dependencies must be battle-tested, open-source, and widely-used.

---

## 14. BUILD AND DEPLOYMENT

### 14.1 Build Configuration
- Builds must be reproducible.
- Production builds must strip debug symbols.
- Stack canaries must be enabled.
- Address Space Layout Randomization must be enabled.
- Position Independent Executable must be enabled.
- Source fortification must be enabled.
- Optimization level must be -O2 minimum for C/C++, release profile for Rust and Go.

---

## 15. CODE QUALITY

### 15.1 Control Flow
- Code flow must be predictable from top to bottom.
- Complex workflows are prohibited.
- Spaghetti code is prohibited.

### 15.2 Preprocessor
- C/C++ define macros are prohibited except for header guards.
- Const, inline, and constexpr must be used instead of define macros.

---

## 16. SECURITY BOUNDARIES

### 16.1 Trust Model
- Trust boundaries must be explicitly documented.
- External input must be considered untrusted.
- Principle of the least privilege must be applied.

### 16.2 Cryptographic Operations
- Cryptographic operations involving secrets must use constant-time implementations. Variable-time operations on secret data are prohibited.
- Output encoding must be context-aware.

---

## 17. FAIL-SAFE MECHANISMS

### 17.1 Resilience
- Resource exhaustion must trigger graceful degradation.
- External dependencies must implement circuit breaker pattern.
- API endpoints must implement rate limiting.
- Blocking operations must implement timeout.
- Retry logic must use exponential backoff with maximum attempt limit.

---

## 18. AUDIT AND COMPLIANCE

### 18.1 Review Process
- Major releases require security audit.
- Changelog must document security fixes explicitly.
- Vulnerability disclosure process must be documented.

---

## 19. DOCUMENTATION

### 19.1 Required Documentation
- Public interfaces must have API documentation.
- Major architectural decisions must be recorded.
- System threat model must be documented.
- Security assumptions must be explicitly documented.
- Production deployment guide must exist.

---

## 20. LANGUAGE-SPECIFIC REQUIREMENTS

### 20.1 Rust
- Unsafe blocks must be minimized, encapsulated, documented, and reviewed.
- FFI boundaries must document safety invariants.
- Send and Sync trait implementations must document thread-safety reasoning.

### 20.2 Go
- Goroutines must propagate context for cancellation.
- Resource cleanup must use defer.
- Error wrapping must use fmt.Errorf with %w verb.

### 20.3 C/C++
- Header files must use include guards.
- C++ resource management must use RAII.
- Const correctness must be maintained.

---

END OF RULES