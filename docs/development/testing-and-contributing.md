# Testing & Development Guide

This guide covers running test suites across Go backend units, database migrations, integration scenarios, and frontend WebCrypto cryptographic verification.

---

## Test Architecture Overview

```text
+-------------------------------------------------------------+
| 1. Frontend WebCrypto Verification                          |
|    node --test frontend/tests/                              |
|    (Checks byte-for-byte derivation matches Go)             |
+-------------------------------------------------------------+
| 2. Backend Unit & Cryptographic Tests                       |
|    go test -tags=test ./internal/...                        |
|    (Pure Go, runs without external database)                |
+-------------------------------------------------------------+
| 3. Database Migration & Integration E2E Tests               |
|    Requires PostgreSQL (containerized or local)             |
|    ./run.sh --test                                          |
+-------------------------------------------------------------+
```

---

## Running Tests

### Option A: Fully Containerized (Recommended)

Run all tests inside an isolated Docker container with a disposable tmpfs PostgreSQL instance:

```bash
./run.sh --test
```

**What this does:**
1. Starts `postgres-test` with temporary in-memory storage (`tmpfs`).
2. Builds `test.Dockerfile` using `CGO_ENABLED=0` (pure Go crypto).
3. Executes unit and integration test packages.
4. Shuts down and cleans up test containers.
5. Emits output to `test-results/output.log`.

---

### Option B: Local Native Go Tests

If developing natively on your host machine:

#### 1. Non-DB Unit Tests (Instant, No Postgres Required)
```bash
cd backend
go test -tags=test -v ./internal/pow/... ./internal/handlers/... ./tests/identity/... ./tests/encryption/... ./tests/utils/...
```

#### 2. Full Suite (Requires Local Postgres running on 5432)
```bash
cd backend

# Step 1: Database Migration Tests (MUST RUN FIRST)
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=noaddress_test go test -tags=test ./tests/database -v

# Step 2: Full Suite with Race Condition Detector
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres DB_PASSWORD=postgres DB_NAME=noaddress_test go test -p 1 -race -tags=test ./...
```

---

### Option C: Frontend WebCrypto Derivation Tests

Verify that JavaScript's native W3C WebCrypto produces identical cryptographic keys, fingerprints, and AAD ciphertexts as Go's internal packages:

```bash
node --test frontend/tests/
```

**Requirements:** Node.js 20+ (utilizes native `node:crypto` and built-in test runner, zero npm dependencies).

**Tests Verified:**
- `auth key matches Go derivation`
- `identity public key matches Go derivation; private key is not extractable`
- `strict base64url rejects malformed account numbers`
- `both peers derive the same conversation key and round-trip a message`
- `AAD binding: wrong message id, sender, conversation, or tampered bytes fail`
- `invite code carries a fingerprint the redeemer can verify`
- `safety number and aura are symmetric and deterministic`
- `payload limit is enforced before encryption`

---

## Code Rules & Concurrency Compliance

All code modifications must strictly comply with project policies:

### 1. Cryptography Whitelist (`RULES.md Section 1`)
- Symmetric encryption: **AES-256-GCM** only.
- Asymmetric keys: **X25519** only.
- Hashing: **SHA-256** only.
- Key derivation: **HKDF-SHA256** or **Argon2id** only.
- Sensitive key material in memory must be zeroized upon deallocation (`cryptoengine.Zeroize`).

### 2. Lock Ordering & Concurrency (`LOCK_HIERARCHY.md`)
To prevent deadlocks, all mutex acquisitions must strictly proceed from lowest to highest priority:

- **Priority Level 1 (Application State):** Rate limiter maps, PoW challenge maps, `realtime.Hub.mu` (leaf lock), `pendingStore.mu` (leaf lock).
- **Priority Level 2 (Per-Resource Locks):** `TokenBucket.mu`.
- **Priority Level 3 (Highest):** Database transaction locks (GORM), `masterKeyOnce`.

**Rule:** Never acquire a lower-priority lock while holding a higher-priority lock!

### 3. Input Triple Validation (`RULES.md Section 5.1`)
Every external client input must pass:
1. **Type validation** (e.g. UUIDv4 struct, exact byte slice).
2. **Range validation** (min and max byte length).
3. **Whitelist validation** (regex character set, e.g. `^[A-Za-z0-9_-]+$`).

---

### Next Steps:
- Review the [**Threat Model & Security**](../security/threat-model.md).
- Explore the [**REST API Reference**](../api/rest-api.md).
