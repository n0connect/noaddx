# noaddx. Documentation Hub

Welcome to the **noaddx.** documentation. This documentation suite is designed to be **accurate to the source code**, **modular**, **human-centric**, and **exhaustive**. It explicitly anticipates common developer/operator pitfalls, hardware constraints, operating system idiosyncrasies, and cryptographic nuances.

---

## Documentation Map

| Module | Purpose | Key Topics |
|---|---|---|
| [**1. Quick Start**](getting-started/quickstart.md) | Up and running in < 3 minutes | 3-step setup, first invite exchange, sanity checks |
| [**2. Installation & Platforms**](getting-started/installation-and-platforms.md) | Deep cross-platform & architecture guide | macOS (Apple Silicon/Intel), Linux (Ubuntu/Debian/Arch), Windows (WSL2, CRLF pitfall), arm64 vs amd64 |
| [**3. System Architecture**](architecture/system-overview.md) | Internal mechanics & data flow | Zero-knowledge identity, per-conversation member tags, scoped sequence numbers, SSE pokes, automatic retention |
| [**4. Threat Model & Security**](security/threat-model.md) | Adversary analysis & database security | What the DB reveals vs hides, stored-record AAD v2, key zeroization on SIGINT/SIGTERM, out-of-band invite fingerprinting |
| [**5. Cryptography Specification**](security/cryptography.md) | Cryptographic primitives & framing | RFC 7748 X25519, RFC 5869 HKDF-SHA256, AES-256-GCM, five power-of-two padding classes, WebCrypto non-extractable keys |
| [**5b. Verifying the Client**](security/verifying-the-client.md) | Proving an instance serves the released JavaScript | Signed frontend manifest, `cosign verify-blob`, `make verify-frontend`, limits of the check |
| [**6. REST API Reference**](api/rest-api.md) | Complete endpoint specification | `/api/v2/*` endpoints, strict JSON validation, PoW phase 1 & 2 registration, error masking |
| [**7. Configuration & Tuning**](operations/configuration-and-tuning.md) | Production configuration & performance | All environment variables, Master Key rotation runbook, Argon2id memory tuning (preventing OOM on 1GB VPS) |
| [**7b. Onion Service (Tor)**](operations/onion-service.md) | Publishing over Tor without losing abuse control | `make onion`, per-circuit rate limits, Tor-layer PoW, onion key custody, Tor Browser requirements |
| [**8. Troubleshooting Guide**](troubleshooting/troubleshooting-guide.md) | Common errors & instant copy-paste fixes | WebCrypto non-secure context error, Docker network range and trusted proxy, Docker DB connection, port 80/5432 conflicts, Windows CRLF |
| [**9. Testing & Development**](development/testing-and-contributing.md) | Test runners & contribution rules | Native Go test flags, frontend WebCrypto tests, DB migration test precedence, lock hierarchy verification |

---

## Core Design Principles

1. **Zero Knowledge of Accounts:** The server generates a 256-bit CSPRNG `AccountNumber` during signup and reveals it once. The browser derives an `auth_key` (sent at login) and an `X25519` identity key (which **never** leaves the browser). The server never stores the `AccountNumber`.
2. **Zero Plaintext & Zero Metadata Storage:** Messages are encrypted in the browser using AES-256-GCM. The server stores only opaque ciphertexts padded to one of five power-of-two sizes (256 to 4096 bytes) and accepts no other size. User accounts contain **no creation or update timestamps**. Message send times reside solely inside the ciphertext; the server only tracks a coarse, day-granular expiry date.
3. **Graph Unlinkability:** Unlike legacy designs where a member tag is shared across all rooms, **noaddx generates a unique, isolated HMAC member tag per conversation**. Even a complete database dump cannot correlate that a user in Conversation A is the participant in Conversation B.
4. **Scoped Ordering:** Sequence numbers (`seq`) are calculated **per conversation**, eliminating global activity correlation across different channels.
5. **Ephemerality by Default:** All messages automatically expire and are purged by an hourly background daemon based on `MESSAGE_TTL_DAYS` (default 7 days). Complete, bilateral conversation wiping ("Burn") is supported at any time.

---

> [!TIP]
> **New to the project?** Start with [**Quick Start**](getting-started/quickstart.md) or check [**Installation & Platforms**](getting-started/installation-and-platforms.md) to ensure your system meets OpenSSL and Docker requirements before running scripts.
