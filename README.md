# noaddress. — anonymous, end-to-end encrypted messaging

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![JavaScript](https://img.shields.io/badge/JavaScript-ES2020-F7DF1E?style=flat&logo=javascript)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-4169E1?style=flat&logo=postgresql)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat&logo=docker)
![Nginx](https://img.shields.io/badge/Nginx-Alpine-009639?style=flat&logo=nginx)
![License](https://img.shields.io/badge/License-AGPL%203.0-blue?style=flat)

No email. No phone number. No password. No username. One random account number, Mullvad-style — and a server that only ever relays ciphertext.

---

## Complete Modular Documentation

Detailed, production-grade documentation is organized under the [`docs/`](docs/README.md) directory:

- [**Quick Start Guide**](docs/getting-started/quickstart.md) - 3-minute setup, testing, and first chat.
- [**Installation & Cross-Platform Guide**](docs/getting-started/installation-and-platforms.md) - macOS (LibreSSL fix), Linux (Ubuntu/Debian/Arch), Windows (WSL2), arm64 vs. amd64.
- [**System Architecture**](docs/architecture/system-overview.md) - Component layout, identity derivation, graph isolation, and retention daemon.
- [**Threat Model & Security**](docs/security/threat-model.md) - Adversary analysis, database snapshot resilience, AAD v2, and memory zeroization.
- [**Cryptography Specification**](docs/security/cryptography.md) - WebCrypto, X25519, HKDF-SHA256, AES-256-GCM, 256-byte bucket padding, and PoW hashcash.
- [**REST API Reference**](docs/api/rest-api.md) - Complete endpoint reference, strict JSON validation, and error masking.
- [**Configuration & Tuning**](docs/operations/configuration-and-tuning.md) - Environment variables, master key rotation runbook, and Argon2id memory tuning.
- [**Troubleshooting Guide**](docs/troubleshooting/troubleshooting-guide.md) - Instant fixes for WebCrypto Secure Context, port collisions, and Docker DB connections.
- [**Testing & Development**](docs/development/testing-and-contributing.md) - Unit tests, WebCrypto verification, lock hierarchy, and security rules.

---

## Overview

**noaddress.** is an anonymous messenger with no address book, no handles, and no recoverable identity.
- An identity is a 256-bit CSPRNG `AccountNumber` (HMAC lookup + Argon2id server side, two-phase registration behind proof of work).
- Everything you say is end-to-end encrypted in the browser (WebCrypto X25519 + AES-256-GCM); the server only relays opaque ciphertext.
- Social graph isolation: **every user receives a unique, isolated HMAC member tag per conversation**. Storing or dumping the database does not link a user's presence across different rooms.
- Sequence numbers (`seq`) are calculated **per conversation**, preventing cross-room activity correlation.
- Ciphertexts expire automatically via a day-granular retention daemon (`MESSAGE_TTL_DAYS`, default 7 days). Bilateral "Burn" allows complete instant deletion at any time.

**Flow in one breath:** create an identity -> copy your account number -> `+ invite` -> send the `noaddress:...` code over any channel you trust -> your peer pastes it under `join` -> talk.

---

## Quick Start

### 1. Configure Secrets & Environment
```bash
chmod +x setup.sh run.sh
./setup.sh
```

> [!IMPORTANT]
> **macOS Users:** macOS ships with LibreSSL by default. `setup.sh` requires OpenSSL >= 3.2.0.
> Run `brew install openssl@3 && export PATH="$(brew --prefix openssl@3)/bin:$PATH"` before `./setup.sh`.
> See [Installation & Platforms](docs/getting-started/installation-and-platforms.md) for details.

### 2. Build & Launch Services
```bash
./run.sh
```

### 3. Open Browser
Navigate to **[http://localhost](http://localhost)**.

> [!CAUTION]
> **WebCrypto Secure Context:** Always access via `http://localhost` or `http://127.0.0.1`. Modern browsers disable `window.crypto.subtle` on unencrypted remote IP addresses (e.g. `http://192.168.x.x`), which will cause cryptographic operations to fail. For remote servers, terminate TLS/HTTPS.

---

## How It Works

### 1. Identity Derivation

```text
AccountNumber (256-bit CSPRNG, base64url, 43 chars) - generated at signup, shown ONCE
   |
   +-- HKDF-SHA256(salt: "noaddress.v1", info: "noaddress/auth") -----------> auth key (sent at login)
   |                                                                          server keeps HMAC + Argon2id only
   `-- HKDF-SHA256(salt: "noaddress.v1", info: "noaddress/identity/x25519") -> X25519 identity (stays in browser)
                                                                             server keeps the public key only
```

Both derivations exist in Go (`backend/internal/identity`) and JavaScript (`frontend/js/crypto.js`) and are tested byte-for-byte against each other (`node --test frontend/tests/`, `backend/tests/identity`).

In the browser, the private key is imported as a **non-extractable** `CryptoKey` into IndexedDB so a reload does not ask for the account number again. Script running on the page can use the key to decrypt, but cannot extract its raw bytes. Logout deletes the database.

### 2. Pairing & Out-of-Band Fingerprinting

```text
Alice                                   Server                                   Bob
  | POST /api/v2/invites --------------> | stores HMAC(token) +                   |
  |                                      | AES-GCM(creator_uuid, master_key)      |
  |<---------------------------- token   |                                        |
  | code = "noaddress:" + b64url(token || SHA-256("noaddress/invite-fp" || token || alicePub)[0:16])
  | ---------------- out of band (Signal, paper, in person) --------------------->|
  |                                      | <----------------- POST /api/v2/invites/redeem {token}
  |                                      | atomically deletes invite, creates conversation
  |<--- SSE "conv"                       | --------------------------------------> alicePub
  |                                      |       Bob checks alicePub against the code's
  |                                      |       fingerprint; mismatch ---> auto-burn!
```

The fingerprint never touches the server. Because it binds to the single-use token, two invites created by the same person share no bytes.

### 3. Messages & Wire Format

```text
conversation key = HKDF-SHA256(X25519(myPriv, peerPub), salt: conversation_id, info: "noaddress/conv/v1")
plaintext        = len(2) || {"t": text, "ts": sentAt} || zero padding to a multiple of 256 bytes
AAD              = "NADM" || 0x01 || conversation_id(16) || message_id(16) || SHA-256(sender_pub)(32)
wire             = base64url(nonce(12) || AES-256-GCM(plaintext, AAD) || tag(16))
```

The message ID is a client-generated UUIDv4 bound into the AAD. A ciphertext cannot be moved to another room, replayed under a different message ID, or reflected back as originating from the other participant.

### 4. Realtime Server-Sent Events (SSE)

`GET /api/v2/events` is an unbuffered Server-Sent Events stream of content-free pokes (`msg` with a conversation ID, `conv` for membership changes). Clients refetch through authorized REST endpoints. Open streams are immediately terminated on logout or server shutdown.

---

## Security Model

### What the Server Stores

| Table | Columns | Readable Without Master Key / Pepper? |
|---|---|---|
| `users` | `uuid`, `account_lookup`, `account_hash`, `public_key`, `session_epoch`, `encrypted_key`, `master_key_id`, `conv_index_enc` | **Public key only**. Account number cannot be derived. No creation/update timestamps. |
| `invites` | `lookup` (HMAC), `creator_ref_enc` (AES-GCM), `master_key_id`, `expires_at` | **Expiry timestamp only**. Token and creator are unreadable. |
| `conversations` | `id` (UUIDv4) | Room ID exists; participants are hidden. |
| `conversation_members` | `conversation_id`, `member_tag` (HMAC per room), `member_ref_enc` (AES-GCM), `master_key_id`, `peer_key_enc` (AES-GCM), `read_seq` | **Read sequence only**. Member tag is isolated to this conversation. |
| `messages` | `conversation_id`, `seq` (per-room atomic counter), `id` (UUIDv4), `sender_tag`, `ciphertext`, `expires_on` (UTC day) | **Nothing about content**. Sequence numbers are scoped per room. |

### Stored-Record AAD (Server-Side)

Server-side database encryption uses authenticated metadata (`backend/internal/encryption/aad.go`):
`MAGIC "PXAD"(4) || VER 0x02(1) || SHA-256(subject)(32) || RECORD_ID(16) || FIELD(1) || PURPOSE(1)` (55 bytes)
- `FIELD 0x01`: Peer public key (`conversation_members.peer_key_enc`)
- `FIELD 0x02`: Invite creator (`invites.creator_ref_enc`)
- `FIELD 0x03`: Member reference (`conversation_members.member_ref_enc`)
- `FIELD 0x04`: User conversation index (`users.conv_index_enc`)

### Graceful Shutdown & Zeroization

When `SIGINT` or `SIGTERM` is received, the server stops accepting new connections, gives in-flight requests 10 seconds to finish, closes all live SSE streams, and executes `encryption.ZeroizeAllKeys()` to overwrite active and old master keys in memory with zeros.

---

## Testing

```bash
# 1. Containerized full test suite (disposable Postgres instance)
./run.sh --test

# 2. Local Go unit tests (fast, no database needed)
cd backend
go test -tags=test ./internal/pow/... ./internal/handlers/... ./tests/identity/... ./tests/encryption/... ./tests/utils/...

# 3. Local Go database & integration tests (requires local Postgres on 5432)
DB_HOST=127.0.0.1 DB_PORT=5432 go test -tags=test ./tests/database -v
DB_HOST=127.0.0.1 DB_PORT=5432 go test -p 1 -race -tags=test ./...

# 4. Frontend WebCrypto derivation verification (requires Node.js 20+)
cd ..
node --test frontend/tests/
```

---

## References & Specifications

- **X25519**: RFC 7748 - Elliptic Curves for Security
- **HKDF**: RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function
- **AES-256-GCM**: NIST SP 800-38D - Galois/Counter Mode (GCM) for Block Ciphers
- **Argon2id**: RFC 9106 - Argon2 Memory-Hard Function for Password Hashing
- **PKCS#8 for X25519**: RFC 8410 - Asymmetric Key Packages (OID 1.3.101.110)
- **Base64URL**: RFC 4648 Section 5 - Base 64 with URL and Filename Safe Alphabet
- **Trusted Types**: W3C Trusted Types API Specification
- **Web Cryptography API**: W3C Recommendation (Secure Contexts)
- **Zero-Trust Architecture**: NIST SP 800-207
- **Mullvad VPN**: AccountNumber-only authentication inspiration

---

**Version**: 1.0-dev  
**License**: GNU Affero General Public License v3.0 (`LICENSE`)
