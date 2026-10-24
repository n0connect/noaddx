# Cryptography Specification

This document details the exact cryptographic standards, key derivation functions, wire framing, and authenticated encryption employed by **noaddx.**

---

## Cryptographic Standards & Primitives

All cryptographic operations strictly adhere to well-vetted, modern standards:

| Primitive | Standard | Purpose |
|---|---|---|
| **X25519** | RFC 7748 | Elliptic-curve Diffie-Hellman key exchange |
| **HKDF-SHA256** | RFC 5869 | Extract-and-expand key derivation |
| **AES-256-GCM** | NIST SP 800-38D | Authenticated encryption with associated data |
| **Argon2id** | RFC 9106 | Server-side memory-hard authentication hashing |
| **HMAC-SHA256** | RFC 2104 | Database lookups, member tagging, and proxy client keys |
| **PKCS#8 for X25519** | RFC 8410 | Encoding private keys for WebCrypto import |
| **Base64URL** | RFC 4648 Section 5 | URL-safe string encoding (no padding `=` characters) |

---

## Key Derivation Hierarchy

### 1. Account Number & Derivations

The account number is a 32-byte (256-bit) cryptographically secure random value generated server-side via `crypto/rand` and encoded in 43 Base64URL characters.

```text
                      AccountNumber (32 raw bytes)
                                   |
         +-------------------------+-------------------------+
         v                                                   v
   HKDF-Extract                                        HKDF-Extract
(Salt: "noaddx.v1")                             (Salt: "noaddx.v1")
         |                                                   |
         v                                                   v
    HKDF-Expand                                         HKDF-Expand
(Info: "noaddx/auth", L: 32)            (Info: "noaddx/identity/x25519", L: 32)
         |                                                   |
         v                                                   v
      auth_key                                       X25519 Private Key
 (Sent at login only)                               (Stays in browser WebCrypto)
```

Both Go (`backend/internal/identity`) and JavaScript (`frontend/js/crypto.js`) implement this exact derivation and are verified byte-for-byte in test suites.

### 2. Browser Key Import (WebCrypto Non-Extractable)

In JavaScript, raw 32-byte X25519 private keys cannot be imported directly into `SubtleCrypto` without PKCS#8 framing.
The browser prepends the RFC 8410 `PrivateKeyInfo` header (OID `1.3.101.110`):

```javascript
const PKCS8_X25519_PREFIX = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
]);

const pkcs8Key = new Uint8Array(PKCS8_X25519_PREFIX.length + 32);
pkcs8Key.set(PKCS8_X25519_PREFIX, 0);
pkcs8Key.set(rawPrivateKeyBytes, PKCS8_X25519_PREFIX.length);

const cryptoKey = await window.crypto.subtle.importKey(
    "pkcs8",
    pkcs8Key,
    { name: "X25519" },
    false, // extractable = false (MANDATORY)
    ["deriveKey", "deriveBits"]
);
```
**Security Property:** `extractable: false` ensures that once imported, the browser sandbox prevents any JavaScript code (including malicious extensions or injected scripts) from exporting the raw private key bytes.

---

## Pairwise Messaging Encryption

### 1. Conversation Key Agreement

```text
Shared Secret = X25519(myPrivateKey, peerPublicKey)

Conversation Key = HKDF-SHA256(
    IKM:   Shared Secret (32 bytes),
    Salt:  Conversation ID (16 bytes UUID raw binary),
    Info:  "noaddx/conv/v1",
    L:     32 bytes
)
```

### 2. Message Framing & Bucket Padding

To thwart traffic analysis based on message length, plaintexts are bucketed into **256-byte multiples**:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Payload Length (2B)     |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                    JSON UTF-8 Payload                         |
|             {"t": "Hello world", "ts": 1729731200}            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Zero Padding (0x00 bytes)                     |
|           Padded to next multiple of 256 bytes                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3. Client-Side Authenticated Associated Data (AAD)

The AES-256-GCM cipher authenticates a 69-byte context binding:

```text
AAD = "NADM" (4 bytes: Magic ASCII)
    || 0x01   (1 byte: Version)
    || Conversation ID (16 bytes: UUIDv4 binary)
    || Message ID      (16 bytes: UUIDv4 binary, client-generated)
    || SHA-256(Sender Public Key) (32 bytes)
```

### 4. Wire Output

```text
Wire Format = base64url( Nonce [12 bytes] || Ciphertext [N bytes] || GCM Tag [16 bytes] )
```

---

## Proof of Work (PoW) Hashcash

To prevent registration floods and Denial-of-Service attacks against server-side Argon2id hashing, registration requires solving a SHA-256 hashcash puzzle in a client Web Worker (`frontend/js/pow-worker.js`).

### Challenge Structure
- **Challenge:** 16 random bytes (hex-encoded string, 32 chars).
- **Salt:** 16 random bytes (hex-encoded string, 32 chars).
- **Difficulty:** Target number of leading zero bits (default: `20`, clamped between `18` and `24`).
- **TTL:** 300 seconds (5 minutes). Single-use only.

### Solution Verification
The client increments an integer `nonce` starting at `0`:
`hash = SHA-256(challenge || salt || str(nonce))`
The solution is valid if and only if `hash` contains at least `Difficulty` leading zero bits.

### Two-Phase Registration Security Flow
1. **Phase 1 (`confirm: false`):**
   - Client requests challenge `GET /api/v2/pow/challenge`.
   - Solves PoW #1.
   - Posts solution to `POST /api/v2/register`.
   - Server returns generated `account_number` preview + signed `pending_token`.
2. **Phase 2 (`confirm: true`):**
   - Client requests a **fresh, second challenge**.
   - Solves PoW #2.
   - Posts `pending_token` + PoW #2 solution.
   - Server validates PoW #2, verifies pending token, computes Argon2id hash, and creates the account.

---

## Visual Identity Verification (Aura & Safety Numbers)

Because users have no usernames, `noaddx.` provides two symmetric, deterministic verification mechanisms:

1. **Aura (`frontend/js/utils.js`):**
   - A friendly adjective-noun combination (e.g., *"Amber Fox"*, *"Quiet Orbit"*) + a symmetric 5x5 pixel SVG glyph.
   - Derived deterministically from `HKDF-SHA256(peerPublicKey, salt="noaddx.v1", info="noaddx/aura")`.
2. **Safety Number:**
   - A 12-digit number derived from sorted public keys:
     `fingerprint = SHA-256(min(key_A, key_B) || max(key_A, key_B))`
   - Displayed in groups of 4 (`XXXX XXXX XXXX`).
   - Symmetrical: Both Alice and Bob see the exact same 12 digits, enabling out-of-band verbal or visual verification.

---

### Next Steps:
- Review the [**REST API Reference**](../api/rest-api.md).
- Learn how to manage keys in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
