# Threat Model & Security Architecture

This document formalizes the security guarantees, adversary capabilities, and cryptographic boundaries of **noaddx.**

---

## Security Objectives

1. **Confidentiality:** No entity other than the verified participants in a conversation can decrypt message contents.
2. **Pseudonymity & Unlinkability:** The server and database observers cannot link a user's presence across different conversations.
3. **PFS Through Burn:** While v1 utilizes static X25519 identities per conversation, bilateral "Burn" guarantees that message deletion removes all ciphertexts from server storage.
4. **Resilience to Database Dumps:** A stolen database snapshot reveals no plaintext, no user credentials, and no direct social graph linkages.
5. **Zero Telemetry:** The platform actively avoids recording client IP addresses, access timestamps, or user activity logs.

---

## Database Storage Analysis

What an adversary learns if they obtain a full SQL database dump:

| Table | Sensitive Columns | Protection Mechanism | Readable Without Master Key / Pepper? |
|---|---|---|---|
| `users` | `account_lookup`<br>`account_hash`<br>`public_key`<br>`encrypted_key`<br>`conv_index_enc` | HMAC-SHA256 (`ACCOUNT_LOOKUP_PEPPER`)<br>Argon2id Memory-Hard Hash<br>Plaintext X25519 Public Key<br>AES-256-GCM wrapped user key (master key)<br>AES-256-GCM encrypted room list (user key) | **Only the public key**.<br>The AccountNumber cannot be reversed. Account IDs cannot be linked to rooms without master key. |
| `invites` | `lookup`<br>`creator_ref_enc`<br>`expires_at` | HMAC-SHA256 (`ACCOUNT_LOOKUP_PEPPER`)<br>AES-256-GCM creator UUID (master key)<br>Unix timestamp | **Only the expiration timestamp**.<br>Invite token and creator identity are unreadable. |
| `conversations` | `id` | Random UUIDv4 | Room exists, but participants are unknown. |
| `conversation_members` | `member_tag`<br>`member_ref_enc`<br>`peer_key_enc`<br>`read_seq` | HMAC-SHA256 per room (`convTagKey`, `uuid \|\| convID`)<br>AES-256-GCM user UUID (master key)<br>AES-256-GCM peer pub key (user key)<br>Integer | **Only the read sequence number**.<br>The member tag is isolated to this room. A user in Room A has a completely different tag in Room B. |
| `messages` | `ciphertext`<br>`sender_tag`<br>`seq`<br>`expires_on` | AES-256-GCM E2E browser encryption<br>Per-room member tag<br>Per-room sequence number<br>Date (UTC, truncated to day) | **Nothing about content**.<br>Sequence numbers are scoped to this room. Expiry dates reveal only day of deletion. |

---

## Adversary Capabilities Matrix

| Adversary Model | What is Protected | What is NOT Protected |
|---|---|---|
| **Passive Network Observer (ISP, Wi-Fi snooper)** | - Message plaintext (E2E AES-256-GCM)<br>- Account numbers & credentials<br>- Message length (one of five padded sizes, 256 to 4096 bytes) | - Connection timing & packet frequency<br>- IP address connecting to Nginx (hidden from the server over the onion service)<br>- Total bytes transferred |
| **Database Thief (Stolen SQL backup)** | - Message contents (encrypted client-side)<br>- Account numbers (Argon2id + HMAC)<br>- Cross-conversation user linkage (per-room HMAC tags)<br>- Fine-grained send timestamps (server stores no seconds/minutes) | - Total message count per room<br>- Internal message ordering within a single room<br>- Coarse day of scheduled message deletion |
| **Curious Server Operator (Has DB + `.env` + Master Keys)** | - Message plaintext (Keys are derived in browser WebCrypto; server never has private X25519 keys) | - Social graph: operator can decrypt `member_ref_enc` to link users to conversations<br>- Active connection presence via realtime hub |
| **Malicious Server at Runtime (Compromised backend)** | - Past messages sent to verified peers cannot be retroactively decrypted.<br>- Peer key substitution is detected by Bob via invite fingerprinting or safety numbers. | - **Web Security Limit:** A malicious server that serves modified JavaScript to the browser can exfiltrate private keys at execution time. |
| **Session Cookie Interceptor** | - Cookie is `HttpOnly`, `SameSite=Strict`, and `Secure` (`__Host-` prefixed in prod); the token never appears in a response body and no header can carry it.<br>- Cross-origin and same-site writes (other ports, sibling subdomains) are refused via `Sec-Fetch-Site`/`Origin`.<br>- Logout immediately invalidates all sessions via `session_epoch` bump; an already revoked token cannot trigger it. | - Access to the authenticated account until the session cookie expires (15m sliding window) or logout is invoked. |
| **User Loses AccountNumber** | - High security: zero backdoor access. | - **Unrecoverable:** By cryptographic design, no admin reset, SMS code, or email recovery exists. |

---

## Stored-Record AAD Specification (v2)

To prevent ciphertext swapping across rows, tables, or identities, all server-side AES-256-GCM operations bind to an authenticated header (`backend/internal/encryption/aad.go`):

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       MAGIC "PXAD"                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  VER (0x02)   |                                               |
+-+-+-+-+-+-+-+-+                                               +
|                  SHA-256(Subject Tag) (32 bytes)              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Record ID (16 bytes UUID)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Field (1)   |  Purpose (1)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Total Length = 55 bytes
```

### Registered Field Codes:
- `0x01` (`FieldPeerPublicKey`): Encrypted peer public key (`conversation_members.peer_key_enc`).
- `0x02` (`FieldInviteCreator`): Encrypted invite creator reference (`invites.creator_ref_enc`).
- `0x03` (`FieldMemberRef`): Encrypted member reference (`conversation_members.member_ref_enc`).
- `0x04` (`FieldConversationIndex`): Encrypted conversation ID index (`users.conv_index_enc`).

---

## Memory Zeroization on Shutdown

To protect against cold-boot attacks and post-termination RAM dumps:
- On `SIGINT` or `SIGTERM`, `backend/cmd/server/main.go` triggers `encryption.ZeroizeAllKeys()`.
- Overwrites the active and old master keys (`MASTER_KEY_ACTIVE`, `MASTER_KEY_OLD`) in heap memory with `0x00`.
- Background janitors are safely stopped, and open Server-Sent Events streams are severed.

---

## What the Server Holds in Memory, and for How Long

- **The AccountNumber:** only inside the phase-1 registration request. The response shows it to the user once; what waits for phase 2 (up to `PENDING_TOKEN_TTL_SEC`) is the derived auth key and X25519 public key, from which the AccountNumber cannot be recovered. Login sends the derived auth key, never the AccountNumber.
- **Master keys:** for the process lifetime, zeroized on shutdown (above).
- **Per-user server keys and conversation indexes:** only while a request that needs them runs.
- **Stream tags and rate-limit keys:** HMACs under per-boot secrets, never persisted.

---

## Known Limitations

These are properties of the design, stated so nobody relies on a guarantee that is not there:

- **No forward secrecy.** Each account has one static X25519 identity key derived from its AccountNumber, and each conversation one key derived from the two identities. Whoever obtains an AccountNumber can decrypt every message of that account that is still stored (up to `MESSAGE_TTL_DAYS`) or was recorded in transit. Retention and **Burn** bound the exposure; treat the AccountNumber like a master key.
- **The invite creator trusts the server for the peer key.** The fingerprint in the invite code protects the *redeemer* against a substituted creator key. The creator learns the redeemer's key from the server and is protected only after both compare safety numbers.
- **Code delivery is trust in the server.** A browser application runs the JavaScript it is served; a malicious or compromised deployment can serve code that leaks keys (see the matrix above). Each release signs the list of frontend file hashes, and `make verify-frontend` proves what an instance serves ([Verifying the Client](verifying-the-client.md)), but only to the verifier: a server can still target one user.
- **Withheld-message detection is per device.** The encrypted sender counter reveals gaps in what one device has seen; it is not a cross-device delivery guarantee.
- **Network metadata.** The server sees connection addresses and timing in transit. It does not log them (`access_log off`; rate-limit keys are HMACs of the address under a per-boot secret), but an operator could capture them at runtime. Over the [onion service](../operations/onion-service.md) there is no client address to see, only a per-circuit number.
- **Deletion is logical, not forensic.** Deleting an identity or burning a conversation removes the rows at once, but PostgreSQL keeps dead row versions until autovacuum reuses the space and keeps the WAL until it is recycled. A disk image taken soon after can still hold them: ciphertext, HMAC tags and encrypted references, never plaintext.

---

### Next Steps:
- Review the low-level math and algorithms in [**Cryptography Specification**](cryptography.md).
- Examine configuration parameters in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
