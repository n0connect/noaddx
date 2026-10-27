# REST API Reference

All API endpoints are mounted under the base prefix `/api/v2`.
Requests are subject to strict JSON validation:
- **Maximum Request Body Size:** 1 MiB (`1048576` bytes).
- **Maximum JSON Nesting Depth:** 2 levels.
- **Unknown Fields:** Rejected immediately.
- **Extraneous Query Parameters:** Any query parameters other than explicitly whitelisted ones (e.g., `?after=seq`) are rejected with `400 Bad Request`.

---

## Authentication & Sessions

- **Session Delivery:** The only credential is an HttpOnly, `SameSite=Strict` cookie: `noaddx_session` in development, `__Host-Session` (Secure, host-only) in production. The token never appears in a response body and the `Authorization` header is ignored, so page script can never read or replay it.
- **Same-Origin Writes:** `POST`/`PUT`/`PATCH`/`DELETE` requests are refused with `403` unless the browser marks them `Sec-Fetch-Site: same-origin` (or, without that header, sends an `Origin` listed exactly in `ALLOWED_ORIGINS`). Clients that send neither header are not browsers and hold no ambient cookies.
- **Sliding Expiration:** Sessions expire after `JWT_EXPIRATION_MINUTES` (default: 15m). If an active session is used past its half-life, the backend automatically issues a refreshed cookie.
- **Saturation:** `POST /api/v2/login` and phase 2 of `POST /api/v2/register` answer `503 Service Unavailable` when every Argon2id slot (`ARGON2_MAX_CONCURRENT`) stays busy for 3 seconds. The answer does not depend on whether the account exists; retry with backoff.
- **Global Invalidation:** `POST /api/v2/logout` with a live session increments the user's `session_epoch`, instantly invalidating every JWT issued for that account on every device. A token revoked earlier cannot trigger this (it no longer authenticates); if revocation fails the endpoint answers `500` instead of reporting success. The cookie is cleared in every case.

---

## Endpoints Summary

| Method | Endpoint | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/v2/pow/challenge` | Public | Request SHA-256 hashcash puzzle (registration and invites) |
| `POST` | `/api/v2/register` | Public | Phase 1 (generate account number) & Phase 2 (confirm account) |
| `POST` | `/api/v2/login` | Public | Authenticate with derived `auth_key` |
| `POST` | `/api/v2/logout` | Session | Revoke all active sessions and wipe cookies |
| `GET` | `/api/v2/me` | Session | Fetch user public key and server retention policy |
| `DELETE` | `/api/v2/me` | Session + auth key | Erase the account, its invites and every conversation (both sides) |
| `POST` | `/api/v2/invites` | Session | Generate single-use pairing token (requires PoW) |
| `POST` | `/api/v2/invites/redeem` | Session | Redeem pairing token and start conversation |
| `GET` | `/api/v2/conversations` | Session | List active conversations |
| `DELETE` | `/api/v2/conversations/{id}` | Session | Burn conversation and erase all messages bilaterally |
| `GET` | `/api/v2/conversations/{id}/messages` | Session | Fetch encrypted messages (supports `?after=seq`) |
| `POST` | `/api/v2/conversations/{id}/messages` | Session | Send E2E encrypted message ciphertext |
| `POST` | `/api/v2/conversations/{id}/read` | Session | Update read sequence marker |
| `GET` | `/api/v2/events` | Session | Server-Sent Events (SSE) realtime poke stream |

---

## 1. Identity & Authentication

### `GET /api/v2/pow/challenge`
Issues a single-use hashcash proof-of-work challenge.

- **Rate Limit:** 5 requests per minute per client key (an IPv4 address, an IPv6 /64, or one Tor circuit on the onion service), shared by registration and invites.
- **Response (200 OK):**
```json
{
  "success": true,
  "message": "PoW challenge generated successfully",
  "challenge": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```

---

### `POST /api/v2/register`
Two-phase registration process to protect against bot accounts and Argon2id DoS.

#### Phase 1: Request Account Number Preview
- **Request Body:**
```json
{
  "confirm": false,
  "pow": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "solution": "1048576",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```
- **Response (200 OK):**
```json
{
  "success": true,
  "message": "Account number generated - click continue to create account",
  "account_number": "k8x9F...43-character-base64url-string...",
  "pending_token": "eyJhbGciOi...",
  "confirmed": false
}
```

#### Phase 2: Confirm Account Creation
Requires solving a fresh, single-use PoW challenge.
- **Request Body:**
```json
{
  "confirm": true,
  "pending_token": "eyJhbGciOi...",
  "pow": {
    "challenge": "new_challenge_hex",
    "salt": "new_salt_hex",
    "solution": "524288",
    "difficulty": 20,
    "timestamp": 1729731230,
    "ttl": 300
  }
}
```
- **Response (201 Created):** Sets the HttpOnly session cookie; the body never carries the token.
```json
{
  "success": true,
  "message": "Account created successfully",
  "confirmed": true
}
```

---

### `POST /api/v2/login`
Authenticates a user via their derived `auth_key`. The `AccountNumber` is **never** sent.

- **Request Body:**
```json
{
  "auth_key": "43-character-base64url-derived-key"
}
```
- **Response (200 OK):** Sets the HttpOnly session cookie; the body never carries the token.
```json
{
  "success": true,
  "message": "Login successful"
}
```

---

### `POST /api/v2/logout`
Revokes all active sessions for this account across all devices by bumping `session_epoch`.

- **Response (200 OK):** Clears session cookie.
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### `GET /api/v2/me`
Retrieves caller's public key and server retention policy.

- **Response (200 OK):**
```json
{
  "public_key": "X25519-public-key-base64url",
  "message_ttl_days": 7
}
```

---

### `DELETE /api/v2/me`
Erases the caller's account: pending invites, every conversation it belongs to (all ciphertext, for both sides; peers get a `conv` event) and the account row. Every session of the account ends and the cookie is cleared.

A live session is not enough: the request re-proves the account number with its derived auth key, exactly as login does. The client checks that the number derives this identity's public key before sending anything, so the server never sees a second account's key.

- **Request Body** (`Content-Type: application/json`, required for any `DELETE` that carries a body):
```json
{
  "auth_key": "HKDF(AccountNumber, \"noaddx/auth\") base64url"
}
```
- **Errors:** `400` malformed body or key, `403` the key belongs to another account, `415` body not declared as JSON, `429` too many attempts.
- **Response (200 OK):**
```json
{
  "success": true,
  "message": "Account deleted"
}
```

---

## 2. Pairing & Invites

### `POST /api/v2/invites`
Creates a single-use pairing token. Every invite costs a fresh, single-use PoW challenge, exactly like each registration phase.

- **Request Body:**
```json
{
  "pow": {
    "challenge": "a4f89b1c2d3e4f5a6b7c8d9e0f1a2b3c",
    "salt": "f1e2d3c4b5a697887766554433221100",
    "solution": "1048576",
    "difficulty": 20,
    "timestamp": 1729731200,
    "ttl": 300
  }
}
```
- **Errors:** `415` without a JSON body, `412` without `pow`, `403` for a solution that is unknown, expired, already used or below the issued difficulty.
- **Rate Limit:** Bounded by `MAX_ACTIVE_INVITES` (default: 5 concurrent unredeemed invites). Returns `429 Too Many Requests` when limit is exceeded. Challenges themselves are limited to 5 per minute per client key, shared with registration.
- **Response (201 Created):**
```json
{
  "token": "16-byte-base64url-token",
  "expires_at": 1729817600
}
```

---

### `POST /api/v2/invites/redeem`
Redeems an invite token and creates an isolated two-party conversation.

- **Request Body:**
```json
{
  "token": "16-byte-base64url-token"
}
```
- **Response (201 Created):**
```json
{
  "conversation": {
    "id": "e9b2c3d4-5678-4abc-9def-0123456789ab",
    "peer_public_key": "peer-X25519-public-key-base64url",
    "last_seq": 0,
    "read_seq": 0
  }
}
```
*Note: Returns `404 Not Found` if token is invalid, expired, already redeemed, or created by the caller.*

---

## 3. Conversations & Messages

### `GET /api/v2/conversations`
Lists all conversations for the authenticated user, ordered by most recent activity.

- **Response (200 OK):**
```json
{
  "conversations": [
    {
      "id": "e9b2c3d4-5678-4abc-9def-0123456789ab",
      "peer_public_key": "peer-public-key-base64url",
      "last_seq": 14,
      "read_seq": 14
    }
  ]
}
```

---

### `DELETE /api/v2/conversations/{id}`
**Burn:** Bilaterally deletes the conversation, all memberships, and all stored ciphertexts from the database.

- **Response:** `204 No Content`

---

### `GET /api/v2/conversations/{id}/messages[?after=seq]`
Fetches encrypted messages for a conversation.
- If `?after=seq` is omitted, returns the latest page of messages up to `MESSAGE_PAGE_LIMIT`.
- If `?after=seq` is provided, returns messages with sequence numbers greater than `seq`.

- **Response (200 OK):**
```json
{
  "messages": [
    {
      "id": "7b1a2c3d-4e5f-4678-890a-bcdef0123456",
      "seq": 15,
      "mine": false,
      "ciphertext": "base64url-encoded-nonce-ciphertext-tag"
    }
  ]
}
```

---

### `POST /api/v2/conversations/{id}/messages`
Sends an end-to-end encrypted message ciphertext.

- **Request Body:**
```json
{
  "id": "7b1a2c3d-4e5f-4678-890a-bcdef0123456",
  "ciphertext": "base64url-encoded-nonce-ciphertext-tag"
}
```
- **Response (201 Created):**
```json
{
  "seq": 15
}
```
*Note: Returns `409 Conflict` if the client-generated message ID was already used.*

---

### `POST /api/v2/conversations/{id}/read`
Advances the caller's read marker. Cannot be moved backwards or past `last_seq`.

- **Request Body:**
```json
{
  "seq": 15
}
```
- **Response:** `204 No Content`

---

## 4. Realtime Server-Sent Events (SSE)

### `GET /api/v2/events`
Opens an unbuffered, content-free SSE stream.

- **Headers:** `Accept: text/event-stream`
- **Stream Events:**
  - `event: msg` with `data: {"c": "<conversation_id>"}` (signals a new message arrived).
  - `event: conv` with `data: {}` (signals conversation list or membership changed).
  - `: ping` (keepalive comment sent every 15 seconds).
- **Authentication:** Validated via session cookie. If session is revoked, the stream closes with `401 Unauthorized`.

---

### Next Steps:
- Learn how to tune server memory and rotation in [**Configuration & Tuning**](../operations/configuration-and-tuning.md).
- Resolve any client/server errors in [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
