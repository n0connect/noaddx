# Configuration & Performance Tuning

This document provides a comprehensive reference for all configuration parameters, master key rotation procedures, and memory optimization profiles for production deployments.

---

## Environment Variables Reference

All settings can be configured via `.env` or injected directly as environment variables into the container runtime. Every value is checked at startup against a whitelist or an inclusive range; the backend refuses to start on anything outside it (nothing is silently clamped or truncated).

### 1. Cryptography & Security Secrets

| Variable | Type | Default | Description & Operational Notes |
|---|---|---|---|
| `JWT_SECRET` | string | *Generated* | HMAC-SHA256 signing secret for session tokens (must be >= `JWT_SECRET_MIN_LEN`). |
| `JWT_SECRET_MIN_LEN` | int | `32` | Minimum length for `JWT_SECRET` (32-1024; cannot be lowered below 32). |
| `JWT_ISSUER` | string | `noaddx-backend` | `iss` claim checked on every JWT validation. |
| `JWT_AUDIENCE` | string | `noaddx-web` | `aud` claim checked on every JWT validation. |
| `JWT_EXPIRATION_MINUTES` | int | `15` | Session lifespan (1-1440). Active sessions sliding-refresh past half-life. The token lives only in the HttpOnly cookie. |
| `MASTER_KEY_ACTIVE` | hex/base64 | *Generated* | Active 256-bit key: exactly 32 bytes as 64 hex characters or base64. Text passphrases are rejected. |
| `MASTER_KEY_ACTIVE_ID` | string | *Generated* | Key id stored next to every record (`[A-Za-z0-9._-]`, 1-32 chars, e.g. `key-2026-01`). |
| `MASTER_KEY_OLD` | string | *Empty* | Previous keys as `id1:key1,id2:key2`. Any malformed entry, repeated id or reuse of the active key stops startup. |
| `ACCOUNT_LOOKUP_PEPPER` | hex/base64 | *Generated* | HMAC pepper (>= 32 bytes, hex or base64) for account lookups and pseudonymous tags. |

---

### 2. Database Connection

| Variable | Type | Default | Description |
|---|---|---|---|
| `DB_HOST` | string | `localhost` | Database host when connecting from host machine (e.g. `go test`). |
| `DOCKER_DB_HOST` | string | `postgres` | Database host inside Docker network (resolves to PostgreSQL container). |
| `DB_PORT` | int | `5432` | PostgreSQL listening port. |
| `DB_USER` | string | `postgres` | Database user. |
| `DB_PASSWORD` | string | *Generated* | Database password (no default; `make setup` generates one; >= 16 characters in production). |
| `DB_NAME` | string | `noaddx` | Database name. |
| `DB_SSL_MODE` | string | `disable` | libpq sslmode. Production requires `verify-ca` or `verify-full` (an unauthenticated `require` link can be intercepted). |

---

### 3. Application Limits & Ephemerality

| Variable | Type | Default | Description |
|---|---|---|---|
| `BACKEND_PORT` | int | `8080` | Port the Go HTTP server listens on. |
| `MAX_REQUEST_BODY_BYTES` | int | `1048576` | Hard ceiling for HTTP request payloads (1 MiB). |
| `MAX_JSON_DEPTH` | int | `2` | Maximum JSON nesting depth to defeat recursive parsing attacks. |
| `INVITE_TTL_SEC` | int | `86400` | Lifetime of unredeemed invites (default 24 hours). |
| `MAX_ACTIVE_INVITES` | int | `5` | Maximum active, unredeemed invites allowed per account. |
| `MAX_CONVERSATIONS_PER_USER` | int | `256` | Maximum conversations allowed per account. |
| `MAX_MESSAGE_BYTES` | int | `8192` | Maximum allowed E2E ciphertext size per message. |
| `MESSAGE_PAGE_LIMIT` | int | `200` | Maximum messages returned per fetch page (1-1000). |
| `MESSAGE_TTL_DAYS` | int | `7` | Days to retain ciphertext before day-granular deletion (1-365). |
| `POW_DIFFICULTY` | int | `20` | Proof-of-work target leading zero bits (18-24). |
| `POW_CHALLENGE_TTL_SEC` | int | `300` | How long an issued challenge stays valid (1-3600). |

---

### 4. Build: Crypto Engine

| Variable | Type | Default | Description |
|---|---|---|---|
| `ENGINE` | `openssl` \| `native` | `openssl` | Crypto engine compiled into the backend (`make up ENGINE=native`). Both are byte-for-byte equivalent; the startup log names the engine and library version. A database written by one build is read by the other. |

### 5. Network, Proxy & Headers

| Variable | Type | Default | Description |
|---|---|---|---|
| `ALLOWED_ORIGINS` | list | `http://localhost,http://127.0.0.1` | Exact origins (scheme, host, port) for CORS and the same-origin check on writes. No wildcard or prefix matching. |
| `TRUSTED_PROXIES` | list | nginx (`PROXY_IP`) | IPs/CIDRs allowed to supply the client address. Empty in Docker means "nginx only". |
| `COMPOSE_SUBNET` | CIDR | `172.29.73.0/24` | Docker network range; change it (with `PROXY_IP`) if it collides with another network. |
| `PROXY_IP` | IP | `172.29.73.10` | nginx's fixed address on that network. |
| `HTTP_PORT` | int | `80` | Loopback port nginx is published on. |
| `DB_HOST_PORT` | int | `5432` | Loopback port PostgreSQL is published on. |
| `SEC_HEADER_COOP` / `SEC_HEADER_CORP` / `SEC_HEADER_COEP` | string | `same-origin` / `same-origin` / `require-corp` | API isolation headers; `off` disables one. |

---

### 6. Argon2id Key Derivation Tuning

Bounds: memory 8192-1048576 KiB (production floor 19456 KiB, the OWASP minimum), time 1-16, parallelism 1-255, salt and hash 16-64 bytes. Stored hashes are checked against the same bounds before verification.


| Variable | Type | Default | High-Security (Default) | Low-RAM VPS (1 GB RAM) |
|---|---|---|---|---|
| `ARGON2_MEMORY_KIB` | int | `65536` | 64 MiB (`65536`) | 32 MiB (`32768`) |
| `ARGON2_TIME` | int | `3` | 3 iterations | 2 iterations |
| `ARGON2_PARALLELISM` | int | `2` | 2 threads | 1 thread |
| `ARGON2_SALT_LENGTH` | int | `16` | 16 bytes | 16 bytes |
| `ARGON2_HASH_LENGTH` | int | `32` | 32 bytes | 32 bytes |
| `ARGON2_MAX_CONCURRENT` | int | `4` | 4 (256 MiB peak) | 2 (64 MiB peak) |

Each Argon2id computation allocates `ARGON2_MEMORY_KIB`; `ARGON2_MAX_CONCURRENT` (1-64) bounds how many run at once, so peak memory is `ARGON2_MAX_CONCURRENT × ARGON2_MEMORY_KIB`. A login or registration that cannot get a slot within 3 seconds is answered with `503 Service Unavailable` (identically for known and unknown accounts) instead of growing memory without limit.

---

## Master Key Rotation Runbook

Master key rotation allows you to replace your database encryption key without losing access to existing user records or encrypted peer public keys.

### When to Rotate:
- Scheduled compliance policy (e.g., every 90 or 180 days).
- Suspected environment credential exposure.

### Step-by-Step Procedure

1. **Generate a fresh 32-byte key:**
   ```bash
   openssl rand -hex 32
   # Example output: d7a18b...64-hex-chars
   ```

2. **Update your `.env` configuration:**
   Move the current active key to `MASTER_KEY_OLD` and assign the new key to `MASTER_KEY_ACTIVE`:
   ```ini
   # PREVIOUS CONFIG:
   # MASTER_KEY_ACTIVE_ID=key-2026-01
   # MASTER_KEY_ACTIVE=<current 64-hex key>

   # UPDATED CONFIG:
   MASTER_KEY_ACTIVE_ID=key-2026-04
   MASTER_KEY_ACTIVE=<new 64-hex key from openssl rand -hex 32>
   MASTER_KEY_OLD=key-2026-01:<current 64-hex key>
   ```

3. **Restart the backend container:**
   ```bash
   docker compose restart backend
   ```

4. **Verify Behavior:**
   - **New records** (new users, new rooms) are encrypted with `key-2026-04`.
   - **Existing records** are decrypted with the key named by their stored id (`key-2026-01` from `MASTER_KEY_OLD`); nothing is ever trial-decrypted under every key.
   - `MASTER_KEY_OLD` supports multiple comma-separated keys (`id1:hex1,id2:hex2`).

---

## Nginx Security Headers & Trusted Types

The reverse proxy (`nginx.conf`) enforces strict browser isolation policies:

```nginx
# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types noaddx-worker;" always;

# Cross-Origin Isolation
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

### Trusted Types Policy
The application registers a single Trusted Types policy in JavaScript (`noaddx-worker`):
```javascript
window.trustedTypes.createPolicy('noaddx-worker', {
    createScriptURL: (url) => {
        if (url !== 'js/pow-worker.js') throw new TypeError('script URL not whitelisted');
        return url;
    }
});
```
This whitelist permits only the background Web Worker script (`js/pow-worker.js`) to be instantiated. Any other DOM sink manipulation throws a browser security exception. Styles follow the same rule: there is no `'unsafe-inline'`, and initially hidden elements are hidden by the stylesheet (`[data-hidden]`), not by inline `style` attributes.

API responses from the backend additionally carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`: they are data, never documents.

---

### Next Steps:
- If encountering runtime or network errors, consult the [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
- To contribute or run tests, read [**Testing & Development**](../development/testing-and-contributing.md).
