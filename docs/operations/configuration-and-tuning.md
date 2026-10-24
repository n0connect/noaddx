# Configuration & Performance Tuning

This document provides a comprehensive reference for all configuration parameters, master key rotation procedures, and memory optimization profiles for production deployments.

---

## Environment Variables Reference

All settings can be configured via `.env` or injected directly as environment variables into the container runtime.

### 1. Cryptography & Security Secrets

| Variable | Type | Default | Description & Operational Notes |
|---|---|---|---|
| `JWT_SECRET` | string | *Generated* | HMAC-SHA256 signing secret for session tokens (must be >= `JWT_SECRET_MIN_LEN`). |
| `JWT_SECRET_MIN_LEN` | int | `32` | Minimum enforced character length for `JWT_SECRET`. |
| `JWT_ISSUER` | string | `noaddx-backend` | `iss` claim checked on every JWT validation. |
| `JWT_AUDIENCE` | string | `noaddx-web` | `aud` claim checked on every JWT validation. |
| `JWT_EXPIRATION_MINUTES` | int | `15` | Session lifespan. Active sessions sliding-refresh past half-life. |
| `MASTER_KEY_ACTIVE` | hex | *Generated* | Active 256-bit encryption key (32 bytes hex) used for encrypting new server records. |
| `MASTER_KEY_ACTIVE_ID` | string | *Generated* | Key identifier tag saved in DB alongside records (e.g., `key-2026-01`). |
| `MASTER_KEY_OLD` | string | *Empty* | Comma-separated list of previous keys: `id1:hex1,id2:hex2` for seamless decryption. |
| `ACCOUNT_LOOKUP_PEPPER` | hex | *Generated* | Independent HMAC pepper (>=32 bytes) used for indexing accounts and member tags. |

---

### 2. Database Connection

| Variable | Type | Default | Description |
|---|---|---|---|
| `DB_HOST` | string | `localhost` | Database host when connecting from host machine (e.g. `go test`). |
| `DOCKER_DB_HOST` | string | `postgres` | Database host inside Docker network (resolves to PostgreSQL container). |
| `DB_PORT` | int | `5432` | PostgreSQL listening port. |
| `DB_USER` | string | `postgres` | Database user. |
| `DB_PASSWORD` | string | `postgres` | Database password. |
| `DB_NAME` | string | `noaddx` | Database name. |
| `DB_SSL_MODE` | string | `disable` | SSL mode (`disable`, `require`, `verify-full`). In production, use `verify-full`. |

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
| `POW_DIFFICULTY` | int | `20` | Proof-of-work target leading zero bits (clamped between 18 and 24). |

---

### 4. Argon2id Key Derivation Tuning

| Variable | Type | Default | High-Security (Default) | Low-RAM VPS (1 GB RAM) |
|---|---|---|---|---|
| `ARGON2_MEMORY_KIB` | int | `65536` | 64 MiB (`65536`) | 32 MiB (`32768`) |
| `ARGON2_TIME` | int | `3` | 3 iterations | 2 iterations |
| `ARGON2_PARALLELISM` | int | `2` | 2 threads | 1 thread |
| `ARGON2_SALT_LENGTH` | int | `16` | 16 bytes | 16 bytes |
| `ARGON2_HASH_LENGTH` | int | `32` | 32 bytes | 32 bytes |

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
   # MASTER_KEY_ACTIVE=aaaa1111...

   # UPDATED CONFIG:
   MASTER_KEY_ACTIVE_ID=key-2026-04
   MASTER_KEY_ACTIVE=bbbb2222...new-key-hex...
   MASTER_KEY_OLD=key-2026-01:aaaa1111...previous-key-hex...
   ```

3. **Restart the backend container:**
   ```bash
   docker compose restart backend
   ```

4. **Verify Behavior:**
   - **New records** (new users, new rooms) are encrypted with `key-2026-04`.
   - **Existing records** are seamlessly decrypted using `key-2026-01` from `MASTER_KEY_OLD`.
   - `MASTER_KEY_OLD` supports multiple comma-separated keys (`id1:hex1,id2:hex2`).

---

## Nginx Security Headers & Trusted Types

The reverse proxy (`nginx.conf`) enforces strict browser isolation policies:

```nginx
# Content Security Policy (CSP)
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; worker-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; require-trusted-types-for 'script'; trusted-types noaddx-worker;" always;

# Cross-Origin Isolation
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
```

### Trusted Types Policy
The application registers a single Trusted Types policy in JavaScript (`noaddx-worker`):
```javascript
window.trustedTypes.createPolicy('noaddx-worker', {
    createScriptURL: string => string
});
```
This whitelist permits only the background Web Worker script (`/js/pow-worker.js`) to be dynamically instantiated. Any other DOM sink manipulation throws a browser security exception.

---

### Next Steps:
- If encountering runtime or network errors, consult the [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
- To contribute or run tests, read [**Testing & Development**](../development/testing-and-contributing.md).
