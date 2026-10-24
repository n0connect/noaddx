# Changelog

All notable changes to noaddx. are recorded here. Security fixes are always listed explicitly
(see [SECURITY.md](SECURITY.md)). The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- **Shared rate limits behind nginx.** `TRUSTED_PROXIES` was empty in the Docker stack, so the
  backend saw every user as nginx's address: about 20 failed logins locked everyone out, and
  five PoW challenges per minute were shared by all clients. nginx now has a fixed address that
  the backend trusts, and only it.
- **Session revocation.** A token revoked by an earlier logout could log out the sessions created
  after it, and a failed revocation still answered "logged out". Logout now uses the same gate as
  every protected route and reports failure.
- **Session token exposure.** Login and registration returned the session token in the JSON body,
  and the API accepted it as a Bearer header. It now lives only in the HttpOnly cookie.
- **CSRF from same-site origins.** `SameSite=Strict` still sends cookies from other ports and
  sibling subdomains. State-changing requests now require `Sec-Fetch-Site: same-origin` (or an
  exactly whitelisted `Origin`).
- **CORS prefix match.** `http://localhost:3000.evil.example` was accepted when `http://localhost`
  was listed. Origins are now matched exactly.
- **Spoofable client address.** `X-Forwarded-For` was read from the left (client-controlled); it
  is now read from the right. IPv6 clients are keyed by /64, so address rotation no longer
  escapes rate limits.
- **Unbounded memory.** The rate limiter grew without bound between cleanups and sorted with an
  O(n²) loop under its global lock; PoW challenges and pending registrations had no cap. All are
  bounded now and fail closed.
- **Weak key material accepted.** A 32-character passphrase was accepted as a master key, and a
  short string as the lookup pepper. Only 32+ bytes of hex or base64 are accepted now; a malformed
  `MASTER_KEY_OLD` stops startup instead of being skipped; records decrypt only under their
  stored key id.
- **Crash on stored parameters.** An Argon2id hash with parallelism 0 or 256 panicked the server;
  stored parameters are range-checked before use.
- **Configuration ranges.** Every numeric setting is range-checked at startup. Production requires
  `verify-ca`/`verify-full` TLS to PostgreSQL and a non-default database password. The
  PostgreSQL URL is built with escaping (no DSN injection).
- **Dependencies.** golang-jwt 5.3.1 (GO-2025-3553), pgx 5.11.0 (GO-2026-5004, SQL injection),
  x/text 0.43.0 (GO-2026-5970, GO-2026-6629); builds use Go 1.27.3 (GO-2026-6809).
- **Browser hardening.** The page CSP no longer allows inline styles or `data:` images; API
  responses are inert (`default-src 'none'`, `no-store`); text from a peer has bidi overrides
  and control characters neutralized before display.
- **Containers.** Every published port binds to loopback; the backend runs as an unprivileged
  user on a read-only filesystem without capabilities.

### Changed

- The project is now **noaddx.** (formerly noaddress.). Protocol labels changed with the name, so
  identities created under the old name do not carry over.
- `make setup` generates the database password and works with any `openssl`; `make test` runs the
  complete suite, database and integration tests included.
- Go 1.26 or newer is required to build.
