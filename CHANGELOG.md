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
- **AccountNumber exposure window.** Phase 1 of registration kept the AccountNumber (which also
  seeds the user's E2E identity) in server memory for up to five minutes; it now keeps only the
  derived auth key and public key, and the AccountNumber leaves memory with the phase-1 response.
- **Argon2id memory bound.** Unlimited concurrent logins could allocate 64 MiB each until the
  process died; at most `ARGON2_MAX_CONCURRENT` run at once and the rest get 503 after 3 s,
  for known and unknown accounts alike.
- **OpenSSL error queue** is cleared on the thread that filled it (cgo calls can change OS
  threads), so no failure detail lingers between calls.

### Added

- **Two byte-for-byte equivalent crypto engines.** The OpenSSL engine (libcrypto >= 3.2 through
  cgo, now with HKDF and X25519) returns alongside the native Go engine; `ENGINE=openssl|native`
  picks one at build time and OpenSSL is the default. Input validation is shared, known-answer
  tests run on both, a differential suite proves identical outputs and rejections
  (`make test-equivalence`), and the server runs a known-answer self-test before it starts.
- Release tags per engine (`noaddx-openssl-vX.Y.Z`, `noaddx-native-vX.Y.Z`), moving dev tags
  (`noaddx-openssl-dev`, `noaddx-native-dev`) and `make build-ref REF=<tag>` to rebuild any of them.
- **Verifiable client.** Each release tag gets the SHA-256 of every frontend file, signed with
  Sigstore keyless by the release workflow; `make verify-frontend URL=…` checks that any
  instance, onion included, serves exactly those bytes.
- **Five padding sizes.** Messages are padded to a power of two from 256 to 4096 bytes, so a
  ciphertext's length reveals one of five size classes (it was one of 24), and the server
  accepts no other size. The longest message drops from 6000 to 4094 bytes of payload, still
  above the 2000-character composer limit; messages stored before the change still open.
- **Delete identity.** `DELETE /api/v2/me` erases the account, its invites and every
  conversation it is in, for both sides; peers are told at once and every session ends. It
  takes the account number again (as its auth key), and the browser checks the number belongs
  to this identity before sending, so the server never sees a second account's key. A `DELETE`
  that carries a body must now declare JSON, like every other write.
- **Onion service (`make onion`).** An opt-in tor container publishes the app as a Tor v3
  onion service with Tor's own PoW and introduction DoS defenses. Abuse control keeps working
  without client IPs: tor names each circuit in a PROXY header, nginx's onion listener accepts
  only the tor container, and the backend rate-limits each circuit separately (it used to group
  Tor's whole address range like one IPv6 subscriber, which would have put every Tor user in
  one bucket). A circuit holding more than 32 open connections is torn down, and the PoW
  issuer forgets idle clients after one window instead of an hour, so a flood of circuits
  cannot fill its client cap and refuse challenges to everyone.
- **Invites cost a proof of work.** `POST /api/v2/invites` now takes `{"pow": …}` with a fresh,
  single-use solution, like each registration phase: missing → 412, invalid or replayed → 403,
  empty body → 415. While the browser solves it, the invite code scrambles, masks and reveals
  exactly like a new account number; the invite panel's "done" button is gone.
- Fuzz tests for every parser that faces the network (stored hash format, E2E ciphertext and its
  AAD bindings, UUID/invite/ciphertext whitelists, PoW solutions, JSON bodies).
- GitHub Actions: both engines with the race detector and fuzzers, the equivalence suite,
  frontend interop tests, govulncheck, gitleaks over the full history, and both Docker images
  booting as the unprivileged user with the self-test passing.

### Changed

- The project is now **noaddx.** (formerly noaddress.). Protocol labels changed with the name, so
  identities created under the old name do not carry over.
- `make setup` generates the database password and works with any `openssl`; `make test` runs the
  complete suite, database and integration tests included.
- Go 1.26 or newer is required to build.
- `setup.sh` and `run.sh` are gone; they only forwarded to `make setup` / `make up` / `make test`.
