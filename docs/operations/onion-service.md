# Onion Service (Tor)

`make onion` starts the normal stack plus a `tor` container that publishes the app as a Tor
v3 onion service. Users reach it with Tor Browser; neither side learns the other's IP address,
and the server's location stays hidden.

It is **opt-in**: a plain `make up` keeps every service on loopback. Publishing an onion
service makes the instance reachable from anywhere on the Tor network.

```bash
make onion            # build and start everything, including tor
make onion-address    # print the .onion address (about a minute after the first start)
```

---

## How a request travels

```text
Tor Browser ──Tor──▶ tor container ──PROXY header + HTTP──▶ nginx :8081 ──X-Forwarded-For──▶ backend
                     (172.29.73.11)   source = this circuit   (onion       = the circuit
                                                               listener)
```

1. **tor** (`tor.Dockerfile`, `tor/torrc`) publishes the service and forwards onion port 80 to
   nginx's onion listener. With `HiddenServiceExportCircuitID haproxy` it opens every
   connection with a PROXY header whose source address encodes the Tor circuit
   (`fc00:dead:beef:4dad::/64`, circuit ID in the low 32 bits).
2. **nginx** listens on `8081 proxy_protocol` and accepts connections from the tor container
   only (`allow ${TOR_IP}; deny all;`). Nothing else can reach that port, so nobody else can
   claim to be a Tor circuit. The circuit address becomes `$client_addr`, which feeds nginx's
   rate limit and is the only address forwarded.
3. **backend** trusts the forwarded address only from nginx (`TRUSTED_PROXIES`), as for
   clearnet traffic, and keys each Tor circuit separately
   (`backend/internal/middleware/trustedproxy.go`).

## Zero trust behind Tor

Every request arrives from the tor container, so without circuit IDs all Tor users would share
one rate-limit bucket: a few failed logins or PoW challenges would lock everyone out. The
defenses stay layered and none of them needs an identity:

| Layer | Defense |
|---|---|
| Tor | `HiddenServicePoWDefensesEnabled` (client puzzles when the service is under load), `HiddenServiceEnableIntroDoSDefense` (rate-limited introductions) |
| nginx | 20 req/s per circuit, onion listener open to the tor container only |
| backend | Per-circuit rate limits and PoW challenge budget, PoW for registration and invites, bounded Argon2id concurrency, every input validated as for clearnet traffic |

A client can open new circuits, but each one costs a Tor rendezvous, and under load also the
Tor-layer puzzle. Registration and invites still cost an application-level proof of work per
request, whatever circuit they arrive on.

## The onion address key

The service identity lives in the `tor_data` volume
(`/var/lib/tor/noaddx/hs_ed25519_secret_key`). Losing it changes the address; leaking it lets
someone impersonate the service. Back it up encrypted and offline. `make clean` deletes it
along with every other volume.

## Browser requirements

- **Tor Browser 15 or newer.** The client needs X25519 in WebCrypto (Firefox ESR 140).
- **Security level Standard.** The client needs JavaScript for all of its cryptography.
  "Safest" disables JavaScript everywhere; "Safer" disables it on non-HTTPS sites, and the Tor
  Project does not document whether that includes a plain-HTTP onion.
- Tor Browser treats `.onion` as a secure context, which WebCrypto requires and which lets the
  production `__Host-Session` cookie (Secure, HttpOnly, SameSite=Strict) be set over the onion
  connection. Confirm the first login in Tor Browser after deploying.

Writes need no extra configuration: Tor Browser sends `Sec-Fetch-Site: same-origin`. Add the
onion origin (`http://<address>.onion`) to `ALLOWED_ORIGINS` only for clients that send no
`Sec-Fetch-Site` header.
