# Disaster Recovery & Failure Handling

The database is useless without the keys in `.env`, and the keys are useless without the
database. Most failures heal by themselves; a few cannot be undone by design. This page lists
what each failure looks like, what the system does about it, and what is left to you.

---

## What must survive

| Asset | Where it lives | If it is lost | If it leaks |
|---|---|---|---|
| `MASTER_KEY_ACTIVE` / `MASTER_KEY_OLD` | `.env` (0600) | Every account key, conversation list and member reference is unreadable for good. No recovery exists, by design. | With a copy of the database: who talks to whom (never message content). [Rotate](configuration-and-tuning.md#master-key-rotation-runbook). |
| `ACCOUNT_LOOKUP_PEPPER` | `.env` (0600) | No account can be found again. No recovery. | With a copy of the database it links accounts to their conversations, like the master key. It **cannot be rotated**: the only remedy is a new instance. |
| `JWT_SECRET` | `.env` (0600) | Everyone is logged out once; nothing else is affected. | Sessions can be forged until it is replaced. Replace it and restart: every session ends, accounts are untouched. |
| `postgres_data` volume | Docker volume | Every account and conversation is gone; users create new identities. | See the database thief in the [threat model](../security/threat-model.md). |
| `tor_data` volume | Docker volume (`make onion`) | The onion address changes. | Someone can impersonate the onion address. See [the onion address key](onion-service.md#the-onion-address-key). |
| An account number | The user's password manager | That identity is gone. There is no recovery, by design. | Full control of that identity: its conversations and its deletion. |

The backend checks `.env` against the database at every start: every master key id that
encrypts records must be configured and must open them, and the pepper must match the one the
database pinned at its first run. A regenerated `.env` or an old key removed too early stops the
start with a message such as:

```text
Key check failed: records are encrypted under master key "key-2026-01", which is not configured: restore it as MASTER_KEY_ACTIVE or in MASTER_KEY_OLD
Key check failed: ACCOUNT_LOOKUP_PEPPER is not the pepper this database was created with: restore the original (it can never change, every account is keyed by it)
```

Restore the `.env` that belongs to this database. If that `.env` is lost for good, nothing in
the database can be read again: `make clean` deletes every volume, then `make setup` starts a
new instance.

---

## Backups: accounts only

Back up `.env` offline, **apart from** any copy of the database: together they reveal the
social graph.

Never back up messages or conversations. Messages expire after `MESSAGE_TTL_DAYS`, and a burned
conversation must stay gone; restoring a full dump would bring both back. What is worth
keeping is the accounts, so that users keep their identities after a lost disk:

```bash
make backup-accounts
```

This writes `backups/accounts-<UTC time>.sql` (mode 0600, ignored by git) with two tables:
`users` (account lookups, Argon2id hashes, public keys, wrapped account keys, encrypted
conversation lists) and `key_checks` (the pepper commitment). Keep few, short-lived copies: a
restore also brings back every account deleted after the backup was taken.

### Restoring onto an empty instance

The tables must be restored **before the backend first starts**, so the backend checks the
restored pepper commitment instead of pinning a new one:

```bash
cp /safe/place/.env .env                     # the .env of the instance that wrote the backup
docker compose up -d postgres                # database only, no backend yet
docker compose exec -T postgres sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' < backups/accounts-<time>.sql
make up
```

Users log in with their account numbers as before. Their conversations are gone; the stale
entries in their encrypted conversation lists are dropped at their first listing.

---

## What happens when…

| Failure | What users see | What the system does | Your part |
|---|---|---|---|
| PostgreSQL stops or restarts | Login answers "service unavailable", never "invalid credentials". Sending says "message not sent". A registration in progress keeps its account number. | The backend keeps running and reconnects by itself; PostgreSQL restarts itself (`restart: unless-stopped`). | Usually nothing; `docker compose logs postgres`. |
| The host reboots | A short outage. | Every service comes back by itself. | Nothing. |
| The backend restarts or is upgraded | Live updates pause and reconnect (backoff up to 30 s, 8 tries; bringing the tab back to the foreground reconnects too). Sessions survive. | nginx reaches the recreated container at its fixed address (`BACKEND_IP`). In-memory state starts over: issued proofs of work, rate limits, and account numbers shown but not yet confirmed. | Nothing. A user who was between "copy" and "continue" is told the number expired and gets a new one. |
| An answer is lost while sending | The message arrives once. | The retry resends the same message id and ciphertext; the server refuses the duplicate id (409), which the client takes as delivered. | Nothing. |
| An answer is lost while creating an account | The account opens. | The retry finds the registration used up, logs in with the number on screen, and enters the app. | Nothing. |
| Argon2id saturated (login or signup flood) | "server busy". A registration in progress keeps its account number. | At most `ARGON2_MAX_CONCURRENT` hashes run at once; the rest wait up to 3 s, then get 503. | Tune the [Argon2id limits](configuration-and-tuning.md). |
| A transaction hangs on a lock | That request fails. | Sessions give up waiting for a lock after 5 s and drop a transaction left idle for 30 s, so a stuck request never holds the connection pool. | Nothing. |
| The disk fills up | Sending fails. | PostgreSQL refuses writes; retention keeps deleting expired ciphertext. | Free space; PostgreSQL recovers by itself. |
| `MAX_CONVERSATIONS_PER_USER` or `MESSAGE_TTL_DAYS` lowered | Nothing breaks. | Accounts above the new cap keep their conversations; stored messages are capped at the new retention. | Nothing. |
| The master key may have leaked | Nothing. | After rotation every record is re-wrapped under the new key in the background. | Follow the [rotation runbook](configuration-and-tuning.md#master-key-rotation-runbook), then remove the old key. |

---

### Next Steps:
- Every environment variable: [**Configuration & Tuning**](configuration-and-tuning.md).
- What a stolen database reveals: [**Threat Model**](../security/threat-model.md).
- Symptoms and fixes: [**Troubleshooting Guide**](../troubleshooting/troubleshooting-guide.md).
