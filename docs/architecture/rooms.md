# Rooms: Code-Based Group Conversations

A **room** is a conversation for two or more people who do not need to know each other. Its creator picks how many people it holds and how long it lives; whoever has the **room code** can join until it is full, and nobody else can. Rooms sit next to the existing one-to-one conversations (pairing by single-use invite), and a member of a room can send another member a **friend request**: an invite delivered end-to-end inside the room, so the two can continue in a one-to-one conversation.

This document is the design of record: what is stored, what is computed where, and why.

---

## Goals

1. **Only code holders get in.** The code never reaches the server. The server stores a keyed hash of a value derived from it and cannot join, read, or forge anything a code holder can.
2. **Content stays end to end.** Every message is encrypted on the sender's device for exactly the members it saw. A member who joins later cannot read what was sent before; a member who left cannot read what is sent after.
3. **No member can impersonate another.** Each recipient authenticates the sender with a key only the sender and that recipient can compute.
4. **Nothing links a member across rooms.** In every room an account appears under a different key and a different storage pseudonym. Neither the server nor other members can tell that two rooms share a person.
5. **The creator's limits hold.** The member limit and the lifetime are carried in the code itself; clients check them against what the server reports and refuse a room that breaks them.
6. **Same engine, same rules.** The server adds no new primitive: rooms use X25519, HKDF-SHA256, AES-256-GCM and SHA-256 only (RULES.md §1.4). The browser and the Go client (`internal/e2e`) implement the protocol byte for byte, pinned by interop vectors.

Non-goals: moderation (kicking a member), editing a room's limits after creation, server-side search, and forward secrecy beyond what the one-to-one protocol offers (see *Limitations*).

---

## The Room Code

```text
code = "noaddx#" || base64url( S (32) || max_members (1) || expires_hour (4, big-endian) )
```

- `S` is 32 bytes from the creator's platform CSPRNG (`crypto.getRandomValues`). It is the room's only secret.
- `max_members` is 2 to 32. `expires_hour` is the room's deletion time in hours since the Unix epoch.
- The code is 57 characters. Anyone holding it holds everything needed to join, so it is handled like an invite: shown once on creation, copyable again from inside the room by its members.

### Values derived from S

All with HKDF-SHA256, salt `"noaddx.v1"`:

| Value | Info | Length | Where it goes |
|---|---|---|---|
| Room id | `noaddx/room/id` | 16 | Formatted as a UUIDv4 (version and variant bits set). Public routing id; the server cannot choose it. |
| Lookup `L` | `noaddx/room/lookup` | 32 | Sent to the server on create and join. The server stores only `HMAC(pepper subkey "noaddx/room-lookup", L)`. |
| Card key `K_card` | `noaddx/room/card` | 32 | Never leaves members' devices. Seals member cards. |

Because the room id is derived from `S`, a client always recomputes it and refuses a server that presents a room under another id.

---

## Per-Account Room Keys

At login the browser derives, from the AccountNumber, a non-extractable HKDF key:

```text
rooms_root = HKDF(AccountNumber, salt "noaddx.v1", info "noaddx/rooms", 32)
```

It is stored in IndexedDB beside the identity key and, like it, cannot be exported by script. From it:

| Value | Salt | Info | Use |
|---|---|---|---|
| Vault key | `"noaddx.v1"` | `noaddx/rooms/vault` | AES-256-GCM key that seals each room's code for this account |
| Member key | room id (16 bytes) | `noaddx/rooms/member/x25519` | X25519 private key this account uses in that room only |

The member key differs per room and cannot be linked to the account's identity key or to its key in any other room without the AccountNumber. It is deterministic, so every device that logs in to the account recovers the same key for the same room.

A browser that kept a session from before rooms existed has no rooms root in its keystore; it asks for the account number once more and derives it.

### Card

A member's card announces their member public key to the room and proves they hold the code:

```text
card = nonce (12) || AES-256-GCM(K_card, nonce, member_public_key (32), AAD = "NADC" || 0x01 || room_id (16))   // 60 bytes
```

The server cannot open or forge a card. It stores each member's card and serves the roster as the list of cards, sorted by their bytes (no join order). Cards are sealed under a random nonce, so the card a device derives at login differs in bytes from the one stored when the account joined; clients use the stored one, because others address notes to it.

### Vault

So that the room survives logout and works on every device, each membership stores the code, sealed for its own account:

```text
vault = nonce (12) || AES-256-GCM(vault_key, nonce, S || max_members || expires_hour (37), AAD = "NADV" || 0x01 || room_id (16))   // 65 bytes
```

On login the client opens the vault, recomputes the room id from `S` and compares it, and compares `max_members` and `expires_hour` with what the server reports. Any mismatch hides the room.

---

## Room Messages

Each message has its own random 32-byte message key `mk`, encrypted once for every member the sender sees (including the sender, so its other devices can read it). There is no shared group key to rotate, so membership changes need no coordination: who can read a message is fixed by who was in the roster when it was sent.

### Wire format (`NADR` v1)

```text
offset  size    field
0       4       "NADR"
4       1       version 0x01
5       60      sender card
65      32      ephemeral X25519 public key (fresh per message)
97      32      commitment = SHA-256("noaddx/room/commit/v1" || mk)
129     32      roster digest (below)
161     1       n = number of wraps, 1..32
162     48·n    wraps, in random order
162+48n F+16    body = AES-256-GCM(mk, nonce 0^12, frame(payload), AAD = room_id || message_id || bytes[0:162])
```

`F` is the padded frame: 256, 512, 1024, 2048 or 4096 bytes, exactly as in one-to-one messages. The payload is the same `{"t": text, "ts": sender clock, "n": sender's counter in this room}`.

### Wraps

For each recipient `r` with member public key `R`, sender member key `a` (public `A`) and ephemeral key `e` (public `E`):

```text
ikm   = X25519(e, R) || X25519(a, R)
KEK_r = HKDF(ikm, salt = message_id (16), info = "noaddx/room/wrap/v1" || room_id || E || A || R, 32)
wrap  = AES-256-GCM(KEK_r, nonce 0^12, mk, AAD = SHA-256(room_id || message_id || bytes[0:162] || body))   // 48 bytes
```

The recipient computes the same `ikm` as `X25519(r, E) || X25519(r, A)` and tries its key on every wrap (there are at most 32, and no wrap says whom it is for).

Why each piece is there:

- **`X25519(a, R)` authenticates the sender.** Only the sender and this recipient can compute it, so another member who learned `mk` cannot build a wrap that opens for this recipient. It also makes messages deniable: a recipient cannot prove to anyone else who wrote them, because the recipient could have computed that value too.
- **`X25519(e, R)` with a fresh `e`** keeps a later leak of the sender's member key from opening messages the sender wrote.
- **The wrap's AAD hashes the whole header and body**, so a member who holds `mk` cannot keep a genuine wrap and swap the body underneath it.
- **The commitment** stops a malicious sender from building a body that decrypts to different texts under different keys (AES-GCM is not key-committing): every recipient checks that the `mk` it unwrapped matches the one the header commits to.
- **Nonces are zero** because every AES-GCM key here encrypts exactly one plaintext: `mk` is fresh per message and each `KEK_r` mixes a fresh ephemeral key and the unique message id.
- **The card in every message** lets members verify messages from people who have since left: the sender's key comes from a card only a code holder could make.

### Roster digest

```text
digest = SHA-256("noaddx/room/roster/v1" || card_1 || ... || card_k)    // cards sorted by their raw bytes
```

It covers the roster as the server served it to the sender. The server recomputes it over the room's current members when the message arrives and refuses the message with `412` if a member joined or left in between. The sender then fetches the roster again and re-encrypts, so no message is ever encrypted for a stale member list. Cards that fail to open or carry an invalid key count in the digest but get no wrap, so a code holder who joins with a broken card cannot stop the room from working.

### Receiving

A client accepts a message only if every check passes, in this order: the size is one of the allowed classes and `n` is in range; the card opens under `K_card`; both X25519 computations succeed; one wrap opens; the commitment matches; the body opens and its payload has exactly the three fields. Anything else is shown as *unreadable*. Gaps in a sender's counter are flagged per sender, as in one-to-one conversations.

---

## Server Behaviour

### Storage

| Table | Columns | A database thief learns |
|---|---|---|
| `rooms` | `id`, `lookup` (HMAC), `max_members`, `expires_at` (hour), `owner_tag` | That a room exists, its limit and its deletion hour. Not the code, not who is in it. |
| `conversation_members` | as today, plus `card`, `vault`, `joined_seq` | Per-room pseudonyms, client-sealed cards and vaults, and from which message each member can read. |
| `messages` | as today | Ciphertext; `n` reveals how many members a message was sent to. |
| `room_notes` | `id`, `conversation_id`, `recipient_tag`, `sender_tag`, `blob`, `expires_at` | That one member sent another a sealed note in that room. |

`owner_tag` is the creator's member pseudonym in that room, so it joins nothing outside it.

### Operations

| Operation | Rule |
|---|---|
| Create | Costs a proof of work (as invites do). The client sends the derived id, `L`, the limit, the hour-aligned expiry (1 hour to `ROOM_MAX_TTL_HOURS` ahead), its card and its vault. |
| Join | The room must exist, be unexpired, have a free seat, and `HMAC(L)` must match in constant time; otherwise `404`, without saying which. A full room answers `409`. Joining again with the same account refreshes the vault and is harmless. The member can read messages sent after it joined (`joined_seq`); leaving and joining again starts from the new join. |
| Send | As in one-to-one conversations, plus the structure check and the roster digest check (`412`). |
| Leave | Any member except the owner leaves: their membership goes, their messages stay readable to the others. |
| Burn | The owner burns the room for everyone, as in one-to-one conversations. |
| Expire | At `expires_at` the room stops answering at once; the retention task deletes it and everything in it within five minutes. |
| Delete account | Rooms the account owns are burned, rooms it joined are left. |

Lock order (LOCK_HIERARCHY.md): `invites` → `users` → `rooms` → `conversations`. Join, leave and send all take the conversation row lock, so a message is always checked against the roster it is stored under.

---

## Friend Requests

A member can ask another member of the same room to become friends without revealing anything until the other side accepts:

1. The requester creates an ordinary single-use invite (a proof of work, counted against `MAX_ACTIVE_INVITES`). Its code carries the fingerprint of the requester's account key.
2. The invite code travels as a **note**: the room message format with magic `NADN`, exactly one wrap (for the addressee), and a roster digest over the addressee's card only. The server delivers it to the member whose card it names and to nobody else, at most one pending note per pair, until the invite expires.
3. The addressee sees *"silent-ember wants to be friends"*. Accepting redeems the invite and checks the fingerprint; ignoring deletes the note.

Because the invite code arrives authenticated by the requester's room key, the server cannot substitute the requester's account key in the new one-to-one conversation. Accounts are revealed to each other only when the addressee accepts.

---

## Limitations

- **The code is the trust anchor.** Anyone who obtains the code can join while a seat is free and read what is sent from then on. Members see every join in the member list and can compare the room's safety number on another channel; that comparison also exposes a malicious server that shows different members different rosters, which only matters if the server also holds the code.
- **No forward secrecy at rest.** As with one-to-one conversations, whoever later obtains a member's AccountNumber can open the messages still stored for that member (until the room expires or `MESSAGE_TTL_DAYS` passes). The fresh ephemeral key protects a sender only against the leak of their room key, not of the recipient's.
- **Metadata the server sees.** Member count, join and leave times, message sizes and timing, and who sent each message (as a per-room pseudonym). Over the onion service the server does not see addresses.
- **Lifetime is enforced by the server.** A compromised server can keep data past expiry; honest clients stop using a room at the hour its code names.
