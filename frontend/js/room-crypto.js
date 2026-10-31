// ========================================
// NOADDX ROOM CRYPTO (WebCrypto only — no third-party code)
// ========================================
// Mirrors backend/internal/e2e/room.go byte for byte (docs/architecture/rooms.md).
//
// room secret S ──HKDF──▶ room id (UUIDv4) · lookup (the only value the server sees) · card key
// account ──HKDF "noaddx/rooms"──▶ rooms root (non-extractable) ──▶ vault key · member key per room
// message = header || wraps || body; each member unwraps the message key with
//           X25519(eph, R) || X25519(sender, R), which also authenticates the sender

const NoaddxRoomCrypto = (() => {
    'use strict';

    const C = NoaddxCrypto;
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    const encoder = new TextEncoder();

    const CODE_PREFIX = 'noaddx#';
    const SECRET_BYTES = 32;
    const CODE_BYTES = SECRET_BYTES + 1 + 4;
    const MIN_MEMBERS = 2;
    const MAX_MEMBERS = 32;
    const KEY_BYTES = 32;
    const ID_BYTES = 16;
    const NONCE_BYTES = 12;
    const TAG_BYTES = 16;
    const CARD_BYTES = NONCE_BYTES + KEY_BYTES + TAG_BYTES;
    const VAULT_BYTES = NONCE_BYTES + CODE_BYTES + TAG_BYTES;
    const WRAP_BYTES = KEY_BYTES + TAG_BYTES;
    const HEADER_BYTES = 4 + 1 + CARD_BYTES + 3 * KEY_BYTES + 1;
    // Header: magic(4) version(1) card(60) ephemeral key(32) commitment(32) digest(32) n(1)
    const OFFSET_CARD = 5;
    const OFFSET_EPH = OFFSET_CARD + CARD_BYTES;
    const OFFSET_COMMIT = OFFSET_EPH + KEY_BYTES;
    const OFFSET_DIGEST = OFFSET_COMMIT + KEY_BYTES;
    const VERSION = 0x01;
    const PAD_BLOCK = 256;
    const MAX_FRAME_BYTES = 4096;
    const HOUR_MS = 3600000;
    // Bounds the rejection sampling of one shuffle index (RULES.md §8.1)
    const MAX_SHUFFLE_DRAWS = 64;

    const SALT = encoder.encode('noaddx.v1');
    const INFO_ID = encoder.encode('noaddx/room/id');
    const INFO_LOOKUP = encoder.encode('noaddx/room/lookup');
    const INFO_CARD = encoder.encode('noaddx/room/card');
    const INFO_ROOT = encoder.encode('noaddx/rooms');
    const INFO_VAULT = encoder.encode('noaddx/rooms/vault');
    const INFO_MEMBER = encoder.encode('noaddx/rooms/member/x25519');
    const INFO_WRAP = encoder.encode('noaddx/room/wrap/v1');
    const COMMIT_PREFIX = encoder.encode('noaddx/room/commit/v1');
    const ROSTER_PREFIX = encoder.encode('noaddx/room/roster/v1');
    const SAFETY_PREFIX = encoder.encode('noaddx/room/safety/v1');
    const AURA_PREFIX = encoder.encode('noaddx/room-aura');
    const MAGIC_MESSAGE = encoder.encode('NADR');
    const MAGIC_NOTE = encoder.encode('NADN');
    const MAGIC_CARD = encoder.encode('NADC');
    const MAGIC_VAULT = encoder.encode('NADV');
    const ZERO_NONCE = new Uint8Array(NONCE_BYTES);

    // ---------- helpers ----------

    // Realm-independent (a Uint8Array from another frame or a test context is still bytes)
    function isBytes(value, length) {
        return Object.prototype.toString.call(value) === '[object Uint8Array]' && value.length === length;
    }

    function bytesEqual(a, b) {
        let diff = a.length ^ b.length;
        for (let i = 0; i < a.length && i < b.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff === 0;
    }

    function compareBytes(a, b) {
        for (let i = 0; i < a.length && i < b.length; i++) {
            if (a[i] !== b[i]) return a[i] - b[i];
        }
        return a.length - b.length;
    }

    function uuidString(bytes) {
        const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
        return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    }

    async function hkdfBits(ikm, salt, info, length) {
        const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: salt, info: info }, base, length * 8));
    }

    function aesKey(raw, usages) {
        return subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
    }

    async function aesSeal(key, iv, data, aad) {
        return new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 }, key, data));
    }

    async function aesOpen(key, iv, data, aad) {
        return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: iv, additionalData: aad, tagLength: 128 }, key, data));
    }

    // X25519 with an all-zero result refused, as both server engines refuse it
    async function dh(privateKey, publicBytes) {
        const peer = await subtle.importKey('raw', publicBytes, { name: 'X25519' }, false, []);
        const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256));
        if (shared.every(b => b === 0)) {
            throw new Error('low-order key');
        }
        return shared;
    }

    function randomIndex(n) {
        const limit = 256 - 256 % n;
        for (let draw = 0; draw < MAX_SHUFFLE_DRAWS; draw++) {
            const b = globalThis.crypto.getRandomValues(new Uint8Array(1))[0];
            if (b < limit) return b % n;
        }
        throw new Error('shuffle draw bound reached');
    }

    // ---------- the code ----------

    function validCode(code) {
        return Boolean(code) && isBytes(code.secret, SECRET_BYTES) &&
            Number.isInteger(code.maxMembers) && code.maxMembers >= MIN_MEMBERS && code.maxMembers <= MAX_MEMBERS &&
            Number.isInteger(code.expiresHour) && code.expiresHour > 0 && code.expiresHour <= 0xffffffff;
    }

    function newRoomCode(maxMembers, expiresHour) {
        const code = { secret: globalThis.crypto.getRandomValues(new Uint8Array(SECRET_BYTES)), maxMembers, expiresHour };
        if (!validCode(code)) {
            throw new Error('invalid room limits');
        }
        return code;
    }

    function codeBytes(code) {
        const out = new Uint8Array(CODE_BYTES);
        out.set(code.secret, 0);
        out[SECRET_BYTES] = code.maxMembers;
        new DataView(out.buffer).setUint32(SECRET_BYTES + 1, code.expiresHour, false);
        return out;
    }

    function parseCodeBytes(raw) {
        if (raw.length !== CODE_BYTES) {
            throw new Error('invalid room code');
        }
        const code = {
            secret: raw.slice(0, SECRET_BYTES),
            maxMembers: raw[SECRET_BYTES],
            expiresHour: new DataView(raw.buffer, raw.byteOffset).getUint32(SECRET_BYTES + 1, false)
        };
        if (!validCode(code)) {
            throw new Error('invalid room code');
        }
        return code;
    }

    function buildRoomCode(code) {
        if (!validCode(code)) {
            throw new Error('invalid room code');
        }
        return CODE_PREFIX + C.b64urlEncode(codeBytes(code));
    }

    function parseRoomCode(text) {
        const trimmed = String(text || '').trim();
        if (!trimmed.startsWith(CODE_PREFIX)) {
            throw new Error('not a room code');
        }
        return parseCodeBytes(C.b64urlDecode(trimmed.slice(CODE_PREFIX.length), CODE_BYTES));
    }

    function expiryHourFor(ttlHours, nowMs) {
        return Math.floor(nowMs / HOUR_MS) + ttlHours + 1;
    }

    // ---------- the room ----------

    async function deriveRoom(secret) {
        if (!isBytes(secret, SECRET_BYTES)) {
            throw new Error('invalid room secret');
        }
        const idBytes = await hkdfBits(secret, SALT, INFO_ID, ID_BYTES);
        idBytes[6] = (idBytes[6] & 0x0f) | 0x40; // version 4
        idBytes[8] = (idBytes[8] & 0x3f) | 0x80; // RFC 4122 variant
        const lookup = await hkdfBits(secret, SALT, INFO_LOOKUP, KEY_BYTES);
        const cardRaw = await hkdfBits(secret, SALT, INFO_CARD, KEY_BYTES);
        try {
            return Object.freeze({
                id: uuidString(idBytes),
                idBytes: idBytes,
                lookup: C.b64urlEncode(lookup),
                cardKey: await aesKey(cardRaw, ['encrypt', 'decrypt'])
            });
        } finally {
            C.wipe(cardRaw);
        }
    }

    async function deriveRoomsRoot(accountNumber) {
        const raw = C.b64urlDecode(accountNumber, KEY_BYTES);
        let rootBytes = null;
        try {
            rootBytes = await hkdfBits(raw, SALT, INFO_ROOT, KEY_BYTES);
            return await subtle.importKey('raw', rootBytes, 'HKDF', false, ['deriveBits', 'deriveKey']);
        } finally {
            C.wipe(raw);
            C.wipe(rootBytes);
        }
    }

    function isRoomsRoot(key) {
        return typeof CryptoKey !== 'undefined' && key instanceof CryptoKey && !key.extractable &&
            key.algorithm.name === 'HKDF' && key.usages.includes('deriveBits') && key.usages.includes('deriveKey');
    }

    // This account's key in this room, and the card announcing it
    async function member(room, root) {
        const seed = new Uint8Array(await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: room.idBytes, info: INFO_MEMBER }, root, KEY_BYTES * 8));
        try {
            const key = await C.x25519FromSeed(seed);
            return Object.freeze({
                privateKey: key.privateKey,
                publicKey: key.publicKey,
                card: await sealCard(room, C.b64urlDecode(key.publicKey, KEY_BYTES))
            });
        } finally {
            C.wipe(seed);
        }
    }

    function cardAAD(room) {
        return C.concat(MAGIC_CARD, new Uint8Array([VERSION]), room.idBytes);
    }

    async function sealCard(room, publicBytes) {
        if (publicBytes.length !== KEY_BYTES) {
            throw new Error('invalid member key');
        }
        const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
        return C.b64urlEncode(C.concat(nonce, await aesSeal(room.cardKey, nonce, publicBytes, cardAAD(room))));
    }

    async function openCardBytes(room, raw) {
        const publicBytes = await aesOpen(room.cardKey, raw.subarray(0, NONCE_BYTES), raw.subarray(NONCE_BYTES), cardAAD(room));
        if (publicBytes.length !== KEY_BYTES) {
            throw new Error('bad card');
        }
        return publicBytes;
    }

    // Only a code holder can make a card the room's card key opens
    function openCard(room, card) {
        return openCardBytes(room, C.b64urlDecode(card, CARD_BYTES));
    }

    // ---------- the vault ----------

    function vaultKey(root) {
        return subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: SALT, info: INFO_VAULT }, root,
            { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    }

    function vaultAAD(roomId) {
        return C.concat(MAGIC_VAULT, new Uint8Array([VERSION]), C.uuidBytes(roomId));
    }

    async function sealVault(root, roomId, code) {
        if (!validCode(code)) {
            throw new Error('invalid room code');
        }
        const plain = codeBytes(code);
        try {
            const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
            return C.b64urlEncode(C.concat(nonce, await aesSeal(await vaultKey(root), nonce, plain, vaultAAD(roomId))));
        } finally {
            C.wipe(plain);
        }
    }

    // Recovers the code and checks that its secret derives roomId
    async function openVault(root, roomId, vault) {
        const raw = C.b64urlDecode(vault, VAULT_BYTES);
        const plain = await aesOpen(await vaultKey(root), raw.subarray(0, NONCE_BYTES), raw.subarray(NONCE_BYTES), vaultAAD(roomId));
        try {
            const code = parseCodeBytes(plain);
            if ((await deriveRoom(code.secret)).id !== roomId) {
                throw new Error('vault holds another room');
            }
            return code;
        } finally {
            C.wipe(plain);
        }
    }

    // ---------- the roster ----------

    async function rosterDigest(cards) {
        if (!Array.isArray(cards) || cards.length === 0 || cards.length > MAX_MEMBERS) {
            throw new Error('invalid roster');
        }
        const raws = cards.map(card => C.b64urlDecode(card, CARD_BYTES)).sort(compareBytes);
        return C.sha256(C.concat(ROSTER_PREFIX, ...raws));
    }

    // The member keys a message to this roster is wrapped for. A card that does not open or
    // carries a key X25519 refuses gets no wrap (`skipped`) but still counts in the digest.
    async function recipients(room, me, roster) {
        const digest = await rosterDigest(roster);
        const keys = [];
        const seen = new Set();
        let skipped = 0;
        for (const card of roster) {
            let publicBytes;
            try {
                publicBytes = await openCard(room, card);
                C.wipe(await dh(me.privateKey, publicBytes));
            } catch (e) {
                skipped++;
                continue;
            }
            const encoded = C.b64urlEncode(publicBytes);
            if (!seen.has(encoded)) {
                seen.add(encoded);
                keys.push(publicBytes);
            }
        }
        if (!seen.has(me.publicKey)) {
            throw new Error('you are not in this roster');
        }
        return { recipients: keys, digest: digest, skipped: skipped };
    }

    // ---------- messages and notes ----------

    function commitment(mk) {
        return C.sha256(C.concat(COMMIT_PREFIX, mk));
    }

    // One recipient's key-encryption key from dh1 || dh2, bound to everyone involved
    async function wrapKey(room, idBytes, dh1, dh2, ephPublic, senderPublic, recipientPublic) {
        const ikm = C.concat(dh1, dh2);
        try {
            const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveKey']);
            const info = C.concat(INFO_WRAP, room.idBytes, ephPublic, senderPublic, recipientPublic);
            return await subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: idBytes, info: info }, base,
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        } finally {
            C.wipe(ikm);
        }
    }

    // header || shuffled wraps || body. Every AES-GCM key seals exactly one plaintext (mk is
    // fresh, each KEK mixes a fresh ephemeral key and the message id), hence the zero nonces.
    async function assemble(room, me, magic, id, keys, digest, mk, commit, framed) {
        if (!C.isUuidV4(id) || !Array.isArray(keys) || keys.length === 0 || keys.length > MAX_MEMBERS ||
            digest.length !== KEY_BYTES || mk.length !== KEY_BYTES || commit.length !== KEY_BYTES) {
            throw new Error('invalid message');
        }
        const idBytes = C.uuidBytes(id);
        const senderPublic = C.b64urlDecode(me.publicKey, KEY_BYTES);
        const eph = await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
        const ephPublic = new Uint8Array(await subtle.exportKey('raw', eph.publicKey));
        const header = C.concat(magic, new Uint8Array([VERSION]), C.b64urlDecode(me.card, CARD_BYTES), ephPublic,
            commit, digest, new Uint8Array([keys.length]));
        const mkKey = await aesKey(mk, ['encrypt']);
        const body = await aesSeal(mkKey, ZERO_NONCE, framed, C.concat(room.idBytes, idBytes, header));
        const wrapAAD = await C.sha256(C.concat(room.idBytes, idBytes, header, body));
        const wraps = [];
        for (const recipient of keys) {
            const dh1 = await dh(eph.privateKey, recipient);
            const dh2 = await dh(me.privateKey, recipient);
            try {
                const kek = await wrapKey(room, idBytes, dh1, dh2, ephPublic, senderPublic, recipient);
                wraps.push(await aesSeal(kek, ZERO_NONCE, mk, wrapAAD));
            } finally {
                C.wipe(dh1);
                C.wipe(dh2);
            }
        }
        // No wrap says whom it is for, and neither does the order
        for (let i = wraps.length - 1; i > 0; i--) {
            const j = randomIndex(i + 1);
            [wraps[i], wraps[j]] = [wraps[j], wraps[i]];
        }
        return C.concat(header, ...wraps, body);
    }

    async function seal(room, me, magic, id, keys, digest, framed) {
        const mk = globalThis.crypto.getRandomValues(new Uint8Array(KEY_BYTES));
        try {
            return C.b64urlEncode(await assemble(room, me, magic, id, keys, digest, mk, await commitment(mk), framed));
        } finally {
            C.wipe(mk);
            C.wipe(framed);
        }
    }

    function sealMessage(room, me, id, keys, digest, text, sentAt, counter) {
        return seal(room, me, MAGIC_MESSAGE, id, keys, digest, C.encodePayload(text, sentAt, counter));
    }

    async function sealNote(room, me, id, toCard, text, sentAt) {
        const recipient = await openCard(room, toCard);
        const digest = await rosterDigest([toCard]);
        return seal(room, me, MAGIC_NOTE, id, [recipient], digest, C.encodePayload(text, sentAt, 1));
    }

    // Structure: magic, version, 1..32 wraps (exactly one in a note), one padded frame size
    function split(raw, magic) {
        if (raw.length < HEADER_BYTES || !bytesEqual(raw.subarray(0, magic.length), magic) || raw[magic.length] !== VERSION) {
            throw new Error('bad message');
        }
        const n = raw[HEADER_BYTES - 1];
        if (n < 1 || n > MAX_MEMBERS || (magic === MAGIC_NOTE && n !== 1)) {
            throw new Error('bad message');
        }
        const bodyStart = HEADER_BYTES + n * WRAP_BYTES;
        const frameLength = raw.length - bodyStart - TAG_BYTES;
        if (frameLength < PAD_BLOCK || frameLength > MAX_FRAME_BYTES || (frameLength & (frameLength - 1)) !== 0) {
            throw new Error('bad message');
        }
        const wraps = [];
        for (let i = 0; i < n; i++) {
            wraps.push(raw.subarray(HEADER_BYTES + i * WRAP_BYTES, HEADER_BYTES + (i + 1) * WRAP_BYTES));
        }
        return { header: raw.subarray(0, HEADER_BYTES), wraps: wraps, body: raw.subarray(bodyStart) };
    }

    // Throws unless every check passes: structure, card, both X25519, a wrap, commitment, body
    async function open(room, me, magic, id, blob) {
        if (!C.isUuidV4(id)) {
            throw new Error('bad message');
        }
        const idBytes = C.uuidBytes(id);
        const { header, wraps, body } = split(C.b64urlDecode(blob), magic);
        const sender = await openCardBytes(room, header.subarray(OFFSET_CARD, OFFSET_EPH));
        const ephPublic = header.slice(OFFSET_EPH, OFFSET_COMMIT);
        const dh1 = await dh(me.privateKey, ephPublic);
        const dh2 = await dh(me.privateKey, sender);
        let kek;
        try {
            kek = await wrapKey(room, idBytes, dh1, dh2, ephPublic, sender, C.b64urlDecode(me.publicKey, KEY_BYTES));
        } finally {
            C.wipe(dh1);
            C.wipe(dh2);
        }
        const wrapAAD = await C.sha256(C.concat(room.idBytes, idBytes, header, body));
        let mk = null;
        for (const wrap of wraps) {
            try {
                mk = await aesOpen(kek, ZERO_NONCE, wrap, wrapAAD);
                break;
            } catch (e) {
                // Someone else's wrap
            }
        }
        if (!mk || mk.length !== KEY_BYTES) {
            throw new Error('not encrypted for you');
        }
        let plain = null;
        try {
            if (!bytesEqual(await commitment(mk), header.subarray(OFFSET_COMMIT, OFFSET_DIGEST))) {
                throw new Error('bad commitment');
            }
            plain = await aesOpen(await aesKey(mk, ['decrypt']), ZERO_NONCE, body, C.concat(room.idBytes, idBytes, header));
            const payload = C.decodePayload(plain);
            return {
                text: payload.text,
                sentAt: payload.sentAt,
                counter: payload.counter,
                sender: C.b64urlEncode(sender),
                digest: header.slice(OFFSET_DIGEST, HEADER_BYTES - 1)
            };
        } finally {
            C.wipe(mk);
            C.wipe(plain);
        }
    }

    function openMessage(room, me, id, blob) {
        return open(room, me, MAGIC_MESSAGE, id, blob);
    }

    // A note must also have been addressed to me alone
    async function openNote(room, me, id, blob) {
        const note = await open(room, me, MAGIC_NOTE, id, blob);
        if (!bytesEqual(note.digest, await rosterDigest([me.card]))) {
            throw new Error('note addressed to someone else');
        }
        return note;
    }

    // ---------- display ----------

    // Members compare these digits on another channel: equal digits, equal member lists
    async function safetyNumber(publicKeys) {
        const raws = publicKeys.map(key => C.b64urlDecode(key, KEY_BYTES)).sort(compareBytes);
        return C.digitGroups(await C.sha256(C.concat(SAFETY_PREFIX, ...raws)));
    }

    async function roomAura(roomId) {
        return C.aura(C.b64urlEncode(await C.sha256(C.concat(AURA_PREFIX, C.uuidBytes(roomId)))));
    }

    return Object.freeze({
        CODE_PREFIX,
        CODE_CHARS: CODE_PREFIX.length + Math.ceil(CODE_BYTES * 4 / 3),
        MIN_MEMBERS,
        MAX_MEMBERS,
        CARD_BYTES,
        WRAP_BYTES,
        HEADER_BYTES,
        newRoomCode,
        buildRoomCode,
        parseRoomCode,
        expiryHourFor,
        deriveRoom,
        deriveRoomsRoot,
        isRoomsRoot,
        member,
        sealCard,
        openCard,
        sealVault,
        openVault,
        rosterDigest,
        recipients,
        sealMessage,
        sealNote,
        openMessage,
        openNote,
        safetyNumber,
        roomAura
    });
})();
