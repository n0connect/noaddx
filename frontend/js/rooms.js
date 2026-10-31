// ========================================
// ROOMS (code-based group conversations)
// ========================================
// docs/architecture/rooms.md. The server stays an untrusted relay: the room id, member limit
// and expiry it reports are checked against the code in this account's vault, every card is
// opened with the code-derived key, and every message is authenticated per sender.

const Rooms = (() => {
    'use strict';

    const R = NoaddxRoomCrypto;
    const HOUR_MS = 3600000;
    const TTL_CHOICES = [1, 24, 168];
    const MAX_CREATE_ATTEMPTS = 3;  // a fresh secret per attempt; a collision is astronomically rare
    const MAX_NOTE_CHARS = 64;      // a note carries one invite code

    function isCount(value, max) {
        return Number.isSafeInteger(value) && value >= 0 && value <= max;
    }

    // ---------- adopting what the server lists ----------

    // Verifies a listed room against the code its vault holds and derives this account's key
    // in it. Throws on any mismatch: the caller hides the room.
    async function adopt(root, item) {
        const view = item.room;
        if (!view || typeof view.vault !== 'string' || !isCount(view.max_members, R.MAX_MEMBERS) ||
            !Number.isSafeInteger(view.expires_at) || typeof view.owner !== 'boolean' ||
            !isCount(view.members, R.MAX_MEMBERS) || !isCount(view.notes, R.MAX_MEMBERS) || item.peer_public_key !== '') {
            throw new Error('malformed room');
        }
        const code = await R.openVault(root, item.id, view.vault);
        if (code.maxMembers !== view.max_members || code.expiresHour * 3600 !== view.expires_at) {
            throw new Error('the server reports other limits than the code');
        }
        const keys = await R.deriveRoom(code.secret);
        return {
            vault: view.vault,
            code: code,
            keys: keys,
            member: await R.member(keys, root),
            maxMembers: code.maxMembers,
            expiresAt: code.expiresHour * HOUR_MS,
            owner: view.owner,
            members: view.members,
            notes: view.notes,
            roster: null,       // [{ card, publicKey, aura, mine, owner }], valid cards only
            rosterCards: null,  // every card as served (the digest covers them all)
            skipped: 0,         // cards that failed to open: counted, never wrapped for
            requested: new Set()
        };
    }

    // The listing's counters change; the code and keys never do
    function refreshView(room, item) {
        const view = item.room;
        if (!view || view.vault !== room.vault || typeof view.owner !== 'boolean' ||
            !isCount(view.members, R.MAX_MEMBERS) || !isCount(view.notes, R.MAX_MEMBERS)) {
            return false;
        }
        room.owner = view.owner;
        room.members = view.members;
        room.notes = view.notes;
        return true;
    }

    function expired(room) {
        return Date.now() >= room.expiresAt;
    }

    // ---------- roster ----------

    async function loadRoster(api, conv) {
        const room = conv.room;
        const result = await api('GET', `/conversations/${conv.id}/members`);
        if (!result.ok || !result.data || !Array.isArray(result.data.members) ||
            result.data.members.length === 0 || result.data.members.length > R.MAX_MEMBERS) {
            throw Object.assign(new Error('roster unavailable'), { status: result.status });
        }
        const cards = [];
        const roster = [];
        const seen = new Set();
        let skipped = 0;
        let storedCard = null;
        for (const entry of result.data.members) {
            if (!entry || typeof entry.card !== 'string' || typeof entry.mine !== 'boolean' || typeof entry.owner !== 'boolean') {
                throw new Error('malformed roster');
            }
            cards.push(entry.card);
            let publicKey;
            try {
                publicKey = NoaddxCrypto.b64urlEncode(await R.openCard(room.keys, entry.card));
            } catch (e) {
                skipped++;
                continue;
            }
            const mine = publicKey === room.member.publicKey;
            if (entry.mine && !mine) {
                throw new Error('the server misattributes a card');
            }
            if ((mine && !entry.mine) || seen.has(publicKey)) {
                // Someone else announcing a key already listed (or ours) adds nobody
                skipped++;
                continue;
            }
            seen.add(publicKey);
            if (mine) storedCard = entry.card;
            roster.push({ card: entry.card, publicKey: publicKey, aura: await NoaddxCrypto.aura(publicKey), mine: mine, owner: entry.owner });
        }
        // The vault says how many seats exist; a longer list is the server breaking the code's limit
        if (!seen.has(room.member.publicKey) || cards.length > room.maxMembers) {
            throw new Error('roster does not match this room');
        }
        // A card is sealed under a random nonce, so the one derived at login differs in bytes from
        // the one stored when this account joined. Others address notes to the stored one.
        room.member = Object.freeze({ privateKey: room.member.privateKey, publicKey: room.member.publicKey, card: storedCard });
        room.roster = roster;
        room.rosterCards = cards;
        room.skipped = skipped;
        room.members = cards.length;
        return roster;
    }

    function senderOf(room, publicKey) {
        return room.roster ? room.roster.find(entry => entry.publicKey === publicKey) : undefined;
    }

    // ---------- messages ----------

    async function seal(conv, id, text, counter) {
        const room = conv.room;
        const { recipients, digest } = await R.recipients(room.keys, room.member, room.rosterCards);
        if (recipients.length > room.maxMembers) {
            throw new Error('roster exceeds the room limit');
        }
        return R.sealMessage(room.keys, room.member, id, recipients, digest, text, Date.now(), counter);
    }

    function open(conv, raw) {
        return R.openMessage(conv.room.keys, conv.room.member, raw.id, raw.ciphertext);
    }

    // ---------- create & join ----------

    function ttlChoices(maxTTLHours) {
        return TTL_CHOICES.filter(hours => hours <= maxTTLHours);
    }

    // Draws a code, pays a proof of work and stores the room. Returns { id, code } or a
    // { status } the caller explains.
    async function create(api, root, maxMembers, ttlHours, solvePow) {
        for (let attempt = 0; attempt < MAX_CREATE_ATTEMPTS; attempt++) {
            const code = R.newRoomCode(maxMembers, R.expiryHourFor(ttlHours, Date.now()));
            const keys = await R.deriveRoom(code.secret);
            const member = await R.member(keys, root);
            const pow = await solvePow();
            if (!pow) return { status: 0 };
            const result = await api('POST', '/rooms', {
                id: keys.id,
                lookup: keys.lookup,
                max_members: code.maxMembers,
                expires_at: code.expiresHour * 3600,
                card: member.card,
                vault: await R.sealVault(root, keys.id, code),
                pow: pow
            });
            if (result.status === 409) continue;
            if (!result.ok || !result.data || !result.data.conversation || result.data.conversation.id !== keys.id) {
                return { status: result.status };
            }
            return { id: keys.id, code: R.buildRoomCode(code) };
        }
        return { status: 409 };
    }

    // Takes a seat. Returns { id, status }.
    async function join(api, root, code) {
        const keys = await R.deriveRoom(code.secret);
        const member = await R.member(keys, root);
        const result = await api('POST', '/rooms/join', {
            id: keys.id,
            lookup: keys.lookup,
            card: member.card,
            vault: await R.sealVault(root, keys.id, code)
        });
        const conv = result.data && result.data.conversation;
        if (result.ok && (!conv || conv.id !== keys.id)) {
            return { id: null, status: 0 };
        }
        return { id: result.ok ? keys.id : null, status: result.status };
    }

    function codeText(conv) {
        return R.buildRoomCode(conv.room.code);
    }

    // ---------- friend requests ----------

    async function befriend(api, conv, entry, inviteCode) {
        const id = NoaddxCrypto.newMessageId();
        const blob = await R.sealNote(conv.room.keys, conv.room.member, id, entry.card, inviteCode, Date.now());
        return api('POST', `/conversations/${conv.id}/notes`, { id: id, to: entry.card, blob: blob });
    }

    // Returns [{ id, from (roster entry or null), invite }] for the notes that open; the server
    // cannot make a note open, so anything else is dropped.
    async function notes(api, conv) {
        const result = await api('GET', `/conversations/${conv.id}/notes`);
        if (!result.ok || !result.data || !Array.isArray(result.data.notes)) {
            return [];
        }
        const opened = [];
        for (const raw of result.data.notes.slice(0, R.MAX_MEMBERS)) {
            if (!raw || !NoaddxCrypto.isUuidV4(raw.id) || typeof raw.blob !== 'string') continue;
            try {
                const note = await R.openNote(conv.room.keys, conv.room.member, raw.id, raw.blob);
                if (note.text.length > MAX_NOTE_CHARS) continue;
                opened.push({ id: raw.id, from: senderOf(conv.room, note.sender) || null, aura: await NoaddxCrypto.aura(note.sender), invite: note.text });
            } catch (e) {
                // Not for us, or tampered with
            }
        }
        return opened;
    }

    function dismissNote(api, conv, noteId) {
        return api('DELETE', `/conversations/${conv.id}/notes/${noteId}`);
    }

    function safetyNumber(conv) {
        return R.safetyNumber(conv.room.roster.map(entry => entry.publicKey));
    }

    return Object.freeze({
        adopt, refreshView, expired, loadRoster, senderOf, seal, open,
        ttlChoices, create, join, codeText, befriend, notes, dismissNote, safetyNumber,
        aura: (id) => R.roomAura(id)
    });
})();
