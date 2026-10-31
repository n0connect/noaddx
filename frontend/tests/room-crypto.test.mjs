// Room protocol tests: frontend/js/room-crypto.js must match backend/internal/e2e/room.go.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
const C = vm.runInContext(read('../js/crypto.js') + '\n;NoaddxCrypto', context);
const R = vm.runInContext(read('../js/room-crypto.js') + '\n;NoaddxRoomCrypto', context);

const ACCOUNT_A = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const ACCOUNT_B = 'HxwdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
const ACCOUNT_C = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8';
const SENT_AT = 1729700000000;
const TEXT = 'oda ✓ <b>&';

// Produced by backend/internal/e2e/room.go (Go): the browser must open all of it.
const ROOM_VECTOR = {
    code: 'noaddx#QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8FAAdTAA',
    id: 'bcde36b2-87a3-43c6-8748-ee62ca2f2939',
    lookup: 'Twh6cxJTOdj3qtOn-Nt1_ADT-RWFAifUus6kjV14vd4',
    publicA: 'W8eS0mxpk64t2ikVSK_TjuuAtndUpH1_XgsDi0ObJm8',
    publicB: 'Rr1i9oWfcZMTHT3ZWyOfTo8I7bdpM2f2TPQD1r13qks',
    message: '5f0c2a1e-7b3d-4c8e-9a6f-1d2e3f4a5b6c',
    note: '8e7d6c5b-4a39-4281-9f0e-0d1c2b3a4958',
    text: 'noaddx. room interop ✓ <b>&',
    noteText: 'noaddx:invite-vector',
    sentAt: 1729700000000
};
const GO_ROOM = {
    cardA: 'vT0I1_0uzOzPNYtlD_Eg8UKrmCff8BbOlHRU3bFWmsG2vSH9T3Fmfg55K_Mr6PLqUQAhlWDn7vv4SeA7',
    cardB: '6pEtzi4iM6I3m2aiRu0WEiruSZw2rBmygTZCcSM0T2XCFC1iJiosqHWBUeY-NhPQGYYrk9jJZ-G43nYw',
    vaultA: 'Xo94LGioNej-0LVbQ9Yl3HHdFzgCBFtIeHTF5w1xUPs1lfW2sTQbQ2JKElu0_jekFZIrQqGkvQpsx6zisj7PHCw',
    digest: 'oxyHu8K8OmYvEfuTw-8MRgJkfHjxAKAAFi0Xej9x_W8',
    blob: 'TkFEUgG9PQjX_S7M7M81i2UP8SDxQquYJ9_wFs6UdFTdsVaawba9If1PcWZ-Dnkr8yvo8upRACGVYOfu-_hJ4DuGN2qGERB3CuGKIN9xLjvLsmZhhXok33jDooDK1vh7N89I19lR5fSomfGWuTkwgiP8lYyy3KzbJB1VE-sc-UyloxyHu8K8OmYvEfuTw-8MRgJkfHjxAKAAFi0Xej9x_W8CE_C9vgdLJRo4CJ4cgdVyhiFDVrFGCsOdOQJUCyUKS9-nIZJ4IaLYrAmvPN6whD0ymdVoqD0TQFLJukcfbKy6_QzhIYl-CKKypd-8KlzRrp2_V6A1OizNmnXgGeS9oZfAXX_XntJFaKHVTyeIdLf6geuQ6GcTqBWGgkLVXUJI_hYf5nr3xAPja8SKNl7zpfTuQ_igL66UmnW37DkP7TOVhaE5iQ7nkGF_ISev5gVkQhF_wWq3j6mKtK0Prducy-HWO6UsHZPBLHHReopvxtJQl8bJ_l8k1-JHLDPNBwOfvYHLC0RXkPpoDMUNuBGCZy70fR5OodrLzezUATG8LSyQm6ztL3uKTJFjOBHutmGABd_RcJXOpegZvRifLczhKm7sVbxJibZLTK_xIwPM2fOFVYbqEN7hVwXxE2v_n-uXH6m3nNmNrH8eg00X5Nkgw4TVdgJ40UzWkVLXaPp1cYZhG27_jvU-ATdlclZwa9rZynk',
    note: 'TkFETgG9PQjX_S7M7M81i2UP8SDxQquYJ9_wFs6UdFTdsVaawba9If1PcWZ-Dnkr8yvo8upRACGVYOfu-_hJ4DvbgkhLpNF0iJqDQoM8Q_RvlIFUwD7vRwPwKb_yCpjiKtv0DPJ0EmQNgSdRrDMnqOV0BtOnMxWB0XvquO04Nu5NugEcAUxFn7sXEcN1GzPPgtdquX5v23DQJ0JNBEHbP2EBmIQzJcylPc04u0rqDsE1u6zVliERH-9YwwrRMfgVarRxTIrLtEeCG8g-yEypKYRjh0O4BNQi95fYEAf51nBK4XJxWlspgXYqjTgNKq7FyUkXfbbrapaX-cdV987zwyFV1NACqV6Oo5HdGBdEFjpAQiVA2WnANEZ0f-Syi50hYIygAeWH8_V8CdSRDZ5GsVobfzarVOTK0zjUlha4L8DdM4Y2vRw2zxmRfksYbLeqSaYJSGs0MtDU-te4ALcuVepbvWY84FQlxhXWHO6s4_-CaceBkVvYYsF3RksK2q0pd5JyqnnZwja-74stdQtmgd1xH-WcxvzBmQ_CWlW3XYRsQGkZ0ix6cP8Wr3plq7TF5iYFsjPOfA1Xi22IpzGxSGA_mkte-IYzfIGrg_X-Mvwj05Dag72JdzgE-m9O56C45KM'
};

async function fixture(maxMembers = 4) {
    const code = R.newRoomCode(maxMembers, 500000);
    const room = await R.deriveRoom(code.secret);
    return { code, room };
}

async function joinAs(room, account) {
    const root = await R.deriveRoomsRoot(account);
    return { root, member: await R.member(room, root) };
}

function flip(blob, index) {
    const raw = C.b64urlDecode(blob);
    raw[index] ^= 1;
    return C.b64urlEncode(raw);
}

async function sealFor(room, from, roster, id, counter = 1) {
    const { recipients, digest } = await R.recipients(room, from.member, roster);
    return R.sealMessage(room, from.member, id, recipients, digest, TEXT, SENT_AT, counter);
}

test('room code round-trips and parses strictly', async () => {
    const { code } = await fixture(8);
    const text = R.buildRoomCode(code);
    assert.equal(text.length, R.CODE_PREFIX.length + 50);
    const parsed = R.parseRoomCode('  ' + text + '\n');
    assert.deepEqual([...parsed.secret], [...code.secret]);
    assert.equal(parsed.maxMembers, 8);
    assert.equal(parsed.expiresHour, 500000);
    const body = text.slice(R.CODE_PREFIX.length);
    const raw = C.b64urlDecode(body);
    const withByte = (index, value) => {
        const b = raw.slice();
        b[index] = value;
        return R.CODE_PREFIX + C.b64urlEncode(b);
    };
    for (const bad of ['noaddx:' + body, body, text.slice(0, -1), text + 'A', text.slice(0, -1) + '+',
        withByte(32, 1), withByte(32, 33), R.CODE_PREFIX + C.b64urlEncode(raw.slice(0, 33))]) {
        assert.throws(() => R.parseRoomCode(bad), `accepted ${bad}`);
    }
    const noExpiry = raw.slice();
    noExpiry.fill(0, 33);
    assert.throws(() => R.parseRoomCode(R.CODE_PREFIX + C.b64urlEncode(noExpiry)));
    assert.throws(() => R.newRoomCode(1, 1));
});

test('room id is a UUIDv4 derived from the secret, lookup is separate', async () => {
    const { code, room } = await fixture();
    assert.ok(C.isUuidV4(room.id));
    const again = await R.deriveRoom(code.secret);
    assert.equal(again.id, room.id);
    assert.equal(again.lookup, room.lookup);
    assert.equal(C.b64urlDecode(room.lookup).length, 32);
    assert.equal(room.cardKey.extractable, false);
    await assert.rejects(R.deriveRoom(code.secret.slice(0, 31)));
});

test('member keys differ per room and per account, root is not extractable', async () => {
    const one = await fixture();
    const two = await fixture();
    const a1 = await joinAs(one.room, ACCOUNT_A);
    const a2 = await joinAs(two.room, ACCOUNT_A);
    const b1 = await joinAs(one.room, ACCOUNT_B);
    assert.equal(a1.root.extractable, false);
    assert.equal(a1.member.privateKey.extractable, false);
    assert.notEqual(a1.member.publicKey, a2.member.publicKey);
    assert.notEqual(a1.member.publicKey, b1.member.publicKey);
    assert.notEqual(a1.member.publicKey, (await C.deriveIdentity(ACCOUNT_A)).publicKey);
    assert.equal((await joinAs(one.room, ACCOUNT_A)).member.publicKey, a1.member.publicKey);
});

test('cards open only in their room; vaults only for their account and room', async () => {
    const { code, room } = await fixture(6);
    const other = await fixture(6);
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    assert.equal(C.b64urlEncode(await R.openCard(room, a.member.card)), a.member.publicKey);
    await assert.rejects(R.openCard(other.room, a.member.card));
    await assert.rejects(R.openCard(room, flip(a.member.card, 30)));

    const vault = await R.sealVault(a.root, room.id, code);
    const opened = await R.openVault(a.root, room.id, vault);
    assert.deepEqual([...opened.secret], [...code.secret]);
    assert.equal(opened.maxMembers, 6);
    await assert.rejects(R.openVault(b.root, room.id, vault));
    await assert.rejects(R.openVault(a.root, other.room.id, vault));
    // Sealed under the wrong id: the secret inside derives another room
    await assert.rejects(R.openVault(a.root, other.room.id, await R.sealVault(a.root, other.room.id, code)));
});

test('roster digest ignores order, not membership', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const c = await joinAs(room, ACCOUNT_C);
    const d1 = await R.rosterDigest([a.member.card, b.member.card, c.member.card]);
    const d2 = await R.rosterDigest([c.member.card, a.member.card, b.member.card]);
    const d3 = await R.rosterDigest([a.member.card, b.member.card]);
    assert.deepEqual([...d1], [...d2]);
    assert.notDeepEqual([...d1], [...d3]);
    await assert.rejects(R.rosterDigest([]));
});

test('every recipient opens a room message and sees who sent it', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const c = await joinAs(room, ACCOUNT_C);
    const id = C.newMessageId();
    const blob = await sealFor(room, a, [a.member.card, b.member.card, c.member.card], id, 5);
    for (const p of [a, b, c]) {
        const msg = await R.openMessage(room, p.member, id, blob);
        assert.deepEqual({ text: msg.text, sentAt: msg.sentAt, counter: msg.counter, sender: msg.sender },
            { text: TEXT, sentAt: SENT_AT, counter: 5, sender: a.member.publicKey });
    }
});

test('a member outside the roster cannot open; a member cannot impersonate another', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const c = await joinAs(room, ACCOUNT_C);
    const id = C.newMessageId();
    const blob = await sealFor(room, a, [a.member.card, b.member.card], id);
    await assert.rejects(R.openMessage(room, c.member, id, blob));

    const forger = { privateKey: c.member.privateKey, publicKey: a.member.publicKey, card: a.member.card };
    const { recipients, digest } = await R.recipients(room, c.member, [a.member.card, b.member.card, c.member.card]);
    const forgedId = C.newMessageId();
    const forged = await R.sealMessage(room, forger, forgedId, recipients, digest, 'i am a', SENT_AT, 1);
    await assert.rejects(R.openMessage(room, b.member, forgedId, forged));
});

test('every binding of a room message is checked', async () => {
    const { room } = await fixture();
    const other = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const id = C.newMessageId();
    const blob = await sealFor(room, a, [a.member.card, b.member.card], id);
    const bodyStart = R.HEADER_BYTES + 2 * R.WRAP_BYTES;
    const bInOther = await joinAs(other.room, ACCOUNT_B);
    const cases = {
        'other id': () => R.openMessage(room, b.member, C.newMessageId(), blob),
        'other room': () => R.openMessage(other.room, bInOther.member, id, blob),
        card: () => R.openMessage(room, b.member, id, flip(blob, 20)),
        ephemeral: () => R.openMessage(room, b.member, id, flip(blob, 70)),
        commitment: () => R.openMessage(room, b.member, id, flip(blob, 100)),
        digest: () => R.openMessage(room, b.member, id, flip(blob, 140)),
        'every wrap': () => R.openMessage(room, b.member, id, flip(flip(blob, R.HEADER_BYTES + 1), R.HEADER_BYTES + R.WRAP_BYTES + 1)),
        body: () => R.openMessage(room, b.member, id, flip(blob, bodyStart + 3)),
        magic: () => R.openMessage(room, b.member, id, flip(blob, 0)),
        'wrap count': () => R.openMessage(room, b.member, id, flip(blob, R.HEADER_BYTES - 1)),
        truncated: () => R.openMessage(room, b.member, id, blob.slice(0, -4)),
        'as a note': () => R.openNote(room, b.member, id, blob)
    };
    for (const [name, open] of Object.entries(cases)) {
        await assert.rejects(open(), `${name} opened`);
    }
});

test('broken, low-order and duplicate cards get no wrap but count in the digest', async () => {
    const { room } = await fixture(8);
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const garbage = C.b64urlEncode(new Uint8Array(R.CARD_BYTES).fill(7));
    const lowOrder = await R.sealCard(room, new Uint8Array(32));
    const roster = [a.member.card, b.member.card, garbage, lowOrder, b.member.card];
    const { recipients, digest, skipped } = await R.recipients(room, a.member, roster);
    assert.equal(recipients.length, 2);
    assert.equal(skipped, 2);
    assert.deepEqual([...digest], [...(await R.rosterDigest(roster))]);
    await assert.rejects(R.recipients(room, a.member, [b.member.card]));
});

test('message size is header, wraps and one padded class', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const { recipients, digest } = await R.recipients(room, a.member, [a.member.card, b.member.card]);
    for (const [length, frame] of [[1, 256], [300, 512], [3000, 4096]]) {
        const blob = await R.sealMessage(room, a.member, C.newMessageId(), recipients, digest, 'x'.repeat(length), SENT_AT, 1);
        assert.equal(C.b64urlDecode(blob).length, R.HEADER_BYTES + 2 * R.WRAP_BYTES + frame + 16);
    }
});

test('a note opens only for its addressee', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const c = await joinAs(room, ACCOUNT_C);
    const id = C.newMessageId();
    const note = await R.sealNote(room, a.member, id, b.member.card, 'noaddx:invite', SENT_AT);
    const opened = await R.openNote(room, b.member, id, note);
    assert.equal(opened.text, 'noaddx:invite');
    assert.equal(opened.sender, a.member.publicKey);
    await assert.rejects(R.openNote(room, a.member, id, note));
    await assert.rejects(R.openNote(room, c.member, id, note));
    await assert.rejects(R.openMessage(room, b.member, id, note));
});

test('room safety number and aura are order-independent and deterministic', async () => {
    const { room } = await fixture();
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    const s1 = await R.safetyNumber([a.member.publicKey, b.member.publicKey]);
    const s2 = await R.safetyNumber([b.member.publicKey, a.member.publicKey]);
    assert.deepEqual(s1, s2);
    assert.equal(s1.length, 6);
    assert.deepEqual(await R.roomAura(room.id), await R.roomAura(room.id));
});

test('expiry hour gives at least the chosen lifetime and at most one hour more', () => {
    const now = Date.UTC(2026, 9, 31, 14, 20);
    const hour = R.expiryHourFor(24, now);
    const lifetime = hour * 3600000 - now;
    assert.ok(lifetime > 24 * 3600000 && lifetime <= 25 * 3600000, `lifetime ${lifetime}`);
});

test('room derivations match Go, and Go-sealed cards, vault, message and note open (interop)', async () => {
    const code = R.parseRoomCode(ROOM_VECTOR.code);
    assert.deepEqual([...code.secret], Array.from({ length: 32 }, (_, i) => 0x40 + i));
    assert.equal(R.buildRoomCode(code), ROOM_VECTOR.code);
    const room = await R.deriveRoom(code.secret);
    assert.equal(room.id, ROOM_VECTOR.id);
    assert.equal(room.lookup, ROOM_VECTOR.lookup);
    const a = await joinAs(room, ACCOUNT_A);
    const b = await joinAs(room, ACCOUNT_B);
    assert.equal(a.member.publicKey, ROOM_VECTOR.publicA);
    assert.equal(b.member.publicKey, ROOM_VECTOR.publicB);
    assert.equal(C.b64urlEncode(await R.openCard(room, GO_ROOM.cardA)), ROOM_VECTOR.publicA);
    assert.equal(C.b64urlEncode(await R.openCard(room, GO_ROOM.cardB)), ROOM_VECTOR.publicB);
    const vault = await R.openVault(a.root, room.id, GO_ROOM.vaultA);
    assert.equal(vault.maxMembers, 5);
    assert.equal(vault.expiresHour, 480000);
    assert.equal(C.b64urlEncode(await R.rosterDigest([GO_ROOM.cardA, GO_ROOM.cardB])), GO_ROOM.digest);
    for (const reader of [a, b]) {
        const msg = await R.openMessage(room, reader.member, ROOM_VECTOR.message, GO_ROOM.blob);
        assert.deepEqual({ text: msg.text, sentAt: msg.sentAt, counter: msg.counter, sender: msg.sender },
            { text: ROOM_VECTOR.text, sentAt: ROOM_VECTOR.sentAt, counter: 4, sender: ROOM_VECTOR.publicA });
    }
    // The note was sealed for B's Go card, whose bytes differ from the card B derives here
    const bWithGoCard = { privateKey: b.member.privateKey, publicKey: b.member.publicKey, card: GO_ROOM.cardB };
    const note = await R.openNote(room, bWithGoCard, ROOM_VECTOR.note, GO_ROOM.note);
    assert.equal(note.text, ROOM_VECTOR.noteText);
    assert.equal(note.sender, ROOM_VECTOR.publicA);
});
