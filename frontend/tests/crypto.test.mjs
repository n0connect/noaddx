// Cross-implementation tests: frontend/js/crypto.js must match backend/internal/identity.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('../js/crypto.js', import.meta.url), 'utf8');
const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
const C = vm.runInContext(source + '\n;NoaddxCrypto', context);

// Same vector as backend/tests/identity/identity_test.go
const ACCOUNT = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const GO_AUTH_KEY = 'Thcc1tNIpP2ejPv8dErwLdXtO1dA_hkaGGbEO4LJanA'; // gitleaks:allow (public test-account vector)
const GO_PUBLIC_KEY = '5RnU1Lh-_CuOr8VzbLd0OGx4uFmd9YeLM2YysXB2Bx4';
const CONV = '3b241101-e2bb-4255-8caf-4136c566a962';
const B_ACCOUNT = 'HxwdHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA';
// Produced by backend/internal/e2e (Go, A → B); the browser implementation must open it.
const GO_VECTOR = {
    message: 'a3f1c2d4-5b6e-4f70-8a91-b2c3d4e5f607',
    ciphertext: 'RJahYupu3_vKSK6E3fDpsrnGDz-sqWvkBTSYcK7E5FYLBs6iNTerLyd9PxE60FSvW0_X9RCp0venX-t-g5Y8chK6NEYezAMXiF0WErcqVab5fYcuARkWgA9Uz348nEp7f-JmBpaPKQI_9GXk_hZaflCiXOOt5FjU6HYIDvBJKglf336vjcZ4KumSuc62G4v46Dxvq29HXaooXNtanRi5w_eTJRZK-5uZZPbkAQ1OlNgmgh4RAUK8DeAyhApLcu5_eNZrrep1kvjtmh2-g_dvU-vDcZ6Uqr0UfjE5UgLpvMLe4Y-Bho13lN_qzDonJ__cqKdVZUSjVkvaw4M3O8tKkjmHdbZ8kthEh0sitEly7kHUchrWUcO1TnjVniY',
    text: 'noaddx. interop ✓ <b>&',
    sentAt: 1729700000000,
    counter: 3
};

test('auth key matches Go derivation', async () => {
    assert.equal(await C.deriveAuthKey(ACCOUNT), GO_AUTH_KEY);
});

test('identity public key matches Go derivation; private key is not extractable', async () => {
    const id = await C.deriveIdentity(ACCOUNT);
    assert.equal(id.publicKey, GO_PUBLIC_KEY);
    assert.equal(id.privateKey.extractable, false);
});

test('strict base64url rejects malformed account numbers', async () => {
    for (const bad of ['', ACCOUNT.slice(1), ACCOUNT + 'A', ACCOUNT.slice(0, -1) + '+', ACCOUNT.slice(0, -1) + '9']) {
        await assert.rejects(C.deriveAuthKey(bad));
    }
});

async function peers() {
    const a = await C.deriveIdentity(ACCOUNT);
    const b = await C.deriveIdentity(B_ACCOUNT);
    const ab = await C.conversationKey(a.privateKey, b.publicKey, CONV);
    const ba = await C.conversationKey(b.privateKey, a.publicKey, CONV);
    return { a, b, ab, ba };
}

test('both peers derive the same conversation key and round-trip a message', async () => {
    const { a, ab, ba } = await peers();
    const msg = C.newMessageId();
    const ct = await C.encryptMessage(ab, CONV, msg, a.publicKey, 'merhaba 👋 <b>', 1729700000000, 7);
    const out = await C.decryptMessage(ba, CONV, msg, a.publicKey, ct);
    assert.deepEqual({ ...out }, { text: 'merhaba 👋 <b>', sentAt: 1729700000000, counter: 7 });
    // Length hiding: ciphertext size is a padded bucket, not the text length
    assert.equal(C.b64urlDecode(ct).length, 12 + 256 + 16);
});

// Payload = {"t":"<text>","ts":1,"n":1}: 21 bytes + text; the frame adds a 2-byte length.
test('ciphertext length is one of five power-of-two buckets', async () => {
    const { a, ab } = await peers();
    const frameFor = async (chars) => C.b64urlDecode(
        await C.encryptMessage(ab, CONV, C.newMessageId(), a.publicKey, 'x'.repeat(chars), 1, 1)).length - 12 - 16;
    assert.equal(await frameFor(1), 256);
    assert.equal(await frameFor(700), 1024);  // 723 framed bytes
    assert.equal(await frameFor(3000), 4096); // 3023 framed bytes
    await assert.rejects(C.encryptMessage(ab, CONV, C.newMessageId(), a.publicKey, 'x'.repeat(4074), 1, 1));
});

test('opens a message encrypted by the Go implementation (interop)', async () => {
    const { a, ba } = await peers();
    const out = await C.decryptMessage(ba, CONV, GO_VECTOR.message, a.publicKey, GO_VECTOR.ciphertext);
    assert.deepEqual({ ...out }, { text: GO_VECTOR.text, sentAt: GO_VECTOR.sentAt, counter: GO_VECTOR.counter });
});

test('AAD binding: wrong message id, sender, conversation, or tampered bytes fail', async () => {
    const { a, b, ab, ba } = await peers();
    const msg = C.newMessageId();
    const ct = await C.encryptMessage(ab, CONV, msg, a.publicKey, 'secret', 1, 1);
    await assert.rejects(C.decryptMessage(ba, CONV, C.newMessageId(), a.publicKey, ct));
    await assert.rejects(C.decryptMessage(ba, CONV, msg, b.publicKey, ct)); // reflected as if sent by b
    const otherConv = await C.conversationKey(b.privateKey, a.publicKey, 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee');
    await assert.rejects(C.decryptMessage(otherConv, CONV, msg, a.publicKey, ct));
    const raw = C.b64urlDecode(ct);
    raw[20] ^= 1;
    const tampered = Buffer.from(raw).toString('base64url');
    await assert.rejects(C.decryptMessage(ba, CONV, msg, a.publicKey, tampered));
});

test('invite code carries a fingerprint the redeemer can verify', async () => {
    const { a, b } = await peers();
    const token = 'AAAAAAAAAAAAAAAAAAAAAA';
    const code = await C.buildInviteCode(token, a.publicKey);
    assert.ok(code.startsWith('noaddx:'));
    const parsed = C.parseInviteCode(code);
    assert.equal(parsed.token, token);
    assert.equal(await C.fingerprintMatches(parsed, a.publicKey), true);
    assert.equal(await C.fingerprintMatches(parsed, b.publicKey), false);
    assert.throws(() => C.parseInviteCode(ACCOUNT)); // an account number is never an invite
    // Two invites from the same creator share no suffix (not linkable)
    const other = await C.buildInviteCode('AQEBAQEBAQEBAQEBAQEBAQ', a.publicKey);
    assert.notEqual(code.slice(-21), other.slice(-21));
});

test('safety number and aura are symmetric and deterministic', async () => {
    const { a, b } = await peers();
    assert.deepEqual([...await C.safetyNumber(a.publicKey, b.publicKey)], [...await C.safetyNumber(b.publicKey, a.publicKey)]);
    const aura1 = await C.aura(a.publicKey);
    const aura2 = await C.aura(a.publicKey);
    assert.equal(aura1.name, aura2.name);
    assert.match(aura1.name, /^[a-z]+-[a-z]+$/);
    assert.match(aura1.code, /^[0-9a-f]{4}$/);
    assert.equal(aura1.grid.length, 5);
});

test('payload limit is enforced before encryption', async () => {
    const { a, ab } = await peers();
    // 4094-byte payloads; payloadFits budgets 48 bytes of JSON for the longest ts and counter
    assert.equal(C.payloadFits('x'.repeat(4046)), true);
    assert.equal(C.payloadFits('x'.repeat(4047)), false);
    await assert.rejects(C.encryptMessage(ab, CONV, C.newMessageId(), a.publicKey, 'x'.repeat(7000), 1, 1));
    await assert.rejects(C.encryptMessage(ab, CONV, C.newMessageId(), a.publicKey, 'hi', 1, 0)); // counter must be >= 1
});
