// ========================================
// NOADDX CRYPTO (WebCrypto only — no third-party code)
// ========================================
// Mirrors backend/internal/identity byte-for-byte. Algorithms are restricted to
// RULES.md §1.4: X25519, HKDF-SHA-256, AES-256-GCM, SHA-256.
//
// AccountNumber ──HKDF "noaddx/auth"──────────────▶ auth key (sent at login)
//               └─HKDF "noaddx/identity/x25519"──▶ X25519 identity (never leaves the browser)
// identity × peer ──X25519──HKDF(conv id)────────▶ per-conversation AES-256-GCM key

const NoaddxCrypto = (() => {
    'use strict';

    const SALT = 'noaddx.v1';
    const INFO_AUTH = 'noaddx/auth';
    const INFO_IDENTITY = 'noaddx/identity/x25519';
    const INFO_CONVERSATION = 'noaddx/conv/v1';
    const INFO_AURA = 'noaddx/aura';
    const INFO_INVITE_FP = 'noaddx/invite-fp';
    const KEY_BYTES = 32;
    const NONCE_BYTES = 12;
    const TAG_BYTES = 16;
    const INVITE_TOKEN_BYTES = 16;
    const INVITE_FP_BYTES = 16;
    const INVITE_PREFIX = 'noaddx:';
    // Plaintext is framed as len(2) || json || zero padding to a multiple of PAD_BLOCK,
    // so ciphertext length only reveals a coarse size bucket.
    // json = {"t": text, "ts": sender clock (ms), "n": sender's per-conversation counter};
    // gaps in a peer's "n" reveal messages the server withheld or deleted.
    const PAD_BLOCK = 256;
    const MAX_PAYLOAD_BYTES = 6000;
    // RFC 8410 PrivateKeyInfo header for an X25519 key (OID 1.3.101.110)
    const PKCS8_X25519_PREFIX = new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
    ]);
    const AAD_MAGIC = [0x4e, 0x41, 0x44, 0x4d]; // "NADM"
    const AAD_VERSION = 0x01;
    const B64URL_RE = /^[A-Za-z0-9_-]+$/;
    const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

    const encoder = new TextEncoder();
    const decoder = new TextDecoder('utf-8', { fatal: true });
    const subtle = globalThis.crypto && globalThis.crypto.subtle;

    // ---------- encoding ----------

    function b64urlEncode(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // Strict decode: alphabet whitelist + exact length + canonical re-encoding
    function b64urlDecode(text, expectedBytes) {
        if (typeof text !== 'string' || text.length === 0 || !B64URL_RE.test(text)) {
            throw new Error('invalid encoding');
        }
        const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        if ((expectedBytes !== undefined && bytes.length !== expectedBytes) || b64urlEncode(bytes) !== text) {
            throw new Error('invalid encoding');
        }
        return bytes;
    }

    function uuidBytes(uuid) {
        if (!UUID_V4_RE.test(uuid)) {
            throw new Error('invalid id');
        }
        const hex = uuid.replace(/-/g, '');
        const out = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            out[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return out;
    }

    function concat(...parts) {
        const total = parts.reduce((n, p) => n + p.length, 0);
        const out = new Uint8Array(total);
        let offset = 0;
        for (const p of parts) {
            out.set(p, offset);
            offset += p.length;
        }
        return out;
    }

    function wipe(bytes) {
        if (bytes && bytes.fill) {
            bytes.fill(0);
        }
    }

    async function sha256(bytes) {
        return new Uint8Array(await subtle.digest('SHA-256', bytes));
    }

    async function hkdf(ikm, salt, info, length) {
        const base = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const bits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: encoder.encode(info) },
            base,
            length * 8
        );
        return new Uint8Array(bits);
    }

    // ---------- identity ----------

    function accountBytes(accountNumber) {
        return b64urlDecode(accountNumber, KEY_BYTES);
    }

    async function deriveAuthKey(accountNumber) {
        const raw = accountBytes(accountNumber);
        try {
            const key = await hkdf(raw, encoder.encode(SALT), INFO_AUTH, KEY_BYTES);
            const encoded = b64urlEncode(key);
            wipe(key);
            return encoded;
        } finally {
            wipe(raw);
        }
    }

    // Returns a NON-extractable private key plus the public key (base64url).
    async function deriveIdentity(accountNumber) {
        const raw = accountBytes(accountNumber);
        let seed = null;
        let pkcs8 = null;
        try {
            seed = await hkdf(raw, encoder.encode(SALT), INFO_IDENTITY, KEY_BYTES);
            pkcs8 = concat(PKCS8_X25519_PREFIX, seed);
            // Extractable only long enough to read the public coordinate (x)
            const temp = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, true, ['deriveBits']);
            const jwk = await subtle.exportKey('jwk', temp);
            const publicKey = jwk.x;
            jwk.d = '';
            b64urlDecode(publicKey, KEY_BYTES);
            const privateKey = await subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
            return { privateKey: privateKey, publicKey: publicKey };
        } finally {
            wipe(raw);
            wipe(seed);
            wipe(pkcs8);
        }
    }

    async function conversationKey(privateKey, peerPublicKey, conversationId) {
        const peer = await subtle.importKey('raw', b64urlDecode(peerPublicKey, KEY_BYTES), { name: 'X25519' }, false, []);
        const shared = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, privateKey, 256));
        try {
            const base = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
            return await subtle.deriveKey(
                { name: 'HKDF', hash: 'SHA-256', salt: uuidBytes(conversationId), info: encoder.encode(INFO_CONVERSATION) },
                base,
                { name: 'AES-GCM', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
        } finally {
            wipe(shared);
        }
    }

    // ---------- messages ----------

    // AAD = "NADM" || v1 || conversation(16) || message(16) || SHA-256(sender public key)(32)
    async function messageAAD(conversationId, messageId, senderPublicKey) {
        const senderTag = await sha256(b64urlDecode(senderPublicKey, KEY_BYTES));
        return concat(new Uint8Array(AAD_MAGIC), new Uint8Array([AAD_VERSION]),
            uuidBytes(conversationId), uuidBytes(messageId), senderTag);
    }

    function frame(payloadBytes) {
        if (payloadBytes.length === 0 || payloadBytes.length > MAX_PAYLOAD_BYTES) {
            throw new Error('message too long');
        }
        const size = Math.ceil((payloadBytes.length + 2) / PAD_BLOCK) * PAD_BLOCK;
        const out = new Uint8Array(size);
        out[0] = payloadBytes.length >> 8;
        out[1] = payloadBytes.length & 0xff;
        out.set(payloadBytes, 2);
        return out;
    }

    function unframe(framed) {
        if (framed.length < 2 || framed.length % PAD_BLOCK !== 0) {
            throw new Error('bad frame');
        }
        const length = (framed[0] << 8) | framed[1];
        if (length === 0 || length > MAX_PAYLOAD_BYTES || length + 2 > framed.length) {
            throw new Error('bad frame');
        }
        for (let i = length + 2; i < framed.length; i++) {
            if (framed[i] !== 0) {
                throw new Error('bad frame');
            }
        }
        return framed.subarray(2, 2 + length);
    }

    const MAX_COUNTER = Number.MAX_SAFE_INTEGER;

    function payloadBytes(text, sentAt, counter) {
        return encoder.encode(JSON.stringify({ t: text, ts: sentAt, n: counter }));
    }

    async function encryptMessage(key, conversationId, messageId, senderPublicKey, text, sentAt, counter) {
        if (!Number.isSafeInteger(counter) || counter < 1) {
            throw new Error('invalid counter');
        }
        const plain = frame(payloadBytes(text, sentAt, counter));
        const nonce = globalThis.crypto.getRandomValues(new Uint8Array(NONCE_BYTES));
        try {
            const aad = await messageAAD(conversationId, messageId, senderPublicKey);
            const sealed = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, plain));
            return b64urlEncode(concat(nonce, sealed));
        } finally {
            wipe(plain);
        }
    }

    // Throws on any tampering (wrong conversation, message id, sender, or modified bytes)
    async function decryptMessage(key, conversationId, messageId, senderPublicKey, ciphertext) {
        const data = b64urlDecode(ciphertext);
        if (data.length < NONCE_BYTES + TAG_BYTES + PAD_BLOCK) {
            throw new Error('ciphertext too short');
        }
        const aad = await messageAAD(conversationId, messageId, senderPublicKey);
        const plain = new Uint8Array(await subtle.decrypt(
            { name: 'AES-GCM', iv: data.subarray(0, NONCE_BYTES), additionalData: aad, tagLength: 128 },
            key,
            data.subarray(NONCE_BYTES)
        ));
        try {
            const parsed = JSON.parse(decoder.decode(unframe(plain)));
            const keys = Object.keys(parsed);
            if (keys.length !== 3 || typeof parsed.t !== 'string' || !Number.isSafeInteger(parsed.ts) || parsed.ts <= 0 ||
                !Number.isSafeInteger(parsed.n) || parsed.n < 1 || parsed.n > MAX_COUNTER) {
                throw new Error('bad payload');
            }
            return { text: parsed.t, sentAt: parsed.ts, counter: parsed.n };
        } finally {
            wipe(plain);
        }
    }

    function payloadFits(text) {
        return payloadBytes(text, Date.now(), MAX_COUNTER).length <= MAX_PAYLOAD_BYTES;
    }

    // ---------- pairing & verification ----------

    // Bound to the token so two invites from the same person share no bytes (unlinkable)
    async function inviteFingerprint(token, publicKey) {
        const digest = await sha256(concat(encoder.encode(INFO_INVITE_FP),
            b64urlDecode(token, INVITE_TOKEN_BYTES), b64urlDecode(publicKey, KEY_BYTES)));
        return digest.subarray(0, INVITE_FP_BYTES);
    }

    // Invite code = "noaddx:" + base64url(token(16) || SHA-256("noaddx/invite-fp" || token || creator key)[0:16]).
    // The fingerprint never goes to the server; it lets the redeemer detect key substitution.
    async function buildInviteCode(token, creatorPublicKey) {
        const fp = await inviteFingerprint(token, creatorPublicKey);
        return INVITE_PREFIX + b64urlEncode(concat(b64urlDecode(token, INVITE_TOKEN_BYTES), fp));
    }

    function parseInviteCode(code) {
        const trimmed = String(code || '').trim();
        if (!trimmed.startsWith(INVITE_PREFIX)) {
            throw new Error('not an invite');
        }
        const raw = b64urlDecode(trimmed.slice(INVITE_PREFIX.length), INVITE_TOKEN_BYTES + INVITE_FP_BYTES);
        return {
            token: b64urlEncode(raw.subarray(0, INVITE_TOKEN_BYTES)),
            fingerprint: raw.slice(INVITE_TOKEN_BYTES)
        };
    }

    async function fingerprintMatches(invite, publicKey) {
        const fingerprint = invite.fingerprint;
        const actual = await inviteFingerprint(invite.token, publicKey);
        let diff = actual.length ^ fingerprint.length;
        for (let i = 0; i < actual.length && i < fingerprint.length; i++) {
            diff |= actual[i] ^ fingerprint[i];
        }
        return diff === 0;
    }

    // Order-independent: both peers compute the same 30 digits
    async function safetyNumber(publicKeyA, publicKeyB) {
        const [first, second] = [publicKeyA, publicKeyB].sort();
        const digest = await sha256(concat(b64urlDecode(first, KEY_BYTES), b64urlDecode(second, KEY_BYTES)));
        const groups = [];
        for (let g = 0; g < 6; g++) {
            let value = 0;
            for (let i = 0; i < 5; i++) {
                value = value * 256 + digest[g * 5 + i];
            }
            groups.push(String(value % 100000).padStart(5, '0'));
        }
        return groups;
    }

    // ---------- aura (local, key-derived display identity) ----------

    const AURA_ADJECTIVES = [
        'silent', 'hollow', 'velvet', 'ashen', 'lunar', 'feral', 'gilded', 'frozen',
        'quiet', 'hidden', 'solar', 'obsidian', 'pale', 'wild', 'ivory', 'misty',
        'stark', 'radiant', 'sable', 'cinder', 'distant', 'faded', 'gentle', 'hushed',
        'iron', 'jade', 'kindred', 'lucid', 'mellow', 'nimble', 'opal', 'polar',
        'quartz', 'rusted', 'saffron', 'tidal', 'umbral', 'vivid', 'woven', 'zephyr',
        'amber', 'briar', 'cobalt', 'dusk', 'eerie', 'frost', 'ghost', 'hazel',
        'indigo', 'jasper', 'karst', 'lilac', 'marble', 'neon', 'onyx', 'prism',
        'quill', 'raven', 'slate', 'thorn', 'ultra', 'vesper', 'winter', 'xenon'
    ];
    const AURA_NOUNS = [
        'ember', 'fox', 'moth', 'wren', 'lynx', 'comet', 'echo', 'harbor',
        'iris', 'kite', 'lotus', 'mist', 'nova', 'orbit', 'pike', 'quasar',
        'reef', 'sage', 'tide', 'umbra', 'vale', 'willow', 'yarrow', 'zenith',
        'atlas', 'bloom', 'crane', 'delta', 'ether', 'fern', 'glade', 'heron',
        'isle', 'jackal', 'koi', 'lark', 'mesa', 'nomad', 'oak', 'petal',
        'quail', 'river', 'spire', 'thistle', 'urchin', 'viper', 'wolf', 'yew',
        'aspen', 'birch', 'cedar', 'dune', 'elk', 'flint', 'grove', 'hawk',
        'ibis', 'juniper', 'kestrel', 'lichen', 'marsh', 'newt', 'owl', 'pine'
    ];

    // { name: "silent-ember", code: "7f3a", grid: 5x5 booleans (mirrored) }
    async function aura(publicKey) {
        const digest = await sha256(concat(encoder.encode(INFO_AURA), b64urlDecode(publicKey, KEY_BYTES)));
        const grid = [];
        let bit = 0;
        for (let row = 0; row < 5; row++) {
            const cells = new Array(5);
            for (let col = 0; col < 3; col++) {
                const byte = digest[4 + (bit >> 3)];
                cells[col] = ((byte >> (bit & 7)) & 1) === 1;
                cells[4 - col] = cells[col];
                bit++;
            }
            grid.push(cells);
        }
        const code = Array.from(digest.subarray(2, 4), b => b.toString(16).padStart(2, '0')).join('');
        return {
            name: AURA_ADJECTIVES[digest[0] % 64] + '-' + AURA_NOUNS[digest[1] % 64],
            code: code,
            grid: grid
        };
    }

    // ---------- capability check ----------

    async function isSupported() {
        if (!subtle || !globalThis.crypto.randomUUID) {
            return false;
        }
        try {
            await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
            return true;
        } catch (e) {
            return false;
        }
    }

    function newMessageId() {
        return globalThis.crypto.randomUUID();
    }

    return Object.freeze({
        INVITE_PREFIX,
        b64urlDecode,
        deriveAuthKey,
        deriveIdentity,
        conversationKey,
        encryptMessage,
        decryptMessage,
        payloadFits,
        buildInviteCode,
        parseInviteCode,
        fingerprintMatches,
        safetyNumber,
        aura,
        isSupported,
        newMessageId,
        isUuidV4: (id) => typeof id === 'string' && UUID_V4_RE.test(id)
    });
})();
