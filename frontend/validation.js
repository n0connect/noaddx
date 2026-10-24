// ========================================
// FRONTEND INPUT VALIDATION (UX Layer)
// ========================================
// Security Strategy: WHITELIST every structured token, OUTPUT-ENCODE free text.
// Message text is end-to-end encrypted and rendered with textContent only,
// so it may contain any Unicode except control characters.

const MAX_MESSAGE_CHARS = 2000;
const ACCOUNT_NUMBER_SHAPE = /^[A-Za-z0-9_-]{43}$/;
// Control characters other than \n and \t (C0, DEL, C1) plus bidi overrides
const FORBIDDEN_TEXT_CHARS = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‪-‮⁦-⁩]/;

/**
 * Validates a chat message before encryption
 * @param {string} input - Raw composer value
 * @returns {object} - {valid: boolean, sanitized: string, error: string}
 */
function validateMessageText(input) {
    if (typeof input !== 'string') {
        return { valid: false, sanitized: '', error: 'invalid input' };
    }

    const normalized = input.replace(/\r\n?/g, '\n').trim();

    if (normalized.length === 0) {
        return { valid: false, sanitized: '', error: 'message is empty' };
    }

    if ([...normalized].length > MAX_MESSAGE_CHARS) {
        return { valid: false, sanitized: '', error: `max ${MAX_MESSAGE_CHARS} characters` };
    }

    if (FORBIDDEN_TEXT_CHARS.test(normalized)) {
        return { valid: false, sanitized: '', error: 'message contains control characters' };
    }

    if (!NoaddxCrypto.payloadFits(normalized)) {
        return { valid: false, sanitized: '', error: 'message too long' };
    }

    return { valid: true, sanitized: normalized, error: '' };
}

// Every forbidden character, for replacement in text received from a peer
const FORBIDDEN_TEXT_CHARS_ALL = new RegExp(FORBIDDEN_TEXT_CHARS.source, 'gu');

/**
 * Neutralizes a decrypted peer message before display. The sender's client already refuses
 * these characters, but a modified client can encrypt them anyway: bidi overrides would
 * reorder what is shown (e.g. disguise a file name), so each becomes U+FFFD.
 * @param {string} text - Decrypted message text
 * @returns {string}
 */
function neutralizeReceivedText(text) {
    return String(text).replace(FORBIDDEN_TEXT_CHARS_ALL, '\uFFFD');
}

/**
 * True when a string has the exact shape of a secret AccountNumber.
 * Used to stop users from pasting their account number where an invite belongs.
 * @param {string} input
 * @returns {boolean}
 */
function looksLikeAccountNumber(input) {
    return typeof input === 'string' && ACCOUNT_NUMBER_SHAPE.test(input.trim());
}

/**
 * Validates an invite code (noaddx:<43 base64url chars>)
 * @param {string} input
 * @returns {object} - {valid: boolean, sanitized: object|null, error: string}
 */
function validateInviteCode(input) {
    const value = typeof input === 'string' ? input.trim() : '';

    if (value.length === 0) {
        return { valid: false, sanitized: null, error: 'paste an invite first' };
    }

    if (looksLikeAccountNumber(value)) {
        return { valid: false, sanitized: null, error: 'that looks like an account number — never share it. ask for an invite instead' };
    }

    try {
        return { valid: true, sanitized: NoaddxCrypto.parseInviteCode(value), error: '' };
    } catch (e) {
        return { valid: false, sanitized: null, error: 'invalid invite' };
    }
}

/**
 * Validates a conversation or message ID (canonical lowercase UUIDv4)
 * @param {any} id
 * @returns {boolean}
 */
function validateConversationId(id) {
    return NoaddxCrypto.isUuidV4(id);
}
