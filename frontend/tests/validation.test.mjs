// frontend/validation.js loaded exactly as the browser loads it (after js/crypto.js).
// Run: node --test frontend/tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const context = vm.createContext({ crypto: globalThis.crypto, TextEncoder, TextDecoder, atob, btoa });
for (const file of ['../js/crypto.js', '../validation.js']) {
    vm.runInContext(readFileSync(new URL(file, import.meta.url), 'utf8'), context);
}
const neutralize = (text) => vm.runInContext('neutralizeReceivedText', context)(text);

// The sender's client refuses these characters, but a modified client can still encrypt
// them: the receiver must not let bidi overrides reorder what it displays.
test('received text: bidi overrides and control characters become U+FFFD', () => {
    const cases = {
        'pay ‮txt.exe': 'pay �txt.exe',
        'a⁦b⁩c': 'a�b�c',
        'bell\u0007 nul\u0000': 'bell� nul�',
        'c1\u0085x\u009F': 'c1�x�',
    };
    for (const [input, want] of Object.entries(cases)) {
        assert.equal(neutralize(input), want);
    }
});

test('received text: newlines, tabs, emoji and right-to-left scripts are untouched', () => {
    for (const text of ['line one\nline two', 'col\tcol', 'merhaba 👋 <b>&', 'שלום עולם', 'مرحبا']) {
        assert.equal(neutralize(text), text);
    }
});
