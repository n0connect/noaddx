// frontend/js/pow-worker.js loaded as a classic script whose global object is `self`,
// as in a dedicated worker. Its hand-written SHA-256 is checked against Node's.
// Run: node --test frontend/tests/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import vm from 'node:vm';

const context = vm.createContext({ TextEncoder });
context.self = context;
vm.runInContext(readFileSync(new URL('../js/pow-worker.js', import.meta.url), 'utf8'), context);
const fn = (name) => vm.runInContext(name, context);

test('worker SHA-256 equals the reference implementation', () => {
    const inputs = ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'x'.repeat(1000),
        'b1946ac92492d2347c6235b4d2611184' + '123456' + '0ffee0ffee0ffee0ffee0ffee0ffee0f'];
    for (const input of inputs) {
        assert.equal(fn('sha256')(input), createHash('sha256').update(input).digest('hex'), `input of length ${input.length}`);
    }
});

// The search must not give up before the expected work is done: at difficulty d the
// expected number of attempts is 2^d, so the budget stays well above it.
test('attempt budget scales with difficulty', () => {
    const budget = fn('attemptBudget');
    for (let d = 18; d <= 24; d++) {
        const attempts = budget(d);
        const failure = Math.exp(-attempts / 2 ** d); // P(no solution in `attempts` tries)
        assert.ok(failure < 1e-6, `difficulty ${d}: budget ${attempts} fails with p=${failure}`);
    }
});

test('only well-formed tasks are worked on', () => {
    const valid = fn('isValidTask');
    const hex = 'ab'.repeat(16);
    assert.equal(valid({ challenge: hex, salt: hex, difficulty: 20 }), true);
    for (const task of [
        { challenge: hex.toUpperCase(), salt: hex, difficulty: 20 },
        { challenge: hex.slice(2), salt: hex, difficulty: 20 },
        { challenge: hex, salt: hex + 'zz', difficulty: 20 },
        { challenge: hex, salt: hex, difficulty: 0 },
        { challenge: hex, salt: hex, difficulty: 33 },
        { challenge: hex, salt: hex, difficulty: 20.5 },
        { challenge: hex, salt: hex, difficulty: '20' },
        null,
    ]) {
        assert.equal(valid(task), false, JSON.stringify(task));
    }
});
