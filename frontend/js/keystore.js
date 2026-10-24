// ========================================
// KEYSTORE (IndexedDB)
// ========================================
// Persists ONLY the non-extractable X25519 CryptoKey and its public key, so a reload
// does not require re-entering the account number. Raw key bytes cannot be read back
// out of a non-extractable CryptoKey, not even by script running on this page.
// The AccountNumber itself is never stored anywhere.
// It also remembers which conversations the user verified (safety number compared),
// bound to the peer key that was verified. None of this ever reaches the server.

const Keystore = (() => {
    'use strict';

    const DB_NAME = 'noaddress';
    const DB_VERSION = 2;
    const STORE = 'keys';
    const VERIFIED_STORE = 'verified';
    const RECORD = 'identity';

    function open() {
        return new Promise((resolve, reject) => {
            if (!window.indexedDB) {
                reject(new Error('indexeddb unavailable'));
                return;
            }
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                for (const name of [STORE, VERIFIED_STORE]) {
                    if (!db.objectStoreNames.contains(name)) {
                        db.createObjectStore(name);
                    }
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function transact(mode, action, storeName = STORE) {
        const db = await open();
        try {
            return await new Promise((resolve, reject) => {
                const tx = db.transaction(storeName, mode);
                const request = action(tx.objectStore(storeName));
                tx.oncomplete = () => resolve(request ? request.result : undefined);
                tx.onerror = () => reject(tx.error);
                tx.onabort = () => reject(tx.error);
            });
        } finally {
            db.close();
        }
    }

    async function save(identity) {
        try {
            await transact('readwrite', store => store.put({
                privateKey: identity.privateKey,
                publicKey: identity.publicKey
            }, RECORD));
            return true;
        } catch (e) {
            // Private windows may block IndexedDB: identity then lives in memory only
            console.warn('keystore: persistence unavailable');
            return false;
        }
    }

    async function load() {
        try {
            const record = await transact('readonly', store => store.get(RECORD));
            if (!record || !(record.privateKey instanceof CryptoKey) || record.privateKey.extractable ||
                typeof record.publicKey !== 'string') {
                return null;
            }
            return { privateKey: record.privateKey, publicKey: record.publicKey };
        } catch (e) {
            return null;
        }
    }

    // Verification is bound to the exact peer key that was compared
    async function setVerified(conversationId, peerPublicKey, verified) {
        try {
            await transact('readwrite', store => verified
                ? store.put(peerPublicKey, conversationId)
                : store.delete(conversationId), VERIFIED_STORE);
            return true;
        } catch (e) {
            return false;
        }
    }

    async function isVerified(conversationId, peerPublicKey) {
        try {
            return (await transact('readonly', store => store.get(conversationId), VERIFIED_STORE)) === peerPublicKey;
        } catch (e) {
            return false;
        }
    }

    function wipe() {
        return new Promise(resolve => {
            if (!window.indexedDB) {
                resolve();
                return;
            }
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = request.onerror = request.onblocked = () => resolve();
        });
    }

    return Object.freeze({ save, load, wipe, setVerified, isVerified });
})();
