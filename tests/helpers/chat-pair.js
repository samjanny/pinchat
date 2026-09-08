'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
const { webcrypto } = require('crypto');

// Separate browser globals, real app/identity/ECDH/Double Ratchet code.
// Only DOM, storage, timers and the relay are replaced. Timers are retained
// but not run: a lost handshake must fail the assertions, not wait 30 seconds.
async function createChatPair() {
    const roomId = '00000000-0000-4000-8000-000000000001';
    const bootstrap = Buffer.alloc(32, 17).toString('base64url');
    const queue = [];
    function client(userId) {
        let init, store;
        const storage = new Map();
        const timers = new Map();
        let nextTimer = 0;
        const context = {
            crypto: webcrypto, console, URL, URLSearchParams, TextEncoder, TextDecoder,
            Uint8Array, ArrayBuffer, DataView, BigUint64Array, Blob, atob, btoa,
            setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
            clearTimeout(id) { timers.delete(id); },
            setInterval() {}, clearInterval() {}, requestAnimationFrame() {},
            debugLog() {}, debugWarn() {}, debugError: console.error,
            location: {
                search: `?room=${roomId}`, pathname: '/static/chat.html',
                hash: `#key=${bootstrap}`, origin: 'https://example.test',
            },
            history: { replaceState() {} },
            sessionStorage: {
                getItem: k => storage.get(k) || null,
                setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k),
            },
            navigator: {}, addEventListener() {},
            document: {
                addEventListener(name, callback) { if (name === 'alpine:init') init = callback; },
                querySelector: () => null,
            },
            Alpine: {
                store(name, value) {
                    if (value) { store = value; store.init = async () => {}; }
                    return store;
                },
            },
        };
        context.window = context;
        vm.createContext(context);
        for (const file of ['nicknames.js', 'crypto.js', 'identity.js', 'double-ratchet.js', 'ecdh.js', 'app.js']) {
            vm.runInContext(fs.readFileSync(path.join(__dirname, '../../static/js', file), 'utf8'), context, { filename: file });
        }
        init();
        Object.assign(store, {
            userId, roomType: 'onetoone', participantCount: 2, connected: true,
            wsManager: {
                send(message) { queue.push({ ...message, sender_id: store.userId }); return true; },
                disconnect() {},
            },
            scrollToBottom() {},
        });
        return { store, crypto: context.cryptoManager, timers };
    }

    const alice = client('11111111-1111-4111-8111-111111111111');
    const bob = client('22222222-2222-4222-8222-222222222222');
    async function deliver() {
        while (queue.length) {
            const message = queue.shift();
            const receiver = message.sender_id === alice.store.userId ? bob : alice;
            await receiver.store.handleWebSocketMessage(message);
        }
    }
    for (const c of [alice, bob]) await c.crypto.extractKeyFromURL();
    await Promise.all([alice.store.startECDHHandshake(), bob.store.startECDHHandshake()]);
    await deliver();
    assert(alice.store.pfsActive && bob.store.pfsActive, 'real initial handshake completes');
    assert.equal(alice.store.sas.hex, bob.store.sas.hex, 'both participants derive the same SAS');
    return { alice, bob, roomId, queue, deliver };
}

module.exports = { createChatPair };
