'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');
const { webcrypto } = require('crypto');

const ROOM_ID = '00000000-0000-4000-8000-000000000001';
const BOOTSTRAP = Buffer.alloc(32, 17).toString('base64url');

// Separate browser globals, real app/identity/ECDH/Double Ratchet code.
// Only DOM, storage, timers and the relay are replaced. Timers are retained
// but not run: a lost handshake must fail the assertions, not wait 30 seconds.
// `send(frame)` receives every frame the client hands to its WebSocket, with
// sender_id set as the relay would; the caller decides what is delivered.
function createChatClient(userId, send) {
    let init, store;
    const storage = new Map();
    const timers = new Map();
    let nextTimer = 0;
    const systemMessages = [];
    const dialogs = [];
    const context = {
        crypto: webcrypto, console, URL, URLSearchParams, TextEncoder, TextDecoder,
        Uint8Array, ArrayBuffer, DataView, BigUint64Array, Blob, atob, btoa,
        setTimeout(callback) { timers.set(++nextTimer, callback); return nextTimer; },
        clearTimeout(id) { timers.delete(id); },
        setInterval() {}, clearInterval() {}, requestAnimationFrame() {},
        debugLog() {}, debugWarn() {}, debugError: console.error,
        location: {
            search: `?room=${ROOM_ID}`, pathname: '/static/chat.html',
            hash: `#key=${BOOTSTRAP}`, origin: 'https://example.test',
        },
        history: { replaceState() {} },
        sessionStorage: {
            getItem: k => storage.get(k) || null,
            setItem: (k, v) => storage.set(k, v), removeItem: k => storage.delete(k),
        },
        navigator: {}, addEventListener() {},
        // Dialog answers are scripted per test: confirm() pops the next
        // queued answer and records the question.
        confirmAnswers: [],
        confirm(text) { dialogs.push(text); return context.confirmAnswers.length ? context.confirmAnswers.shift() : false; },
        alert(text) { dialogs.push(text); },
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
    for (const file of ['nicknames.js', 'crypto.js', 'identity.js', 'double-ratchet.js', 'ecdh.js', 'image-metadata.js', 'app.js']) {
        vm.runInContext(fs.readFileSync(path.join(__dirname, '../../static/js', file), 'utf8'), context, { filename: file });
    }
    init();
    Object.assign(store, {
        userId, roomType: 'onetoone', participantCount: 2, connected: true,
        wsManager: {
            send(message) { send({ ...message, sender_id: store.userId }); return true; },
            disconnect() {},
            disconnectWithError() {},
        },
        scrollToBottom() {},
    });
    const addSystemMessage = store.addSystemMessage.bind(store);
    store.addSystemMessage = (text) => { systemMessages.push(text); return addSystemMessage(text); };
    return {
        store, crypto: context.cryptoManager, timers, context, systemMessages, dialogs,
        async recv(message) { await store.handleWebSocketMessage(message); },
        async fireTimer(id) {
            const callback = timers.get(id);
            timers.delete(id);
            callback();
            // ECDHKeyExchange.startTimeout runs its callback on a promise it
            // does not return; give it real time to settle (WebCrypto work
            // included) before the caller asserts.
            await new Promise(r => setTimeout(r, 100));
        },
    };
}

async function createChatPair() {
    const roomId = ROOM_ID;
    const queue = [];
    const alice = createChatClient('11111111-1111-4111-8111-111111111111', m => queue.push(m));
    const bob = createChatClient('22222222-2222-4222-8222-222222222222', m => queue.push(m));
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

module.exports = { createChatPair, createChatClient, ROOM_ID };
