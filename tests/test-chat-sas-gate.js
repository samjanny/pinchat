#!/usr/bin/env node

/** Regression tests for the 1:1 SAS application-data gate. */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadChatStore() {
    let alpineInit;
    let store;
    const windowObject = {
        location: {
            search: '?room=test-room',
            href: 'https://pinchat.io/static/chat.html?room=test-room#key',
            pathname: '/static/chat.html',
            hash: '#key',
            origin: 'https://pinchat.io'
        },
        addEventListener() {},
        alert() {},
        confirm: () => true,
        cryptoManager: null
    };
    const context = {
        window: windowObject,
        document: {
            addEventListener(name, callback) {
                if (name === 'alpine:init') alpineInit = callback;
            }
        },
        Alpine: {
            store(name, value) {
                if (name !== 'chatRoom') return undefined;
                if (arguments.length === 2) {
                    store = value;
                    // The suite exercises store methods directly; suppress the
                    // real network/bootstrap initialization triggered at the
                    // end of the alpine:init callback.
                    store.init = async () => {};
                }
                return store;
            }
        },
        URLSearchParams,
        URL,
        Blob,
        Uint8Array,
        Date,
        console,
        setTimeout,
        clearTimeout,
        setInterval,
        requestAnimationFrame: (callback) => callback(),
        generateNickname: () => ({ display: 'Test Peer' }),
        debugLog() {},
        sessionStorage: { getItem: () => null, setItem() {} },
        navigator: { clipboard: { writeText: async () => {} } }
    };
    vm.createContext(context);
    const source = fs.readFileSync(path.join(__dirname, '../static/js/app.js'), 'utf8');
    vm.runInContext(source, context, { filename: 'static/js/app.js' });
    assert(alpineInit, 'app.js did not register alpine:init');
    alpineInit();
    assert(store, 'app.js did not register the chatRoom store');
    return { store, windowObject };
}

async function run() {
    console.log('='.repeat(70));
    console.log('CHAT SAS GATE TEST SUITE');
    console.log('='.repeat(70));

    const { store, windowObject } = loadChatStore();
    const decrypted = [];
    let encrypted = 0;
    windowObject.cryptoManager = {
        async decryptMessage(payload) {
            decrypted.push(`message:${payload}`);
            return { text: payload, outOfOrder: false };
        },
        async decryptImage(payload) {
            decrypted.push(`image:${payload}`);
            return { data: new Uint8Array([1]), mimeType: 'image/png', outOfOrder: false };
        },
        async encryptMessage() {
            encrypted++;
            return { payload: 'encrypted', header: {} };
        },
        async encryptImage() {
            encrypted++;
            return { payload: 'encrypted-image', header: {} };
        }
    };

    Object.assign(store, {
        connected: true,
        participantCount: 2,
        roomType: 'onetoone',
        pfsActive: true,
        sasVerificationStatus: 'pending',
        messageInput: 'must not send',
        pendingImage: {
            previewUrl: 'blob:test',
            arrayBuffer: new Uint8Array([1]),
            mimeType: 'image/png'
        },
        wsManager: { send: () => true },
        scrollToBottom() {}
    });

    assert.strictEqual(store.isComposerLocked(), true, 'pending SAS must lock composer');
    await store.sendMessage();
    await store.sendImage();
    assert.strictEqual(encrypted, 0, 'programmatic sends must not bypass pending SAS');

    await store.handleIncomingMessage({ payload: 'one', sender_id: 'peer', timestamp: 1 });
    await store.handleIncomingImage({ payload: 'two', sender_id: 'peer', timestamp: 2 });
    assert.deepStrictEqual(decrypted, [], 'pending SAS must not decrypt application data');
    assert.strictEqual(store.pendingSecureMessages.length, 2, 'ciphertexts must be quarantined');

    await store.handleSasVerified();
    assert.deepStrictEqual(
        decrypted,
        ['message:one', 'image:two'],
        'verification must release ciphertexts in arrival order'
    );
    assert.strictEqual(store.pendingSecureMessages.length, 0, 'quarantine must drain');
    assert.strictEqual(store.isComposerLocked(), false, 'verified SAS must unlock composer');

    store.sasReverifyRequired = true;
    store.sasVerificationStatus = 'verified';
    assert.strictEqual(store.isComposerLocked(), true, 'identity change must re-lock composer');
    await store.handleIncomingMessage({ payload: 'three', sender_id: 'peer', timestamp: 3 });
    assert.strictEqual(decrypted.length, 2, 're-verification must restore inbound quarantine');

    const skippedCase = loadChatStore();
    const skippedDecryptions = [];
    skippedCase.windowObject.cryptoManager = {
        async decryptMessage(payload) {
            skippedDecryptions.push(payload);
            return { text: payload, outOfOrder: false };
        }
    };
    Object.assign(skippedCase.store, {
        connected: true,
        participantCount: 2,
        roomType: 'onetoone',
        pfsActive: true,
        sasVerificationStatus: 'pending',
        scrollToBottom() {}
    });
    await skippedCase.store.handleIncomingMessage({ payload: 'explicit-risk', sender_id: 'peer', timestamp: 4 });
    await skippedCase.store.handleSasSkipped();
    assert.strictEqual(skippedCase.store.sasVerificationStatus, 'skipped');
    assert.deepStrictEqual(skippedDecryptions, ['explicit-risk'], 'confirmed skip must release quarantine');
    assert.strictEqual(skippedCase.store.isComposerLocked(), false, 'confirmed skip must unlock composer');

    console.log('PASSED: send/receive are fail-closed until verify or explicit skip');
}

run().catch((error) => {
    console.error('FAILED:', error);
    process.exit(1);
});
