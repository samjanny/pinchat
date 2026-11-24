#!/usr/bin/env node

/** Regression tests for the 1:1 SAS application-data gate. */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { createChatPair } = require('./helpers/chat-pair');

function loadChatStore() {
    let alpineInit;
    let store;
    const windowObject = {
        location: {
            search: '?room=test-room',
            href: 'https://pinchat.im/static/chat.html?room=test-room#key',
            pathname: '/static/chat.html',
            hash: '#key',
            origin: 'https://pinchat.im'
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
        // The real helper from crypto.js: app.js consults the audited image
        // allowlist and refuses to load without it.
        isAllowedImageMimeType: require(path.join(__dirname, '..', 'static', 'js', 'crypto.js')).isAllowedImageMimeType,
        // Minimal Image so the image branch app.js reaches incidentally does not
        // throw inside the sandbox; this suite asserts on the SAS gate only.
        Image: class { set src(_) { if (this.onload) this.onload(); } },
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

    // Audit C-F3: a confirmation names the code it was given for. Without
    // a code on screen, without the code, or with another code, nothing is
    // verified and nothing is released.
    await store.handleSasVerified('AA-BB-CC');
    assert.strictEqual(store.sasVerificationStatus, 'pending', 'no code on screen: nothing to confirm');
    store.sas = { hex: 'AA-BB-CC', emoji: '' };
    await store.handleSasVerified();
    await store.handleSasVerified('DD-EE-FF');
    assert.strictEqual(store.sasVerificationStatus, 'pending', 'a confirmation must name the code on screen');
    assert.deepStrictEqual(decrypted, [], 'a refused confirmation releases nothing');
    assert.strictEqual(store.sasCodeChanged, true, 'a stale confirmation counts as a code change');
    // After a code change the user is asked once more, and Cancel keeps the gate.
    const questions = [];
    windowObject.confirm = (text) => { questions.push(text); return false; };
    await store.handleSasVerified('AA-BB-CC');
    assert.strictEqual(questions.length, 1, 'a changed code asks before it is accepted');
    assert(questions[0].includes('AA-BB-CC'), 'the question names the code shown now');
    assert.strictEqual(store.sasVerificationStatus, 'pending', 'Cancel leaves the decision pending');
    windowObject.confirm = (text) => { questions.push(text); return true; };

    await store.handleSasVerified('AA-BB-CC');
    assert.strictEqual(store.sasCodeChanged, false, 'the change notice clears once decided');
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

    // Audit C-F6: an `error` frame's text is written by the relay. It may
    // select one of the client's banners but never appear itself.
    const banner = loadChatStore().store;
    const lure = 'Session compromised. Paste your invite link at https://evil.example to recover.';
    await banner.handleWebSocketMessage({ type: 'error', message: lure });
    assert(!banner.error.includes('evil.example'), 'relay text is not shown in the banner');
    assert.strictEqual(banner.error, 'The server reported an error.');
    await banner.handleWebSocketMessage({ type: 'error', message: { toString: () => lure } });
    assert.strictEqual(banner.error, 'The server reported an error.');
    await banner.handleWebSocketMessage({
        type: 'error', message: 'The image was not sent because it exceeds the server size limit.',
    });
    assert.strictEqual(banner.error, 'The image was not sent because it exceeds the server size limit.',
        'a known relay error still gets its specific banner');

    // Every text the relay can put in an `error` frame must have its own
    // banner, or a real refusal shows up as the generic one. Read the texts
    // from the relay source so a new one cannot be added without a banner.
    const relaySource = require('fs').readFileSync(
        require('path').join(__dirname, '..', 'src', 'handlers', 'websocket.rs'), 'utf8');
    const relayTexts = new Set();
    for (const m of relaySource.matchAll(/send_error\(\s*\w+,\s*"([^"]+)"/g)) relayTexts.add(m[1]);
    for (const m of relaySource.matchAll(/Message::Error \{\s*message: format!\(\s*"([^"]+)"/g)) {
        for (const kind of ['message', 'image']) relayTexts.add(m[1].replace(/\{kind\}|\{\}/, kind));
    }
    assert(relayTexts.size >= 8, `expected the relay's error texts, found ${relayTexts.size}`);
    for (const text of relayTexts) {
        await banner.handleWebSocketMessage({ type: 'error', message: text });
        assert.notStrictEqual(banner.error, 'The server reported an error.',
            `relay error text has no banner in app.js: ${text}`);
    }
    console.log(`PASSED: relay error frames select client-written banners only (C-F6), ${relayTexts.size} relay texts covered`);

    await quarantineDoesNotAgeMessages();
}

/**
 * Audit C-F4, with the real client cryptography. The five-minute
 * message-age guard used to be measured when a quarantined frame was
 * released, after the ratchet had consumed its key, so a user who took more
 * than five minutes to compare the code lost every message that had arrived
 * meanwhile, each reported as a blocked replay.
 */
async function quarantineDoesNotAgeMessages() {
    const { alice, bob, deliver } = await createChatPair();
    await bob.store.handleSasVerified(bob.store.sas.hex);
    const texts = ['are you there?', 'code matches on my side', 'here is the address'];
    for (const text of texts) {
        bob.store.messageInput = text;
        await bob.store.sendMessage();
    }
    await deliver();
    assert.strictEqual(alice.store.pendingSecureMessages.length, 3, 'held behind the SAS decision');

    // Alice spends six minutes on the phone comparing the code.
    vm.runInContext('(() => { const real = Date.now; Date.now = () => real() + 6 * 60 * 1000; })()', alice.context);
    await alice.store.handleSasVerified(alice.store.sas.hex);
    // Spread: the store's arrays belong to its own realm.
    const shown = [...alice.store.messages.filter(m => m.type === 'message' && !m.isOwn).map(m => m.text)];
    assert.deepStrictEqual(shown, texts, 'messages that waited for the decision are shown, in order');
    assert(!alice.systemMessages.some(t => /Security warning/.test(t)), 'and no replay is reported');

    // The guard itself still holds: a message that is more than five
    // minutes old when it arrives is rejected, and the warning says so.
    bob.store.messageInput = 'sent six minutes before it arrived';
    await bob.store.sendMessage();
    await deliver();
    assert(!alice.store.messages.some(m => m.text === 'sent six minutes before it arrived'));
    assert(alice.systemMessages.some(t => /sent more than 5 minutes before it reached this device/.test(t)),
        'the warning describes what happened');
    console.log('PASSED: the message-age guard counts from arrival, not from the SAS decision (C-F4)');
}

run().catch((error) => {
    console.error('FAILED:', error);
    process.exit(1);
});
