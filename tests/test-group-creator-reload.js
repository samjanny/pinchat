#!/usr/bin/env node

/**
 * Creator reload boundary for group rooms.
 *
 * The creator's MLS group state lives only in its page. A creator arrives
 * from the homepage with a bare key fragment; the group pins are attached to
 * that fragment only after the tab has minted the group. So a creator start
 * that already sees pins is a reloaded (or re-opened) creator whose group is
 * gone. It must not mint a second group behind the same link: that would
 * split the room, with the shared link rejecting new joiners and the members
 * unable to read the creator. It must lock the composer and say so.
 */

const path = require('path');
const fs = require('fs');

let passed = 0;
let failed = 0;

function assert(condition, name, detail = '') {
    if (condition) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? ` - ${detail}` : ''}`);
        failed += 1;
    }
}

let chatStore = null;
const constructed = [];
const pinsInstalled = [];

global.window = {
    location: { search: '?room=creator-reload-test', href: '' },
    MLSSession: class {
        constructor(options) {
            constructed.push(options);
            this.role = options.role;
            this.bootstrapPins = options.role === 'creator'
                ? { groupId: new Uint8Array(32).fill(7), creatorKeyHash: new Uint8Array(32).fill(9) }
                : null;
        }

        async start() {}
    },
    cryptoManager: {
        mlsPskSecret: new Uint8Array(32).fill(1),
        mlsExpectedGroupId: null,
        mlsExpectedCreatorKeyHash: null,
        setMlsBootstrapPins(groupId, creatorKeyHash) {
            pinsInstalled.push({ groupId, creatorKeyHash });
            this.mlsExpectedGroupId = Uint8Array.from(groupId);
            this.mlsExpectedCreatorKeyHash = Uint8Array.from(creatorKeyHash);
        },
    },
};
global.alert = () => {
    throw new Error('unexpected alert while loading app.js test harness');
};
global.requestAnimationFrame = () => 0;
global.URL.createObjectURL = () => 'blob:creator-reload-test';
global.URL.revokeObjectURL = () => {};
global.createImageBitmap = async () => ({ width: 1, height: 1, close() {} });
global.debugLog = () => {};
global.generateNickname = (value) => ({ display: `relay-derived:${value}` });
global.Alpine = {
    store(name, value) {
        if (arguments.length === 2) {
            if (name === 'chatRoom') chatStore = value;
            return value;
        }
        return { init() {} };
    },
};
global.document = {
    addEventListener(name, callback) {
        if (name === 'alpine:init') callback();
    },
};
global.isAllowedImageMimeType =
    require(path.join(__dirname, '..', 'static', 'js', 'crypto.js'))
        .isAllowedImageMimeType;

require(path.join(__dirname, '..', 'static', 'js', 'app.js'));

function resetStore() {
    chatStore.roomType = 'group';
    chatStore.userId = 'relay-self-route';
    chatStore.connected = true;
    chatStore.participantCount = 2;
    chatStore.mlsSession = null;
    chatStore.mlsReady = false;
    chatStore.mlsGroupEnded = false;
    chatStore.error = '';
    chatStore.wsManager = { send() { return true; }, cancelPendingMlsControl() {} };
    constructed.length = 0;
    pinsInstalled.length = 0;
}

async function main() {
    console.log('# Group creator reload boundary');
    assert(Boolean(chatStore), 'app.js registered the Alpine chat store');
    const cm = global.window.cryptoManager;

    // Case 1: a creator that already sees group pins was reloaded.
    resetStore();
    chatStore.mlsRole = 'creator';
    cm.mlsExpectedGroupId = new Uint8Array(32).fill(7);
    cm.mlsExpectedCreatorKeyHash = new Uint8Array(32).fill(9);
    await chatStore._ensureMlsSession();
    assert(constructed.length === 0 && chatStore.mlsSession === null,
        'reloaded creator does not mint a second group');
    assert(chatStore.mlsGroupEnded === true && chatStore.mlsReady === false,
        'reloaded creator marks the group as ended');
    assert(/reloaded/.test(chatStore.error) && /new room/i.test(chatStore.error),
        'error names the reload and points at a new room');
    assert(chatStore.isComposerLocked() === true
        && /Group ended/.test(chatStore.composerPlaceholder())
        && /Group ended/.test(chatStore.composerLockedLabel()),
        'composer is locked with a group-ended reason');
    const firstError = chatStore.error;
    await chatStore._ensureMlsSession();
    assert(constructed.length === 0 && chatStore.error === firstError,
        'a second start attempt stays a no-op');

    // Case 2: a fresh creator (bare key fragment, no pins) mints the group
    // and installs the pins it produced.
    resetStore();
    chatStore.mlsRole = 'creator';
    cm.mlsExpectedGroupId = null;
    cm.mlsExpectedCreatorKeyHash = null;
    await chatStore._ensureMlsSession();
    assert(constructed.length === 1 && constructed[0].role === 'creator',
        'fresh creator starts an MLS session as creator');
    assert(pinsInstalled.length === 1
        && cm.mlsExpectedGroupId && cm.mlsExpectedGroupId[0] === 7,
        'fresh creator attaches the pins its group produced');
    assert(chatStore.mlsGroupEnded === false && chatStore.error === '',
        'fresh creator is not treated as a reload');

    // Case 3: a joiner always carries pins; that is not a reload signal.
    resetStore();
    chatStore.mlsRole = 'joiner';
    await chatStore._ensureMlsSession();
    assert(constructed.length === 1 && constructed[0].role === 'joiner'
        && constructed[0].expectedGroupId === cm.mlsExpectedGroupId,
        'joiner with pins starts normally with the pinned group id');
    assert(chatStore.mlsGroupEnded === false, 'joiner with pins is not a reload');

    // Case 4: the page shows the state and the trust notice honestly.
    const chatHtml = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'chat.html'), 'utf8',
    );
    assert(chatHtml.includes('x-show="mlsGroupEnded"')
        && chatHtml.includes('Group ended'),
        'chat template renders the group-ended banner');
    assert(chatHtml.includes('!groupTrustNoticeDismissed')
        && chatHtml.includes('dismissGroupTrustNotice()')
        && chatHtml.includes('Identities not verified'),
        'chat template renders the dismissible group trust notice');
    chatStore.groupTrustNoticeDismissed = false;
    chatStore.dismissGroupTrustNotice();
    assert(chatStore.groupTrustNoticeDismissed === true,
        'dismissing the trust notice is a per-tab flag');

    console.log('');
    console.log(`${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((error) => {
    console.error('FAIL harness error:', error);
    process.exit(1);
});
