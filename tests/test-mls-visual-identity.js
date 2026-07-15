#!/usr/bin/env node

/**
 * Browser UI boundary for authenticated MLS visual identities.
 *
 * Load app.js with a minimal Alpine harness (without running init()), then
 * prove that only MLSSession roster/message identities can populate group
 * labels. Relay userjoined/userleft/MLS sender_id values remain routing and
 * presence metadata and cannot become a displayed group identity.
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
        console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
        failed += 1;
    }
}

let chatStore = null;
const nicknameInputs = [];

global.window = {
    location: { search: '?room=visual-identity-test', href: '' },
};
global.alert = () => {
    throw new Error('unexpected alert while loading app.js test harness');
};
global.requestAnimationFrame = () => 0;
global.URL.createObjectURL = () => 'blob:mls-visual-identity-test';
global.debugLog = () => {};
global.generateNickname = (value) => {
    nicknameInputs.push(value);
    return { display: `relay-derived:${value}` };
};
global.Alpine = {
    store(name, value) {
        if (arguments.length === 2) {
            if (name === 'chatRoom') chatStore = value;
            return value;
        }
        // app.js calls Alpine.store('chatRoom').init() after registration.
        // Suppress network/bootstrap init while retaining the real store.
        return { init() {} };
    },
};
global.document = {
    addEventListener(name, callback) {
        if (name === 'alpine:init') callback();
    },
};

require(path.join(__dirname, '..', 'static', 'js', 'app.js'));

async function main() {
    console.log('# MLS authenticated visual identity UI');
    assert(Boolean(chatStore), 'app.js registered the Alpine chat store');

    chatStore.roomType = 'group';
    chatStore.userId = 'relay-self-route';
    chatStore.participantCount = 2;
    chatStore.mlsReady = false;

    const creator = {
        leafIndex: 0,
        fingerprint: '11'.repeat(32),
        shortFingerprint: '1111 1111 1111 1111 1111',
        displayName: 'Creator · 1111 1111 1111 1111 1111',
        isCreator: true,
        isSelf: false,
    };
    const selfMember = {
        leafIndex: 1,
        fingerprint: '22'.repeat(32),
        shortFingerprint: '2222 2222 2222 2222 2222',
        displayName: 'Member · 2222 2222 2222 2222 2222',
        isCreator: false,
        isSelf: true,
    };

    chatStore._handleMlsEvent({
        kind: 'roster',
        epoch: '1',
        myLeafIndex: 1,
        members: [creator, selfMember],
    });
    assert(chatStore.mlsRosterValid
        && chatStore.mlsSelfIdentity.fingerprint === selfMember.fingerprint,
    'validated MLS roster installs authenticated self identity');
    assert(chatStore.groupPeers.length === 1
        && chatStore.groupPeers[0].fingerprint === creator.fingerprint
        && chatStore.groupPeers[0].nickname === creator.displayName,
    'sidebar peer is keyed and named by signature-key fingerprint');
    assert(chatStore.groupPeers[0].userId === undefined
        && chatStore.groupPeers[0].identityTitle.includes(creator.fingerprint),
    'group roster exposes full key fingerprint and no relay user ID');
    assert(chatStore.authenticatedMemberCount() === 2
        && chatStore.ownDisplayName() === selfMember.displayName
        && chatStore.ownIdentityTitle().includes(selfMember.fingerprint),
    'group counts and own label use authenticated roster state');
    assert(nicknameInputs.length === 0,
        'installing MLS roster never calls relay nickname generator');
    const chatHtml = fs.readFileSync(
        path.join(__dirname, '..', 'static', 'chat.html'), 'utf8',
    );
    assert(chatHtml.includes(':key="p.fingerprint"')
        && chatHtml.includes(':title="p.identityTitle"')
        && chatHtml.includes(':title="msg.senderTitle"')
        && chatHtml.includes('x-text="ownDisplayName()"')
        && chatHtml.includes('x-text="ownAvatarLetter()"')
        && !chatHtml.includes(':key="p.userId"'),
    'chat template keys roster/messages by authenticated identity fields');

    const messagesBefore = chatStore.messages.length;
    chatStore._handleMlsEvent({
        kind: 'message',
        text: 'authenticated text',
        senderLeafIndex: 0,
        senderIdentity: creator,
        // Even if a future caller accidentally forwards this field, the UI
        // handler must ignore it for naming and tooltips.
        senderId: 'relay-forged-display-name',
        attributionWarning: false,
    });
    const displayed = chatStore.messages.at(-1);
    assert(chatStore.messages.length === messagesBefore + 1
        && displayed.nickname === creator.displayName
        && displayed.senderFingerprint === creator.fingerprint,
    'message bubble uses authenticated MLS identity');
    assert(displayed.senderId === undefined
        && displayed.senderTitle.includes(creator.fingerprint)
        && !displayed.senderTitle.includes('relay-forged-display-name'),
    'message tooltip excludes relay sender_id');
    assert(nicknameInputs.length === 0,
        'MLS message rendering never calls relay nickname generator');

    chatStore._handleMlsEvent({
        kind: 'image',
        mimeType: 'image/png',
        data: new Uint8Array([0x89, 0x50, 0x4e, 0x47]),
        senderLeafIndex: 0,
        senderIdentity: creator,
        senderId: 'another-relay-forged-name',
        attributionWarning: false,
    });
    const displayedImage = chatStore.messages.at(-1);
    assert(displayedImage.type === 'image'
        && displayedImage.nickname === creator.displayName
        && displayedImage.senderFingerprint === creator.fingerprint
        && displayedImage.senderId === undefined,
    'image bubble also uses only authenticated MLS identity');

    const acceptedMessages = chatStore.messages.length;
    chatStore._handleMlsEvent({
        kind: 'message',
        text: 'must not display',
        senderLeafIndex: 0,
    });
    assert(chatStore.messages.length === acceptedMessages
        && chatStore.error.includes('omitted its authenticated sender identity'),
    'UI fails closed when an MLS plaintext lacks key identity');

    let routedEnvelope = null;
    let removedRoute = null;
    chatStore.mlsSession = {
        shouldHandleOwnEnvelope: () => false,
        onRelayEnvelope: async (envelope) => { routedEnvelope = envelope; },
        removeMemberBySenderId: async (senderId) => { removedRoute = senderId; },
    };
    const rosterBeforeRelayEvents = JSON.stringify(chatStore.groupPeers);
    await chatStore.handleWebSocketMessage({
        type: 'userjoined',
        user_id: 'relay-injected-joiner',
        participant_count: 3,
    });
    assert(JSON.stringify(chatStore.groupPeers) === rosterBeforeRelayEvents
        && nicknameInputs.length === 0,
    'relay userjoined cannot add or name an MLS roster member');

    await chatStore.handleWebSocketMessage({
        type: 'mls',
        sender_id: 'relay-envelope-spoof',
        wire_format: 2,
        payload: 'opaque-test-payload',
    });
    assert(routedEnvelope && routedEnvelope.sender_id === 'relay-envelope-spoof'
        && JSON.stringify(chatStore.groupPeers) === rosterBeforeRelayEvents,
    'MLS envelope sender_id is routed but never backfills the visual roster');

    await chatStore.handleWebSocketMessage({
        type: 'userleft',
        user_id: 'relay-injected-joiner',
        participant_count: 2,
    });
    await Promise.resolve();
    assert(removedRoute === 'relay-injected-joiner'
        && JSON.stringify(chatStore.groupPeers) === rosterBeforeRelayEvents,
    'relay userleft requests routing removal but cannot erase roster identity');

    chatStore._handleMlsEvent({
        kind: 'roster',
        epoch: '2',
        myLeafIndex: 1,
        members: [selfMember],
    });
    assert(chatStore.groupPeers.length === 0
        && chatStore.authenticatedMemberCount() === 1,
    'authenticated post-Remove roster is the only event that removes the peer');

    chatStore.mlsReady = true;
    chatStore._handleMlsEvent({
        kind: 'roster',
        epoch: '3',
        myLeafIndex: 1,
        members: [{
            ...selfMember,
            displayName: 'relay-derived:relay-self-route',
        }],
    });
    assert(chatStore.mlsReady === false && chatStore.mlsRosterValid === false
        && chatStore.mlsSelfIdentity === null
        && chatStore.groupPeers.length === 0,
    'relay-style label cannot override the fingerprint-derived member label');

    chatStore.mlsReady = true;
    chatStore._handleMlsEvent({
        kind: 'roster',
        epoch: '4',
        myLeafIndex: 1,
        members: [{ ...selfMember, fingerprint: 'not-a-fingerprint' }],
    });
    assert(chatStore.mlsReady === false && chatStore.mlsRosterValid === false
        && chatStore.mlsSelfIdentity === null
        && chatStore.groupPeers.length === 0,
        'malformed authenticated roster locks group messaging fail-closed');

    console.log('');
    console.log(`mls-visual-identity: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
