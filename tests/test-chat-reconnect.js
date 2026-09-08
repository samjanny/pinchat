#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { createChatPair } = require('./helpers/chat-pair');

async function reconnect(client, overrides = {}) {
    client.store.transportReconnectPending = true;
    await client.store.handleWebSocketMessage({
        type: 'connected', user_id: client.store.userId,
        room_type: 'onetoone', participant_count: 2, resumed: true,
        ...overrides,
    });
}

async function run() {
    const { alice, bob, roomId, queue, deliver } = await createChatPair();
    await alice.store.handleSasVerified();
    await bob.store.handleSasVerified();
    const originalRatchet = alice.crypto.doubleRatchet;
    const originalSas = alice.store.sas;

    alice.store.messageInput = 'before disconnect';
    await alice.store.sendMessage();
    await deliver();
    assert.equal(bob.store.messages.at(-1).text, 'before disconnect');

    // Ephemeral traffic sent while Alice was away is lost. The surviving
    // ratchet must still decrypt the next message across that counter gap.
    await bob.crypto.encryptMessage('lost during disconnect', roomId, bob.store.userId);
    await reconnect(alice);
    assert.strictEqual(alice.crypto.doubleRatchet, originalRatchet, 'stable resume must retain the ratchet');
    assert.strictEqual(alice.store.sas, originalSas, 'stable resume must retain the verified transcript');
    assert.equal(alice.store.sasVerificationStatus, 'verified');
    assert.equal(queue.length, 0, 'stable resume must not publish a unilateral handshake');
    assert.equal(alice.store.isComposerLocked(), false);

    for (const [sender, receiver, text] of [
        [bob, alice, 'after one-sided resume'],
        [alice, bob, 'reply after resume'],
    ]) {
        sender.store.messageInput = text;
        await sender.store.sendMessage();
        await deliver();
        assert.equal(receiver.store.messages.at(-1).text, text);
    }
    await Promise.all([reconnect(alice), reconnect(bob)]);
    bob.store.messageInput = 'after both resumed';
    await bob.store.sendMessage();
    await deliver();
    assert.equal(alice.store.messages.at(-1).text, 'after both resumed');

    // Fresh admission changes the sender ID bound into AEAD. It still needs
    // a new handshake after the old participant's real leave/join lifecycle.
    await bob.store.handleWebSocketMessage({
        type: 'userleft', user_id: alice.store.userId, participant_count: 1,
    });
    await reconnect(alice, { resumed: false, user_id: '33333333-3333-4333-8333-333333333333' });
    assert.equal(alice.store.pfsActive, false, 'fresh identity cannot reuse old AEAD state');
    await bob.store.handleWebSocketMessage({
        type: 'userjoined', user_id: alice.store.userId, participant_count: 2,
    });
    await deliver();
    assert(alice.store.pfsActive && bob.store.pfsActive);
    alice.store.messageInput = 'after fresh admission';
    await alice.store.sendMessage();
    await deliver();
    assert.equal(bob.store.messages.at(-1).text, 'after fresh admission');
    console.log('PASSED: stable resume retains ratchet/SAS and decrypts across gaps; fresh admission rekeys');

    // A resume must not turn a pending SAS decision into approval.
    const pending = await createChatPair();
    await reconnect(pending.alice);
    assert.equal(pending.alice.store.sasVerificationStatus, 'pending');
    assert(pending.alice.store.isComposerLocked());
    console.log('PASSED: resume preserves the pending SAS gate');
}

run().catch(error => { console.error(error); process.exit(1); });
