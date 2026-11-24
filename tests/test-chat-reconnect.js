#!/usr/bin/env node
'use strict';

const assert = require('assert');
const { createChatPair, createChatClient } = require('./helpers/chat-pair');

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

    await relayForgedIdentitySwap();
}

const ALICE = '11111111-1111-4111-8111-111111111111';
const BOB = '22222222-2222-4222-8222-222222222222';
const hex = (bytes) => Buffer.from(bytes || []).toString('hex');

/**
 * Audit C-F1. Membership frames come from the relay and are not
 * authenticated. A relay that knows the invite link forges a leave, a join
 * whose handshake it drops, and another leave: the handshake timer of the
 * discarded attempt used to stay armed and, up to 30 s later, tore down the
 * live session that replaced it, without arming the identity comparison.
 * The relay's own client then answered the next handshake with its own
 * identity key and inherited "verified", because the verdict was a boolean.
 */
async function relayForgedIdentitySwap() {
    const outbox = { alice: [], bob: [], mallory: [] };
    const alice = createChatClient(ALICE, m => outbox.alice.push(m));
    const bob = createChatClient(BOB, m => outbox.bob.push(m));
    const take = (name) => outbox[name].splice(0);
    async function exchange(a, aName, b, bName) {
        for (let round = 0; round < 20; round++) {
            const fromA = take(aName);
            const fromB = take(bName);
            if (!fromA.length && !fromB.length) return;
            for (const m of fromA) await b.recv(m);
            for (const m of fromB) await a.recv(m);
        }
        throw new Error('handshake did not settle');
    }
    const left = (id) => ({ type: 'userleft', user_id: id, participant_count: 1 });
    const joined = (id) => ({ type: 'userjoined', user_id: id, participant_count: 2 });

    for (const c of [alice, bob]) await c.crypto.extractKeyFromURL();
    await alice.store.startECDHHandshake();
    await bob.store.startECDHHandshake();
    await exchange(alice, 'alice', bob, 'bob');
    assert(alice.store.pfsActive && bob.store.pfsActive);
    await alice.store.handleSasVerified();
    await bob.store.handleSasVerified();
    const verifiedBob = hex(alice.store.identityManager.peerIdentityPublicKeyRaw);
    assert.equal(alice.store.sasVerificationStatus, 'verified');

    // Forged departure of each side, then a forged return to Alice whose
    // handshake frame the relay drops, then a forged departure again.
    await alice.recv(left(BOB));
    await bob.recv(left(ALICE));
    const armedBefore = new Set(alice.timers.keys());
    await alice.recv(joined(BOB));
    take('alice');
    const staleTimer = [...alice.timers.keys()].find(id => !armedBefore.has(id));
    assert(staleTimer, 'the handshake attempt armed its timeout');
    const staleCallback = alice.timers.get(staleTimer);
    await alice.recv(left(BOB));
    assert(!alice.timers.has(staleTimer),
        'discarding an ECDH manager stops its handshake timer');

    // The relay now lets an honest re-handshake through: same identity, so
    // the verdict carries over.
    await alice.recv(joined(BOB));
    await bob.recv(joined(ALICE));
    await exchange(alice, 'alice', bob, 'bob');
    assert(alice.store.pfsActive && alice.store.sasVerificationStatus === 'verified');

    // Even if the stale callback runs, it belongs to a discarded attempt and
    // must leave the live session alone (also the non-hostile case: a peer
    // that leaves and returns during a handshake no longer loses the next
    // session 30 s later).
    await staleCallback();
    await new Promise(r => setTimeout(r, 100));
    assert.equal(alice.store.pfsActive, true, 'a stale timer cannot tear down the live session');
    assert.equal(alice.store.sasVerificationStatus, 'verified');

    // Whatever ends the session (here the same soft teardown the stale timer
    // used to run, which does not arm the one-shot identity diff), the next
    // identity key is judged against the verified one.
    await alice.store.handleECDHAborted();
    alice.store.ecdhHandshakeStatus = 'none';
    const mallory = createChatClient(BOB, m => outbox.mallory.push(m));
    await mallory.crypto.extractKeyFromURL();
    await alice.recv(joined(BOB));
    await mallory.store.startECDHHandshake();
    await exchange(alice, 'alice', mallory, 'mallory');
    const malloryKey = hex(new Uint8Array(await mallory.context.crypto.subtle.exportKey(
        'raw', mallory.store.identityManager.identityKeyPair.publicKey)));
    assert.equal(hex(alice.store.identityManager.peerIdentityPublicKeyRaw), malloryKey);
    assert.notEqual(malloryKey, verifiedBob);
    assert(alice.store.pfsActive);
    assert.notEqual(alice.store.sasVerificationStatus, 'verified',
        'a different identity key must not inherit the verified badge');
    assert.equal(alice.store.sasReverifyRequired, true, 'a fresh verification is required');
    assert.equal(alice.store.isComposerLocked(), true, 'the composer is gated as for a first verification');
    assert(alice.systemMessages.some(t => /identity key changed since verification/.test(t)),
        'the user is told the identity key changed');
    await alice.store.handleSasSkipped();
    assert.equal(alice.store.sasVerificationStatus, 'pending', 'skipping is refused after an identity change');

    alice.store.messageInput = 'meet at 9, bring the documents';
    await alice.store.sendMessage();
    assert(!take('alice').some(m => m.type === 'message'), 'nothing is encrypted to the new identity');
    await mallory.store.handleSasVerified();
    mallory.store.messageInput = 'hi, it is me';
    await mallory.store.sendMessage();
    for (const m of take('mallory')) await alice.recv(m);
    assert(!alice.store.messages.some(m => m.type === 'message' && !m.isOwn),
        'the new identity cannot put messages on screen before verification');
    console.log('PASSED: relay-forged leave/join cannot carry the SAS verdict to another identity key (C-F1)');

    // The verified peer coming back is recognised again.
    await alice.store.handleECDHAborted();
    alice.store.ecdhHandshakeStatus = 'none';
    await bob.recv(left(ALICE));
    await alice.recv(joined(BOB));
    await bob.recv(joined(ALICE));
    await exchange(alice, 'alice', bob, 'bob');
    assert.equal(alice.store.sasVerificationStatus, 'verified');
    assert.equal(alice.store.sasReverifyRequired, false);
    assert.equal(alice.store.isComposerLocked(), false);
    console.log('PASSED: the verdict carries over only to the verified identity key');
}

run().catch(error => { console.error(error); process.exit(1); });
