#!/usr/bin/env node

/**
 * PFS Handshake Key-Separation Test
 *
 * Regression guard for the "initial secret is recomputable after cleanup"
 * finding. The handshake ECDH keypair that derives the initial shared
 * secret S must NOT be the same object the Double Ratchet retains as DHs.
 * If it is, then after destroyEphemeralKeys() the ratchet still holds a
 * private key with `deriveBits`, so any code with page access (XSS,
 * malicious extension, compromised frontend) can:
 *
 *   1. recompute S = ECDH(DHs.privateKey, DHr)      (both still reachable)
 *   2. re-run HKDF('DoubleRatchet-Init-v1')          (deterministic)
 *   3. rebuild the initial chain keys
 *   4. decrypt captured initial-chain ciphertext
 *
 * ...which violates the stated PFS guarantee ("historical messages remain
 * secure even if the page is compromised", ecdh.js). extractable:false
 * blocks EXFILTRATION of the key but not its USE as an ECDH oracle, so it
 * is not a mitigation.
 *
 * This suite drives the REAL production handshake end-to-end (two live
 * ECDHKeyExchange instances exchanging encrypted, signed public keys) and
 * the app.js-style handoff into DoubleRatchet, then mounts the attack from
 * the reachable post-cleanup state and asserts it FAILS.
 *
 * Expected status:
 *   - against the v1 (shared-keypair) handshake: FAILS (attack recovers the
 *     plaintext) -> this is the red test.
 *   - against the v2 (separated handshake/ratchet keypairs) handshake:
 *     PASSES (S's private input is destroyed; the ratchet holds a distinct
 *     key that does not reconstruct S).
 */

'use strict';

const assert = require('assert');
const { webcrypto } = require('crypto');

// ── Polyfill / setup ────────────────────────────────────────────────────
global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};
global.PINCHAT_PROTOCOL_VERSION = 1;
// ecdh.js is browser-only (ends in `window.ECDHKeyExchange = ...`, no
// module.exports). Shim window so the require captures the class.
global.window = global.window || {};

// crypto.js first: promotes AAD_FIELD_TYPES / encodeAADWithLengthPrefix /
// ChainRatchet onto globalThis for the modules that reference them.
const { ChainRatchet, AAD_FIELD_TYPES, encodeAADWithLengthPrefix } = require('../static/js/crypto.js');
const { IdentityKeyManager } = require('../static/js/identity.js');
const { DoubleRatchet } = require('../static/js/double-ratchet.js');
require('../static/js/ecdh.js');
const ECDHKeyExchange = global.window.ECDHKeyExchange;

// ALICE_ID < BOB_ID lexicographically -> alice is the initiator (app.js rule).
const ROOM = '00000000-0000-0000-0000-000000000001';
const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const BOB_ID = '22222222-2222-2222-2222-222222222222';
const ALICE_PLAIN = 'pfs-should-hide-alice';
const BOB_PLAIN = 'pfs-should-hide-bob';

function bytesEqual(a, b) {
    a = new Uint8Array(a);
    b = new Uint8Array(b);
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
}

function pass(label) {
    console.log(`  [OK] ${label}`);
}

function assertPeerStateEmpty(ecdh, identity, label) {
    assert.strictEqual(identity.peerIdentityPublicKey, null, `${label}: peer identity key mutated`);
    assert.strictEqual(identity.peerIdentityPublicKeyRaw, null, `${label}: peer identity raw bytes mutated`);
    assert.strictEqual(ecdh.otherHandshakePublicKey, null, `${label}: handshake public key mutated`);
    assert.strictEqual(ecdh.otherRatchetPublicKey, null, `${label}: ratchet public key mutated`);
    assert.strictEqual(ecdh.otherTimestamp, null, `${label}: peer timestamp mutated`);
    assert.strictEqual(ecdh.otherNonce, null, `${label}: peer nonce mutated`);
}

async function deriveWith(privateKey, publicKey) {
    return new Uint8Array(await webcrypto.subtle.deriveBits(
        { name: 'ECDH', public: publicKey }, privateKey, 256,
    ));
}

async function attemptInitialChainRecovery(secret, isInitiator, peerIdentityRaw, peerDh, packet, senderId) {
    const attackerId = new IdentityKeyManager();
    await attackerId.generateIdentityKeypair();
    await attackerId.importPeerIdentityPublicKey(peerIdentityRaw);
    const attacker = new DoubleRatchet(attackerId);
    const throwaway = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits'],
    );

    try {
        await attacker.initialize(secret, isInitiator, throwaway, peerDh);
        const out = await attacker.decryptMessage(packet.payload, packet.header, ROOM, senderId);
        return out && out.text;
    } catch (_) {
        return null;
    }
}

async function encryptCustomEnvelope(bootstrapKey, senderEcdh, senderId, handshakeRaw, ratchetRaw) {
    const timestamp = Date.now();
    const nonce = webcrypto.getRandomValues(new Uint8Array(16));
    const transcript = senderEcdh._buildHandshakeTranscript(
        ROOM, senderId, timestamp, nonce, handshakeRaw, ratchetRaw,
    );
    const signature = new Uint8Array(await senderEcdh.identityManager.sign(transcript));
    const identityRaw = new Uint8Array(await senderEcdh.identityManager.exportIdentityPublicKey());
    const envelope = senderEcdh._concat([
        new Uint8Array([senderEcdh.HANDSHAKE_VERSION]),
        senderEcdh._lenPrefix(handshakeRaw),
        senderEcdh._lenPrefix(ratchetRaw),
        senderEcdh._lenPrefix(identityRaw),
        senderEcdh._lenPrefix(signature),
    ]);
    const aad = encodeAADWithLengthPrefix([
        { type: AAD_FIELD_TYPES.ROOM_ID, value: ROOM },
        { type: AAD_FIELD_TYPES.SENDER_ID, value: senderId },
        { type: AAD_FIELD_TYPES.TIMESTAMP, value: timestamp },
        { type: AAD_FIELD_TYPES.NONCE, value: nonce },
    ]);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad }, bootstrapKey, envelope,
    ));
    const combined = new Uint8Array(iv.length + ciphertext.length);
    combined.set(iv, 0);
    combined.set(ciphertext, iv.length);
    return {
        version: 2,
        encryptedEnvelope: senderEcdh.arrayBufferToBase64url(combined),
        timestamp,
        nonce: senderEcdh.arrayBufferToBase64url(nonce),
    };
}

/**
 * Drive a full two-party ECDH handshake between two real ECDHKeyExchange
 * instances, then wire the Double Ratchets exactly as app.js does, capture
 * initial-chain ciphertexts in BOTH directions, generate the SAS, and run
 * destroyEphemeralKeys() on both sides. The returned initialSecret is a test
 * oracle only; production zeroes this buffer after ratchet initialization.
 */
async function runHandshake() {
    // Shared bootstrap key (both peers read it from the same URL fragment).
    const bootstrapKey = await webcrypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );

    const aliceId = new IdentityKeyManager();
    const bobId = new IdentityKeyManager();
    await aliceId.generateIdentityKeypair();
    await bobId.generateIdentityKeypair();
    const aliceIdPub = await aliceId.exportIdentityPublicKey();

    const aliceEcdh = new ECDHKeyExchange(bootstrapKey, aliceId);
    const bobEcdh = new ECDHKeyExchange(bootstrapKey, bobId);
    await aliceEcdh.generateKeypair();
    await bobEcdh.generateKeypair();

    assert.notStrictEqual(aliceEcdh.handshakeKeyPair, aliceEcdh.ratchetKeyPair,
        'Alice handshake and ratchet keypairs must be distinct objects');
    assert.notStrictEqual(bobEcdh.handshakeKeyPair, bobEcdh.ratchetKeyPair,
        'Bob handshake and ratchet keypairs must be distinct objects');

    // Exchange handshake v2 envelopes (dual keys + encrypted identity/signature).
    const aliceMsg = await aliceEcdh.encryptPublicKey(ROOM, ALICE_ID);
    const bobMsg = await bobEcdh.encryptPublicKey(ROOM, BOB_ID);
    await aliceEcdh.decryptPublicKey(
        bobMsg.encryptedEnvelope, ROOM, BOB_ID, bobMsg.timestamp, bobMsg.nonce, bobMsg.version,
    );
    await bobEcdh.decryptPublicKey(
        aliceMsg.encryptedEnvelope, ROOM, ALICE_ID, aliceMsg.timestamp, aliceMsg.nonce, aliceMsg.version,
    );

    const aliceS = await aliceEcdh.deriveSessionKey();
    const bobS = await bobEcdh.deriveSessionKey();
    assert.ok(bytesEqual(aliceS, bobS), 'both peers must derive the same shared secret');
    const initialSecret = aliceS.slice();

    // Model the recorded handshake. Under the documented threat model the
    // attacker may later recover the bootstrap key and decrypt these PUBLIC
    // handshake points, even though the live ECDH managers have discarded them.
    const recordedAliceHandshakePublic = bobEcdh.otherHandshakePublicKey;
    const recordedBobHandshakePublic = aliceEcdh.otherHandshakePublicKey;

    // app.js handoff: pass the RATCHET keypair + peer ratchet public key into
    // the ratchet (never the handshake keypair that derived S).
    const aliceDR = new DoubleRatchet(aliceId);
    const bobDR = new DoubleRatchet(bobId);
    await aliceDR.initialize(aliceS, true, aliceEcdh.ratchetKeyPair, aliceEcdh.otherRatchetPublicKey);
    await bobDR.initialize(bobS, false, bobEcdh.ratchetKeyPair, null);

    // SAS is generated before the ephemeral keys are destroyed.
    const aliceSAS = await aliceEcdh.generateSAS(ROOM);
    const bobSAS = await bobEcdh.generateSAS(ROOM);
    assert.strictEqual(aliceSAS.hex, bobSAS.hex, 'SAS must match on both sides');

    // Capture initial-chain ciphertext in BOTH directions before either side
    // receives a message or performs its first DH rotation.
    const capturedAlice = await aliceDR.encryptMessage(ALICE_PLAIN, ROOM, ALICE_ID);
    const capturedBob = await bobDR.encryptMessage(BOB_PLAIN, ROOM, BOB_ID);

    // Match app.js: the raw S buffers are cleared once the ratchet and SAS are ready.
    aliceS.fill(0);
    bobS.fill(0);

    // Cleanup, exactly as app.js does after handshake completion.
    aliceEcdh.deleteBootstrapKey();
    bobEcdh.deleteBootstrapKey();
    aliceEcdh.destroyEphemeralKeys();
    bobEcdh.destroyEphemeralKeys();

    return {
        aliceDR, bobDR, aliceId, bobId,
        aliceIdPub,
        bobIdPub: await bobId.exportIdentityPublicKey(),
        aliceEcdh, bobEcdh,
        initialSecret,
        recordedAliceHandshakePublic,
        recordedBobHandshakePublic,
        capturedAlice,
        capturedBob,
    };
}

// ── Test 1: honest peer decrypts (guards against a vacuous pass) ─────────
async function testHonestPathWorks() {
    const { aliceDR, bobDR, capturedAlice, capturedBob } = await runHandshake();
    const atBob = await bobDR.decryptMessage(capturedAlice.payload, capturedAlice.header, ROOM, ALICE_ID);
    const atAlice = await aliceDR.decryptMessage(capturedBob.payload, capturedBob.header, ROOM, BOB_ID);
    assert.strictEqual(atBob.text, ALICE_PLAIN, 'Bob must decrypt Alice initial-chain message');
    assert.strictEqual(atAlice.text, BOB_PLAIN, 'Alice must decrypt Bob initial-chain message');
    pass('honest peers decrypt captured initial-chain messages in both directions');
}

// ── Test 1b: bidirectional round-trip through the real v2 handshake ──────
// Exercises the ratchet-key wiring end to end: the DH ratchet must rotate
// correctly when the keys handed to it are the ratchet keys, not the
// handshake keys.
async function testBidirectionalRoundTrip() {
    const { aliceDR, bobDR, capturedAlice, capturedBob } = await runHandshake();
    await bobDR.decryptMessage(capturedAlice.payload, capturedAlice.header, ROOM, ALICE_ID);
    await aliceDR.decryptMessage(capturedBob.payload, capturedBob.header, ROOM, BOB_ID);
    const a1 = await aliceDR.encryptMessage('alice-1', ROOM, ALICE_ID);
    assert.strictEqual((await bobDR.decryptMessage(a1.payload, a1.header, ROOM, ALICE_ID)).text, 'alice-1');
    const b1 = await bobDR.encryptMessage('bob-1', ROOM, BOB_ID);
    assert.strictEqual((await aliceDR.decryptMessage(b1.payload, b1.header, ROOM, BOB_ID)).text, 'bob-1');
    const a2 = await aliceDR.encryptMessage('alice-2', ROOM, ALICE_ID);
    assert.strictEqual((await bobDR.decryptMessage(a2.payload, a2.header, ROOM, ALICE_ID)).text, 'alice-2');
    pass('bidirectional round-trip works after v2 handshake (ratchet-key DH rotation)');
}

// ── Test 2: THE INVARIANT - S not recomputable from reachable state ─────
async function testInitialSecretNotRecomputableAfterCleanup() {
    const {
        aliceDR, bobDR, initialSecret,
        recordedAliceHandshakePublic, recordedBobHandshakePublic,
    } = await runHandshake();

    // Exact late-compromise attack for BOTH roles: combine the retained ratchet
    // private key with the recorded peer HANDSHAKE public key. A regression that
    // aliases either local handshake key into DHs is caught even if the peer's
    // handshake and ratchet public keys remain distinct.
    const aliceCandidate = await deriveWith(aliceDR.DHs.privateKey, recordedBobHandshakePublic);
    const bobCandidate = await deriveWith(bobDR.DHs.privateKey, recordedAliceHandshakePublic);
    assert.ok(!bytesEqual(aliceCandidate, initialSecret),
        'PFS VIOLATION: initiator retained a private key that reconstructs S');
    assert.ok(!bytesEqual(bobCandidate, initialSecret),
        'PFS VIOLATION: responder retained a private key that reconstructs S');
    pass('initial secret S not recomputable for initiator or responder');
}

// ── Test 3: end-to-end - captured ciphertext not recoverable ─────────────
async function testCapturedCiphertextNotRecoverable() {
    const {
        aliceDR, bobDR, aliceIdPub, bobIdPub,
        recordedAliceHandshakePublic, recordedBobHandshakePublic,
        capturedAlice, capturedBob,
    } = await runHandshake();

    const aliceCandidate = await deriveWith(aliceDR.DHs.privateKey, recordedBobHandshakePublic);
    const bobCandidate = await deriveWith(bobDR.DHs.privateKey, recordedAliceHandshakePublic);
    const recoveredAlice = await attemptInitialChainRecovery(
        aliceCandidate, false, aliceIdPub, null, capturedAlice, ALICE_ID,
    );
    const recoveredBob = await attemptInitialChainRecovery(
        bobCandidate, true, bobIdPub, bobDR.DHs.publicKey, capturedBob, BOB_ID,
    );
    assert.notStrictEqual(recoveredAlice, ALICE_PLAIN,
        'PFS VIOLATION: initiator initial-chain plaintext recovered');
    assert.notStrictEqual(recoveredBob, BOB_PLAIN,
        'PFS VIOLATION: responder initial-chain plaintext recovered');
    pass('captured initial-chain ciphertext unrecoverable for both roles');
}

// ── Test 4: cleanup removes every ECDH-manager reference ─────────────────
async function testManagersContainNoResidualKeyReferences() {
    const { aliceEcdh, bobEcdh } = await runHandshake();
    for (const [label, manager] of [['Alice', aliceEcdh], ['Bob', bobEcdh]]) {
        assert.strictEqual(manager.handshakeKeyPair, null, `${label}: handshake keypair retained`);
        assert.strictEqual(manager.otherHandshakePublicKey, null, `${label}: peer handshake key retained`);
        assert.strictEqual(manager.ratchetKeyPair, null, `${label}: ratchet keypair retained by ECDH manager`);
        assert.strictEqual(manager.otherRatchetPublicKey, null, `${label}: peer ratchet key retained`);
        assert.strictEqual(manager.bootstrapKey, null, `${label}: bootstrap key retained`);
        assert.strictEqual(manager.keysDestroyed, true, `${label}: cleanup flag not set`);
        await assert.rejects(() => manager.deriveSessionKey(), /keys have been destroyed/);
    }
    pass('post-cleanup ECDH managers retain no key handles or handshake context');
}

// ── Test 5: validate-before-mutate is fully transactional ────────────────
async function testInvalidSignedPointDoesNotCommitPeerState() {
    const bootstrapKey = await webcrypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
    const senderId = new IdentityKeyManager();
    const receiverId = new IdentityKeyManager();
    await senderId.generateIdentityKeypair();
    await receiverId.generateIdentityKeypair();
    const sender = new ECDHKeyExchange(bootstrapKey, senderId);
    const receiver = new ECDHKeyExchange(bootstrapKey, receiverId);
    await sender.generateKeypair();
    await receiver.generateKeypair();

    const validHandshakeRaw = new Uint8Array(await webcrypto.subtle.exportKey(
        'raw', sender.handshakeKeyPair.publicKey,
    ));
    const invalidRatchetRaw = new Uint8Array(65);
    invalidRatchetRaw[0] = 0x04; // correct encoding shape, off-curve coordinates
    const malicious = await encryptCustomEnvelope(
        bootstrapKey, sender, BOB_ID, validHandshakeRaw, invalidRatchetRaw,
    );

    await assert.rejects(
        () => receiver.decryptPublicKey(
            malicious.encryptedEnvelope, ROOM, BOB_ID,
            malicious.timestamp, malicious.nonce, malicious.version,
        ),
        /Invalid keyData|invalid/i,
    );
    assertPeerStateEmpty(receiver, receiverId, 'signed off-curve ratchet point');
    pass('signed invalid ECDH point rejected without partial peer-state commit');
}

// ── Test 6: downgrade and outer schema fail closed ───────────────────────
async function testDowngradeAndSchemaFailClosed() {
    const bootstrapKey = await webcrypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
    const senderId = new IdentityKeyManager();
    await senderId.generateIdentityKeypair();
    const sender = new ECDHKeyExchange(bootstrapKey, senderId);
    await sender.generateKeypair();
    const message = await sender.encryptPublicKey(ROOM, BOB_ID);
    assert.deepStrictEqual(
        Object.keys(message).sort(),
        ['encryptedEnvelope', 'nonce', 'timestamp', 'version'],
        'outer handshake must not expose identity/signature/key material',
    );
    assert.ok(Buffer.byteLength(JSON.stringify(message)) < 8192,
        'handshake payload exceeds relay limit');

    const receiverId = new IdentityKeyManager();
    await receiverId.generateIdentityKeypair();
    const receiver = new ECDHKeyExchange(bootstrapKey, receiverId);
    await receiver.generateKeypair();
    await assert.rejects(
        () => receiver.decryptPublicKey(
            message.encryptedEnvelope, ROOM, BOB_ID,
            message.timestamp, message.nonce, 1,
        ),
        /Unsupported handshake version/,
    );
    assertPeerStateEmpty(receiver, receiverId, 'v1 downgrade');

    await assert.rejects(
        () => receiver.decryptPublicKey(
            message.encryptedEnvelope, ROOM, BOB_ID,
            message.timestamp, 'AA', message.version,
        ),
        /nonce length/,
    );
    assertPeerStateEmpty(receiver, receiverId, 'invalid nonce schema');
    pass('v1 downgrade and malformed outer schema fail closed without mutation');
}

// ── Test 7: signature binds both ephemeral keys ──────────────────────────
async function testTranscriptSignatureBindsBothKeys() {
    const bootstrapKey = await webcrypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
    const senderId = new IdentityKeyManager();
    await senderId.generateIdentityKeypair();
    const sender = new ECDHKeyExchange(bootstrapKey, senderId);
    await sender.generateKeypair();
    const message = await sender.encryptPublicKey(ROOM, BOB_ID);

    const nonce = new Uint8Array(sender.base64urlToArrayBuffer(message.nonce));
    const aad = encodeAADWithLengthPrefix([
        { type: AAD_FIELD_TYPES.ROOM_ID, value: ROOM },
        { type: AAD_FIELD_TYPES.SENDER_ID, value: BOB_ID },
        { type: AAD_FIELD_TYPES.TIMESTAMP, value: message.timestamp },
        { type: AAD_FIELD_TYPES.NONCE, value: nonce },
    ]);
    const combined = new Uint8Array(sender.base64urlToArrayBuffer(message.encryptedEnvelope));
    const plaintext = new Uint8Array(await webcrypto.subtle.decrypt(
        { name: 'AES-GCM', iv: combined.slice(0, 12), additionalData: aad },
        bootstrapKey,
        combined.slice(12),
    ));

    // Layout: version || u16(65) || handshake[65] || u16(65) || ratchet[65] ...
    // Mutate a coordinate byte (not the 0x04 encoding marker) in each key.
    for (const [label, byteOffset] of [['handshake', 4], ['ratchet', 71]]) {
        const tampered = plaintext.slice();
        tampered[byteOffset] ^= 0x01;
        const iv = webcrypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(await webcrypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: aad }, bootstrapKey, tampered,
        ));
        const repacked = new Uint8Array(iv.length + ciphertext.length);
        repacked.set(iv, 0);
        repacked.set(ciphertext, iv.length);

        const receiverId = new IdentityKeyManager();
        await receiverId.generateIdentityKeypair();
        const receiver = new ECDHKeyExchange(bootstrapKey, receiverId);
        await receiver.generateKeypair();
        await assert.rejects(
            () => receiver.decryptPublicKey(
                receiver.arrayBufferToBase64url(repacked), ROOM, BOB_ID,
                message.timestamp, message.nonce, message.version,
            ),
            /signature is invalid/,
        );
        assertPeerStateEmpty(receiver, receiverId, `${label} transcript tamper`);
    }
    pass('transcript signature binds both handshake and ratchet public keys');
}

// ── Runner ──────────────────────────────────────────────────────────────
async function main() {
    console.log('PFS Handshake Key-Separation Test\n');
    let failures = 0;
    const tests = [
        testHonestPathWorks,
        testBidirectionalRoundTrip,
        testInitialSecretNotRecomputableAfterCleanup,
        testCapturedCiphertextNotRecoverable,
        testManagersContainNoResidualKeyReferences,
        testInvalidSignedPointDoesNotCommitPeerState,
        testDowngradeAndSchemaFailClosed,
        testTranscriptSignatureBindsBothKeys,
    ];
    for (const t of tests) {
        try {
            await t();
        } catch (err) {
            failures++;
            console.error(`  [FAIL] ${t.name}`);
            console.error(`         ${err.message}`);
        }
    }
    console.log('');
    if (failures) {
        console.error(`FAILED: ${failures}/${tests.length} test(s) failed`);
        process.exit(1);
    }
    console.log(`PASSED: ${tests.length}/${tests.length} tests`);
}

main().catch((err) => {
    console.error('Fatal:', err);
    process.exit(1);
});
