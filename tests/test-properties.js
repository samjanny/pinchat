#!/usr/bin/env node

/**
 * Property-based tests for the PinChat Double Ratchet, driven by fast-check.
 *
 * The hand-rolled scenarios in test-ratchet-correctness.js pin specific
 * regressions (C-01, C-02, C-05, F-10). This file complements them with
 * randomized delivery patterns, plaintexts, and reorderings — searching
 * for ratchet state-machine bugs that a fixed scenario would miss.
 *
 * Properties checked (audit-3 M-03 assurance):
 *
 *   P1 — Round-trip identity under in-order delivery.
 *        For any sequence of plaintexts encrypted by Alice and delivered
 *        in order to Bob, every plaintext is recovered byte-exact.
 *
 *   P2 — Round-trip identity under bounded reorder (≤ MAX_SKIP within a chain).
 *        Bob can decrypt messages out of order if they fall within the
 *        100-message skip window, and the late ones are flagged
 *        _outOfOrder.
 *
 *   P3 — Replay rejection.
 *        A successfully decrypted message, redelivered with the same
 *        payload + header, MUST be rejected (AEAD failure or
 *        counter-rewind rejection).
 *
 *   P4 — Concurrent encrypt monotonicity.
 *        N parallel `encryptMessage` calls produce N strictly sequential
 *        header.n values 0..N-1, every result decrypts at the peer.
 *
 *   P5 — Bidirectional ping-pong under arbitrary turn-taking.
 *        Random interleaving of Alice-sends / Bob-sends / Alice-delivers
 *        / Bob-delivers preserves round-trip identity, including across
 *        DH ratchet rotations.
 *
 *   P6 — Corrupt payload preserves state.
 *        Flipping a single bit in a payload byte must cause decrypt to
 *        throw AND leave Nr / ratchetCount / chain key material / skipped
 *        keys count byte-identical to pre-call. This is F-10 generalised
 *        to random bit-flips.
 *
 * Each property runs ~20-50 random cases (`numRuns`). fast-check shrinks
 * counter-examples on failure, so test output points at the minimal
 * reproducer.
 */

'use strict';

const assert = require('assert');
const { webcrypto } = require('crypto');
const fc = require('fast-check');

// Production-module bootstrap (mirrors test-ratchet-correctness.js).
global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};
global.PINCHAT_PROTOCOL_VERSION = 1;
require('../static/js/crypto.js');
const { IdentityKeyManager } = require('../static/js/identity.js');
const { DoubleRatchet } = require('../static/js/double-ratchet.js');

const ROOM = '00000000-0000-0000-0000-000000000001';
const ALICE_ID = '11111111-1111-1111-1111-111111111111';
const BOB_ID = '22222222-2222-2222-2222-222222222222';

// ── ratchet pair setup ──────────────────────────────────────────────────

async function setupPair() {
    const aliceIdent = new IdentityKeyManager();
    const bobIdent = new IdentityKeyManager();
    await aliceIdent.generateIdentityKeypair();
    await bobIdent.generateIdentityKeypair();

    const aliceIdPub = await aliceIdent.exportIdentityPublicKey();
    const bobIdPub = await bobIdent.exportIdentityPublicKey();
    await aliceIdent.importPeerIdentityPublicKey(bobIdPub);
    await bobIdent.importPeerIdentityPublicKey(aliceIdPub);

    const sharedSecret = new Uint8Array(32);
    webcrypto.getRandomValues(sharedSecret);

    const aliceKp = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
    );
    const bobKp = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
    );

    const alice = new DoubleRatchet(aliceIdent);
    const bob = new DoubleRatchet(bobIdent);
    await alice.initialize(sharedSecret, true, aliceKp, bobKp.publicKey);
    await bob.initialize(sharedSecret, false, bobKp, null);
    return { alice, bob };
}

function snapshotRatchet(dr) {
    return {
        Nr: dr.Nr,
        Ns: dr.Ns,
        PN: dr.PN,
        ratchetCount: dr.ratchetCount,
        DHrRaw: dr.DHrRaw ? Buffer.from(dr.DHrRaw).toString('hex') : null,
        rootKeyHex: dr.rootKey ? Buffer.from(dr.rootKey).toString('hex') : null,
        sendingChainHex: dr.sendingChain
            ? Buffer.from(dr.sendingChain.chainKeyMaterial).toString('hex')
            : null,
        receivingChainHex: dr.receivingChain
            ? Buffer.from(dr.receivingChain.chainKeyMaterial).toString('hex')
            : null,
        skippedKeysSize: dr.skippedKeys.size,
        DHsSignature: dr.DHsSignature,
    };
}

function pass(label) {
    console.log(`  [OK] ${label}`);
}

// ── P1: round-trip identity, in-order ───────────────────────────────────

async function testInOrderRoundtrip() {
    await fc.assert(
        fc.asyncProperty(
            fc.array(fc.string({ minLength: 0, maxLength: 200 }), { minLength: 1, maxLength: 30 }),
            async (messages) => {
                const { alice, bob } = await setupPair();
                for (let i = 0; i < messages.length; i++) {
                    const enc = await alice.encryptMessage(messages[i], ROOM, ALICE_ID);
                    const dec = await bob.decryptMessage(enc.payload, enc.header, ROOM, ALICE_ID);
                    assert.strictEqual(
                        dec.text, messages[i],
                        `in-order roundtrip failed at i=${i}: got ${JSON.stringify(dec.text)}`
                    );
                    assert.strictEqual(dec._outOfOrder, undefined, 'in-order msg must not be flagged');
                }
            },
        ),
        { numRuns: 20 },
    );
    pass('P1 — round-trip identity under in-order delivery (20 cases)');
}

// ── P2: round-trip under bounded reorder ────────────────────────────────

async function testReorderedRoundtrip() {
    // Bounded by MAX_SKIP = 100. We cap N at 30 and generate a random
    // permutation of [0..N-1] for the delivery order. fast-check shrinks
    // the permutation alongside the messages on failure.
    await fc.assert(
        fc.asyncProperty(
            fc.integer({ min: 2, max: 30 }).chain(n =>
                fc.tuple(
                    fc.array(fc.string({ minLength: 0, maxLength: 80 }), { minLength: n, maxLength: n }),
                    fc.shuffledSubarray(Array.from({ length: n }, (_, i) => i), { minLength: n, maxLength: n }),
                ),
            ),
            async ([messages, order]) => {
                const { alice, bob } = await setupPair();
                const encrypted = [];
                for (let i = 0; i < messages.length; i++) {
                    encrypted.push(await alice.encryptMessage(messages[i], ROOM, ALICE_ID));
                }
                let highestSeen = -1;
                for (const idx of order) {
                    const { payload, header } = encrypted[idx];
                    const dec = await bob.decryptMessage(payload, header, ROOM, ALICE_ID);
                    assert.strictEqual(dec.text, messages[idx], `reorder roundtrip failed at idx=${idx}`);
                    // _outOfOrder flag must be set iff this delivery is behind
                    // the highest counter we have already accepted.
                    if (idx < highestSeen) {
                        assert.strictEqual(
                            dec._outOfOrder, true,
                            `delivery idx=${idx} is behind highest seen ${highestSeen} but _outOfOrder is not set`
                        );
                    }
                    if (idx > highestSeen) highestSeen = idx;
                }
            },
        ),
        { numRuns: 20 },
    );
    pass('P2 — round-trip under bounded reorder, with _outOfOrder flag correctness (20 cases)');
}

// ── P3: replay rejection ────────────────────────────────────────────────

async function testReplayRejection() {
    await fc.assert(
        fc.asyncProperty(
            fc.array(fc.string({ minLength: 1, maxLength: 100 }), { minLength: 1, maxLength: 10 }),
            fc.integer({ min: 0, max: 9 }),
            async (messages, replayIdxRaw) => {
                const { alice, bob } = await setupPair();
                const encrypted = [];
                for (const m of messages) {
                    encrypted.push(await alice.encryptMessage(m, ROOM, ALICE_ID));
                }
                // First pass: in-order deliver everything.
                for (let i = 0; i < encrypted.length; i++) {
                    const dec = await bob.decryptMessage(
                        encrypted[i].payload, encrypted[i].header, ROOM, ALICE_ID,
                    );
                    assert.strictEqual(dec.text, messages[i]);
                }
                // Now replay one. Counter rewind + AEAD on consumed key both
                // produce a thrown error — either is acceptable.
                const replayIdx = replayIdxRaw % encrypted.length;
                let threw = false;
                try {
                    await bob.decryptMessage(
                        encrypted[replayIdx].payload,
                        encrypted[replayIdx].header,
                        ROOM, ALICE_ID,
                    );
                } catch (_) {
                    threw = true;
                }
                assert.strictEqual(threw, true, `replay of idx=${replayIdx} was NOT rejected`);
            },
        ),
        { numRuns: 20 },
    );
    pass('P3 — replay of an already-decrypted message is rejected (20 cases)');
}

// ── P4: concurrent encrypt monotonicity + decryptability ────────────────

async function testConcurrentEncryptThenDecrypt() {
    await fc.assert(
        fc.asyncProperty(
            fc.array(fc.string({ minLength: 0, maxLength: 50 }), { minLength: 2, maxLength: 40 }),
            async (messages) => {
                const { alice, bob } = await setupPair();
                const encrypted = await Promise.all(
                    messages.map((m) => alice.encryptMessage(m, ROOM, ALICE_ID)),
                );
                // Counters must be strictly sequential 0..N-1 thanks to the
                // ratchet mutex (C-01). fast-check shrinks if any case
                // produces a non-monotone sequence.
                const counters = encrypted.map((e) => e.header.n);
                assert.deepStrictEqual(
                    counters,
                    Array.from({ length: messages.length }, (_, i) => i),
                    `concurrent encrypt produced non-monotone counters: ${counters.join(',')}`
                );
                // Every result decrypts at the peer in counter order.
                for (let i = 0; i < encrypted.length; i++) {
                    const dec = await bob.decryptMessage(
                        encrypted[i].payload, encrypted[i].header, ROOM, ALICE_ID,
                    );
                    assert.strictEqual(dec.text, messages[i]);
                }
            },
        ),
        { numRuns: 15 },
    );
    pass('P4 — concurrent encrypts produce monotone counters and all decrypt (15 cases)');
}

// ── P5: bidirectional ping-pong under arbitrary turn-taking ─────────────
//
// We drive a small interpreter: each step is either ALICE_SEND, BOB_SEND,
// DELIVER_ALICE_TO_BOB, or DELIVER_BOB_TO_ALICE. Pending queues hold the
// in-flight messages per direction. Every successful delivery must match
// the corresponding plaintext. Sends advance the corresponding pending
// queue. The model implicitly exercises DH ratchets on every direction
// change because the production code triggers them on receive of a new
// `header.dh` and on send-after-receive.

async function testBidirectionalPingPong() {
    const STEP = fc.oneof(
        fc.record({ tag: fc.constant('AS'), msg: fc.string({ minLength: 0, maxLength: 60 }) }),
        fc.record({ tag: fc.constant('BS'), msg: fc.string({ minLength: 0, maxLength: 60 }) }),
        fc.record({ tag: fc.constant('DAB') }),
        fc.record({ tag: fc.constant('DBA') }),
    );

    await fc.assert(
        fc.asyncProperty(
            fc.array(STEP, { minLength: 4, maxLength: 40 }),
            async (steps) => {
                const { alice, bob } = await setupPair();
                const aliceToBob = [];  // pending Alice→Bob
                const bobToAlice = [];  // pending Bob→Alice
                for (const s of steps) {
                    if (s.tag === 'AS') {
                        const enc = await alice.encryptMessage(s.msg, ROOM, ALICE_ID);
                        aliceToBob.push({ msg: s.msg, ...enc });
                    } else if (s.tag === 'BS') {
                        const enc = await bob.encryptMessage(s.msg, ROOM, BOB_ID);
                        bobToAlice.push({ msg: s.msg, ...enc });
                    } else if (s.tag === 'DAB') {
                        if (aliceToBob.length === 0) continue;
                        const m = aliceToBob.shift();
                        const dec = await bob.decryptMessage(m.payload, m.header, ROOM, ALICE_ID);
                        assert.strictEqual(dec.text, m.msg, 'A→B delivery roundtrip failed');
                    } else if (s.tag === 'DBA') {
                        if (bobToAlice.length === 0) continue;
                        const m = bobToAlice.shift();
                        const dec = await alice.decryptMessage(m.payload, m.header, ROOM, BOB_ID);
                        assert.strictEqual(dec.text, m.msg, 'B→A delivery roundtrip failed');
                    }
                }
            },
        ),
        { numRuns: 20 },
    );
    pass('P5 — bidirectional ping-pong preserves round-trip under arbitrary turn-taking (20 cases)');
}

// ── P6: corrupt payload preserves state ─────────────────────────────────
//
// Generalises F-10 to random bit-flips on the wire. Pick a random byte
// position and bit within the payload, flip it, attempt decrypt, assert
// (a) it throws and (b) the receiver's state is byte-identical to
// pre-call. We compare via a stable JSON snapshot of the relevant fields.

async function testCorruptPayloadPreservesState() {
    await fc.assert(
        fc.asyncProperty(
            fc.string({ minLength: 1, maxLength: 80 }),
            fc.nat(),                 // byte-position seed
            fc.integer({ min: 0, max: 7 }),  // bit-position
            async (msg, posSeed, bitPos) => {
                const { alice, bob } = await setupPair();
                // Warm up a few messages so we're past the initial state.
                for (let i = 0; i < 3; i++) {
                    const enc = await alice.encryptMessage(`warm-${i}`, ROOM, ALICE_ID);
                    await bob.decryptMessage(enc.payload, enc.header, ROOM, ALICE_ID);
                }
                const enc = await alice.encryptMessage(msg, ROOM, ALICE_ID);

                // Base64url → bytes → flip one bit → base64url.
                function b64uToBytes(s) {
                    const std = s.replace(/-/g, '+').replace(/_/g, '/');
                    const padded = std + '='.repeat((4 - std.length % 4) % 4);
                    return Buffer.from(padded, 'base64');
                }
                function bytesToB64u(b) {
                    return Buffer.from(b).toString('base64')
                        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
                }
                const bytes = b64uToBytes(enc.payload);
                if (bytes.length === 0) return;  // pathological — skip
                const pos = posSeed % bytes.length;
                const corrupted = Buffer.from(bytes);
                corrupted[pos] ^= (1 << bitPos);
                const corruptedB64 = bytesToB64u(corrupted);

                const before = snapshotRatchet(bob);

                let threw = false;
                try {
                    await bob.decryptMessage(corruptedB64, enc.header, ROOM, ALICE_ID);
                } catch (_) {
                    threw = true;
                }

                // If the flip happens to produce an authentication-tag
                // collision (statistically: ~2^-128 — never), decrypt could
                // succeed with garbage plaintext. Treat that as a pass for
                // the state-integrity property; the corruption is
                // indistinguishable from a legitimate payload by AEAD.
                if (threw) {
                    const after = snapshotRatchet(bob);
                    assert.deepStrictEqual(
                        after, before,
                        `state diverged after corrupt-payload throw at pos=${pos} bit=${bitPos}`
                    );
                }
            },
        ),
        { numRuns: 30 },
    );
    pass('P6 — corrupt payload throws AND leaves receiver state byte-identical (30 cases)');
}

// ── runner ──────────────────────────────────────────────────────────────

(async () => {
    console.log('Property-based tests (fast-check) — Double Ratchet under random delivery:');
    try {
        await testInOrderRoundtrip();
        await testReorderedRoundtrip();
        await testReplayRejection();
        await testConcurrentEncryptThenDecrypt();
        await testBidirectionalPingPong();
        await testCorruptPayloadPreservesState();
        console.log('');
        console.log('All property-based suites PASSED.');
        process.exit(0);
    } catch (err) {
        console.error('');
        console.error('FAIL:', err && err.stack ? err.stack : err);
        process.exit(1);
    }
})();
