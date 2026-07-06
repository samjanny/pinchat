/**
 * Coverage-guided fuzz target for the Double Ratchet decrypt path.
 *
 * Fuzz strategy
 * -------------
 * Each iteration draws bytes from libFuzzer (via @jazzer.js/core's
 * FuzzedDataProvider) and shapes them into a plausible `(header, payload)`
 * pair, then drives `bob.decryptMessage(...)` on a warmed-up DR pair.
 *
 * The warm-up runs ONCE at module load: three legitimate in-order
 * Alice→Bob messages, just enough to push Bob past the "first-message"
 * branch in `_decryptMessageImpl`. We snapshot Bob's state at that
 * point and restore from the snapshot before every iteration, so each
 * iteration starts from the same well-defined state and the fuzzer
 * isn't chasing an ever-evolving model.
 *
 * Invariants asserted per iteration
 * ---------------------------------
 *   1. NO uncaught exception / unhandled rejection. Any error must
 *      surface synchronously to libFuzzer through `throw`. Async
 *      rejections that escape would mark the JS process unhealthy
 *      and the fuzzer would not see them — `process.on('unhandledRejection')`
 *      below promotes them into thrown findings.
 *
 *   2. STATE INTEGRITY on a thrown decrypt. After
 *      `await bob.decryptMessage(...)` rejects, Bob's complete state
 *      (Nr, Ns, PN, ratchetCount, root key bytes, both chain key bytes,
 *      DHrRaw, DHsSignature, skippedKeys size, hasRatchetedSinceReceive)
 *      MUST be byte-identical to the post-warm-up snapshot. This is the
 *      universal version of F-10 — every decrypt failure must leave the
 *      ratchet untouched. A drift here is a real bug.
 *
 *   3. NO unexpected success. Random bytes cannot, by AEAD assumption,
 *      authenticate against our chain key + AAD. If `decryptMessage`
 *      returns instead of throwing, we surface that to the fuzzer as a
 *      finding (could be a tag collision at ~2^-128, or a real bug).
 *
 * Out of scope
 * ------------
 * - Encrypt-side fuzzing: encrypt inputs are caller-provided (plaintext
 *   string, room id, sender id). The decrypt path is where untrusted
 *   peer input lives.
 * - ECDH handshake: `decryptPublicKey` has its own AAD-validated path,
 *   could be a future target.
 */

'use strict';

const { FuzzedDataProvider } = require('@jazzer.js/core');
const { webcrypto } = require('crypto');

global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};
global.PINCHAT_PROTOCOL_VERSION = 1;

require('../../static/js/crypto.js');
const { IdentityKeyManager } = require('../../static/js/identity.js');
const { DoubleRatchet } = require('../../static/js/double-ratchet.js');

const ROOM = '00000000-0000-0000-0000-000000000001';
const ALICE_ID = '11111111-1111-1111-1111-111111111111';

let bob = null;
let warmSnapshot = null;
let warmStateProbe = null;

// ── warm-up: set up Alice+Bob, deliver 3 messages, snapshot Bob ────────

async function warmUp() {
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
    bob = new DoubleRatchet(bobIdent);
    await alice.initialize(sharedSecret, true, aliceKp, bobKp.publicKey);
    await bob.initialize(sharedSecret, false, bobKp, null);

    for (let i = 0; i < 3; i++) {
        const enc = await alice.encryptMessage(`warm-${i}`, ROOM, ALICE_ID);
        await bob.decryptMessage(enc.payload, enc.header, ROOM, ALICE_ID);
    }

    warmSnapshot = snapshotForRestore(bob);
    warmStateProbe = stableStateProbe(bob);
}

function snapshotForRestore(dr) {
    return {
        Nr: dr.Nr,
        Ns: dr.Ns,
        PN: dr.PN,
        ratchetCount: dr.ratchetCount,
        DHr: dr.DHr,
        DHrRaw: dr.DHrRaw ? new Uint8Array(dr.DHrRaw) : null,
        DHs: dr.DHs,
        DHsSignature: dr.DHsSignature,
        rootKey: dr.rootKey ? new Uint8Array(dr.rootKey) : null,
        sendingChain: dr.sendingChain ? dr.sendingChain.clone() : null,
        receivingChain: dr.receivingChain ? dr.receivingChain.clone() : null,
        skippedKeys: new Map(dr.skippedKeys),
        hasRatchetedSinceReceive: dr.hasRatchetedSinceReceive,
        maxRatchetSeen: dr.maxRatchetSeen,
        maxCounterSeen: dr.maxCounterSeen,
    };
}

function restoreFromSnapshot(dr, snap) {
    dr.Nr = snap.Nr;
    dr.Ns = snap.Ns;
    dr.PN = snap.PN;
    dr.ratchetCount = snap.ratchetCount;
    dr.DHr = snap.DHr;
    dr.DHrRaw = snap.DHrRaw ? new Uint8Array(snap.DHrRaw) : null;
    dr.DHs = snap.DHs;
    dr.DHsSignature = snap.DHsSignature;
    dr.rootKey = snap.rootKey ? new Uint8Array(snap.rootKey) : null;
    dr.sendingChain = snap.sendingChain ? snap.sendingChain.clone() : null;
    dr.receivingChain = snap.receivingChain ? snap.receivingChain.clone() : null;
    dr.skippedKeys = new Map(snap.skippedKeys);
    dr.hasRatchetedSinceReceive = snap.hasRatchetedSinceReceive;
    dr.maxRatchetSeen = snap.maxRatchetSeen;
    dr.maxCounterSeen = snap.maxCounterSeen;
}

// Stable, comparable probe of the state. We don't compare the snapshot
// objects directly (CryptoKey references differ across snapshot+restore)
// but rather the bytes of the mutable fields that a misbehaving decrypt
// could disturb.
function stableStateProbe(dr) {
    return JSON.stringify({
        Nr: dr.Nr,
        Ns: dr.Ns,
        PN: dr.PN,
        rc: dr.ratchetCount,
        skipN: dr.skippedKeys.size,
        hrsr: dr.hasRatchetedSinceReceive,
        sig: dr.DHsSignature,
        DHrRaw: dr.DHrRaw ? Buffer.from(dr.DHrRaw).toString('hex') : null,
        root: dr.rootKey ? Buffer.from(dr.rootKey).toString('hex') : null,
        sChain: dr.sendingChain ? Buffer.from(dr.sendingChain.chainKeyMaterial).toString('hex') : null,
        rChain: dr.receivingChain ? Buffer.from(dr.receivingChain.chainKeyMaterial).toString('hex') : null,
        sChainN: dr.sendingChain ? dr.sendingChain.messageNumber : null,
        rChainN: dr.receivingChain ? dr.receivingChain.messageNumber : null,
    });
}

// ── input construction ─────────────────────────────────────────────────

function toB64u(bytes) {
    return Buffer.from(bytes).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function buildInputs(fdp) {
    // Header version: usually 1 (the only accepted value), but occasionally
    // a random byte to exercise the rejection path.
    const vRoll = fdp.consumeIntegralInRange(0, 9);
    const v = vRoll < 8 ? 1 : fdp.consumeIntegralInRange(0, 255);

    // dh: P-256 raw uncompressed export is 65 bytes → 87 base64url chars.
    // The fuzzer should mostly produce strings of plausible length to
    // exercise the verify path; occasionally weird lengths to exercise
    // parse/reject branches.
    const dhLen = fdp.consumeIntegralInRange(0, 200);
    const dhBytes = fdp.consumeBytes(dhLen);
    const dh = toB64u(dhBytes);

    // sig: ECDSA P-256 raw is 64 bytes → 86 base64url chars.
    const sigLen = fdp.consumeIntegralInRange(0, 200);
    const sigBytes = fdp.consumeBytes(sigLen);
    const sig = toB64u(sigBytes);

    const pn = fdp.consumeIntegralInRange(0, 0xffff);
    const n = fdp.consumeIntegralInRange(0, 0xffff);
    const rc = fdp.consumeIntegralInRange(0, 0xffff);

    const header = { v, dh, pn, n, rc, sig };

    // Payload: AES-GCM ciphertext is iv(12) + ct + tag(16), so minimum 28
    // bytes for the production format. Fuzz from 0 to ~256 bytes.
    const payloadLen = fdp.consumeIntegralInRange(0, 256);
    const payload = toB64u(fdp.consumeBytes(payloadLen));

    return { header, payload };
}

// ── unhandled-rejection promotion ───────────────────────────────────────
// Async work inside _decryptMessageImpl can throw across `await` points.
// Our `try/catch` around `bob.decryptMessage(...)` already turns rejected
// Promises into local catches. But if the production code accidentally
// fires-and-forgets a Promise (e.g. a setTimeout micro-task), the
// rejection would escape to process-level. Wire those into the iteration
// so jazzer-js sees them as findings.
let pendingUnhandled = null;
process.on('unhandledRejection', (reason) => {
    pendingUnhandled = reason;
});

// ── fuzz entry point ───────────────────────────────────────────────────

async function fuzz(data) {
    if (bob === null) {
        await warmUp();
    }

    pendingUnhandled = null;

    // Restore Bob to the post-warm-up snapshot so this iteration is
    // independent of the previous one.
    restoreFromSnapshot(bob, warmSnapshot);

    const fdp = new FuzzedDataProvider(data);
    const { header, payload } = buildInputs(fdp);

    let threw = false;
    let returned = false;
    try {
        await bob.decryptMessage(payload, header, ROOM, ALICE_ID);
        returned = true;
    } catch (_) {
        threw = true;
    }

    // Any unhandled rejection that snuck out becomes a finding.
    if (pendingUnhandled !== null) {
        const reason = pendingUnhandled;
        pendingUnhandled = null;
        throw new Error(`Unhandled rejection escaped decryptMessage: ${reason}`);
    }

    if (returned) {
        // Random bytes authenticating against a real AEAD key + AAD has
        // probability ~2^-128. If we ever hit this, log the input and
        // mark as a finding for investigation. The Buffer is short.
        throw new Error(
            'UNEXPECTED_SUCCESS: random input decrypted. ' +
            `header=${JSON.stringify(header)} payload(b64u)=${payload}`
        );
    }

    if (threw) {
        const after = stableStateProbe(bob);
        if (after !== warmStateProbe) {
            throw new Error(
                'STATE_DIVERGED after thrown decrypt.\n' +
                `before: ${warmStateProbe}\n` +
                `after:  ${after}\n` +
                `header: ${JSON.stringify(header)}`
            );
        }
    }
}

module.exports.fuzz = fuzz;
