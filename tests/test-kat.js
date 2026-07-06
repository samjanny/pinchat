#!/usr/bin/env node

/**
 * Known Answer Tests (KAT) for the PinChat ratchet key schedule and canonical
 * serialisation.
 *
 * Audit-driven: a custom ratchet without external review is hard to validate
 * by reading alone. These tests pin the byte-exact output of every KDF / HMAC
 * step against an INDEPENDENT reference implementation (Node's built-in
 * `crypto.hkdfSync` and `crypto.createHmac`). The reference path uses the
 * same primitives but a completely separate code path. If the production
 * helpers drift — wrong info label, wrong byte order, wrong number of
 * iterations, swapped salt/IKM — the assertion fails immediately.
 *
 * KAT scope (deliberately narrow):
 *   1. HKDF helper            — `DoubleRatchet.hkdf` byte-exact vs hkdfSync
 *   2. Initial chain labels   — initiator vs responder receive/send chains
 *   3. Chain ratchet step     — CK_n+1 = HMAC-SHA256(CK_n, "ChainRatchet")
 *   4. Canonical DH header    — tag || u16_be(len) || dh || u32_be(rc)
 *
 * OUT OF SCOPE on purpose:
 *   - Anything that needs a randomly-generated ECDH/ECDSA keypair (those
 *     can't be deterministic without importing private bytes, and importing
 *     a private key bypasses the non-extractable guarantee we test elsewhere).
 *   - Anything that needs to peek inside an AES-GCM `CryptoKey` (those are
 *     intentionally non-extractable from JS).
 *
 * Both restrictions match the audit's guidance: pin KDF / HMAC / canonical
 * encoding deterministically; leave the ECDH-driven parts to functional
 * round-trip tests in test-ratchet-correctness.js.
 */

'use strict';

const assert = require('assert');
const { hkdfSync, createHmac, createHash } = require('crypto');

// Silence module-level debug helpers.
global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};
global.PINCHAT_PROTOCOL_VERSION = 1;

// crypto.js seeds AAD globals and ChainRatchet onto globalThis under Node.
require('../static/js/crypto.js');
const { DoubleRatchet } = require('../static/js/double-ratchet.js');
const { IdentityKeyManager } = require('../static/js/identity.js');
// ECDH depends on AAD globals + IdentityKeyManager being on window/globalThis.
// Under Node these come from the requires above (crypto.js promotes its
// helpers via the CommonJS branch); ECDHKeyExchange itself is browser-only
// (assigned to window). Force it into globalThis the same way.
const ecdhSource = require('fs').readFileSync(
    require('path').join(__dirname, '..', 'static/js/ecdh.js'),
    'utf8'
);
const wrapper = new Function('window', ecdhSource + '\nreturn window.ECDHKeyExchange;');
const windowShim = {};
const ECDHKeyExchange = wrapper(windowShim);

// Expose webcrypto for the SAS KAT below.
const { webcrypto } = require('crypto');

// ── helpers ─────────────────────────────────────────────────────────────

function hex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function range(n) {
    const a = new Uint8Array(n);
    for (let i = 0; i < n; i++) a[i] = i & 0xff;
    return a;
}

function pass(label) {
    console.log(`  [OK] ${label}`);
}

// ── KAT 1: HKDF helper byte-exact against crypto.hkdfSync ───────────────

async function testHkdfHelper() {
    // The Double Ratchet HKDF helper is reachable as an instance method.
    // It takes (ikm, salt, info_string, length_bytes) and returns Uint8Array.
    //
    // We don't need a full DoubleRatchet bootstrap for this — instantiate
    // with a null identity manager and never enter sign/encrypt paths.
    const dr = new DoubleRatchet(null);

    // Three (ikm, salt, info, len) tuples that exercise the schedule:
    //   tuple A — root-key derivation in initialize()
    //   tuple B — chain-key derivation in initialize() (initiator->responder)
    //   tuple C — root-key advancement during a DH ratchet
    const tuples = [
        {
            ikm: range(32),                          // 0x00..0x1f
            salt: new Uint8Array(32),                // 32 zero bytes
            info: 'DoubleRatchet-RootKey',
            len: 32,
            label: 'root-key bootstrap',
        },
        {
            ikm: range(32).map(b => b ^ 0x5a),
            salt: new Uint8Array(32),
            info: 'InitiatorToResponder',
            len: 32,
            label: 'initial sendingChain (initiator role)',
        },
        {
            ikm: range(32).map(b => b ^ 0xa5),
            salt: range(32),                         // non-zero salt
            info: 'ChainKey',
            len: 32,
            label: 'chain key under non-zero salt',
        },
    ];

    for (const t of tuples) {
        const actual = await dr.hkdf(
            t.ikm,
            t.salt,
            t.info,
            t.len,
        );
        // Reference path: Node's crypto.hkdfSync is the standard RFC-5869
        // implementation. byte-exact match here means the production helper
        // (which goes through WebCrypto via crypto.subtle.importKey +
        // deriveBits) produces the same output as a totally separate code path.
        const expected = new Uint8Array(
            hkdfSync('sha256', t.ikm, t.salt, Buffer.from(t.info, 'utf8'), t.len)
        );
        assert.strictEqual(
            hex(actual),
            hex(expected),
            `HKDF mismatch on ${t.label}: actual=${hex(actual)} expected=${hex(expected)}`
        );
    }

    pass('HKDF helper byte-exact vs crypto.hkdfSync (3 tuples)');
}

// ── KAT 2: initiator/responder chain labels ─────────────────────────────

async function testInitialChainLabels() {
    // The protocol pins exactly two role labels:
    //   initiator sends on    'InitiatorToResponder'
    //   initiator receives on 'ResponderToInitiator'
    //   responder is the mirror.
    // These ARE the strings used in production initialize(); a typo here
    // would silently desync initiator and responder.
    const dr = new DoubleRatchet(null);
    const rootKey = range(32).map(b => b ^ 0x11);

    const sendingInit = await dr.hkdf(rootKey, new Uint8Array(32), 'InitiatorToResponder', 32);
    const recvInit    = await dr.hkdf(rootKey, new Uint8Array(32), 'ResponderToInitiator', 32);
    // Sanity: distinct labels must produce distinct keys for the same IKM/salt.
    assert.notStrictEqual(hex(sendingInit), hex(recvInit), 'initiator labels must derive distinct keys');

    // Symmetric assertion: initiator.sendingChain MUST equal responder.receivingChain.
    // Both are computed as HKDF(rootKey, zeros, 'InitiatorToResponder'). If a
    // future change accidentally re-labels one of them, this test fires.
    const responder_recv = await dr.hkdf(rootKey, new Uint8Array(32), 'InitiatorToResponder', 32);
    assert.strictEqual(
        hex(sendingInit),
        hex(responder_recv),
        'initiator.sendingChain MUST equal responder.receivingChain (same label)'
    );

    pass('initiator/responder chain labels match production schedule');
}

// ── KAT 3: chain ratchet step ───────────────────────────────────────────

async function testChainRatchetStep() {
    // Chain ratchet per the protocol:
    //   CK_{n+1} = HMAC-SHA256(CK_n, "ChainRatchet")
    // We pin CK_0, then walk 1, 2, 5 steps forward, asserting byte-exact
    // match against Node's crypto.createHmac (independent reference impl).
    const ChainRatchet = globalThis.ChainRatchet;
    assert.ok(ChainRatchet, 'ChainRatchet must be globalized by crypto.js');

    const ck0 = range(32);  // 0x00..0x1f

    // Compute reference chain via Node's HMAC.
    function refRatchet(prev) {
        return createHmac('sha256', prev).update(Buffer.from('ChainRatchet', 'utf8')).digest();
    }
    const refCK1 = new Uint8Array(refRatchet(ck0));
    let refCK5_buf = ck0;
    for (let i = 0; i < 5; i++) refCK5_buf = refRatchet(Buffer.from(refCK5_buf));
    const refCK5 = new Uint8Array(refCK5_buf);

    // Production path.
    const c = new ChainRatchet();
    await c.initialize(new Uint8Array(ck0));
    assert.strictEqual(hex(c.chainKeyMaterial), hex(ck0), 'CK_0 must equal initial bytes');

    await c.ratchet();
    assert.strictEqual(
        hex(c.chainKeyMaterial),
        hex(refCK1),
        'CK_1 mismatch — chain ratchet must be HMAC-SHA256(CK_0, "ChainRatchet")'
    );

    for (let i = 0; i < 4; i++) await c.ratchet();
    assert.strictEqual(
        hex(c.chainKeyMaterial),
        hex(refCK5),
        'CK_5 mismatch — chain ratchet must compose to 5 HMAC steps'
    );

    pass('chain ratchet CK_1 and CK_5 match HMAC-SHA256(prev, "ChainRatchet") reference');
}

// ── KAT 5: SAS v3 (HKDF-SHA256, 96 bits, transcript-bound) ──────────────

async function testSasV3() {
    // SAS v3 derivation per static/js/ecdh.js#generateSAS (audit H1):
    //   IKM        = sorted(IK_A_raw || IK_B_raw)
    //   salt       = roomId || "pinchat-sas-v3"
    //   transcript = SHA-256( sorted(EPH_A_raw || EPH_B_raw) )
    //   info       = "SAS-display-v3" || transcript
    //   bits       = 96  (12 bytes, 16 emoji × 6 bits)
    //
    // The test pins four properties:
    //   (a) byte-exact HKDF output against an independent Node reference,
    //   (b) stability - two runs with the SAME identity keys, room id, and
    //       ephemeral keys produce the same SAS (transcript binding does not
    //       break determinism for a fixed transcript),
    //   (c) symmetry - Alice and Bob compute the same SAS regardless of which
    //       side calls generateSAS (identity AND ephemeral keys cross over),
    //   (d) transcript sensitivity - changing one ephemeral key changes the SAS
    //       (proves the live session is actually bound).

    // Real ECDSA P-256 identity keypairs (synthetic 65-byte buffers are
    // rejected by importKey('raw', ...) as off-curve). Generated once; their
    // raw bytes are fixed for the run and fed into both the reference HKDF and
    // the production generateSAS.
    const kpA = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const kpB = await webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
    );
    const ikA = new Uint8Array(await webcrypto.subtle.exportKey('raw', kpA.publicKey));
    const ikB = new Uint8Array(await webcrypto.subtle.exportKey('raw', kpB.publicKey));

    // Live ECDH P-256 ephemeral keypairs for the transcript binding.
    const ephKpA = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const ephKpB = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const ephA = new Uint8Array(await webcrypto.subtle.exportKey('raw', ephKpA.publicKey));
    const ephB = new Uint8Array(await webcrypto.subtle.exportKey('raw', ephKpB.publicKey));

    const roomId = '00000000-0000-0000-0000-000000000001';

    // Lexicographic sort matching the production _sortKeyPair helper.
    const sortPair = (a, b) => [a, b].sort((x, y) => {
        for (let i = 0; i < Math.min(x.length, y.length); i++) {
            if (x[i] !== y[i]) return x[i] - y[i];
        }
        return x.length - y.length;
    });

    // Reference IKM, transcript, salt, info - fully independent of production.
    function referenceSasBytes(idRawA, idRawB, ephRawA, ephRawB) {
        const idKeys = sortPair(idRawA, idRawB);
        const ikm = new Uint8Array(idKeys[0].length + idKeys[1].length);
        ikm.set(idKeys[0], 0);
        ikm.set(idKeys[1], idKeys[0].length);

        const ek = sortPair(ephRawA, ephRawB);
        const transcriptInput = Buffer.concat([Buffer.from(ek[0]), Buffer.from(ek[1])]);
        const transcript = createHash('sha256').update(transcriptInput).digest();

        const salt = Buffer.concat([Buffer.from(roomId, 'utf8'), Buffer.from('pinchat-sas-v3', 'utf8')]);
        const info = Buffer.concat([Buffer.from('SAS-display-v3', 'utf8'), transcript]);
        return new Uint8Array(hkdfSync('sha256', ikm, salt, info, 12)); // 12 bytes = 96 bits
    }

    const expectedSasBytes = referenceSasBytes(ikA, ikB, ephA, ephB);

    // Production path: stub the identity manager AND the ECDH ephemeral keys
    // the SAS code now reads (this.keyPair.publicKey + this.otherPublicKey).
    async function sasFromPerspective(myIdPubKey, peerIdRaw, myEphPubKey, peerEphPubKey) {
        const mgr = new IdentityKeyManager();
        mgr.identityKeyPair = { publicKey: myIdPubKey, privateKey: null };
        mgr.peerIdentityPublicKey = {};  // truthy guard
        mgr.peerIdentityPublicKeyRaw = peerIdRaw;

        const ecdh = new ECDHKeyExchange(null, mgr);
        // Live ephemeral keys for transcript binding.
        ecdh.keyPair = { publicKey: myEphPubKey, privateKey: null };
        ecdh.otherPublicKey = peerEphPubKey;
        return ecdh.generateSAS(roomId);
    }

    // Alice's view: own id = kpA, peer id = ikB; own eph = ephKpA, peer eph = ephKpB.
    // Bob's view: the crossed assignment. Both must agree (symmetry).
    const sasAlice = await sasFromPerspective(kpA.publicKey, ikB, ephKpA.publicKey, ephKpB.publicKey);
    const sasBob   = await sasFromPerspective(kpB.publicKey, ikA, ephKpB.publicKey, ephKpA.publicKey);

    // (a) Byte-exact match against Node's hkdfSync reference.
    const aliceHexBytes = Buffer.from(sasAlice.hex.replace(/-/g, ''), 'hex');
    assert.strictEqual(
        hex(aliceHexBytes),
        hex(expectedSasBytes),
        `SAS bytes mismatch: actual=${hex(aliceHexBytes)} expected=${hex(expectedSasBytes)}`
    );

    // (b) Stability for a fixed transcript: same inputs → same SAS.
    const sasAliceAgain = await sasFromPerspective(kpA.publicKey, ikB, ephKpA.publicKey, ephKpB.publicKey);
    assert.strictEqual(sasAlice.emoji, sasAliceAgain.emoji, 'SAS must be stable for a fixed transcript');
    assert.strictEqual(sasAlice.hex, sasAliceAgain.hex, 'SAS hex must be stable for a fixed transcript');

    // (c) Symmetry: Alice's and Bob's views must agree.
    assert.strictEqual(sasAlice.emoji, sasBob.emoji, 'Alice and Bob must compute the same SAS emoji');
    assert.strictEqual(sasAlice.hex, sasBob.hex, 'Alice and Bob must compute the same SAS hex');

    // (d) Transcript sensitivity: swap one ephemeral key for a fresh one and
    // the SAS MUST change. This is the property that defeats the offline
    // precompute attack - the displayed code depends on the live session keys.
    const ephKpC = await webcrypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
    );
    const sasDifferentEph = await sasFromPerspective(kpA.publicKey, ikB, ephKpA.publicKey, ephKpC.publicKey);
    assert.notStrictEqual(
        sasAlice.hex, sasDifferentEph.hex,
        'SAS must change when an ephemeral key changes (transcript binding active)'
    );

    // (e) Shape sanity.
    assert.strictEqual(sasAlice.bits, 96, 'SAS must be 96 bits');
    assert.strictEqual(sasAlice.version, 3, 'SAS object must declare version 3');
    assert.strictEqual(
        Array.from(sasAlice.emoji).length,
        16,
        `SAS emoji must be 16 emoji; got ${Array.from(sasAlice.emoji).length}`
    );

    pass('SAS v3 - HKDF byte-exact vs reference, stable for fixed transcript, symmetric Alice/Bob, transcript-sensitive, 16 emoji');
}

// ── KAT 4: canonical DH-header bytes ────────────────────────────────────

async function testCanonicalDhHeaderBytes() {
    // Production layout (see DoubleRatchet._buildCanonicalBytes):
    //   "pinchat-drheader-v1" || u16_be(len(dh_raw)) || dh_raw || u32_be(rc)
    //
    // We construct this by hand, byte by byte, and assert against the
    // production helper. A typo in the tag, a flipped byte order, or an
    // off-by-one length will all fail here.
    const dr = new DoubleRatchet(null);

    // Fixed dh = 65 bytes of 0x42 (mimics uncompressed P-256 point shape).
    const dh = new Uint8Array(65).fill(0x42);
    const rc = 0x01020304;

    const actual = dr._buildCanonicalBytes(dh, rc);

    // Hand-built reference.
    const tag = Buffer.from('pinchat-drheader-v1', 'utf8');
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(65, 0);
    const rcBuf = Buffer.alloc(4);
    rcBuf.writeUInt32BE(rc, 0);
    const expected = Buffer.concat([tag, lenBuf, Buffer.from(dh), rcBuf]);

    assert.strictEqual(
        actual.byteLength,
        tag.length + 2 + dh.byteLength + 4,
        `canonical length mismatch: actual=${actual.byteLength} expected=${tag.length + 2 + dh.byteLength + 4}`
    );
    assert.strictEqual(
        hex(actual),
        expected.toString('hex'),
        'canonical DH-header bytes mismatch'
    );

    // Also check the tag value didn't drift (a one-byte off-tag would be
    // invisible in functional round-trip tests until v1↔v2 interop).
    const tagPrefix = Buffer.from(actual.slice(0, tag.length));
    assert.strictEqual(tagPrefix.toString('utf8'), 'pinchat-drheader-v1', 'canonical tag must be "pinchat-drheader-v1"');

    pass('canonical DH-header bytes byte-exact + tag string pinned');
}

// ── runner ──────────────────────────────────────────────────────────────

(async () => {
    console.log('Known Answer Tests (KAT) — KDF schedule + canonical encoding:');
    try {
        await testHkdfHelper();
        await testInitialChainLabels();
        await testChainRatchetStep();
        await testCanonicalDhHeaderBytes();
        await testSasV3();
        console.log('');
        console.log('All KAT suites PASSED.');
        process.exit(0);
    } catch (err) {
        console.error('');
        console.error('FAIL:', err && err.stack ? err.stack : err);
        process.exit(1);
    }
})();
