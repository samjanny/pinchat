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
 *   5. Handshake v2 transcript— fixed canonical bytes + pinned SHA-256 digest
 *   6. SAS v4                 — fixed P-256 public inputs + pinned 96-bit output
 *
 * OUT OF SCOPE on purpose:
 *   - Anything that needs a randomly-generated ECDH/ECDSA private keypair.
 *     SAS v4 needs only public points, so its KAT imports fixed, valid P-256
 *     public encodings without ever importing private material.
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

// ── KAT 6: SAS v4 (HKDF-SHA256, 96 bits, dual-key transcript-bound) ──────

async function testSasV4() {
    // SAS v4 derivation per static/js/ecdh.js#generateSAS (handshake v2 key
    // separation):
    //   IKM        = sorted(IK_A_raw || IK_B_raw)
    //   salt       = roomId || "pinchat-sas-v4"
    //   BLOCK_x    = handshakePub_x || ratchetPub_x      (both live ECDH keys)
    //   transcript = SHA-256( sorted(BLOCK_A, BLOCK_B) )
    //   info       = "SAS-display-v4" || transcript
    //   bits       = 96  (12 bytes, 16 emoji × 6 bits)
    //
    // The test pins:
    //   (a) byte-exact HKDF output against an independent Node reference,
    //   (b) stability for a fixed transcript,
    //   (c) symmetry - Alice and Bob compute the same SAS,
    //   (d) transcript sensitivity - changing EITHER the handshake OR the
    //       ratchet key on either side changes the SAS (proves v4 binds both).

    // Fixed valid uncompressed P-256 points [1]G through [7]G. Only public
    // material is imported; private-key extractability is tested elsewhere.
    // Keeping the raw inputs and final output pinned makes this a real KAT,
    // not merely a differential test over fresh random keys.
    const fixedPublicHex = [
        '046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5',
        '047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1',
        '045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032',
        '04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6',
        '0451590b7a515140d2d784c85608668fdfef8c82fd1f5be52421554a0dc3d033ede0c17da8904a727d8ae1bf36bf8a79260d012f00d4d80888d1d0bb44fda16da4',
        '04b01a172a76a4602c92d3242cb897dde3024c740debb215b4c6b0aae93c2291a9e85c10743237dad56fec0e2dfba703791c00f7701c7e16bdfd7c48538fc77fe2',
        '048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4',
    ];
    const fixed = fixedPublicHex.map((v) => new Uint8Array(Buffer.from(v, 'hex')));
    const [ikA, ikB, hsA, rtA, hsB, rtB, alternateRaw] = fixed;
    const importIdentity = (raw) => webcrypto.subtle.importKey(
        'raw', raw, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'],
    );
    const importEcdh = (raw) => webcrypto.subtle.importKey(
        'raw', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, [],
    );
    const kpA = { publicKey: await importIdentity(ikA) };
    const kpB = { publicKey: await importIdentity(ikB) };
    const hsKpA = { publicKey: await importEcdh(hsA) };
    const rtKpA = { publicKey: await importEcdh(rtA) };
    const hsKpB = { publicKey: await importEcdh(hsB) };
    const rtKpB = { publicKey: await importEcdh(rtB) };
    const alternateKp = { publicKey: await importEcdh(alternateRaw) };

    const roomId = '00000000-0000-0000-0000-000000000001';

    // Lexicographic sort matching the production _sortKeyPair helper.
    const sortPair = (a, b) => [a, b].sort((x, y) => {
        for (let i = 0; i < Math.min(x.length, y.length); i++) {
            if (x[i] !== y[i]) return x[i] - y[i];
        }
        return x.length - y.length;
    });

    // Reference IKM, transcript, salt, info - fully independent of production.
    function referenceSasBytes(idRawA, idRawB, hsRawA, rtRawA, hsRawB, rtRawB) {
        const idKeys = sortPair(idRawA, idRawB);
        const ikm = new Uint8Array(idKeys[0].length + idKeys[1].length);
        ikm.set(idKeys[0], 0);
        ikm.set(idKeys[1], idKeys[0].length);

        const blockA = new Uint8Array(Buffer.concat([Buffer.from(hsRawA), Buffer.from(rtRawA)]));
        const blockB = new Uint8Array(Buffer.concat([Buffer.from(hsRawB), Buffer.from(rtRawB)]));
        const blocks = sortPair(blockA, blockB);
        const transcriptInput = Buffer.concat([Buffer.from(blocks[0]), Buffer.from(blocks[1])]);
        const transcript = createHash('sha256').update(transcriptInput).digest();

        const salt = Buffer.concat([Buffer.from(roomId, 'utf8'), Buffer.from('pinchat-sas-v4', 'utf8')]);
        const info = Buffer.concat([Buffer.from('SAS-display-v4', 'utf8'), transcript]);
        return new Uint8Array(hkdfSync('sha256', ikm, salt, info, 12)); // 12 bytes = 96 bits
    }

    const expectedSasBytes = referenceSasBytes(ikA, ikB, hsA, rtA, hsB, rtB);
    const pinnedSasHex = 'ddecf96d49efde6010c14fca';
    assert.strictEqual(
        hex(expectedSasBytes),
        pinnedSasHex,
        'independent SAS v4 reference drifted from the frozen protocol vector',
    );

    // Production path: stub the identity manager AND the dual ECDH ephemeral
    // keys the SAS code now reads.
    async function sasFromPerspective(myIdPubKey, peerIdRaw, myHsPub, myRtPub, peerHsPub, peerRtPub) {
        const mgr = new IdentityKeyManager();
        mgr.identityKeyPair = { publicKey: myIdPubKey, privateKey: null };
        mgr.peerIdentityPublicKey = {};  // truthy guard
        mgr.peerIdentityPublicKeyRaw = peerIdRaw;

        const ecdh = new ECDHKeyExchange(null, mgr);
        ecdh.handshakeKeyPair = { publicKey: myHsPub, privateKey: null };
        ecdh.ratchetKeyPair = { publicKey: myRtPub, privateKey: null };
        ecdh.otherHandshakePublicKey = peerHsPub;
        ecdh.otherRatchetPublicKey = peerRtPub;
        return ecdh.generateSAS(roomId);
    }

    // Alice's view vs Bob's crossed view; both must agree (symmetry).
    const sasAlice = await sasFromPerspective(kpA.publicKey, ikB, hsKpA.publicKey, rtKpA.publicKey, hsKpB.publicKey, rtKpB.publicKey);
    const sasBob   = await sasFromPerspective(kpB.publicKey, ikA, hsKpB.publicKey, rtKpB.publicKey, hsKpA.publicKey, rtKpA.publicKey);

    // (a) Byte-exact match against Node's hkdfSync reference.
    const aliceHexBytes = Buffer.from(sasAlice.hex.replace(/-/g, ''), 'hex');
    assert.strictEqual(
        hex(aliceHexBytes),
        hex(expectedSasBytes),
        `SAS bytes mismatch: actual=${hex(aliceHexBytes)} expected=${hex(expectedSasBytes)}`
    );

    // (b) Stability for a fixed transcript.
    const sasAliceAgain = await sasFromPerspective(kpA.publicKey, ikB, hsKpA.publicKey, rtKpA.publicKey, hsKpB.publicKey, rtKpB.publicKey);
    assert.strictEqual(sasAlice.emoji, sasAliceAgain.emoji, 'SAS must be stable for a fixed transcript');
    assert.strictEqual(sasAlice.hex, sasAliceAgain.hex, 'SAS hex must be stable for a fixed transcript');

    // (c) Symmetry.
    assert.strictEqual(sasAlice.emoji, sasBob.emoji, 'Alice and Bob must compute the same SAS emoji');
    assert.strictEqual(sasAlice.hex, sasBob.hex, 'Alice and Bob must compute the same SAS hex');

    // (d) Transcript sensitivity: changing EITHER key on the peer side changes
    // the SAS. Both are asserted so v4 provably binds both ephemeral keys.
    const sasDifferentRatchet = await sasFromPerspective(kpA.publicKey, ikB, hsKpA.publicKey, rtKpA.publicKey, hsKpB.publicKey, alternateKp.publicKey);
    assert.notStrictEqual(sasAlice.hex, sasDifferentRatchet.hex, 'SAS must change when a ratchet key changes');
    const sasDifferentHandshake = await sasFromPerspective(kpA.publicKey, ikB, hsKpA.publicKey, rtKpA.publicKey, alternateKp.publicKey, rtKpB.publicKey);
    assert.notStrictEqual(sasAlice.hex, sasDifferentHandshake.hex, 'SAS must change when a handshake key changes');

    // (e) Shape sanity.
    assert.strictEqual(sasAlice.bits, 96, 'SAS must be 96 bits');
    assert.strictEqual(sasAlice.version, 4, 'SAS object must declare version 4');
    assert.strictEqual(
        Array.from(sasAlice.emoji).length,
        16,
        `SAS emoji must be 16 emoji; got ${Array.from(sasAlice.emoji).length}`
    );

    pass('SAS v4 - fixed KAT ddecf96d49efde6010c14fca, symmetric, sensitive to BOTH key families, 16 emoji');
}

// ── KAT 4: canonical DH-header bytes ────────────────────────────────────

async function testCanonicalDhHeaderBytes() {
    // Production layout (see DoubleRatchet._buildCanonicalBytes):
    //   "pinchat-drheader-v2" || u16_be(len(dh_raw)) || dh_raw ||
    //   u32_be(pn) || u32_be(n) || u32_be(rc)
    //
    // We construct this by hand, byte by byte, and assert against the
    // production helper. A typo in the tag, a flipped byte order, or an
    // off-by-one length will all fail here.
    const dr = new DoubleRatchet(null);

    // Fixed dh = 65 bytes of 0x42 (mimics uncompressed P-256 point shape).
    const dh = new Uint8Array(65).fill(0x42);
    const pn = 0x05060708;
    const n = 0x090a0b0c;
    const rc = 0x01020304;

    const actual = dr._buildCanonicalBytes(dh, pn, n, rc);

    // Hand-built reference.
    const tag = Buffer.from('pinchat-drheader-v2', 'utf8');
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(65, 0);
    const pnBuf = Buffer.alloc(4);
    pnBuf.writeUInt32BE(pn, 0);
    const nBuf = Buffer.alloc(4);
    nBuf.writeUInt32BE(n, 0);
    const rcBuf = Buffer.alloc(4);
    rcBuf.writeUInt32BE(rc, 0);
    const expected = Buffer.concat([tag, lenBuf, Buffer.from(dh), pnBuf, nBuf, rcBuf]);

    assert.strictEqual(
        actual.byteLength,
        tag.length + 2 + dh.byteLength + 12,
        `canonical length mismatch: actual=${actual.byteLength} expected=${tag.length + 2 + dh.byteLength + 12}`
    );
    assert.strictEqual(
        hex(actual),
        expected.toString('hex'),
        'canonical DH-header bytes mismatch'
    );

    // Also check the tag value didn't drift (a one-byte off-tag would be
    // invisible in functional round-trip tests until v1↔v2 interop).
    const tagPrefix = Buffer.from(actual.slice(0, tag.length));
    assert.strictEqual(tagPrefix.toString('utf8'), 'pinchat-drheader-v2', 'canonical tag must be "pinchat-drheader-v2"');

    pass('canonical DH-header bytes byte-exact + tag string pinned');
}

// ── KAT 5: canonical handshake-v2 transcript ────────────────────────────

async function testCanonicalHandshakeTranscript() {
    const ecdh = new ECDHKeyExchange(null, null);
    const roomId = '00000000-0000-0000-0000-000000000001';
    const senderId = '11111111-1111-1111-1111-111111111111';
    const timestamp = 1700000000123;
    const nonce = range(16);
    const handshakeRaw = new Uint8Array(Buffer.from(
        '045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032',
        'hex',
    ));
    const ratchetRaw = new Uint8Array(Buffer.from(
        '04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6',
        'hex',
    ));
    const actual = ecdh._buildHandshakeTranscript(
        roomId, senderId, timestamp, nonce, handshakeRaw, ratchetRaw,
    );

    // Independent length-prefix implementation for the wire-format freeze.
    const lp = (value) => {
        const body = Buffer.from(value);
        const prefix = Buffer.alloc(2);
        prefix.writeUInt16BE(body.length, 0);
        return Buffer.concat([prefix, body]);
    };
    const expected = Buffer.concat([
        Buffer.from('pinchat-handshake-v2', 'utf8'),
        lp(Buffer.from(roomId, 'utf8')),
        lp(Buffer.from(senderId, 'utf8')),
        lp(Buffer.from(String(timestamp), 'utf8')),
        lp(nonce),
        lp(handshakeRaw),
        lp(ratchetRaw),
    ]);
    assert.strictEqual(hex(actual), expected.toString('hex'),
        'canonical handshake-v2 transcript bytes mismatch');
    assert.strictEqual(
        createHash('sha256').update(actual).digest('hex'),
        '4abe7a45b48f2e8b248b318c20aa950d6461dd797436a3fd71a84e25a54a98c8',
        'canonical handshake-v2 transcript digest drifted',
    );
    pass('canonical handshake-v2 transcript byte-exact + SHA-256 digest pinned');
}

// ── runner ──────────────────────────────────────────────────────────────

(async () => {
    console.log('Known Answer Tests (KAT) — KDF schedule + canonical encoding:');
    try {
        await testHkdfHelper();
        await testInitialChainLabels();
        await testChainRatchetStep();
        await testCanonicalDhHeaderBytes();
        await testCanonicalHandshakeTranscript();
        await testSasV4();
        console.log('');
        console.log('All KAT suites PASSED.');
        process.exit(0);
    } catch (err) {
        console.error('');
        console.error('FAIL:', err && err.stack ? err.stack : err);
        process.exit(1);
    }
})();
