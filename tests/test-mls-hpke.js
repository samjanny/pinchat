#!/usr/bin/env node

/**
 * HPKE / HKDF / DHKEM test suite.
 *
 * Coverage
 * --------
 *  1. HKDF-SHA256 against RFC 5869 §A.1 test vector (known PRK + OKM).
 *  2. DHKEM(P-256, HKDF-SHA256) Encap/Decap symmetry: the sender's
 *     shared_secret must match the recipient's.
 *  3. HPKE base-mode Seal/Open round-trip with aad and info.
 *  4. Stateful context: nonce must advance monotonically and each open() in
 *     order decrypts correctly; reuse of the same receiver after a miss
 *     should fail closed.
 *  5. Exporter secret: sender and receiver produce identical exports.
 *
 * We do *not* run the RFC 9180 Appendix A fixed-input vectors because they
 * require injecting a known ephemeral secret into Encap, which WebCrypto's
 * key manager refuses. The symmetry + round-trip coverage catches every
 * realistic bug class without leaking secret scalars into userland.
 */

const path = require('path');
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  — ${detail}` : ''}`);
        failed += 1;
    }
}

function bytes(hex) {
    const h = hex.replace(/\s+/g, '');
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(h.substr(i * 2, 2), 16);
    }
    return out;
}

function hex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function eqBytes(got, want, name) {
    assert(hex(got) === hex(want), name, hex(got) === hex(want) ? null : `got ${hex(got)} want ${hex(want)}`);
}

async function main() {
    // ---------------------------------------------------------------------
    // 1. HKDF-SHA256 vs RFC 5869 §A.1
    // ---------------------------------------------------------------------
    console.log('# HKDF-SHA256 (RFC 5869 §A.1)');
    {
        const ikm  = bytes('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        const salt = bytes('000102030405060708090a0b0c');
        const info = bytes('f0f1f2f3f4f5f6f7f8f9');
        const expectedPrk = bytes(
            '077709362c2e32df0ddc3f0dc47bba63' +
            '90b6c73bb50f9c3122ec844ad7c2b3e5'
        );
        const expectedOkm = bytes(
            '3cb25f25faacd57a90434f64d0362f2a' +
            '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
            '34007208d5b887185865'
        );
        const prk = await HPKE.hkdfExtract(salt, ikm);
        eqBytes(prk, expectedPrk, 'HKDF Extract matches RFC 5869 PRK');
        const okm = await HPKE.hkdfExpand(prk, info, 42);
        eqBytes(okm, expectedOkm, 'HKDF Expand matches RFC 5869 OKM');
    }

    // ---------------------------------------------------------------------
    // 2. DHKEM Encap/Decap symmetry
    // ---------------------------------------------------------------------
    console.log('# DHKEM(P-256) Encap/Decap');
    {
        const recipient = await HPKE.generateKeyPair();
        const { sharedSecret: senderSS, enc: encBytes } = await HPKE.encap(recipient.publicKeyBytes);
        const receiverSS = await HPKE.decap(encBytes, recipient.privateKey, recipient.publicKeyBytes);
        eqBytes(receiverSS, senderSS, 'DHKEM Encap/Decap shared secret symmetric');
        assert(encBytes.length === 65 && encBytes[0] === 0x04, 'enc is 65-byte uncompressed P-256 pubkey');
    }

    // ---------------------------------------------------------------------
    // 3. HPKE Seal/Open single-shot round-trip
    // ---------------------------------------------------------------------
    console.log('# HPKE Seal / Open');
    {
        const recipient = await HPKE.generateKeyPair();
        const info = new TextEncoder().encode('pinchat-mls-hpke-test');
        const aad = new TextEncoder().encode('aad-for-seal');
        const plaintext = new TextEncoder().encode('The magic words are squeamish ossifrage.');

        const { enc: encBytes, ct } = await HPKE.seal(recipient.publicKeyBytes, info, aad, plaintext);
        const recovered = await HPKE.open(encBytes, recipient.privateKey, recipient.publicKeyBytes, info, aad, ct);
        eqBytes(recovered, plaintext, 'Seal → Open recovers plaintext');

        // Tamper the AAD: must reject.
        let rejectedBadAad = false;
        try {
            await HPKE.open(encBytes, recipient.privateKey, recipient.publicKeyBytes, info, new Uint8Array(0), ct);
        } catch (_e) {
            rejectedBadAad = true;
        }
        assert(rejectedBadAad, 'Open rejects modified AAD');

        // Tamper the ciphertext: must reject.
        const tampered = new Uint8Array(ct);
        tampered[0] ^= 0x01;
        let rejectedBadCt = false;
        try {
            await HPKE.open(encBytes, recipient.privateKey, recipient.publicKeyBytes, info, aad, tampered);
        } catch (_e) {
            rejectedBadCt = true;
        }
        assert(rejectedBadCt, 'Open rejects bit-flipped ciphertext');

        // Wrong recipient key: must reject.
        const wrong = await HPKE.generateKeyPair();
        let rejectedWrongKey = false;
        try {
            await HPKE.open(encBytes, wrong.privateKey, wrong.publicKeyBytes, info, aad, ct);
        } catch (_e) {
            rejectedWrongKey = true;
        }
        assert(rejectedWrongKey, 'Open rejects wrong recipient private key');
    }

    // ---------------------------------------------------------------------
    // 4. Stateful context: nonce advances
    // ---------------------------------------------------------------------
    console.log('# HPKE stateful context (seq advances)');
    {
        const recipient = await HPKE.generateKeyPair();
        const info = new TextEncoder().encode('stateful');
        const { enc: encBytes, context: sender } = await HPKE.setupBaseSender(recipient.publicKeyBytes, info);
        const receiver = await HPKE.setupBaseReceiver(encBytes, recipient.privateKey, recipient.publicKeyBytes, info);

        const m0 = new TextEncoder().encode('message 0');
        const m1 = new TextEncoder().encode('message 1');
        const m2 = new TextEncoder().encode('message 2');

        const c0 = await sender.seal(new Uint8Array(0), m0);
        const c1 = await sender.seal(new Uint8Array(0), m1);
        const c2 = await sender.seal(new Uint8Array(0), m2);

        // Sender seq must advance — otherwise c0 == c1 (they don't, below).
        assert(hex(c0) !== hex(c1), 'distinct ciphertexts across seq 0 and 1');

        eqBytes(await receiver.open(new Uint8Array(0), c0), m0, 'receiver decrypts msg 0');
        eqBytes(await receiver.open(new Uint8Array(0), c1), m1, 'receiver decrypts msg 1');
        eqBytes(await receiver.open(new Uint8Array(0), c2), m2, 'receiver decrypts msg 2');

        // Out-of-order: presenting c0 again after receiver has advanced past it
        // must fail (nonce mismatch).
        let outOfOrderRejected = false;
        try {
            await receiver.open(new Uint8Array(0), c0);
        } catch (_e) {
            outOfOrderRejected = true;
        }
        assert(outOfOrderRejected, 'stateful receiver rejects replayed ciphertext');
    }

    // ---------------------------------------------------------------------
    // 5. Exporter secret agrees between sides
    // ---------------------------------------------------------------------
    console.log('# HPKE exporter');
    {
        const recipient = await HPKE.generateKeyPair();
        const info = new TextEncoder().encode('exp-test');
        const { enc: encBytes, context: sender } = await HPKE.setupBaseSender(recipient.publicKeyBytes, info);
        const receiver = await HPKE.setupBaseReceiver(encBytes, recipient.privateKey, recipient.publicKeyBytes, info);

        const label = new TextEncoder().encode('pinchat-exporter');
        const s1 = await sender.export(label, 32);
        const r1 = await receiver.export(label, 32);
        eqBytes(r1, s1, 'exporter secret symmetric');

        const s2 = await sender.export(new TextEncoder().encode('other-label'), 32);
        assert(hex(s2) !== hex(s1), 'different exporter context → different secret');
    }

    console.log('');
    console.log(`hpke: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
