#!/usr/bin/env node

/**
 * Cross-check the MLS §5 labeled KDF / hash operations against the
 * IETF crypto-basics.json reference vectors for cipher_suite = 2.
 *
 * Covers:
 *   - DeriveSecret        → against crypto-basics.derive_secret
 *   - ExpandWithLabel     → against crypto-basics.expand_with_label
 *   - RefHash             → against crypto-basics.ref_hash
 *
 * The SignWithLabel and EncryptWithLabel fields of crypto-basics.json
 * are verified in the modules that own their primitives (signature,
 * labeled-hpke) once those land.
 */

const path = require('path');
const KS = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-schedule.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'crypto-basics.json'));

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

function hexDecode(h) {
    const clean = h.replace(/\s+/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}

function hex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function throws(fn, name) {
    let threw = false;
    try {
        fn();
    } catch (_err) {
        threw = true;
    }
    assert(threw, name, threw ? null : 'expected throw');
}

function bytesToBigInt(bytes) {
    return BigInt(`0x${hex(bytes)}`);
}

function bigIntToFixed(value, length) {
    const out = new Uint8Array(length);
    let remaining = value;
    for (let i = length - 1; i >= 0; i -= 1) {
        out[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    if (remaining !== 0n) throw new Error('test scalar overflow');
    return out;
}

// Independent test encoder: unlike production rawToDer(), preserve high-S so
// the rejection path can be exercised with a mathematically valid signature.
function rawToDerPreservingS(raw) {
    function integer(bytes) {
        let start = 0;
        while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
        const value = bytes.subarray(start);
        const padded = (value[0] & 0x80) !== 0;
        const out = new Uint8Array(2 + value.length + (padded ? 1 : 0));
        out[0] = 0x02;
        out[1] = out.length - 2;
        out.set(value, padded ? 3 : 2);
        return out;
    }
    const r = integer(raw.subarray(0, 32));
    const s = integer(raw.subarray(32));
    const out = new Uint8Array(2 + r.length + s.length);
    out[0] = 0x30;
    out[1] = out.length - 2;
    out.set(r, 2);
    out.set(s, 2 + r.length);
    return out;
}

async function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);
    if (!v) {
        console.log('  FAIL no cipher_suite=2 entry');
        process.exit(1);
    }

    console.log(`# crypto-basics — cipher_suite=2`);

    // --- DeriveSecret ---
    {
        const secret = hexDecode(v.derive_secret.secret);
        const out = await KS.deriveSecret(secret, v.derive_secret.label);
        assert(hex(out) === v.derive_secret.out.toLowerCase(),
            `DeriveSecret("${v.derive_secret.label}")`,
            `got ${hex(out)} want ${v.derive_secret.out}`);
    }

    // --- ExpandWithLabel ---
    {
        const secret = hexDecode(v.expand_with_label.secret);
        const context = hexDecode(v.expand_with_label.context);
        const out = await KS.expandWithLabel(
            secret, v.expand_with_label.label, context, v.expand_with_label.length);
        assert(hex(out) === v.expand_with_label.out.toLowerCase(),
            `ExpandWithLabel("${v.expand_with_label.label}", len=${v.expand_with_label.length})`,
            `got ${hex(out)} want ${v.expand_with_label.out}`);
    }

    // --- RefHash ---
    {
        const value = hexDecode(v.ref_hash.value);
        const out = await Labeled.refHash(v.ref_hash.label, value);
        assert(hex(out) === v.ref_hash.out.toLowerCase(),
            `RefHash("${v.ref_hash.label}")`,
            `got ${hex(out)} want ${v.ref_hash.out}`);
    }

    // --- SignWithLabel / VerifyWithLabel ---
    // Two directions of the cross-check:
    //   a) Import the vector's public key, verify the vector's DER signature
    //      over the vector's content: must succeed.
    //   b) Import the vector's private scalar, sign the same content, and
    //      verify the resulting signature with the public key: must succeed.
    //      (ECDSA is randomized so the signature bytes themselves will not
    //      match the vector byte-for-byte.)
    {
        const pubBytes = hexDecode(v.sign_with_label.pub);
        const privBytes = hexDecode(v.sign_with_label.priv);
        const content = hexDecode(v.sign_with_label.content);
        const vectorSig = hexDecode(v.sign_with_label.signature);
        const label = v.sign_with_label.label;

        const pub = await Signature.importPublicKey(pubBytes);
        const verified = await Labeled.verifyWithLabel(pub, label, content, vectorSig);
        assert(verified === true,
            `VerifyWithLabel("${label}") accepts IETF vector signature`);

        // Tamper the content — verification must fail.
        const tampered = new Uint8Array(content);
        tampered[0] ^= 0x01;
        const verifiedBad = await Labeled.verifyWithLabel(pub, label, tampered, vectorSig);
        assert(verifiedBad === false,
            `VerifyWithLabel("${label}") rejects tampered content`);

        // Round-trip with the vector's private scalar.
        const priv = await Signature.importPrivateKey(privBytes, pubBytes);
        const mySig = await Labeled.signWithLabel(priv, label, content);
        const verifiedMine = await Labeled.verifyWithLabel(pub, label, content, mySig);
        assert(verifiedMine === true,
            `SignWithLabel round-trip (priv import + sign + verify)`);

        // Canonical DER is unique and consumes the complete SEQUENCE.
        const rawVectorSig = Signature.derToRaw(vectorSig);
        assert(hex(Signature.rawToDer(rawVectorSig)) === hex(vectorSig),
            'DER parse + re-encode is byte-exact for canonical signature');

        const extraInside = new Uint8Array(vectorSig.length + 1);
        extraInside.set(vectorSig);
        extraInside[1] += 1;
        extraInside[extraInside.length - 1] = 0;
        throws(() => Signature.derToRaw(extraInside),
            'DER rejects unconsumed byte inside ECDSA SEQUENCE');

        const trailingOutside = new Uint8Array(vectorSig.length + 1);
        trailingOutside.set(vectorSig);
        throws(() => Signature.derToRaw(trailingOutside),
            'DER rejects byte after ECDSA SEQUENCE');

        const longSequenceLength = new Uint8Array(vectorSig.length + 1);
        longSequenceLength[0] = 0x30;
        longSequenceLength[1] = 0x81;
        longSequenceLength[2] = vectorSig.length - 2;
        longSequenceLength.set(vectorSig.subarray(2), 3);
        throws(() => Signature.derToRaw(longSequenceLength),
            'DER rejects non-minimal long-form SEQUENCE length');

        // The vector's r starts below 0x80, so a leading zero is redundant.
        const rLen = vectorSig[3];
        const redundantRZero = new Uint8Array(vectorSig.length + 1);
        redundantRZero[0] = 0x30;
        redundantRZero[1] = vectorSig[1] + 1;
        redundantRZero[2] = 0x02;
        redundantRZero[3] = rLen + 1;
        redundantRZero[4] = 0x00;
        redundantRZero.set(vectorSig.subarray(4, 4 + rLen), 5);
        redundantRZero.set(vectorSig.subarray(4 + rLen), 5 + rLen);
        throws(() => Signature.derToRaw(redundantRZero),
            'DER rejects redundant INTEGER sign octet');
        throws(() => Signature.derToRaw(hexDecode('3006020180020101')),
            'DER rejects negative INTEGER');
        throws(() => Signature.derToRaw(hexDecode('3006020100020101')),
            'DER rejects zero r scalar');

        // (r, n-s) is mathematically equivalent, but the PinChat profile
        // accepts only the low-S representative.
        const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
        const lowS = bytesToBigInt(rawVectorSig.subarray(32));
        const highRaw = new Uint8Array(rawVectorSig);
        highRaw.set(bigIntToFixed(order - lowS, 32), 32);
        const highDer = rawToDerPreservingS(highRaw);
        const signContent = Labeled.signContentBytes(label, content);
        const mathematicallyValid = await require('crypto').webcrypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' }, pub, highRaw, signContent);
        assert(mathematicallyValid === true,
            'high-S twin is mathematically valid ECDSA');
        assert(await Signature.verify(pub, signContent, highDer) === false,
            'PinChat verification rejects canonical high-S signature');
        throws(() => Signature.derToRaw(highDer),
            'DER-to-raw production boundary rejects high-S');
        assert(hex(Signature.normalizeDerLowS(highDer)) === hex(vectorSig),
            'explicit migration helper maps high-S twin to unique low-S DER');
        assert(hex(Signature.normalizeDerLowS(mySig)) === hex(mySig),
            'SignWithLabel always emits canonical low-S DER');
    }

    // --- EncryptWithLabel / DecryptWithLabel ---
    // The vector gives us a known (priv, pub, kem_output, ciphertext,
    // plaintext) tuple for HPKE base mode with MLS labeling. Deterministic
    // check: importing priv and decrypting must recover the plaintext.
    // Round-trip check: encrypting our own plaintext and decrypting gives
    // the same bytes back (the HPKE enc is randomized, so we cannot
    // byte-compare ciphertexts against the vector).
    {
        const pubBytes = hexDecode(v.encrypt_with_label.pub);
        const privBytes = hexDecode(v.encrypt_with_label.priv);
        const context = hexDecode(v.encrypt_with_label.context);
        const kemOutput = hexDecode(v.encrypt_with_label.kem_output);
        const ciphertext = hexDecode(v.encrypt_with_label.ciphertext);
        const plaintext = hexDecode(v.encrypt_with_label.plaintext);
        const label = v.encrypt_with_label.label;

        const priv = await HPKE.importPrivateKey(privBytes, pubBytes);
        const recovered = await Labeled.decryptWithLabel(
            priv, pubBytes, label, context, kemOutput, ciphertext);
        assert(hex(recovered) === hex(plaintext),
            `DecryptWithLabel("${label}") recovers IETF vector plaintext`,
            `got ${hex(recovered)} want ${hex(plaintext)}`);

        // Round-trip: encrypt to the vector's public key, then decrypt.
        const { kemOutput: ownEnc, ciphertext: ownCt } =
            await Labeled.encryptWithLabel(pubBytes, label, context, plaintext);
        const mine = await Labeled.decryptWithLabel(
            priv, pubBytes, label, context, ownEnc, ownCt);
        assert(hex(mine) === hex(plaintext),
            `EncryptWithLabel round-trip (encrypt + decrypt)`);
    }

    console.log('');
    console.log(`crypto-basics: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
