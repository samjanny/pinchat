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
