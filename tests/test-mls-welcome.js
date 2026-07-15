#!/usr/bin/env node

/**
 * MLS Welcome / GroupInfo end-to-end test.
 *
 * Given welcome.json's {init_priv, key_package, signer_pub, welcome} tuple
 * for cipher_suite = 2, we exercise the full joiner code path:
 *
 *   1. Unwrap the MLSMessage(mls_welcome) framing.
 *   2. Parse the Welcome struct; round-trip the bytes.
 *   3. Locate our own EncryptedGroupSecrets entry by matching the
 *      new_member ref against RefHash("MLS 1.0 KeyPackage Reference",
 *      serialized_key_package).
 *   4. HPKE-DecryptWithLabel with the init private key to recover
 *      GroupSecrets, extracting joiner_secret.
 *   5. Derive welcome_secret = ExpandWithLabel(
 *          KDF.Extract(joiner_secret, zero(Nh)),
 *          "welcome", "", Nh) — no PSKs in these vectors.
 *   6. Derive welcome_key / welcome_nonce from welcome_secret.
 *   7. AES-128-GCM decrypt encrypted_group_info → GroupInfo bytes.
 *   8. Parse GroupInfo; verify SignWithLabel("GroupInfoTBS", tbs,
 *      signature) against the vector's signer_pub.
 *   9. Round-trip every intermediate struct to confirm our serdes are
 *      byte-for-byte stable.
 *
 * A single green run here validates a substantial end-to-end slice of
 * our MLS stack: MLSMessage framing, Welcome serde, HPKE
 * EncryptWithLabel/DecryptWithLabel, the labeled KDF, AEAD framing,
 * GroupContext + GroupInfo serde, SignWithLabel, RefHash.
 */

const path = require('path');
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const Welcome = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'welcome.js'));
const GroupInfo = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group-info.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'welcome.json'));

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
    const b = Buffer.from(h, 'hex');
    return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

function hex(u8) {
    return Buffer.from(u8).toString('hex');
}

function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
    return true;
}

async function main() {
    console.log('# Welcome end-to-end — welcome.json cs=2');

    const v = VECTORS.find((x) => x.cipher_suite === 2);
    const initPrivBytes = hexDecode(v.init_priv);
    const kpWrapped = hexDecode(v.key_package);
    const welcomeWrapped = hexDecode(v.welcome);
    const signerPubBytes = hexDecode(v.signer_pub);

    // Step 1–2: unwrap MLSMessage, parse Welcome, round-trip.
    const welFrame = MLSMessage.parseMLSMessage(welcomeWrapped);
    assert(welFrame.wireFormat === MLSMessage.WireFormat.MLS_WELCOME, 'wire_format == mls_welcome');
    const welcome = Welcome.parseWelcome(welFrame.body);
    assert(welcome.cipherSuite === 0x0002, 'Welcome.cipher_suite == 0x0002');
    assert(
        hex(Welcome.welcomeBytes(welcome)) === hex(welFrame.body),
        'Welcome body round-trips byte-for-byte'
    );

    // Step 3: find our entry by keyPackageRef.
    const kpFrame = MLSMessage.parseMLSMessage(kpWrapped);
    assert(kpFrame.wireFormat === MLSMessage.WireFormat.MLS_KEY_PACKAGE, 'wire_format == mls_key_package');
    const kpBytes = kpFrame.body;
    const kp = KeyPackage.parseKeyPackage(kpBytes);
    const ref = await KeyPackage.keyPackageRef(kpBytes);
    const myEntry = welcome.secrets.find((e) => bytesEqual(e.newMember, ref));
    assert(!!myEntry, 'EncryptedGroupSecrets entry for our KeyPackage ref is present');

    // Step 4: import init_priv, DecryptWithLabel → GroupSecrets.
    const initPriv = await HPKE.importPrivateKey(initPrivBytes, kp.initKey);
    const gs = await Welcome.decryptGroupSecrets(
        myEntry.encryptedGroupSecrets, initPriv, kp.initKey, welcome.encryptedGroupInfo
    );
    assert(gs.joinerSecret.length === 32, 'joiner_secret is 32 bytes');
    assert(gs.psks.length === 0, 'no PSKs in vector');

    // GroupSecrets round-trip
    const gsBytes = Welcome.groupSecretsBytes(gs);
    const gs2 = Welcome.parseGroupSecrets(gsBytes);
    assert(
        hex(gs2.joinerSecret) === hex(gs.joinerSecret),
        'GroupSecrets round-trip (joiner_secret intact)'
    );

    // Step 5–6: derive welcome_secret → welcome_key/nonce.
    const psk = new Uint8Array(32); // no PSKs
    const welcomeSecret = await Welcome.deriveWelcomeSecret(gs.joinerSecret, psk);
    const { key: welcomeKey, nonce: welcomeNonce } = await Welcome.welcomeKeyNonce(welcomeSecret);
    assert(welcomeKey.length === HPKE.Nk, 'welcome_key is Nk bytes');
    assert(welcomeNonce.length === HPKE.Nn, 'welcome_nonce is Nn bytes');

    // Step 7: AES-128-GCM decrypt encrypted_group_info.
    let giBytes;
    try {
        giBytes = await Welcome.openEncryptedGroupInfo(
            welcomeKey, welcomeNonce, welcome.encryptedGroupInfo
        );
    } catch (err) {
        assert(false, 'AES-GCM open encrypted_group_info', err.message);
        process.exit(1);
    }
    assert(giBytes.length > 0, 'GroupInfo bytes recovered');

    // Step 8: parse GroupInfo + verify signature.
    const gi = GroupInfo.parseGroupInfo(giBytes);
    assert(gi.groupContext.cipherSuite === 0x0002, 'GroupInfo.group_context.cipher_suite == 0x0002');
    assert(gi.confirmationTag.length === 32, 'confirmation_tag is 32 bytes');

    // GroupInfo round-trip
    const giRound = GroupInfo.groupInfoBytes(gi);
    assert(hex(giRound) === hex(giBytes), 'GroupInfo struct round-trip');

    // Verify GroupInfoTBS signature against the vector's signer_pub.
    const signerPub = await Signature.importPublicKey(signerPubBytes);
    const tbs = GroupInfo.groupInfoTbsBytes(gi);
    const profileSignature = Signature.normalizeDerLowS(gi.signature);
    const originalIsLowS = hex(profileSignature) === hex(gi.signature);
    const originalSigOk = await Labeled.verifyWithLabel(
        signerPub, 'GroupInfoTBS', tbs, gi.signature);
    assert(originalSigOk === originalIsLowS,
        'GroupInfo PinChat profile accepts low-S and rejects high-S IETF form');
    const sigOk = await Labeled.verifyWithLabel(
        signerPub, 'GroupInfoTBS', tbs, profileSignature);
    assert(sigOk === true,
        'normalized GroupInfo signature verifies with signer_pub');

    // Step 9: Welcome byte round-trip with our own serde.
    const welcomeBodyOut = Welcome.welcomeBytes(welcome);
    const wrappedOut = MLSMessage.serializeMLSMessage(
        MLSMessage.WireFormat.MLS_WELCOME, welcomeBodyOut
    );
    assert(
        hex(wrappedOut) === hex(welcomeWrapped),
        'MLSMessage(Welcome) re-wraps to original vector bytes'
    );

    console.log('');
    console.log(`welcome: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
