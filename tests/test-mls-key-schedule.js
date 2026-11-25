#!/usr/bin/env node

/**
 * MLS key-schedule test suite.
 *
 * Verifies every step of tests/vectors/mls/key-schedule.json for
 * cipher_suite = 2 (MLS_128_DHKEMP256_AES128GCM_SHA256_P256) byte-for-byte.
 *
 * The official MLS test vector file lives at
 *   https://github.com/mlswg/mls-implementations/blob/main/test-vectors/key-schedule.json
 * and is cached in tests/vectors/mls/ so the test runs offline.
 *
 * Each group entry has:
 *   - group_id                  : u8<V>
 *   - initial_init_secret       : the init_secret_[-1] to seed the chain
 *   - epochs[]                  : per-epoch inputs + expected outputs
 *
 * For each epoch we:
 *   1. Run deriveEpoch with (prevInitSecret, commit_secret, psk_secret,
 *      group_context) from the vector.
 *   2. Assert that every derived secret we compute matches the vector's
 *      expected hex byte-for-byte.
 *   3. Carry our own `init_secret` forward as the next epoch's
 *      `init_secret_[n-1]`.
 *
 * We also cross-check `exporter`: vector.exporter = {label, context, length,
 * secret} - secret must equal mlsExporter(exporter_secret, label,
 * SHA-256(context), length).
 */

const path = require('path');
const { webcrypto } = require('crypto');
const KS = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-schedule.js'));

const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));
const Welcome = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'welcome.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'key-schedule.json'));
const PSK_VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'psk_secret.json'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  - ${detail}` : ''}`);
        failed += 1;
    }
}

function hexDecode(h) {
    const clean = h.replace(/\s+/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
}

function hex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function eqHex(got, want, name) {
    const g = hex(got);
    const w = typeof want === 'string' ? want.toLowerCase() : hex(want);
    assert(g === w, name, g === w ? null : `got ${g} want ${w}`);
}

async function sha256(data) {
    const d = await webcrypto.subtle.digest('SHA-256', data);
    return new Uint8Array(d);
}

async function runEpoch(groupIdx, epochIdx, prevInitSecret, epochVector) {
    const commitSecret  = hexDecode(epochVector.commit_secret);
    const pskSecret     = hexDecode(epochVector.psk_secret);
    const groupContext  = hexDecode(epochVector.group_context);

    const out = await KS.deriveEpoch({
        initSecretPrev: prevInitSecret,
        commitSecret,
        pskSecret,
        groupContext,
    });

    const prefix = `g${groupIdx} e${epochIdx}`;
    eqHex(out.joinerSecret,       epochVector.joiner_secret,       `${prefix} joiner_secret`);
    eqHex(out.welcomeSecret,      epochVector.welcome_secret,      `${prefix} welcome_secret`);
    eqHex(out.senderDataSecret,   epochVector.sender_data_secret,  `${prefix} sender_data_secret`);
    eqHex(out.encryptionSecret,   epochVector.encryption_secret,   `${prefix} encryption_secret`);
    eqHex(out.exporterSecret,     epochVector.exporter_secret,     `${prefix} exporter_secret`);
    eqHex(out.externalSecret,     epochVector.external_secret,     `${prefix} external_secret`);
    eqHex(out.confirmationKey,    epochVector.confirmation_key,    `${prefix} confirmation_key`);
    eqHex(out.membershipKey,      epochVector.membership_key,      `${prefix} membership_key`);
    eqHex(out.resumptionPsk,      epochVector.resumption_psk,      `${prefix} resumption_psk`);
    eqHex(out.epochAuthenticator, epochVector.epoch_authenticator, `${prefix} epoch_authenticator`);
    eqHex(out.initSecret,         epochVector.init_secret,         `${prefix} init_secret`);

    // Exporter cross-check
    const exp = epochVector.exporter;
    const contextHash = await sha256(hexDecode(exp.context));
    const exported = await KS.mlsExporter(
        out.exporterSecret,
        exp.label,
        contextHash,
        exp.length,
    );
    eqHex(exported, exp.secret, `${prefix} exporter(${JSON.stringify(exp.label)})`);

    return out.initSecret;
}

/**
 * RFC 9420 section 8.4 psk_secret over a list of external PSKs:
 *
 *   psk_extracted_[i] = KDF.Extract(0, psk_[i])
 *   psk_input_[i]     = ExpandWithLabel(psk_extracted_[i], "derived psk",
 *                                       PSKLabel{id, index, count}, Nh)
 *   psk_secret_[0]    = 0
 *   psk_secret_[i]    = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
 *
 * The PinChat profile carries no PSK identifiers (GroupSecrets.psks is
 * always empty) and injects its invite-derived 32-byte PSK directly as
 * psk_secret, so this composition is not on the production path. It still
 * pins the library's KDF.Extract, ExpandWithLabel and PreSharedKeyID
 * encoding against the IETF psk_secret vectors, and the empty-list vector
 * pins the all-zero psk_secret used when no invite PSK is supplied.
 */
async function pskSecret(psks) {
    let secret = new Uint8Array(HPKE.Nh);
    for (let i = 0; i < psks.length; i += 1) {
        const extracted = await HPKE.hkdfExtract(
            new Uint8Array(0), hexDecode(psks[i].psk),
        );
        const label = new Codec.Encoder();
        Welcome.writePreSharedKeyID(label, {
            psktype: 1,
            pskId: hexDecode(psks[i].psk_id),
            pskNonce: hexDecode(psks[i].psk_nonce),
        });
        label.writeU16(i);
        label.writeU16(psks.length);
        const input = await KS.expandWithLabel(
            extracted, 'derived psk', label.bytes(), HPKE.Nh,
        );
        secret = await HPKE.hkdfExtract(input, secret);
    }
    return secret;
}

async function runPskVectors() {
    const cs2 = PSK_VECTORS.filter((v) => v.cipher_suite === 2);
    console.log(`# psk_secret.json - cipher_suite=2 (${cs2.length} PSK lists)`);
    assert(cs2.length > 0, 'psk_secret vectors present for cipher_suite=2');
    for (let i = 0; i < cs2.length; i += 1) {
        eqHex(await pskSecret(cs2[i].psks), cs2[i].psk_secret,
            `psk_secret vector ${i} (${cs2[i].psks.length} PSKs)`);
    }
}

async function main() {
    await runPskVectors();

    // Run cipher_suite = 2 (our target) against all 5 epochs across 1 group.
    const group = VECTORS.find((g) => g.cipher_suite === 2);
    if (!group) {
        console.log('  FAIL no cipher_suite=2 vector found');
        process.exit(1);
    }

    console.log(`# MLS key schedule - cipher_suite=2, group_id=${group.group_id.slice(0, 16)}...`);

    let prevInitSecret = hexDecode(group.initial_init_secret);
    for (let i = 0; i < group.epochs.length; i += 1) {
        prevInitSecret = await runEpoch(1, i, prevInitSecret, group.epochs[i]);
    }

    console.log('');
    console.log(`key-schedule: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
