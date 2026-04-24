#!/usr/bin/env node

/**
 * Cross-check the transcript-hashes module against the IETF
 * transcript-hashes.json reference vectors for cipher_suite = 2.
 *
 * The vector gives us:
 *   - authenticated_content : serialized AuthenticatedContent
 *                             (wire_format || FramedContent ||
 *                              opaque(signature) || opaque(confirmation_tag))
 *   - confirmation_key
 *   - interim_transcript_hash_before
 *   - confirmed_transcript_hash_after
 *   - interim_transcript_hash_after
 *
 * We recover ConfirmedTranscriptHashInput by dropping the trailing
 * opaque<V> confirmation_tag (33 bytes = 1-byte varint length 0x20 + 32
 * HMAC-SHA256 bytes) from authenticated_content.
 */

const path = require('path');
const TH = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'transcript-hashes.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'transcript-hashes.json'));

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

async function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);
    if (!v) {
        console.log('  FAIL no cipher_suite=2 entry');
        process.exit(1);
    }

    console.log(`# transcript-hashes — cipher_suite=2`);

    const ac = hexDecode(v.authenticated_content);
    const confKey = hexDecode(v.confirmation_key);
    const itBefore = hexDecode(v.interim_transcript_hash_before);

    // Strip the trailing opaque<V> confirmation_tag (33 bytes for SHA-256).
    // MAC values in MLS are always opaque<V>; for our ciphersuite Nh=32, so
    // the confirmation_tag on the wire is varint(32)=0x20 followed by 32
    // HMAC output bytes.
    const tagLen = 1 + 32;
    const confirmedInput = ac.slice(0, ac.length - tagLen);

    const { confirmedTranscriptHashAfter, confirmationTag, interimTranscriptHashAfter } =
        await TH.applyCommit(itBefore, confKey, confirmedInput);

    assert(
        hex(confirmedTranscriptHashAfter) === v.confirmed_transcript_hash_after.toLowerCase(),
        'confirmed_transcript_hash_after',
        `got ${hex(confirmedTranscriptHashAfter)} want ${v.confirmed_transcript_hash_after}`
    );

    // The confirmation_tag we compute must match the 32 bytes embedded in
    // authenticated_content (after the 1-byte varint length prefix).
    const embeddedTag = ac.slice(ac.length - 32);
    assert(
        hex(confirmationTag) === hex(embeddedTag),
        'confirmation_tag equals embedded MAC in authenticated_content',
        `got ${hex(confirmationTag)} want ${hex(embeddedTag)}`
    );

    assert(
        hex(interimTranscriptHashAfter) === v.interim_transcript_hash_after.toLowerCase(),
        'interim_transcript_hash_after',
        `got ${hex(interimTranscriptHashAfter)} want ${v.interim_transcript_hash_after}`
    );

    console.log('');
    console.log(`transcript-hashes: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
