#!/usr/bin/env node

/**
 * MLS PublicMessage end-to-end test.
 *
 * Uses message-protection.json cs=2 to verify our PublicMessage
 * serde + signature + membership_tag against IETF reference values.
 *
 * For each of `proposal_pub` and `commit_pub`:
 *   1. Unwrap MLSMessage(mls_public_message).
 *   2. Parse PublicMessage with a Proposal/Commit-aware payload callback.
 *   3. Round-trip the body bytes byte-for-byte.
 *   4. Verify SignWithLabel("FramedContentTBS", tbs) using signature_pub.
 *   5. Verify membership_tag via HMAC-SHA256(membership_key,
 *      FramedContentTBS || FramedContentAuthData).
 *
 * Together these confirm: FramedContent serialization, FramedContentTBS
 * layout (with GroupContext suffix for member sender), signature
 * construction, and the AuthenticatedContentTBM layout.
 */

const path = require('path');

const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Proposal = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'proposal.js'));
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'message-protection.json'));

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

function parsePayloadCallback(decoder, contentType) {
    if (contentType === Framing.ContentType.PROPOSAL) {
        return Proposal.readProposal(decoder);
    }
    if (contentType === Framing.ContentType.COMMIT) {
        return Commit.readCommit(decoder);
    }
    throw new Error(`unexpected content_type ${contentType}`);
}

async function verifyOne(v, label, wrappedHex) {
    console.log(`# PublicMessage — ${label}`);
    const wrapped = hexDecode(wrappedHex);

    const frame = MLSMessage.parseMLSMessage(wrapped);
    assert(
        frame.wireFormat === MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
        `${label}: wire_format == mls_public_message`
    );

    const pm = PublicMessage.parsePublicMessage(frame.body, parsePayloadCallback);
    assert(!!pm.content, `${label}: PublicMessage parsed`);

    const round = PublicMessage.publicMessageBytes(pm);
    assert(
        hex(round) === hex(frame.body),
        `${label}: PublicMessage body round-trip byte-for-byte`
    );

    // Construct the GroupContext the sender would have signed / MAC'd over.
    const groupContextStruct = {
        version: 0x0001,
        cipherSuite: 0x0002,
        groupId: hexDecode(v.group_id),
        epoch: BigInt(v.epoch),
        treeHash: hexDecode(v.tree_hash),
        confirmedTranscriptHash: hexDecode(v.confirmed_transcript_hash),
        extensions: [],
    };

    // Signature verification (FramedContentTBS).
    const sigPub = await Signature.importPublicKey(hexDecode(v.signature_pub));
    const sigOk = await PublicMessage.verifyFramedContent(
        sigPub,
        frame.wireFormat,
        pm.content,
        groupContextStruct,
        pm.auth.signature,
    );
    assert(sigOk === true, `${label}: SignWithLabel("FramedContentTBS") verifies`);

    // Tampered content: signature must fail.
    const tamperedContent = {
        ...pm.content,
        authenticatedData: new Uint8Array([0x01]),
    };
    const sigBad = await PublicMessage.verifyFramedContent(
        sigPub, frame.wireFormat, tamperedContent, groupContextStruct, pm.auth.signature
    );
    assert(sigBad === false, `${label}: signature rejects tampered content`);

    // Membership tag.
    const memKey = hexDecode(v.membership_key);
    const tagOk = await PublicMessage.verifyMembershipTag(
        memKey, frame.wireFormat, pm.content, pm.auth, groupContextStruct, pm.membershipTag
    );
    assert(tagOk === true, `${label}: membership_tag verifies`);

    // Tampered membership key: must fail.
    const wrongKey = new Uint8Array(memKey.length);
    wrongKey.set(memKey);
    wrongKey[0] ^= 0x01;
    const tagBad = await PublicMessage.verifyMembershipTag(
        wrongKey, frame.wireFormat, pm.content, pm.auth, groupContextStruct, pm.membershipTag
    );
    assert(tagBad === false, `${label}: membership_tag rejects wrong key`);
}

async function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);

    await verifyOne(v, 'proposal_pub', v.proposal_pub);
    await verifyOne(v, 'commit_pub', v.commit_pub);

    console.log('');
    console.log(`public-message: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
