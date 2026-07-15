#!/usr/bin/env node

/**
 * MLS PrivateMessage end-to-end test.
 *
 * Uses message-protection.json cs=2 to verify our PrivateMessage
 * AEAD + sender_data encryption + signature + padding model.
 *
 * The IETF vector's group has nLeaves = 2 (discovered by rejection
 * sampling during implementation — the vector does not advertise it
 * directly, it falls out of SenderData's leaf_index once decrypted).
 *
 * For each of `proposal_priv`, `commit_priv`, `application_priv`:
 *   1. Unwrap MLSMessage(mls_private_message).
 *   2. Parse PrivateMessage + round-trip byte-for-byte.
 *   3. Decrypt sender_data with senderDataKeyNonce(sender_data_secret,
 *      ciphertext) → (leaf_index, generation, reuse_guard).
 *   4. Derive ratchet key/nonce from the per-leaf secret tree; mask the
 *      first 4 nonce bytes with reuse_guard.
 *   5. AEAD-decrypt the ciphertext.
 *   6. Parse PrivateMessageContent → inner payload + auth + padding.
 *   7. Assert the decrypted inner payload matches the vector's raw
 *      `proposal` / `commit` / `application` bytes.
 *   8. Verify SignWithLabel("FramedContentTBS") using signature_pub
 *      against the reconstructed FramedContent (sender is inferred
 *      as member(leaf_index) once SenderData is known).
 *   9. Re-encrypt with encryptPrivateMessage and decrypt — confirms
 *      our encryption path is symmetric.
 */

const path = require('path');

const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PrivateMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'private-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'message-protection.json'));

const N_LEAVES = 2; // group size under test

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

async function verifyOne(v, label, wrappedHex, rawPayloadHex, contentType) {
    console.log(`# PrivateMessage — ${label}`);
    const wrapped = hexDecode(wrappedHex);

    const frame = MLSMessage.parseMLSMessage(wrapped);
    assert(
        frame.wireFormat === MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE,
        `${label}: wire_format == mls_private_message`
    );

    const pm = PrivateMessage.parsePrivateMessage(frame.body);
    assert(pm.contentType === contentType, `${label}: content_type matches`);

    // Round-trip byte-for-byte
    const round = PrivateMessage.privateMessageBytes(pm);
    assert(hex(round) === hex(frame.body), `${label}: PrivateMessage body round-trip`);

    // Decrypt
    const senderDataSecret = hexDecode(v.sender_data_secret);
    const encryptionSecret = hexDecode(v.encryption_secret);
    const out = await PrivateMessage.decryptPrivateMessage({
        pm, senderDataSecret, encryptionSecret, nLeaves: N_LEAVES,
    });
    assert(
        hex(out.content.payloadBytes) === rawPayloadHex.toLowerCase(),
        `${label}: decrypted payload matches vector's raw ${label.split('_')[0]}`
    );
    assert(out.content.auth.signature.length > 0, `${label}: auth.signature recovered`);
    if (contentType === Framing.ContentType.COMMIT) {
        assert(
            out.content.auth.confirmationTag && out.content.auth.confirmationTag.length === 32,
            `${label}: confirmation_tag recovered`
        );
    }

    // Verify signature via the reconstructed FramedContent.
    const groupContext = {
        version: 0x0001,
        cipherSuite: 0x0002,
        groupId: hexDecode(v.group_id),
        epoch: BigInt(v.epoch),
        treeHash: hexDecode(v.tree_hash),
        confirmedTranscriptHash: hexDecode(v.confirmed_transcript_hash),
        extensions: [],
    };
    const content = {
        groupId: pm.groupId,
        epoch: pm.epoch,
        sender: { senderType: Framing.SenderType.MEMBER, leafIndex: out.senderData.leafIndex },
        authenticatedData: pm.authenticatedData,
        contentType: pm.contentType,
        payload: out.content.payloadBytes,
    };
    const sigPub = await Signature.importPublicKey(hexDecode(v.signature_pub));
    const profileSignature = Signature.normalizeDerLowS(out.content.auth.signature);
    const originalIsLowS = hex(profileSignature) === hex(out.content.auth.signature);
    const originalSigOk = await PublicMessage.verifyFramedContent(
        sigPub, frame.wireFormat, content, groupContext, out.content.auth.signature
    );
    assert(originalSigOk === originalIsLowS,
        `${label}: PinChat profile accepts low-S and rejects high-S IETF form`);
    const sigOk = await PublicMessage.verifyFramedContent(
        sigPub, frame.wireFormat, content, groupContext, profileSignature
    );
    assert(sigOk === true,
        `${label}: normalized IETF signature verifies under PinChat profile`);

    // Re-encrypt with our path and round-trip
    const reenc = await PrivateMessage.encryptPrivateMessage({
        groupId: pm.groupId,
        epoch: pm.epoch,
        contentType: pm.contentType,
        authenticatedData: pm.authenticatedData,
        payloadBytes: out.content.payloadBytes,
        auth: out.content.auth,
        senderData: out.senderData,
        paddingLen: out.content.paddingLen,
        senderDataSecret, encryptionSecret, nLeaves: N_LEAVES,
    });
    const redec = await PrivateMessage.decryptPrivateMessage({
        pm: reenc, senderDataSecret, encryptionSecret, nLeaves: N_LEAVES,
    });
    assert(
        hex(redec.content.payloadBytes) === hex(out.content.payloadBytes),
        `${label}: re-encrypt → decrypt round-trip`
    );
}

async function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);

    await verifyOne(v, 'application_priv', v.application_priv, v.application, Framing.ContentType.APPLICATION);
    await verifyOne(v, 'proposal_priv', v.proposal_priv, v.proposal, Framing.ContentType.PROPOSAL);
    await verifyOne(v, 'commit_priv', v.commit_priv, v.commit, Framing.ContentType.COMMIT);

    console.log('');
    console.log(`private-message: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
