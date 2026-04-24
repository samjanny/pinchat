#!/usr/bin/env node

/**
 * MLS framing — synthetic round-trip tests for FramedContent +
 * FramedContentAuthData + AuthenticatedContent.
 *
 * This commit lands the framing layer with application-content support
 * only; proposal/commit body parsing is handed to a follow-up when the
 * Proposal/Commit struct decoders exist. The synthetic tests here
 * exercise:
 *   - Sender encoding for every sender_type
 *   - FramedContent encoding for application_data
 *   - FramedContentAuthData with/without confirmation_tag (commit vs.
 *     non-commit tail)
 *   - AuthenticatedContent round-trip with application and a commit
 *     stand-in where the Commit body is a fixed byte blob and the
 *     parsePayload callback just consumes that blob.
 */

const path = require('path');
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));

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

function hex(u8) { return Buffer.from(u8).toString('hex'); }

function makeBytes(n, start = 0) {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i += 1) out[i] = (start + i) & 0xff;
    return out;
}

function main() {
    console.log('# framing — Sender encoding');
    const senders = [
        { senderType: Framing.SenderType.MEMBER, leafIndex: 7 },
        { senderType: Framing.SenderType.EXTERNAL, senderIndex: 42 },
        { senderType: Framing.SenderType.NEW_MEMBER_PROPOSAL },
        { senderType: Framing.SenderType.NEW_MEMBER_COMMIT },
    ];
    for (const s of senders) {
        const enc = new Codec.Encoder();
        Framing.writeSender(enc, s);
        const dec = new Codec.Decoder(enc.bytes());
        const back = Framing.readSender(dec);
        assert(
            JSON.stringify(back) === JSON.stringify(s) && dec.remaining() === 0,
            `Sender round-trip for type ${s.senderType}`
        );
    }

    console.log('# framing — FramedContent(application) round-trip');
    {
        const fc = {
            groupId: makeBytes(16),
            epoch: 1234567890n,
            sender: { senderType: Framing.SenderType.MEMBER, leafIndex: 3 },
            authenticatedData: makeBytes(4, 0xa0),
            contentType: Framing.ContentType.APPLICATION,
            payload: makeBytes(20, 0xc0),
        };
        const bytes = Framing.framedContentBytes(fc);
        const dec = new Codec.Decoder(bytes);
        const parsed = Framing.readFramedContentShallow(dec);
        assert(dec.remaining() === 0, 'FramedContent(application) fully consumed');
        assert(
            parsed.contentType === Framing.ContentType.APPLICATION
            && hex(parsed.payload) === hex(fc.payload),
            'FramedContent(application) payload round-trip'
        );
        assert(
            parsed.epoch === fc.epoch
            && parsed.sender.leafIndex === 3
            && hex(parsed.groupId) === hex(fc.groupId)
            && hex(parsed.authenticatedData) === hex(fc.authenticatedData),
            'FramedContent(application) fields round-trip'
        );
    }

    console.log('# framing — FramedContentAuthData (commit vs non-commit tail)');
    {
        // Non-commit: signature only.
        const encAppl = new Codec.Encoder();
        Framing.writeFramedContentAuthData(encAppl,
            { signature: makeBytes(70) },
            Framing.ContentType.APPLICATION);
        const decAppl = new Codec.Decoder(encAppl.bytes());
        const authAppl = Framing.readFramedContentAuthData(decAppl,
            Framing.ContentType.APPLICATION);
        assert(
            authAppl.signature.length === 70 && decAppl.remaining() === 0
                && authAppl.confirmationTag === undefined,
            'AuthData (application) has signature only'
        );

        // Commit: signature + confirmation_tag.
        const encCommit = new Codec.Encoder();
        Framing.writeFramedContentAuthData(encCommit,
            { signature: makeBytes(70), confirmationTag: makeBytes(32) },
            Framing.ContentType.COMMIT);
        const decCommit = new Codec.Decoder(encCommit.bytes());
        const authCommit = Framing.readFramedContentAuthData(decCommit,
            Framing.ContentType.COMMIT);
        assert(
            authCommit.signature.length === 70
                && authCommit.confirmationTag.length === 32
                && decCommit.remaining() === 0,
            'AuthData (commit) has signature + confirmation_tag'
        );
    }

    console.log('# framing — AuthenticatedContent round-trip (application)');
    {
        const ac = {
            wireFormat: 0x0001,
            content: {
                groupId: makeBytes(16, 0x10),
                epoch: 99n,
                sender: { senderType: Framing.SenderType.MEMBER, leafIndex: 5 },
                authenticatedData: new Uint8Array(0),
                contentType: Framing.ContentType.APPLICATION,
                payload: new TextEncoder().encode('hello pinchat group'),
            },
            auth: { signature: makeBytes(71, 0x55) },
        };
        const bytes = Framing.authenticatedContentBytes(ac);
        const parsed = Framing.parseAuthenticatedContent(bytes);
        assert(parsed.wireFormat === 0x0001, 'ac.wireFormat preserved');
        assert(parsed.content.contentType === Framing.ContentType.APPLICATION, 'ac content_type');
        assert(
            hex(parsed.content.payload) === hex(ac.content.payload),
            'ac application payload round-trip'
        );
        assert(
            hex(parsed.auth.signature) === hex(ac.auth.signature),
            'ac signature round-trip'
        );
        const roundtrip = Framing.authenticatedContentBytes({
            wireFormat: parsed.wireFormat,
            content: parsed.content,
            auth: parsed.auth,
        });
        assert(hex(roundtrip) === hex(bytes), 'ac bytes round-trip');
    }

    console.log('# framing — AuthenticatedContent with callback payload parser (commit)');
    {
        // A commit body of 10 arbitrary bytes, plus signature+conf_tag.
        const commitBody = makeBytes(10, 0xee);
        const ac = {
            wireFormat: 0x0001,
            content: {
                groupId: makeBytes(8, 0xb0),
                epoch: 42n,
                sender: { senderType: Framing.SenderType.MEMBER, leafIndex: 0 },
                authenticatedData: new Uint8Array(0),
                contentType: Framing.ContentType.COMMIT,
                payload: commitBody,
            },
            auth: { signature: makeBytes(71, 0x66), confirmationTag: makeBytes(32, 0xaa) },
        };
        const bytes = Framing.authenticatedContentBytes(ac);

        // Callback that "knows" the commit body is exactly 10 bytes.
        const parsed = Framing.parseAuthenticatedContentWith(bytes, (decoder) => {
            decoder.readBytes(10);
            return null;
        });
        assert(parsed.content.contentType === Framing.ContentType.COMMIT, 'commit content_type');
        assert(hex(parsed.content.payload) === hex(commitBody), 'commit body slice round-trip');
        assert(
            hex(parsed.auth.signature) === hex(ac.auth.signature)
                && hex(parsed.auth.confirmationTag) === hex(ac.auth.confirmationTag),
            'commit auth round-trip'
        );
    }

    console.log('');
    console.log(`framing: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main();
