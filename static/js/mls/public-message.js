/**
 * PinChat MLS — PublicMessage (RFC 9420 §6.2).
 *
 *   struct {
 *       FramedContent content;
 *       FramedContentAuthData auth;
 *       select (FramedContent.sender.sender_type) {
 *           case member: MAC membership_tag;    // opaque<V>, HMAC-SHA256
 *           case other:  struct {};
 *       };
 *   } PublicMessage;
 *
 * Signing (FramedContentTBS, §6.1):
 *
 *   struct {
 *       ProtocolVersion version = mls10;         // u16
 *       WireFormat wire_format;                  // u16
 *       FramedContent content;
 *       select (FramedContent.sender.sender_type) {
 *           case member or external: GroupContext context;
 *           case new_member_*:       struct {};
 *       };
 *   } FramedContentTBS;
 *
 *   signature = SignWithLabel(sig_key, "FramedContentTBS", tbs_bytes)
 *
 * Membership tag (§6.2):
 *
 *   struct {
 *       FramedContentTBS content_tbs;
 *       FramedContentAuthData auth;
 *   } AuthenticatedContentTBM;
 *
 *   membership_tag = MAC(membership_key, AuthenticatedContentTBM_bytes)
 *
 * where MAC is HMAC-SHA256 for ciphersuite 0x0002.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./framing.js'),
            require('./labeled.js'),
            require('./group-context.js'),
            require('./hpke.js'),
            require('./mls-message.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.PublicMessage = factory(
            root.MLS.Codec, root.MLS.Framing, root.MLS.Labeled,
            root.MLS.GroupContext, root.MLS.HPKE, root.MLS.MLSMessage,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Framing, Labeled, GroupContext, HPKE, MLSMessage) {
    'use strict';

    function hasMembershipTag(content) {
        return content.sender.senderType === Framing.SenderType.MEMBER;
    }

    function hasGroupContextInTbs(content) {
        return content.sender.senderType === Framing.SenderType.MEMBER
            || content.sender.senderType === Framing.SenderType.EXTERNAL;
    }

    /**
     * Serialise FramedContentTBS for a given (content, wireFormat, groupContext).
     * Callers that know their sender is a new_member may pass null for
     * groupContext.
     */
    function framedContentTbsBytes(wireFormat, content, groupContextStruct) {
        const encoder = new Codec.Encoder();
        encoder.writeU16(MLSMessage.PROTOCOL_VERSION_MLS10);
        encoder.writeU16(wireFormat);
        Framing.writeFramedContent(encoder, content);
        if (hasGroupContextInTbs(content)) {
            if (!groupContextStruct) {
                throw new Error('public-message: member/external sender requires GroupContext');
            }
            GroupContext.writeGroupContext(encoder, groupContextStruct);
        }
        return encoder.bytes();
    }

    /**
     * Serialise AuthenticatedContentTBM = (FramedContentTBS || FramedContentAuthData).
     * This is the plaintext input to membership_tag's HMAC.
     */
    function authenticatedContentTbmBytes(wireFormat, content, auth, groupContextStruct) {
        const tbs = framedContentTbsBytes(wireFormat, content, groupContextStruct);
        const encoder = new Codec.Encoder();
        encoder.writeBytes(tbs);
        Framing.writeFramedContentAuthData(encoder, auth, content.contentType);
        return encoder.bytes();
    }

    // --- Wire serialisation ----------------------------------------------
    //
    // PublicMessage has no length prefix on the payload body — each
    // section (content, auth, optional membership_tag) is written
    // contiguously. Since FramedContent uses a variable-length inline
    // proposal/commit body, we need the caller to supply a parsePayload
    // callback for non-application content types (same contract as
    // framing.parseAuthenticatedContentWith).

    function writePublicMessage(encoder, pm) {
        Framing.writeFramedContent(encoder, pm.content);
        Framing.writeFramedContentAuthData(encoder, pm.auth, pm.content.contentType);
        if (hasMembershipTag(pm.content)) {
            if (!pm.membershipTag) {
                throw new Error('public-message: member sender requires membership_tag');
            }
            encoder.writeOpaque(pm.membershipTag);
        }
    }

    function readPublicMessage(decoder, parsePayload) {
        const groupId = decoder.readOpaque();
        const epoch = decoder.readU64();
        const sender = Framing.readSender(decoder);
        const authenticatedData = decoder.readOpaque();
        const contentType = decoder.readU8();

        let content;
        if (contentType === Framing.ContentType.APPLICATION) {
            const payload = decoder.readOpaque();
            content = { groupId, epoch, sender, authenticatedData, contentType, payload };
        } else if (contentType === Framing.ContentType.PROPOSAL
                || contentType === Framing.ContentType.COMMIT) {
            if (typeof parsePayload !== 'function') {
                throw new Error('public-message: proposal/commit content requires parsePayload callback');
            }
            const start = decoder.pos;
            const parsed = parsePayload(decoder, contentType);
            const end = decoder.pos;
            const payload = decoder.buf.slice(start, end);
            content = { groupId, epoch, sender, authenticatedData, contentType, payload, parsed };
        } else {
            throw new Error(`public-message: unsupported content_type ${contentType}`);
        }

        const auth = Framing.readFramedContentAuthData(decoder, contentType);
        let membershipTag;
        if (content.sender.senderType === Framing.SenderType.MEMBER) {
            membershipTag = decoder.readOpaque();
        }
        return { content, auth, membershipTag };
    }

    function publicMessageBytes(pm) {
        const encoder = new Codec.Encoder();
        writePublicMessage(encoder, pm);
        return encoder.bytes();
    }

    function parsePublicMessage(bytes, parsePayload) {
        const decoder = new Codec.Decoder(bytes);
        const pm = readPublicMessage(decoder, parsePayload);
        if (decoder.remaining() !== 0) {
            throw new Error(`public-message: ${decoder.remaining()} trailing bytes`);
        }
        return pm;
    }

    // --- Crypto helpers ---------------------------------------------------

    async function computeMembershipTag(membershipKey, wireFormat, content, auth, groupContextStruct) {
        const tbm = authenticatedContentTbmBytes(wireFormat, content, auth, groupContextStruct);
        return HPKE.hmacSha256(membershipKey, tbm);
    }

    async function verifyMembershipTag(membershipKey, wireFormat, content, auth, groupContextStruct, tag) {
        const expected = await computeMembershipTag(membershipKey, wireFormat, content, auth, groupContextStruct);
        if (expected.length !== tag.length) return false;
        let diff = 0;
        for (let i = 0; i < expected.length; i += 1) diff |= expected[i] ^ tag[i];
        return diff === 0;
    }

    async function signFramedContent(signaturePrivateKey, wireFormat, content, groupContextStruct) {
        const tbs = framedContentTbsBytes(wireFormat, content, groupContextStruct);
        return Labeled.signWithLabel(signaturePrivateKey, 'FramedContentTBS', tbs);
    }

    async function verifyFramedContent(signaturePublicKey, wireFormat, content, groupContextStruct, signature) {
        const tbs = framedContentTbsBytes(wireFormat, content, groupContextStruct);
        return Labeled.verifyWithLabel(signaturePublicKey, 'FramedContentTBS', tbs, signature);
    }

    return Object.freeze({
        framedContentTbsBytes,
        authenticatedContentTbmBytes,
        writePublicMessage,
        readPublicMessage,
        publicMessageBytes,
        parsePublicMessage,
        computeMembershipTag,
        verifyMembershipTag,
        signFramedContent,
        verifyFramedContent,
    });
});
