/**
 * PinChat MLS — FramedContent / AuthenticatedContent framing (RFC 9420 §6).
 *
 * The framing layer wraps every group operation (application message,
 * proposal, commit) with a common envelope that carries:
 *   - the sending leaf (Sender)
 *   - the authenticated_data side channel
 *   - a signature over the content + group context
 *   - for commits, a confirmation_tag over the transcript hash
 *
 * This file owns the outer wrappers only — the proposal / commit bodies
 * are handled as opaque `payload` byte blobs here and parsed by the
 * proposal module in a follow-up commit. Keeping proposal/commit
 * decoding out of framing.js lets the framing layer ship byte-for-byte
 * verified ahead of the Proposal/Commit struct work.
 *
 * Structs implemented
 * -------------------
 *   enum { reserved(0), application(1), proposal(2), commit(3) } ContentType;
 *   enum { reserved(0), member(1), external(2),
 *          new_member_proposal(3), new_member_commit(4) } SenderType;
 *
 *   struct {
 *       SenderType sender_type;
 *       select {
 *           case member:               uint32 leaf_index;
 *           case external:             uint32 sender_index;
 *           case new_member_proposal:  struct {};
 *           case new_member_commit:    struct {};
 *       };
 *   } Sender;
 *
 *   struct {
 *       opaque group_id<V>;
 *       uint64 epoch;
 *       Sender sender;
 *       opaque authenticated_data<V>;
 *       ContentType content_type;
 *       opaque payload<V>;   // application_data / encoded Proposal / encoded Commit
 *   } FramedContent;
 *
 *   struct {
 *       opaque signature<V>;
 *       select (content.content_type) {
 *           case commit: MAC confirmation_tag;   // opaque<V>
 *           case other:  struct {};
 *       };
 *   } FramedContentAuthData;
 *
 *   struct {
 *       WireFormat wire_format;        // for signature domain separation
 *       FramedContent content;
 *       FramedContentAuthData auth;
 *   } AuthenticatedContent;
 *
 * Note on FramedContent.payload
 * -----------------------------
 * For content_type == application, `payload` is `opaque application_data<V>`
 * on the wire — i.e. a length-prefixed opaque blob. For content_type
 * == proposal / commit, the RFC embeds the Proposal / Commit struct
 * *inline* (no length prefix). We paper over that by exposing
 * `writeFramedContent(encoder, fc, { inlinePayload: true })` for the
 * proposal/commit path and leaving the default behaviour (opaque) for
 * the application path. The proposal module will call the inline path
 * once it lands.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Framing = factory(root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    const ContentType = Object.freeze({
        RESERVED: 0, APPLICATION: 1, PROPOSAL: 2, COMMIT: 3,
    });

    const SenderType = Object.freeze({
        RESERVED: 0, MEMBER: 1, EXTERNAL: 2,
        NEW_MEMBER_PROPOSAL: 3, NEW_MEMBER_COMMIT: 4,
    });

    // --- Sender -----------------------------------------------------------

    function writeSender(encoder, sender) {
        encoder.writeU8(sender.senderType);
        switch (sender.senderType) {
            case SenderType.MEMBER:
                encoder.writeU32(sender.leafIndex);
                break;
            case SenderType.EXTERNAL:
                encoder.writeU32(sender.senderIndex);
                break;
            case SenderType.NEW_MEMBER_PROPOSAL:
            case SenderType.NEW_MEMBER_COMMIT:
                break; // empty struct
            default:
                throw new Error(`sender: unsupported sender_type ${sender.senderType}`);
        }
    }

    function readSender(decoder) {
        const senderType = decoder.readU8();
        switch (senderType) {
            case SenderType.MEMBER:
                return { senderType, leafIndex: decoder.readU32() };
            case SenderType.EXTERNAL:
                return { senderType, senderIndex: decoder.readU32() };
            case SenderType.NEW_MEMBER_PROPOSAL:
            case SenderType.NEW_MEMBER_COMMIT:
                return { senderType };
            default:
                throw new Error(`sender: unsupported sender_type ${senderType}`);
        }
    }

    // --- FramedContent ----------------------------------------------------

    /**
     * Write a FramedContent. `payloadBytes` must be:
     *   - for content_type=application: the raw application_data bytes
     *     (we prefix them with an opaque<V> length as per the RFC)
     *   - for content_type=proposal/commit: the inline struct bytes
     *     (no extra length prefix — the proposal/commit has its own
     *     internal varint-length fields)
     */
    function writeFramedContent(encoder, fc) {
        encoder.writeOpaque(fc.groupId);
        encoder.writeU64(fc.epoch);
        writeSender(encoder, fc.sender);
        encoder.writeOpaque(fc.authenticatedData);
        encoder.writeU8(fc.contentType);
        if (fc.contentType === ContentType.APPLICATION) {
            encoder.writeOpaque(fc.payload);
        } else if (fc.contentType === ContentType.PROPOSAL
                || fc.contentType === ContentType.COMMIT) {
            encoder.writeBytes(fc.payload);
        } else {
            throw new Error(`framed_content: unsupported content_type ${fc.contentType}`);
        }
    }

    /**
     * Read a FramedContent. For proposal/commit content types we read the
     * remaining bytes of the slice as the inline payload — the caller
     * must bound the decoder before calling (e.g. by reading
     * AuthenticatedContent in a single shot and slicing off auth bytes
     * at the end), or the decoder will consume trailing auth bytes.
     *
     * Because we don't know the on-wire length of a Proposal/Commit
     * without parsing it, we expose a two-step parser:
     *   readFramedContentShallow(decoder) — reads through content_type
     *   then returns { groupId, epoch, sender, authenticatedData,
     *                  contentType, payloadStart }
     * and the caller finishes by slicing payload bytes from
     * `payloadStart` up to the known tail.
     *
     * For APPLICATION content_type this function reads the opaque<V>
     * payload and returns a fully populated FramedContent.
     */
    function readFramedContentShallow(decoder) {
        const groupId = decoder.readOpaque();
        const epoch = decoder.readU64();
        const sender = readSender(decoder);
        const authenticatedData = decoder.readOpaque();
        const contentType = decoder.readU8();
        if (contentType === ContentType.APPLICATION) {
            const payload = decoder.readOpaque();
            return {
                groupId, epoch, sender, authenticatedData, contentType, payload,
            };
        }
        if (contentType === ContentType.PROPOSAL || contentType === ContentType.COMMIT) {
            // Caller slices remaining payload up to its own boundary.
            return {
                groupId, epoch, sender, authenticatedData, contentType,
                payloadStart: decoder.pos,
            };
        }
        throw new Error(`framed_content: unsupported content_type ${contentType}`);
    }

    function framedContentBytes(fc) {
        const encoder = new Codec.Encoder();
        writeFramedContent(encoder, fc);
        return encoder.bytes();
    }

    // --- FramedContentAuthData -------------------------------------------

    function writeFramedContentAuthData(encoder, auth, contentType) {
        encoder.writeOpaque(auth.signature);
        if (contentType === ContentType.COMMIT) {
            encoder.writeOpaque(auth.confirmationTag);
        }
    }

    function readFramedContentAuthData(decoder, contentType) {
        const signature = decoder.readOpaque();
        if (contentType === ContentType.COMMIT) {
            return { signature, confirmationTag: decoder.readOpaque() };
        }
        return { signature };
    }

    // --- AuthenticatedContent ---------------------------------------------
    //
    //   struct {
    //       WireFormat wire_format;   // u16
    //       FramedContent content;
    //       FramedContentAuthData auth;
    //   } AuthenticatedContent;
    //
    // WireFormat is the same enum as mls-message.js; it is folded into
    // AuthenticatedContent so signatures are domain-separated between
    // PublicMessage and PrivateMessage framings.

    function writeAuthenticatedContent(encoder, ac) {
        encoder.writeU16(ac.wireFormat);
        writeFramedContent(encoder, ac.content);
        writeFramedContentAuthData(encoder, ac.auth, ac.content.contentType);
    }

    function authenticatedContentBytes(ac) {
        const encoder = new Codec.Encoder();
        writeAuthenticatedContent(encoder, ac);
        return encoder.bytes();
    }

    /**
     * Parse an AuthenticatedContent from bytes. For commit/proposal
     * content types, the embedded payload is returned as raw bytes
     * (`content.payload` is the concatenation of the Proposal/Commit
     * wire bytes). Trailing bytes after auth are not allowed.
     */
    function parseAuthenticatedContent(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const wireFormat = decoder.readU16();
        const shallow = readFramedContentShallow(decoder);

        if (shallow.contentType === ContentType.APPLICATION) {
            const auth = readFramedContentAuthData(decoder, shallow.contentType);
            if (decoder.remaining() !== 0) {
                throw new Error(`authenticated_content: ${decoder.remaining()} trailing bytes`);
            }
            return { wireFormat, content: shallow, auth };
        }

        // For proposal/commit, the payload is inlined and variable-length.
        // We locate the payload end by scanning the fixed tail structure of
        // FramedContentAuthData: an opaque<V> signature, and — for commit —
        // an opaque<V> confirmation_tag.
        //
        // Strategy: peel the tail off the end by treating the bytes BACK-
        // wards. For a commit, the last 33 bytes are the confirmation_tag
        // opaque<V> (0x20 || 32-byte MAC). Before that, the signature
        // opaque<V> ends at (bytes.length - 33). We cannot find a
        // signature's start without parsing, so we parse forwards: read
        // the FramedContentAuthData structure positions by scanning
        // forward after the assumed payload boundary candidates. But
        // that's O(N) scans.
        //
        // Simpler: decoders for Proposal and Commit know their own length.
        // They expose `parse(decoder)` that advances the cursor exactly
        // the right amount. framing.js is content-type-agnostic, so we
        // delegate: the caller supplies a `parsePayload(decoder, contentType)`
        // callback to advance past the inline body.
        throw new Error(
            'framing: use parseAuthenticatedContentWith(bytes, parsePayload) ' +
            'for non-application content types — Proposal/Commit parsing ' +
            'lives in proposal.js'
        );
    }

    /**
     * Variant of parseAuthenticatedContent that accepts a
     * `parsePayload(decoder, contentType)` callback responsible for
     * advancing the decoder across the inline Proposal/Commit body and
     * returning its parsed representation. Used by the proposal module.
     */
    function parseAuthenticatedContentWith(bytes, parsePayload) {
        const decoder = new Codec.Decoder(bytes);
        const wireFormat = decoder.readU16();

        const groupId = decoder.readOpaque();
        const epoch = decoder.readU64();
        const sender = readSender(decoder);
        const authenticatedData = decoder.readOpaque();
        const contentType = decoder.readU8();

        let content;
        if (contentType === ContentType.APPLICATION) {
            const payload = decoder.readOpaque();
            content = { groupId, epoch, sender, authenticatedData, contentType, payload };
        } else if (contentType === ContentType.PROPOSAL || contentType === ContentType.COMMIT) {
            const start = decoder.pos;
            const parsed = parsePayload(decoder, contentType);
            const end = decoder.pos;
            const payloadBytes = bytes.slice(start, end);
            content = {
                groupId, epoch, sender, authenticatedData, contentType,
                payload: payloadBytes, parsed,
            };
        } else {
            throw new Error(`authenticated_content: unsupported content_type ${contentType}`);
        }

        const auth = readFramedContentAuthData(decoder, contentType);
        if (decoder.remaining() !== 0) {
            throw new Error(`authenticated_content: ${decoder.remaining()} trailing bytes`);
        }
        return { wireFormat, content, auth };
    }

    return Object.freeze({
        ContentType,
        SenderType,
        writeSender,
        readSender,
        writeFramedContent,
        framedContentBytes,
        readFramedContentShallow,
        writeFramedContentAuthData,
        readFramedContentAuthData,
        writeAuthenticatedContent,
        authenticatedContentBytes,
        parseAuthenticatedContent,
        parseAuthenticatedContentWith,
    });
});
