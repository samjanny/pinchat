/**
 * PinChat MLS — GroupContext (RFC 9420 §8.1).
 *
 *   struct {
 *       ProtocolVersion version = mls10;    // u16, 0x0001
 *       CipherSuite cipher_suite;           // u16
 *       opaque group_id<V>;
 *       uint64 epoch;
 *       opaque tree_hash<V>;
 *       opaque confirmed_transcript_hash<V>;
 *       Extension extensions<V>;
 *   } GroupContext;
 *
 * The serialized GroupContext is the `context` input to the joiner/epoch
 * legs of the key schedule, and the AAD for PrivateMessage framing. It's
 * also hashed and embedded in SignWithLabel contexts for Commit-adjacent
 * signatures.
 *
 * We commit to `version = 0x0001` (mls10) and `cipher_suite = 0x0002`.
 * Other values will fail decode — defensive by design.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'), require('./nodes.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.GroupContext = factory(root.MLS.Codec, root.MLS.Nodes);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes) {
    'use strict';

    const PROTOCOL_VERSION_MLS10 = 0x0001;
    const CIPHERSUITE_MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002;

    function writeGroupContext(encoder, ctx) {
        encoder.writeU16(ctx.version);
        encoder.writeU16(ctx.cipherSuite);
        encoder.writeOpaque(ctx.groupId);
        encoder.writeU64(ctx.epoch);
        encoder.writeOpaque(ctx.treeHash);
        encoder.writeOpaque(ctx.confirmedTranscriptHash);
        Nodes.writeExtensions(encoder, ctx.extensions || []);
    }

    function readGroupContext(decoder) {
        return {
            version: decoder.readU16(),
            cipherSuite: decoder.readU16(),
            groupId: decoder.readOpaque(),
            epoch: decoder.readU64(),
            treeHash: decoder.readOpaque(),
            confirmedTranscriptHash: decoder.readOpaque(),
            extensions: Nodes.readExtensions(decoder),
        };
    }

    function groupContextBytes(ctx) {
        const encoder = new Codec.Encoder();
        writeGroupContext(encoder, ctx);
        return encoder.bytes();
    }

    function parseGroupContext(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const ctx = readGroupContext(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`group_context: ${decoder.remaining()} trailing bytes`);
        }
        return ctx;
    }

    return Object.freeze({
        PROTOCOL_VERSION_MLS10,
        CIPHERSUITE_MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
        writeGroupContext,
        readGroupContext,
        groupContextBytes,
        parseGroupContext,
    });
});
