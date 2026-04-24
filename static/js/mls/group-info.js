/**
 * PinChat MLS — GroupInfo (RFC 9420 §12.4.3.1).
 *
 *   struct {
 *       GroupContext group_context;
 *       Extension extensions<V>;
 *       MAC confirmation_tag;           // opaque<V>, HMAC-SHA256 = 32 bytes
 *       uint32 signer;                   // leaf index of the signer
 *       // to-be-signed ends here
 *       opaque signature<V>;
 *   } GroupInfo;
 *
 * GroupInfo carries the group state a joiner needs to reconstruct the
 * ratchet tree and align on the current epoch. It is signed by the
 * committing member (the leaf at `signer`) using
 *   signature = SignWithLabel(leaf.signature_key, "GroupInfoTBS",
 *                             GroupInfoTBS_bytes)
 * and then AEAD-encrypted inside a Welcome using welcome_key /
 * welcome_nonce derived from welcome_secret.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./group-context.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.GroupInfo = factory(root.MLS.Codec, root.MLS.Nodes, root.MLS.GroupContext);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, GroupContext) {
    'use strict';

    function writeGroupInfoTbs(encoder, gi) {
        GroupContext.writeGroupContext(encoder, gi.groupContext);
        Nodes.writeExtensions(encoder, gi.extensions || []);
        encoder.writeOpaque(gi.confirmationTag);
        encoder.writeU32(gi.signer);
    }

    function writeGroupInfo(encoder, gi) {
        writeGroupInfoTbs(encoder, gi);
        encoder.writeOpaque(gi.signature);
    }

    function readGroupInfo(decoder) {
        return {
            groupContext: GroupContext.readGroupContext(decoder),
            extensions: Nodes.readExtensions(decoder),
            confirmationTag: decoder.readOpaque(),
            signer: decoder.readU32(),
            signature: decoder.readOpaque(),
        };
    }

    function groupInfoTbsBytes(gi) {
        const encoder = new Codec.Encoder();
        writeGroupInfoTbs(encoder, gi);
        return encoder.bytes();
    }

    function groupInfoBytes(gi) {
        const encoder = new Codec.Encoder();
        writeGroupInfo(encoder, gi);
        return encoder.bytes();
    }

    function parseGroupInfo(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const gi = readGroupInfo(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`group_info: ${decoder.remaining()} trailing bytes`);
        }
        return gi;
    }

    return Object.freeze({
        writeGroupInfoTbs,
        writeGroupInfo,
        readGroupInfo,
        groupInfoTbsBytes,
        groupInfoBytes,
        parseGroupInfo,
    });
});
