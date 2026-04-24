/**
 * PinChat MLS — KeyPackage (RFC 9420 §10).
 *
 *   struct {
 *       ProtocolVersion version;          // u16
 *       CipherSuite cipher_suite;         // u16
 *       HPKEPublicKey init_key;           // opaque<V>
 *       LeafNode leaf_node;
 *       Extension extensions<V>;
 *       // to-be-signed ends here
 *       opaque signature<V>;
 *   } KeyPackage;
 *
 * A KeyPackage is the "join token" another member uses to add us to a
 * group. It carries both the HPKE init key that the committer will
 * encrypt Welcome under and the LeafNode that takes our place in the
 * ratchet tree.
 *
 * Signing
 * -------
 * The KeyPackageTBS (everything up to and including extensions) is signed
 * with the leaf's signature key under label "KeyPackageTBS":
 *
 *   signature = SignWithLabel(leaf.signature_key, "KeyPackageTBS",
 *                             KeyPackageTBS_bytes)
 *
 * Reference
 * ---------
 * A KeyPackage reference (used inside Welcome.secrets[i].new_member)
 * is the hash of the full serialized KeyPackage under the RFC 9420 §5.2
 * RefHash label "MLS 1.0 KeyPackage Reference" (no auto-prefix — RefHash
 * writes the label verbatim).
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./labeled.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.KeyPackage = factory(root.MLS.Codec, root.MLS.Nodes, root.MLS.Labeled);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, Labeled) {
    'use strict';

    // Cloning this from group-context.js would create a dependency cycle
    // the other direction; both modules just inline the constants.
    const PROTOCOL_VERSION_MLS10 = 0x0001;
    const CIPHERSUITE_P256 = 0x0002;

    function writeKeyPackageTbs(encoder, kp) {
        encoder.writeU16(kp.version);
        encoder.writeU16(kp.cipherSuite);
        encoder.writeOpaque(kp.initKey);
        Nodes.writeLeafNode(encoder, kp.leafNode);
        Nodes.writeExtensions(encoder, kp.extensions || []);
    }

    function writeKeyPackage(encoder, kp) {
        writeKeyPackageTbs(encoder, kp);
        encoder.writeOpaque(kp.signature);
    }

    function readKeyPackage(decoder) {
        const kp = {};
        kp.version = decoder.readU16();
        kp.cipherSuite = decoder.readU16();
        kp.initKey = decoder.readOpaque();
        kp.leafNode = Nodes.readLeafNode(decoder);
        kp.extensions = Nodes.readExtensions(decoder);
        kp.signature = decoder.readOpaque();
        return kp;
    }

    function keyPackageTbsBytes(kp) {
        const encoder = new Codec.Encoder();
        writeKeyPackageTbs(encoder, kp);
        return encoder.bytes();
    }

    function keyPackageBytes(kp) {
        const encoder = new Codec.Encoder();
        writeKeyPackage(encoder, kp);
        return encoder.bytes();
    }

    function parseKeyPackage(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const kp = readKeyPackage(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`key_package: ${decoder.remaining()} trailing bytes`);
        }
        return kp;
    }

    /**
     * RFC 9420 §5.2 KeyPackage reference. The label "MLS 1.0 KeyPackage
     * Reference" is written *verbatim* — RefHash does not auto-prefix.
     */
    async function keyPackageRef(kpBytes) {
        return Labeled.refHash('MLS 1.0 KeyPackage Reference', kpBytes);
    }

    return Object.freeze({
        PROTOCOL_VERSION_MLS10,
        CIPHERSUITE_P256,
        writeKeyPackageTbs,
        writeKeyPackage,
        readKeyPackage,
        keyPackageTbsBytes,
        keyPackageBytes,
        parseKeyPackage,
        keyPackageRef,
    });
});
