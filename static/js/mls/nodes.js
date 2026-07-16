/**
 * PinChat MLS — ratchet-tree node structs (RFC 9420 §7.2 + §7.6).
 *
 * A ratchet tree is a vector<optional<Node>> where a Node is either a
 * LeafNode or a ParentNode. This module owns the encode/decode of every
 * node-adjacent struct:
 *
 *   Credential      — §5.3          (basic only; x509 deferred)
 *   Capabilities    — §7.2.1
 *   Extension / Extensions<V> — §7.2
 *   Lifetime        — §7.2
 *   LeafNodeSource  — §7.2 (u8)
 *   LeafNode        — §7.2 (select on leaf_node_source)
 *   ParentNode      — §7.3
 *   NodeType        — §7.6 (u8)
 *   Node            — §7.6 (select on node_type)
 *   optional<Node>  — §7.6
 *
 * Every function here operates on raw bytes via the codec — no
 * cryptographic side effects. Higher layers (tree-hash, ratchet-tree,
 * TreeKEM) layer on top.
 *
 * Encoding notes
 * --------------
 * - MLS uses opaque<V> for all variable-length byte fields. A varint
 *   length prefix precedes every such field.
 * - Vectors T<V> are also varint-length-prefixed (total encoded byte
 *   length, not element count).
 * - `optional<T>` in MLS is `present_byte (u8: 0 or 1) || [T if 1]`.
 *
 * Credential types
 * ----------------
 *   basic (0x0001) is implemented. x509 (0x0002) is not — PinChat does
 *   not ship an X.509 trust store and the extra complexity is not
 *   justified for our ephemeral rooms.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Nodes = factory(root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    // --- Enum constants ----------------------------------------------------

    const CredentialType = Object.freeze({ BASIC: 0x0001, X509: 0x0002 });

    const LeafNodeSource = Object.freeze({
        RESERVED: 0, KEY_PACKAGE: 1, UPDATE: 2, COMMIT: 3,
    });

    const NodeType = Object.freeze({ RESERVED: 0, LEAF: 1, PARENT: 2 });

    // --- optional<T> -------------------------------------------------------

    function writeOptional(encoder, value, writeT) {
        if (value === null || value === undefined) {
            encoder.writeU8(0);
        } else {
            encoder.writeU8(1);
            writeT(encoder, value);
        }
    }

    function readOptional(decoder, readT) {
        const present = decoder.readU8();
        if (present === 0) return null;
        if (present === 1) return readT(decoder);
        throw new Error(`optional: invalid presence byte 0x${present.toString(16)}`);
    }

    // --- Credential --------------------------------------------------------

    function writeCredential(encoder, credential) {
        encoder.writeU16(credential.credentialType);
        if (credential.credentialType === CredentialType.BASIC) {
            encoder.writeOpaque(credential.identity);
        } else {
            throw new Error(`credential: unsupported credential_type 0x${credential.credentialType.toString(16)}`);
        }
    }

    function readCredential(decoder) {
        const credentialType = decoder.readU16();
        if (credentialType === CredentialType.BASIC) {
            const identity = decoder.readOpaque();
            return { credentialType, identity };
        }
        throw new Error(`credential: unsupported credential_type 0x${credentialType.toString(16)}`);
    }

    // --- Capabilities ------------------------------------------------------
    //
    // Five parallel vectors of u16 values advertising what the leaf
    // supports. Order matters — it is part of the signed content.

    function writeU16Vector(encoder, items) {
        encoder.writeVector(items, (e, v) => e.writeU16(v));
    }

    function readU16Vector(decoder) {
        return decoder.readVector((d) => d.readU16());
    }

    function writeCapabilities(encoder, caps) {
        writeU16Vector(encoder, caps.versions);
        writeU16Vector(encoder, caps.cipherSuites);
        writeU16Vector(encoder, caps.extensions);
        writeU16Vector(encoder, caps.proposals);
        writeU16Vector(encoder, caps.credentials);
    }

    function readCapabilities(decoder) {
        return {
            versions: readU16Vector(decoder),
            cipherSuites: readU16Vector(decoder),
            extensions: readU16Vector(decoder),
            proposals: readU16Vector(decoder),
            credentials: readU16Vector(decoder),
        };
    }

    // --- Extension ---------------------------------------------------------

    function writeExtension(encoder, ext) {
        encoder.writeU16(ext.extensionType);
        encoder.writeOpaque(ext.extensionData);
    }

    function readExtension(decoder) {
        const extensionType = decoder.readU16();
        const extensionData = decoder.readOpaque();
        return { extensionType, extensionData };
    }

    function validateExtensionTypes(exts) {
        if (!Array.isArray(exts)) {
            throw new Error('extensions: expected an array');
        }
        const seen = new Set();
        for (const ext of exts) {
            if (!ext || !Number.isInteger(ext.extensionType)
                || ext.extensionType < 0 || ext.extensionType > 0xffff
                || !(ext.extensionData instanceof Uint8Array)) {
                throw new Error('extensions: malformed extension');
            }
            if (seen.has(ext.extensionType)) {
                throw new Error(
                    `extensions: duplicate extension_type ${ext.extensionType}`,
                );
            }
            seen.add(ext.extensionType);
        }
        return exts;
    }

    function writeExtensions(encoder, exts) {
        validateExtensionTypes(exts);
        encoder.writeVector(exts, writeExtension);
    }

    function readExtensions(decoder) {
        return validateExtensionTypes(decoder.readVector(readExtension));
    }

    // --- Lifetime ----------------------------------------------------------

    function writeLifetime(encoder, lifetime) {
        encoder.writeU64(lifetime.notBefore);
        encoder.writeU64(lifetime.notAfter);
    }

    function readLifetime(decoder) {
        return { notBefore: decoder.readU64(), notAfter: decoder.readU64() };
    }

    // --- LeafNode ----------------------------------------------------------
    //
    //   struct {
    //       HPKEPublicKey encryption_key;
    //       SignaturePublicKey signature_key;
    //       Credential credential;
    //       Capabilities capabilities;
    //       LeafNodeSource leaf_node_source;
    //       select (LeafNode.leaf_node_source) {
    //           case key_package: Lifetime lifetime;
    //           case update:      struct {};
    //           case commit:      opaque parent_hash<V>;
    //       };
    //       Extension extensions<V>;
    //       /* signed content ends here; signature follows */
    //       opaque signature<V>;
    //   } LeafNode;
    //
    // The "tbs" (to-be-signed) bytes are everything up to and including
    // extensions. We expose a helper that produces those bytes so the
    // caller can run SignWithLabel / VerifyWithLabel over them.

    function writeLeafNodeTbs(encoder, leaf) {
        encoder.writeOpaque(leaf.encryptionKey);
        encoder.writeOpaque(leaf.signatureKey);
        writeCredential(encoder, leaf.credential);
        writeCapabilities(encoder, leaf.capabilities);
        encoder.writeU8(leaf.leafNodeSource);
        switch (leaf.leafNodeSource) {
            case LeafNodeSource.KEY_PACKAGE:
                writeLifetime(encoder, leaf.lifetime);
                break;
            case LeafNodeSource.UPDATE:
                break; // empty struct
            case LeafNodeSource.COMMIT:
                encoder.writeOpaque(leaf.parentHash);
                break;
            default:
                throw new Error(`leaf_node: unsupported leaf_node_source ${leaf.leafNodeSource}`);
        }
        writeExtensions(encoder, leaf.extensions);
    }

    function writeLeafNode(encoder, leaf) {
        writeLeafNodeTbs(encoder, leaf);
        encoder.writeOpaque(leaf.signature);
    }

    function readLeafNode(decoder) {
        const leaf = {};
        leaf.encryptionKey = decoder.readOpaque();
        leaf.signatureKey = decoder.readOpaque();
        leaf.credential = readCredential(decoder);
        leaf.capabilities = readCapabilities(decoder);
        leaf.leafNodeSource = decoder.readU8();
        switch (leaf.leafNodeSource) {
            case LeafNodeSource.KEY_PACKAGE:
                leaf.lifetime = readLifetime(decoder);
                break;
            case LeafNodeSource.UPDATE:
                break;
            case LeafNodeSource.COMMIT:
                leaf.parentHash = decoder.readOpaque();
                break;
            default:
                throw new Error(`leaf_node: unsupported leaf_node_source ${leaf.leafNodeSource}`);
        }
        leaf.extensions = readExtensions(decoder);
        leaf.signature = decoder.readOpaque();
        return leaf;
    }

    /** Serialize only the to-be-signed portion of a LeafNode (no signature). */
    function leafNodeTbsBytes(leaf) {
        const encoder = new Codec.Encoder();
        writeLeafNodeTbs(encoder, leaf);
        return encoder.bytes();
    }

    /** Serialize a full LeafNode (TBS + signature). */
    function leafNodeBytes(leaf) {
        const encoder = new Codec.Encoder();
        writeLeafNode(encoder, leaf);
        return encoder.bytes();
    }

    // --- ParentNode --------------------------------------------------------
    //
    //   struct {
    //       HPKEPublicKey encryption_key;
    //       opaque parent_hash<V>;
    //       uint32 unmerged_leaves<V>;
    //   } ParentNode;

    function writeParentNode(encoder, parent) {
        encoder.writeOpaque(parent.encryptionKey);
        encoder.writeOpaque(parent.parentHash);
        encoder.writeVector(parent.unmergedLeaves, (e, leafIdx) => e.writeU32(leafIdx));
    }

    function readParentNode(decoder) {
        return {
            encryptionKey: decoder.readOpaque(),
            parentHash: decoder.readOpaque(),
            unmergedLeaves: decoder.readVector((d) => d.readU32()),
        };
    }

    function parentNodeBytes(parent) {
        const encoder = new Codec.Encoder();
        writeParentNode(encoder, parent);
        return encoder.bytes();
    }

    // --- Node (discriminated union) + optional<Node> ----------------------
    //
    //   struct {
    //       NodeType node_type;
    //       select (Node.node_type) {
    //           case leaf:   LeafNode leaf_node;
    //           case parent: ParentNode parent_node;
    //       };
    //   } Node;
    //
    //   optional<Node> in the ratchet-tree extension.

    function writeNode(encoder, node) {
        encoder.writeU8(node.nodeType);
        if (node.nodeType === NodeType.LEAF) {
            writeLeafNode(encoder, node.leaf);
        } else if (node.nodeType === NodeType.PARENT) {
            writeParentNode(encoder, node.parent);
        } else {
            throw new Error(`node: unsupported node_type ${node.nodeType}`);
        }
    }

    function readNode(decoder) {
        const nodeType = decoder.readU8();
        if (nodeType === NodeType.LEAF) {
            return { nodeType, leaf: readLeafNode(decoder) };
        }
        if (nodeType === NodeType.PARENT) {
            return { nodeType, parent: readParentNode(decoder) };
        }
        throw new Error(`node: unsupported node_type ${nodeType}`);
    }

    function writeOptionalNode(encoder, optNode) {
        writeOptional(encoder, optNode, writeNode);
    }

    function readOptionalNode(decoder) {
        return readOptional(decoder, readNode);
    }

    // --- RatchetTree (the ratchet-tree extension payload) -----------------
    //
    //   optional<Node> ratchet_tree<V>;
    //
    // i.e. a vector<optional<Node>>. Total byte length is varint-prefixed.

    function writeRatchetTree(encoder, tree) {
        encoder.writeVector(tree, writeOptionalNode);
    }

    function readRatchetTree(decoder) {
        return decoder.readVector(readOptionalNode);
    }

    function ratchetTreeBytes(tree) {
        const encoder = new Codec.Encoder();
        writeRatchetTree(encoder, tree);
        return encoder.bytes();
    }

    function parseRatchetTree(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const tree = readRatchetTree(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`ratchet_tree: ${decoder.remaining()} trailing bytes`);
        }
        return tree;
    }

    /**
     * Pad a ratchet-tree array with trailing blank slots up to the given
     * width. RFC 9420 §12.4.3.3 allows the wire form to omit trailing
     * blanks, so callers that need the full `node_width(n_leaves)` shape
     * (tree hash, ratchet-tree storage) must pad explicitly.
     *
     * Returns a new array; the input is not mutated. `width` must be
     * greater than or equal to `tree.length`.
     */
    function padRatchetTree(tree, width) {
        if (width < tree.length) {
            throw new Error(`padRatchetTree: target width ${width} < tree length ${tree.length}`);
        }
        const out = new Array(width);
        for (let i = 0; i < tree.length; i += 1) out[i] = tree[i];
        for (let i = tree.length; i < width; i += 1) out[i] = null;
        return out;
    }

    // --- HPKECiphertext + UpdatePath (RFC 9420 §6.3) -----------------------
    //
    //   struct {
    //       opaque kem_output<V>;
    //       opaque ciphertext<V>;
    //   } HPKECiphertext;
    //
    //   struct {
    //       HPKEPublicKey encryption_key;         // opaque<V>
    //       HPKECiphertext encrypted_path_secret<V>;
    //   } UpdatePathNode;
    //
    //   struct {
    //       LeafNode leaf_node;
    //       UpdatePathNode nodes<V>;
    //   } UpdatePath;

    function writeHPKECiphertext(encoder, hpkeCt) {
        encoder.writeOpaque(hpkeCt.kemOutput);
        encoder.writeOpaque(hpkeCt.ciphertext);
    }

    function readHPKECiphertext(decoder) {
        return {
            kemOutput: decoder.readOpaque(),
            ciphertext: decoder.readOpaque(),
        };
    }

    function writeUpdatePathNode(encoder, node) {
        encoder.writeOpaque(node.encryptionKey);
        encoder.writeVector(node.encryptedPathSecret, writeHPKECiphertext);
    }

    function readUpdatePathNode(decoder) {
        return {
            encryptionKey: decoder.readOpaque(),
            encryptedPathSecret: decoder.readVector(readHPKECiphertext),
        };
    }

    function writeUpdatePath(encoder, up) {
        writeLeafNode(encoder, up.leafNode);
        encoder.writeVector(up.nodes, writeUpdatePathNode);
    }

    function readUpdatePath(decoder) {
        return {
            leafNode: readLeafNode(decoder),
            nodes: decoder.readVector(readUpdatePathNode),
        };
    }

    function updatePathBytes(up) {
        const encoder = new Codec.Encoder();
        writeUpdatePath(encoder, up);
        return encoder.bytes();
    }

    function parseUpdatePath(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const up = readUpdatePath(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`update_path: ${decoder.remaining()} trailing bytes`);
        }
        return up;
    }

    return Object.freeze({
        // Enums
        CredentialType,
        LeafNodeSource,
        NodeType,
        // Serialization primitives
        writeOptional,
        readOptional,
        writeCredential,
        readCredential,
        writeCapabilities,
        readCapabilities,
        writeExtension,
        readExtension,
        writeExtensions,
        readExtensions,
        validateExtensionTypes,
        writeLifetime,
        readLifetime,
        writeLeafNode,
        readLeafNode,
        writeLeafNodeTbs,
        leafNodeTbsBytes,
        leafNodeBytes,
        writeParentNode,
        readParentNode,
        parentNodeBytes,
        writeNode,
        readNode,
        writeOptionalNode,
        readOptionalNode,
        writeRatchetTree,
        readRatchetTree,
        ratchetTreeBytes,
        parseRatchetTree,
        padRatchetTree,
        writeHPKECiphertext,
        readHPKECiphertext,
        writeUpdatePathNode,
        readUpdatePathNode,
        writeUpdatePath,
        readUpdatePath,
        updatePathBytes,
        parseUpdatePath,
    });
});
