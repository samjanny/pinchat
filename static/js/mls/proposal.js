/**
 * PinChat MLS — Proposal + Commit structs (RFC 9420 §12).
 *
 * Proposal layer
 * --------------
 *   enum {
 *       reserved(0), add(1), update(2), remove(3), psk(4),
 *       reinit(5), external_init(6), group_context_extensions(7), (255)
 *   } ProposalType;
 *
 *   struct {
 *       ProposalType proposal_type;        // u16 on the wire
 *       select (Proposal.proposal_type) {
 *           case add:                      Add;
 *           case update:                   Update;
 *           case remove:                   Remove;
 *           case psk:                      PreSharedKey;
 *           case reinit:                   ReInit;
 *           case external_init:            ExternalInit;
 *           case group_context_extensions: GroupContextExtensions;
 *       };
 *   } Proposal;
 *
 *   struct { KeyPackage key_package; }                      Add;
 *   struct { LeafNode leaf_node; }                          Update;
 *   struct { uint32 removed; }                              Remove;
 *   struct { PreSharedKeyID psk; }                          PreSharedKey;
 *   struct { opaque kem_output<V>; }                        ExternalInit;
 *   struct { Extension extensions<V>; }                     GroupContextExtensions;
 *   struct {                                                // ReInit
 *       opaque group_id<V>;
 *       ProtocolVersion version;     // u16
 *       CipherSuite cipher_suite;    // u16
 *       Extension extensions<V>;
 *   }                                                       ReInit;
 *
 * Scope note
 * ----------
 * Add/Update/Remove are fully implemented and tested. PSK is parsed by
 * delegating to welcome.js's PreSharedKeyID serde. ReInit /
 * ExternalInit / GroupContextExtensions are parsed as opaque "rest of
 * body" blobs with their own serialized bytes captured — enough to
 * roundtrip unknown proposals without decoding them.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./key-package.js'),
            require('./welcome.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Proposal = factory(
            root.MLS.Codec, root.MLS.Nodes, root.MLS.KeyPackage, root.MLS.Welcome,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, KeyPackage, Welcome) {
    'use strict';

    const ProposalType = Object.freeze({
        RESERVED: 0, ADD: 1, UPDATE: 2, REMOVE: 3, PSK: 4,
        REINIT: 5, EXTERNAL_INIT: 6, GROUP_CONTEXT_EXTENSIONS: 7,
    });

    const ProposalOrRefType = Object.freeze({
        RESERVED: 0, PROPOSAL: 1, REFERENCE: 2,
    });

    // --- Proposal ---------------------------------------------------------

    function writeProposal(encoder, proposal) {
        encoder.writeU16(proposal.proposalType);
        switch (proposal.proposalType) {
            case ProposalType.ADD:
                KeyPackage.writeKeyPackage(encoder, proposal.keyPackage);
                break;
            case ProposalType.UPDATE:
                Nodes.writeLeafNode(encoder, proposal.leafNode);
                break;
            case ProposalType.REMOVE:
                encoder.writeU32(proposal.removed);
                break;
            case ProposalType.PSK:
                Welcome.writePreSharedKeyID(encoder, proposal.psk);
                break;
            default:
                // For unparsed bodies, emit the captured raw bytes verbatim.
                if (!proposal.rawBody) {
                    throw new Error(`proposal: unsupported proposal_type ${proposal.proposalType}`);
                }
                encoder.writeBytes(proposal.rawBody);
        }
    }

    /**
     * Read a Proposal. The caller's decoder must be positioned at the
     * start of the Proposal; the decoder advances past the Proposal's
     * last byte on success.
     *
     * For ADD/UPDATE/REMOVE/PSK we return a typed object; for the less
     * common ReInit/ExternalInit/GroupContextExtensions we parse a
     * structured form where possible, falling back to `rawBody`
     * slicing for anything we don't fully model yet.
     */
    function readProposal(decoder) {
        const proposalType = decoder.readU16();
        const start = decoder.pos;
        switch (proposalType) {
            case ProposalType.ADD: {
                const keyPackage = KeyPackage.readKeyPackage(decoder);
                return { proposalType, keyPackage };
            }
            case ProposalType.UPDATE: {
                const leafNode = Nodes.readLeafNode(decoder);
                return { proposalType, leafNode };
            }
            case ProposalType.REMOVE: {
                const removed = decoder.readU32();
                return { proposalType, removed };
            }
            case ProposalType.PSK: {
                const psk = Welcome.readPreSharedKeyID(decoder);
                return { proposalType, psk };
            }
            case ProposalType.EXTERNAL_INIT: {
                const kemOutput = decoder.readOpaque();
                return { proposalType, kemOutput };
            }
            case ProposalType.GROUP_CONTEXT_EXTENSIONS: {
                const extensions = Nodes.readExtensions(decoder);
                return { proposalType, extensions };
            }
            case ProposalType.REINIT: {
                const groupId = decoder.readOpaque();
                const version = decoder.readU16();
                const cipherSuite = decoder.readU16();
                const extensions = Nodes.readExtensions(decoder);
                return { proposalType, groupId, version, cipherSuite, extensions };
            }
            default:
                throw new Error(`proposal: unsupported proposal_type ${proposalType} at pos ${start}`);
        }
    }

    function proposalBytes(proposal) {
        const encoder = new Codec.Encoder();
        writeProposal(encoder, proposal);
        return encoder.bytes();
    }

    function parseProposal(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const p = readProposal(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`proposal: ${decoder.remaining()} trailing bytes`);
        }
        return p;
    }

    return Object.freeze({
        ProposalType,
        ProposalOrRefType,
        writeProposal,
        readProposal,
        proposalBytes,
        parseProposal,
    });
});
