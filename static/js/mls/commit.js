/**
 * PinChat MLS — Commit + ProposalOrRef (RFC 9420 §12.4).
 *
 *   struct {
 *       ProposalOrRefType type;           // u8
 *       select {
 *           case value:     Proposal proposal;
 *           case reference: opaque reference<V>;   // = ProposalRef
 *       };
 *   } ProposalOrRef;
 *
 *   struct {
 *       ProposalOrRef proposals<V>;
 *       optional<UpdatePath> path;
 *   } Commit;
 *
 * ProposalRef (§5.2):
 *   ref = RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./proposal.js'),
            require('./labeled.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Commit = factory(
            root.MLS.Codec, root.MLS.Nodes, root.MLS.Proposal, root.MLS.Labeled,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, Proposal, Labeled) {
    'use strict';

    function writeProposalOrRef(encoder, por) {
        encoder.writeU8(por.type);
        if (por.type === Proposal.ProposalOrRefType.PROPOSAL) {
            Proposal.writeProposal(encoder, por.proposal);
        } else if (por.type === Proposal.ProposalOrRefType.REFERENCE) {
            encoder.writeOpaque(por.reference);
        } else {
            throw new Error(`proposal_or_ref: unsupported type ${por.type}`);
        }
    }

    function readProposalOrRef(decoder) {
        const type = decoder.readU8();
        if (type === Proposal.ProposalOrRefType.PROPOSAL) {
            return { type, proposal: Proposal.readProposal(decoder) };
        }
        if (type === Proposal.ProposalOrRefType.REFERENCE) {
            return { type, reference: decoder.readOpaque() };
        }
        throw new Error(`proposal_or_ref: unsupported type ${type}`);
    }

    function writeCommit(encoder, commit) {
        encoder.writeVector(commit.proposals, writeProposalOrRef);
        Nodes.writeOptional(encoder, commit.path, Nodes.writeUpdatePath);
    }

    function readCommit(decoder) {
        return {
            proposals: decoder.readVector(readProposalOrRef),
            path: Nodes.readOptional(decoder, Nodes.readUpdatePath),
        };
    }

    function commitBytes(commit) {
        const encoder = new Codec.Encoder();
        writeCommit(encoder, commit);
        return encoder.bytes();
    }

    function parseCommit(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const c = readCommit(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`commit: ${decoder.remaining()} trailing bytes`);
        }
        return c;
    }

    /**
     * RFC 9420 §5.2 ProposalRef:
     *   ref = RefHash("MLS 1.0 Proposal Reference", authenticated_content)
     * The label is written verbatim (no auto "MLS 1.0 " prefix in RefHash).
     */
    async function proposalRef(authenticatedContentBytes) {
        return Labeled.refHash('MLS 1.0 Proposal Reference', authenticatedContentBytes);
    }

    return Object.freeze({
        writeProposalOrRef,
        readProposalOrRef,
        writeCommit,
        readCommit,
        commitBytes,
        parseCommit,
        proposalRef,
    });
});
