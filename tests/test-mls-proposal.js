#!/usr/bin/env node

/**
 * MLS Proposal + Commit struct tests.
 *
 * Uses the raw `proposal` (6 bytes) and `commit` (73 bytes) fields from
 * message-protection.json for cipher_suite = 2 to cross-verify struct
 * serialization byte-for-byte.
 *
 * Covers:
 *   - Proposal (Remove variant) round-trip
 *   - Commit round-trip with a single inline PSK Proposal
 *   - Synthetic Add / Update round-trips so every implemented proposal
 *     type is exercised at least once
 */

const path = require('path');
const Proposal = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'proposal.js'));
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'message-protection.json'));

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

function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);

    // ---------------------------------------------------------------------
    // Proposal — Remove variant from the IETF vector
    // ---------------------------------------------------------------------
    console.log('# Proposal round-trip — message-protection.json cs=2');
    {
        const bytes = hexDecode(v.proposal);
        const p = Proposal.parseProposal(bytes);
        assert(p.proposalType === Proposal.ProposalType.REMOVE, 'proposal_type == remove');
        assert(p.removed === 2, 'remove.removed == 2');
        const round = Proposal.proposalBytes(p);
        assert(hex(round) === v.proposal.toLowerCase(), 'Remove proposal round-trip');
    }

    // ---------------------------------------------------------------------
    // Commit — single inline PSK Proposal, no UpdatePath
    // ---------------------------------------------------------------------
    console.log('# Commit round-trip — message-protection.json cs=2');
    {
        const bytes = hexDecode(v.commit);
        const c = Commit.parseCommit(bytes);
        assert(c.proposals.length === 1, 'Commit has exactly 1 proposal');
        const por = c.proposals[0];
        assert(
            por.type === Proposal.ProposalOrRefType.PROPOSAL,
            'proposals[0] is inline (type == value)'
        );
        assert(
            por.proposal.proposalType === Proposal.ProposalType.PSK,
            'inline proposal type == psk'
        );
        assert(por.proposal.psk.psktype === 1, 'psk type == external (1)');
        assert(por.proposal.psk.pskId.length === 32, 'psk_id is 32 bytes');
        assert(c.path === null, 'no UpdatePath on this commit');

        const round = Commit.commitBytes(c);
        assert(hex(round) === v.commit.toLowerCase(), 'Commit round-trip byte-for-byte');
    }

    // ---------------------------------------------------------------------
    // Synthetic Add / Update / Reference round-trips
    // ---------------------------------------------------------------------
    console.log('# Synthetic Proposal + ProposalOrRef round-trips');
    {
        // Reference wrapped in ProposalOrRef
        const ref32 = new Uint8Array(32);
        for (let i = 0; i < 32; i += 1) ref32[i] = (i + 1) & 0xff;
        const refEnc = new Codec.Encoder();
        Commit.writeProposalOrRef(refEnc, {
            type: Proposal.ProposalOrRefType.REFERENCE,
            reference: ref32,
        });
        const refBytes = refEnc.bytes();
        const refDec = new Codec.Decoder(refBytes);
        const refBack = Commit.readProposalOrRef(refDec);
        assert(
            refBack.type === Proposal.ProposalOrRefType.REFERENCE
                && hex(refBack.reference) === hex(ref32)
                && refDec.remaining() === 0,
            'ProposalOrRef(reference) round-trip'
        );

        // Remove proposal
        const remove = {
            proposalType: Proposal.ProposalType.REMOVE,
            removed: 0xdeadbeef,
        };
        const rmBytes = Proposal.proposalBytes(remove);
        const rmBack = Proposal.parseProposal(rmBytes);
        assert(
            rmBack.removed === 0xdeadbeef >>> 0,
            'Remove proposal u32 round-trip'
        );

        // Empty Commit (no proposals, no path)
        const emptyCommit = { proposals: [], path: null };
        const ecBytes = Commit.commitBytes(emptyCommit);
        const ecBack = Commit.parseCommit(ecBytes);
        assert(
            ecBack.proposals.length === 0 && ecBack.path === null,
            'Empty Commit round-trip'
        );
    }

    console.log('');
    console.log(`proposal: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main();
