#!/usr/bin/env node

/**
 * Cross-check ratchet-tree.js against the IETF vectors:
 *
 *   - tree-validation.json `resolutions` for cipher_suite = 2. Each vector
 *     entry has a per-node `resolutions[i]` array of node indexes. We
 *     parse + pad the tree and compare.
 *   - tree-operations.json: one Add, Update or Remove proposal applied to
 *     a tree (RFC 9420 sections 7.8, 12.1). The resulting wire tree and both tree
 *     hashes must match. These trees have leaf counts that are not powers
 *     of two on the wire, so they pin the full-tree extend/truncate rules.
 *     The vectors use cipher_suite 1, but tree hashing and the tree
 *     operations do not depend on the suite (SHA-256 in both).
 */

const path = require('path');
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const RatchetTree = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'ratchet-tree.js'));
const TreeHash = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-hash.js'));
const Proposal = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'proposal.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'tree-validation.json'));
const TREE_OPERATIONS = require(path.join(__dirname, 'vectors', 'mls', 'tree-operations.json'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        passed += 1;
    } else {
        failed += 1;
        console.log(`  FAIL ${name}${detail ? `  - ${detail}` : ''}`);
    }
}

function hexDecode(h) {
    const b = Buffer.from(h, 'hex');
    return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

function hex(u8) {
    return Buffer.from(u8).toString('hex');
}

async function treeOperations() {
    console.log(`# tree-operations.json (${TREE_OPERATIONS.length} proposals)`);
    const kinds = new Set();
    for (let i = 0; i < TREE_OPERATIONS.length; i += 1) {
        const v = TREE_OPERATIONS[i];
        const before = RatchetTree.fromWireNodes(
            Nodes.parseRatchetTree(hexDecode(v.tree_before)),
        );
        assert(hex(await TreeHash.hashRoot(before)) === v.tree_hash_before,
            `tree-operations ${i}: tree_hash_before`);
        const decoder = new Codec.Decoder(hexDecode(v.proposal));
        const proposal = Proposal.readProposal(decoder);
        assert(decoder.remaining() === 0, `tree-operations ${i}: proposal fully parsed`);
        let after;
        if (proposal.proposalType === Proposal.ProposalType.ADD) {
            kinds.add('add');
            after = RatchetTree.addLeaf(before, proposal.keyPackage.leafNode).tree;
        } else if (proposal.proposalType === Proposal.ProposalType.UPDATE) {
            kinds.add('update');
            after = RatchetTree.updateLeaf(before, v.proposal_sender, proposal.leafNode);
        } else if (proposal.proposalType === Proposal.ProposalType.REMOVE) {
            kinds.add('remove');
            after = RatchetTree.removeLeaf(before, proposal.removed);
        } else {
            assert(false, `tree-operations ${i}: unexpected proposal type ${proposal.proposalType}`);
            continue;
        }
        assert(hex(Nodes.ratchetTreeBytes(after)) === v.tree_after,
            `tree-operations ${i}: tree_after bytes (${proposal.proposalType})`);
        assert(hex(await TreeHash.hashRoot(after)) === v.tree_hash_after,
            `tree-operations ${i}: tree_hash_after`);
        assert(hex(Nodes.ratchetTreeBytes(before)) === v.tree_before,
            `tree-operations ${i}: input tree is not mutated`);
    }
    assert(kinds.has('add') && kinds.has('update') && kinds.has('remove'),
        'tree-operations vectors cover Add, Update and Remove');

    // The wire form omits trailing blanks; a vector that ends in a blank
    // node is not valid RFC 9420 encoding and must be refused.
    let refused = false;
    try {
        RatchetTree.fromWireNodes([...Nodes.parseRatchetTree(
            hexDecode(TREE_OPERATIONS[0].tree_before),
        ), null]);
    } catch (_e) {
        refused = true;
    }
    assert(refused, 'ratchet_tree ending in a blank node is refused');
}

async function main() {
    await treeOperations();
    const cs2 = VECTORS.filter((v) => v.cipher_suite === 2);
    console.log(`# ratchet-tree resolutions - cipher_suite=2 (${cs2.length} trees)`);

    for (let i = 0; i < cs2.length; i += 1) {
        const v = cs2[i];
        const parsed = Nodes.parseRatchetTree(hexDecode(v.tree));
        const tree = Nodes.padRatchetTree(parsed, v.resolutions.length);

        const got = RatchetTree.resolutions(tree);
        const want = v.resolutions;

        assert(got.length === want.length, `entry ${i}: resolution count`);
        let allMatch = true;
        for (let j = 0; j < got.length; j += 1) {
            const a = JSON.stringify(got[j]);
            const b = JSON.stringify(want[j]);
            if (a !== b) {
                allMatch = false;
                console.log(`  MISMATCH entry=${i} node=${j} got=${a} want=${b}`);
                break;
            }
        }
        assert(allMatch, `entry ${i}: all ${got.length} resolutions match`);
    }

    console.log('');
    console.log(`ratchet-tree: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
