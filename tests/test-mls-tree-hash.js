#!/usr/bin/env node

/**
 * Cross-check tree-hash.js + nodes.js against the IETF tree-validation.json
 * reference vectors for cipher_suite = 2.
 *
 * For each vector entry:
 *   1. Parse the serialized `tree` into a vector<optional<Node>>.
 *   2. Round-trip the parsed tree back to bytes and confirm byte equality.
 *   3. Compute tree_hash for every node and compare to the vector's
 *      `tree_hashes` array.
 *
 * tree-validation.json also carries a `resolutions` array per node — the
 * resolution check is handled by the ratchet-tree module once it lands.
 */

const path = require('path');
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const TreeHash = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-hash.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'tree-validation.json'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        passed += 1;
    } else {
        failed += 1;
        console.log(`  FAIL ${name}${detail ? `  — ${detail}` : ''}`);
    }
}

function hexDecode(h) {
    const b = Buffer.from(h, 'hex');
    return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

function hex(u8) {
    return Buffer.from(u8).toString('hex');
}

async function main() {
    const cs2 = VECTORS.filter((v) => v.cipher_suite === 2);
    console.log(`# tree-hash — cipher_suite=2 (${cs2.length} trees)`);

    for (let i = 0; i < cs2.length; i += 1) {
        const v = cs2[i];
        const bytes = hexDecode(v.tree);

        // 1. Parse + round-trip. The wire form may omit trailing blanks;
        //    round-trip is only valid on the *wire-length* representation.
        const parsed = Nodes.parseRatchetTree(bytes);
        assert(
            hex(Nodes.ratchetTreeBytes(parsed)) === v.tree.toLowerCase(),
            `entry ${i}: ratchet-tree round-trip (${parsed.length} wire nodes)`
        );

        // 2. Pad to full node_width for hashing — the IETF tree_hashes
        //    array is always sized to node_width(nLeaves).
        const tree = Nodes.padRatchetTree(parsed, v.tree_hashes.length);

        // 3. Per-node tree-hash
        const hashes = await TreeHash.hashAll(tree);
        const wantHashes = v.tree_hashes;
        assert(
            hashes.length === wantHashes.length,
            `entry ${i}: hash count ${hashes.length} == ${wantHashes.length}`
        );

        let allMatch = true;
        for (let j = 0; j < hashes.length; j += 1) {
            if (hex(hashes[j]) !== wantHashes[j].toLowerCase()) {
                allMatch = false;
                console.log(`  MISMATCH entry=${i} node=${j} got=${hex(hashes[j])} want=${wantHashes[j]}`);
                break;
            }
        }
        assert(allMatch, `entry ${i}: all ${hashes.length} tree_hashes match`);
    }

    console.log('');
    console.log(`tree-hash: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
