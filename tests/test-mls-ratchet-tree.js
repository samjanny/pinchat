#!/usr/bin/env node

/**
 * Cross-check ratchet-tree.js (resolution) against the IETF
 * tree-validation.json `resolutions` field for cipher_suite = 2.
 *
 * Each vector entry has a per-node `resolutions[i]` array of node
 * indexes. We parse + pad the tree and compare.
 */

const path = require('path');
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const RatchetTree = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'ratchet-tree.js'));
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

function main() {
    const cs2 = VECTORS.filter((v) => v.cipher_suite === 2);
    console.log(`# ratchet-tree resolutions — cipher_suite=2 (${cs2.length} trees)`);

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

main();
