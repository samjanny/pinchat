#!/usr/bin/env node

/**
 * MLS UpdatePath wire-format round-trip test.
 *
 * For every cipher_suite=2 entry in treekem.json, parse each
 * update_paths[i].update_path into the struct shape declared in nodes.js,
 * then re-serialize it and confirm byte equality with the source bytes.
 *
 * This validates the UpdatePath / UpdatePathNode / HPKECiphertext
 * serialization layout, which is a prerequisite for the TreeKEM
 * encrypt/decrypt logic (landing in a follow-up commit).
 */

const path = require('path');
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'treekem.json'));

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

function main() {
    const cs2 = VECTORS.filter((v) => v.cipher_suite === 2);
    console.log(`# update-path round-trip — cipher_suite=2 (${cs2.length} entries)`);

    let totalPaths = 0;
    for (let i = 0; i < cs2.length; i += 1) {
        const v = cs2[i];
        for (let j = 0; j < v.update_paths.length; j += 1) {
            totalPaths += 1;
            const origHex = v.update_paths[j].update_path;
            const orig = hexDecode(origHex);

            let parsed;
            try {
                parsed = Nodes.parseUpdatePath(orig);
            } catch (err) {
                failed += 1;
                console.log(`  FAIL entry ${i} path ${j}: parse threw — ${err.message}`);
                continue;
            }

            const round = Nodes.updatePathBytes(parsed);
            const match = hex(round) === origHex.toLowerCase();
            if (match) {
                passed += 1;
            } else {
                failed += 1;
                console.log(`  FAIL entry ${i} path ${j}: round-trip mismatch (${orig.length} bytes)`);
            }
        }
    }

    console.log(`  -- ${totalPaths} UpdatePath structures parsed + round-tripped`);
    console.log('');
    console.log(`update-path: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main();
