#!/usr/bin/env node

/**
 * Cross-check secret-tree.js against IETF secret-tree.json for
 * cipher_suite = 2.
 *
 * Per entry, the vector gives:
 *   - encryption_secret    : the key-schedule output (tree root)
 *   - sender_data.{sender_data_secret, ciphertext, key, nonce}
 *   - leaves[leafIdx][generation].{application_key, application_nonce,
 *                                   handshake_key, handshake_nonce}
 *
 * We verify:
 *   1. senderDataKeyNonce matches the expected {key, nonce}.
 *   2. For every (leaf, generation) pair in the vector, the derived
 *      application and handshake {key, nonce} match byte-for-byte.
 */

const path = require('path');
const ST = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'secret-tree.js'));

const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'secret-tree.json'));

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
    const cs2 = VECTORS.filter((x) => x.cipher_suite === 2);
    console.log(`# secret-tree — cipher_suite=2 (${cs2.length} trees)`);

    for (let ei = 0; ei < cs2.length; ei += 1) {
        const v = cs2[ei];
        const encSecret = hexDecode(v.encryption_secret);
        const nLeaves = v.leaves.length;

        // Sender data
        {
            const sds = hexDecode(v.sender_data.sender_data_secret);
            const ct = hexDecode(v.sender_data.ciphertext);
            const { key, nonce } = await ST.senderDataKeyNonce(sds, ct);
            assert(
                hex(key) === v.sender_data.key.toLowerCase(),
                `entry ${ei} sender_data.key`
            );
            assert(
                hex(nonce) === v.sender_data.nonce.toLowerCase(),
                `entry ${ei} sender_data.nonce`
            );
        }

        // Per-leaf application + handshake ratchet at every generation the
        // vector specifies.
        for (let leafIdx = 0; leafIdx < nLeaves; leafIdx += 1) {
            const leafVectors = v.leaves[leafIdx];
            const leafSec = await ST.leafSecret(encSecret, leafIdx, nLeaves);

            const appRoot = await ST.leafChainRoot(leafSec, 'application');
            const hsRoot  = await ST.leafChainRoot(leafSec, 'handshake');

            for (const genKey of Object.keys(leafVectors)) {
                const expect = leafVectors[genKey];
                const generation = expect.generation;
                {
                    const { key, nonce } = await ST.keyNonceAtGeneration(appRoot, generation);
                    assert(
                        hex(key) === expect.application_key.toLowerCase(),
                        `entry ${ei} leaf ${leafIdx} gen ${generation} application_key`
                    );
                    assert(
                        hex(nonce) === expect.application_nonce.toLowerCase(),
                        `entry ${ei} leaf ${leafIdx} gen ${generation} application_nonce`
                    );
                }
                {
                    const { key, nonce } = await ST.keyNonceAtGeneration(hsRoot, generation);
                    assert(
                        hex(key) === expect.handshake_key.toLowerCase(),
                        `entry ${ei} leaf ${leafIdx} gen ${generation} handshake_key`
                    );
                    assert(
                        hex(nonce) === expect.handshake_nonce.toLowerCase(),
                        `entry ${ei} leaf ${leafIdx} gen ${generation} handshake_nonce`
                    );
                }
            }
        }
    }

    console.log('');
    console.log(`secret-tree: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
