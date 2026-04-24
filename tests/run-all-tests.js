#!/usr/bin/env node

/**
 * Signal Protocol Test Runner
 *
 * Runs all Signal Protocol test suites:
 * - Chain Ratchet (symmetric key ratchet)
 * - Double Ratchet (DH + symmetric)
 *
 * Usage:
 *   node tests/run-all-tests.js           # Run all tests
 *   node tests/run-all-tests.js chain     # Run only chain ratchet tests
 *   node tests/run-all-tests.js double    # Run only double ratchet tests
 */

const { spawn } = require('child_process');
const path = require('path');

const TESTS_DIR = __dirname;

const TEST_SUITES = {
    chain: {
        name: 'Chain Ratchet',
        file: 'test-chain-ratchet.js',
        description: 'Symmetric key ratchet for Perfect Forward Secrecy (PFS)'
    },
    double: {
        name: 'Double Ratchet',
        file: 'test-double-ratchet.js',
        description: 'DH + Symmetric ratchet for PFS + Post-Compromise Security (PCS)'
    },
    'mls-tree-math': {
        name: 'MLS tree math',
        file: 'test-mls-tree-math.js',
        description: 'Left-balanced binary tree arithmetic (RFC 9420 §4.1)'
    },
    'mls-codec': {
        name: 'MLS wire-format codec',
        file: 'test-mls-codec.js',
        description: 'QUIC varint + opaque/vector round-trip (RFC 9420 §2)'
    },
    'mls-hpke': {
        name: 'MLS HPKE',
        file: 'test-mls-hpke.js',
        description: 'DHKEM(P-256)+HKDF-SHA256+AES-128-GCM (RFC 9180)'
    },
    'mls-key-schedule': {
        name: 'MLS key schedule',
        file: 'test-mls-key-schedule.js',
        description: 'Epoch secret chain + derived secrets (RFC 9420 §8, vs IETF vectors)'
    },
    'mls-crypto-basics': {
        name: 'MLS labeled ops (RefHash, DeriveSecret, ExpandWithLabel)',
        file: 'test-mls-crypto-basics.js',
        description: 'RFC 9420 §5.1 / §5.2 labeled operations vs IETF vectors'
    },
    'mls-transcript-hashes': {
        name: 'MLS transcript hashes',
        file: 'test-mls-transcript-hashes.js',
        description: 'Confirmed/interim transcript hash chain (RFC 9420 §5.3 + §8.2)'
    },
    'mls-tree-hash': {
        name: 'MLS tree hash + node structs',
        file: 'test-mls-tree-hash.js',
        description: 'LeafNode/ParentNode serde + tree-hash vs IETF tree-validation vectors'
    },
    'mls-ratchet-tree': {
        name: 'MLS ratchet-tree container',
        file: 'test-mls-ratchet-tree.js',
        description: 'Resolution (RFC 9420 §7.7) vs IETF tree-validation.resolutions'
    },
    'mls-treekem': {
        name: 'MLS TreeKEM path-secret chain',
        file: 'test-mls-treekem.js',
        description: 'P-256 scalar-mul, HPKE DeriveKeyPair, path-secret derivation (RFC 9420 §7.5)'
    },
    'mls-update-path': {
        name: 'MLS UpdatePath wire-format',
        file: 'test-mls-update-path.js',
        description: 'UpdatePath/UpdatePathNode/HPKECiphertext round-trip vs IETF vectors'
    },
    'mls-key-package': {
        name: 'MLS KeyPackage + GroupContext + MLSMessage framing',
        file: 'test-mls-key-package.js',
        description: 'KeyPackage round-trip + signature verify + GroupContext vs IETF vectors'
    },
    'mls-welcome': {
        name: 'MLS Welcome / GroupInfo end-to-end',
        file: 'test-mls-welcome.js',
        description: 'Full joiner flow: unwrap → HPKE-decrypt → AES-decrypt → verify GroupInfo'
    },
    'mls-secret-tree': {
        name: 'MLS secret tree + per-leaf AEAD ratchet',
        file: 'test-mls-secret-tree.js',
        description: 'Application/handshake chains + sender_data (RFC 9420 §9) vs IETF vectors'
    },
    'mls-framing': {
        name: 'MLS FramedContent / AuthenticatedContent framing',
        file: 'test-mls-framing.js',
        description: 'Sender + FramedContent + FramedContentAuthData serde (RFC 9420 §6)'
    },
    'mls-proposal': {
        name: 'MLS Proposal + Commit structs',
        file: 'test-mls-proposal.js',
        description: 'Proposal/Commit serde (RFC 9420 §12) vs message-protection IETF vectors'
    },
    'mls-public-message': {
        name: 'MLS PublicMessage end-to-end',
        file: 'test-mls-public-message.js',
        description: 'FramedContentTBS + membership_tag verification vs IETF vectors'
    },
    'mls-private-message': {
        name: 'MLS PrivateMessage end-to-end',
        file: 'test-mls-private-message.js',
        description: 'sender_data + AEAD + padding + signature for all content types'
    }
};

function runTest(suiteName) {
    return new Promise((resolve, reject) => {
        const suite = TEST_SUITES[suiteName];
        if (!suite) {
            reject(new Error(`Unknown test suite: ${suiteName}`));
            return;
        }

        const testPath = path.join(TESTS_DIR, suite.file);

        console.log('');
        console.log('#'.repeat(74));
        console.log(`# ${suite.name}`);
        console.log(`# ${suite.description}`);
        console.log('#'.repeat(74));
        console.log('');

        const proc = spawn('node', [testPath], {
            stdio: 'inherit',
            cwd: TESTS_DIR
        });

        proc.on('close', (code) => {
            resolve({ name: suiteName, passed: code === 0 });
        });

        proc.on('error', (err) => {
            reject(err);
        });
    });
}

async function main() {
    const args = process.argv.slice(2);

    console.log('');
    console.log('*'.repeat(74));
    console.log('*  SIGNAL PROTOCOL TEST VECTORS                                          *');
    console.log('*  PinChat End-to-End Encryption Test Suite                              *');
    console.log('*'.repeat(74));

    let suitesToRun;

    if (args.length === 0) {
        // Run all tests
        suitesToRun = Object.keys(TEST_SUITES);
    } else {
        // Run specified test(s)
        suitesToRun = args.filter(arg => TEST_SUITES[arg]);
        if (suitesToRun.length === 0) {
            console.log('');
            console.log('Usage: node run-all-tests.js [chain|double|mls-tree-math|mls-codec|mls-hpke|mls-key-schedule|mls-crypto-basics|mls-transcript-hashes|mls-tree-hash|mls-ratchet-tree|mls-treekem|mls-update-path|mls-key-package|mls-welcome|mls-secret-tree|mls-framing|mls-proposal|mls-public-message|mls-private-message]');
            console.log('');
            console.log('Available test suites:');
            for (const [key, suite] of Object.entries(TEST_SUITES)) {
                console.log(`  ${key.padEnd(10)} - ${suite.name}: ${suite.description}`);
            }
            process.exit(1);
        }
    }

    const results = [];

    for (const suite of suitesToRun) {
        try {
            const result = await runTest(suite);
            results.push(result);
        } catch (err) {
            console.error(`Error running ${suite}:`, err.message);
            results.push({ name: suite, passed: false });
        }
    }

    // Summary
    console.log('');
    console.log('*'.repeat(74));
    console.log('*  OVERALL SUMMARY                                                        *');
    console.log('*'.repeat(74));
    console.log('');

    let allPassed = true;
    for (const result of results) {
        const status = result.passed ? 'PASSED' : 'FAILED';
        const icon = result.passed ? '[OK]' : '[X]';
        console.log(`  ${icon} ${TEST_SUITES[result.name].name}: ${status}`);
        if (!result.passed) allPassed = false;
    }

    console.log('');

    if (allPassed) {
        console.log('ALL TEST SUITES PASSED');
        process.exit(0);
    } else {
        console.log('SOME TEST SUITES FAILED');
        process.exit(1);
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
