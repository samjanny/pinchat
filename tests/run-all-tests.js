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
    security: {
        name: 'Security Properties',
        file: 'test-security.js',
        description: 'Key extractability invariants (bootstrap key, identity key)'
    },
    'websocket-resume': {
        name: 'WebSocket stable-identity resume',
        file: 'test-websocket-resume.js',
        description: 'In-memory resume bearer propagation and fail-closed identity recovery'
    },
    correctness: {
        name: 'Ratchet Correctness',
        file: 'test-ratchet-correctness.js',
        description: 'C-01 concurrency, C-02 cross-DH late delivery, C-05 non-extractable DH'
    },
    kat: {
        name: 'Known Answer Tests',
        file: 'test-kat.js',
        description: 'KDF schedule + canonical DH-header bytes pinned against independent reference'
    },
    wycheproof: {
        name: 'Wycheproof Vectors',
        file: 'test-wycheproof.js',
        description: 'ECDSA P-256/SHA-256 + HKDF-SHA256 against vendored C2SP/wycheproof vectors'
    },
    properties: {
        name: 'Property-Based',
        file: 'test-properties.js',
        description: 'Double Ratchet round-trip / replay / reorder / state-integrity under random delivery (fast-check)'
    },
    fuzz: {
        name: 'Fuzz Smoke',
        file: 'test-fuzz-smoke.js',
        description: 'jazzer-js coverage-guided decrypt-path fuzz, short smoke run (longer: node tests/run-fuzz.js N)'
    },
    'mls-tree-math': {
        name: 'MLS tree math',
        file: 'test-mls-tree-math.js',
        description: 'Left-balanced binary tree arithmetic (RFC 9420 §4.1)'
    },
    'mls-codec': {
        name: 'MLS wire-format codec',
        file: 'test-mls-codec.js',
        description: 'Canonical MLS varint + opaque/vector round-trip (RFC 9420 §2)'
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
    'mls-parent-hash': {
        name: 'MLS parent-hash chaining',
        file: 'test-mls-parent-hash.js',
        description: 'Parent-hash chain round-trip + subtree-splice rejection (RFC 9420 §7.9)'
    },
    'mls-update-path-validation': {
        name: 'MLS UpdatePath ciphertext layout',
        file: 'test-mls-update-path-validation.js',
        description: 'Whole-path copath-resolution cardinality validation (RFC 9420 §7.6)'
    },
    'mls-imported-tree': {
        name: 'MLS imported Welcome tree validation',
        file: 'test-mls-imported-tree.js',
        description: 'Whole-tree LeafNode, parent-hash, and key-uniqueness validation at join'
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
    },
    'mls-group': {
        name: 'MLS Group orchestrator (steady state)',
        file: 'test-mls-group.js',
        description: 'Group.create + app-message encrypt/decrypt between two members'
    },
    'mls-session-join': {
        name: 'MLS session Welcome orchestration',
        file: 'test-mls-session-join.js',
        description: 'Browser-level Commit buffering + fail-closed Welcome join'
    },
    'mls-group-add': {
        name: 'MLS Group Add/Commit/Welcome flow',
        file: 'test-mls-group-add.js',
        description: 'Alice adds Bob via Welcome; both exchange messages at epoch 1'
    },
    'mls-group-add-3leaf': {
        name: 'MLS Group N-leaf flow (processCommit + multi-Add)',
        file: 'test-mls-group-add-3leaf.js',
        description: 'Sequential adds up to 4 members; existing members process Commit'
    },
    'mls-group-remove': {
        name: 'MLS Group Remove flow',
        file: 'test-mls-group-remove.js',
        description: 'Remove proposal + tree blanking; removed member loses access'
    },
    'mls-creator-policy': {
        name: 'MLS creator-only Commit policy',
        file: 'test-mls-creator-policy.js',
        description: 'Authenticated leaf-0 admin enforcement and creator preservation'
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
            // Exit code 77 = SKIPPED (autotools convention). The two
            // suites that depend on optional npm dev-deps (fast-check,
            // @jazzer.js/core) emit 77 when their require() throws on a
            // fresh clone without `npm ci`. The runner treats SKIP as
            // non-failing — `npm ci` is required for full coverage but
            // the core suites stay usable offline.
            let status;
            if (code === 0) status = 'passed';
            else if (code === 77) status = 'skipped';
            else status = 'failed';
            resolve({ name: suiteName, status });
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
            console.log('Usage: node run-all-tests.js [chain|double|mls-tree-math|mls-codec|mls-hpke|mls-key-schedule|mls-crypto-basics|mls-transcript-hashes|mls-tree-hash|mls-ratchet-tree|mls-treekem|mls-update-path|mls-key-package|mls-welcome|mls-secret-tree|mls-framing|mls-proposal|mls-public-message|mls-private-message|mls-group|mls-group-add]');
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
            results.push({ name: suite, status: 'failed' });
        }
    }

    // Summary
    console.log('');
    console.log('*'.repeat(74));
    console.log('*  OVERALL SUMMARY                                                        *');
    console.log('*'.repeat(74));
    console.log('');

    let anyFailed = false;
    let skipped = 0;
    for (const result of results) {
        let icon, label;
        switch (result.status) {
            case 'passed':  icon = '[OK]';   label = 'PASSED';  break;
            case 'skipped': icon = '[SKIP]'; label = 'SKIPPED'; skipped++; break;
            case 'failed':
            default:        icon = '[X]';    label = 'FAILED';  anyFailed = true;
        }
        console.log(`  ${icon} ${TEST_SUITES[result.name].name}: ${label}`);
    }

    console.log('');

    if (anyFailed) {
        console.log('SOME TEST SUITES FAILED');
        process.exit(1);
    } else if (skipped > 0) {
        console.log(`ALL TEST SUITES PASSED (${skipped} SKIPPED — install dev-deps with \`npm ci\` for full coverage)`);
        process.exit(0);
    } else {
        console.log('ALL TEST SUITES PASSED');
        process.exit(0);
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
