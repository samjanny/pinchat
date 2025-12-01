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
            console.log('Usage: node run-all-tests.js [chain|double]');
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
