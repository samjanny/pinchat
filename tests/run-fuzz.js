#!/usr/bin/env node

/**
 * Fuzz campaign runner for the Double Ratchet decrypt target.
 *
 * Usage:
 *   node tests/run-fuzz.js                 # 10-second smoke (default)
 *   node tests/run-fuzz.js 60              # 60-second pass
 *   node tests/run-fuzz.js 3600            # 1-hour pass
 *   node tests/run-fuzz.js 86400           # 24-hour campaign
 *
 * Output:
 *   - libFuzzer's standard stats are printed inline.
 *   - Any finding (state divergence, unhandled rejection, unexpected
 *     decrypt success, crash) prints a counter-example bytes-sequence
 *     to stderr and exits non-zero.
 *
 * The fuzz target lives in tests/fuzz/decrypt-fuzz.js. See its header
 * for the invariants asserted per iteration.
 *
 * Corpus / artifacts directory:
 *   tests/fuzz/corpus/ (auto-created, .gitignored). libFuzzer writes
 *   interesting inputs here and reuses them across runs — re-running
 *   after a long campaign benefits from the saved corpus.
 */

'use strict';

const path = require('path');
const fs = require('fs');

// Defensive: when invoked directly by a user on a fresh clone without
// dev-deps installed, fail with the SKIP exit code (77) and a clear
// pointer instead of an opaque module-not-found stack trace.
let startFuzzing;
try {
    ({ startFuzzing } = require('@jazzer.js/core'));
} catch (e) {
    console.log('SKIPPED: @jazzer.js/core not installed.');
    console.log('  Install dev-deps with: npm ci');
    process.exit(77);
}

const FUZZ_DIR = path.join(__dirname, 'fuzz');
const CORPUS_DIR = path.join(FUZZ_DIR, 'corpus');

if (!fs.existsSync(CORPUS_DIR)) {
    fs.mkdirSync(CORPUS_DIR, { recursive: true });
}

const seconds = parseInt(process.argv[2] || '10', 10);
if (!(seconds > 0)) {
    console.error('Usage: node tests/run-fuzz.js [seconds]');
    process.exit(2);
}

const fuzzerOptions = [
    `-max_total_time=${seconds}`,
    `-max_len=512`,
    `-print_final_stats=1`,
    `-rss_limit_mb=1024`,
    CORPUS_DIR,
];

console.log('PinChat decrypt-path fuzz campaign');
console.log(`  Target:   tests/fuzz/decrypt-fuzz.js (fuzz)`);
console.log(`  Duration: ${seconds}s`);
console.log(`  Corpus:   ${path.relative(process.cwd(), CORPUS_DIR)}`);
console.log('');

(async () => {
    try {
        await startFuzzing({
            fuzzTarget: path.join(FUZZ_DIR, 'decrypt-fuzz.js'),
            fuzzEntryPoint: 'fuzz',
            includes: ['static/js/'],
            excludes: ['node_modules', 'tests/vectors'],
            customHooks: [],
            expectedErrors: [],
            timeout: 10000,
            sync: false,
            fuzzerOptions,
            mode: 'fuzzing',
            dryRun: false,
            verbose: false,
            coverage: false,
            coverageDirectory: '',
            coverageReporters: [],
            disableBugDetectors: [],
        });
        console.log('');
        console.log(`Fuzz campaign completed cleanly after ${seconds}s — no findings.`);
        process.exit(0);
    } catch (err) {
        console.error('');
        console.error('FUZZ FINDING (or fatal error):');
        console.error(err && err.stack ? err.stack : err);
        process.exit(1);
    }
})();
