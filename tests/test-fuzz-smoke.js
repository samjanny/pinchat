#!/usr/bin/env node

/**
 * Fuzz-harness smoke test.
 *
 * Runs the decrypt-path fuzz target for a short, fixed budget (default
 * 5 seconds). Purpose:
 *   - Catches harness rot — if the fuzz target stops loading because
 *     the production module shape changed, this suite fails first.
 *   - Quick coverage of the random-input decrypt path on every CI run.
 *
 * Longer campaigns (minutes / hours / 24h) are launched manually via:
 *     node tests/run-fuzz.js 3600
 *
 * libFuzzer's stdout is captured and only summarised — full output
 * lives in the manual campaign runner.
 */

'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

// Soft-skip if @jazzer.js/core is not installed (no native binding,
// offline clone, npm registry blocked). Exit 77 = SKIPPED per
// autotools convention; the runner treats it as non-failing.
try {
    require('@jazzer.js/core');
} catch (e) {
    console.log('SKIPPED: @jazzer.js/core not installed.');
    console.log('  Install dev-deps with: npm ci  (or: npm install)');
    console.log('  Note: jazzer-js requires GLIBC ≥ 2.36 for the 2.x prebuilt binary.');
    process.exit(77);
}

const SMOKE_SECONDS = parseInt(process.env.PINCHAT_FUZZ_SMOKE_SECS || '5', 10);

console.log(`Fuzz smoke (${SMOKE_SECONDS}s decrypt-path campaign):`);

const runner = path.join(__dirname, 'run-fuzz.js');
const res = spawnSync('node', [runner, String(SMOKE_SECONDS)], {
    stdio: ['ignore', 'pipe', 'pipe'],
    cwd: path.dirname(__dirname),
});

const stdout = (res.stdout || '').toString();
const stderr = (res.stderr || '').toString();
// libFuzzer writes its summary statistics to stderr (it's a C library
// running below Node's stdout), so search both streams for the stat
// lines printed by `-print_final_stats=1`.
const combined = stdout + '\n' + stderr;

const m = combined.match(/stat::number_of_executed_units:\s+(\d+)/);
const execs = m ? m[1] : 'unknown';
const r = combined.match(/stat::average_exec_per_sec:\s+(\d+)/);
const execsPerSec = r ? r[1] : '?';

if (res.status === 0) {
    console.log(`  [OK] ${execs} iterations (${execsPerSec} exec/s) — no findings`);
    console.log('  Longer campaigns: node tests/run-fuzz.js <seconds>');
    process.exit(0);
} else {
    console.log(`  [FAIL] fuzz runner exited with status ${res.status}`);
    console.log('--- stdout ---');
    console.log(stdout);
    console.log('--- stderr ---');
    console.log(stderr);
    process.exit(1);
}
