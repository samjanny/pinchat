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
 * Runner output is captured and summarised; full output is shown on failure.
 */

'use strict';

const { runCampaign } = require('./run-fuzz');

const SMOKE_SECONDS = parseInt(process.env.PINCHAT_FUZZ_SMOKE_SECS || '5', 10);

console.log(`Fuzz smoke (${SMOKE_SECONDS}s decrypt-path campaign):`);

runCampaign(SMOKE_SECONDS)
    .then((result) => {
        console.log(`  [OK] ${result.iterations} iterations (${result.perSecond} exec/s) — no findings`);
        console.log(`  Replay seed: ${result.seed}`);
        console.log('  Longer campaigns: node tests/run-fuzz.js <seconds>');
    })
    .catch((error) => {
        console.log(`  [FAIL] seed=${error.fuzzSeed} iteration=${error.fuzzIteration}`);
        console.error(error && error.stack ? error.stack : error);
        process.exitCode = 1;
    });
