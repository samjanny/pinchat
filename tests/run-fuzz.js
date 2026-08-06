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
 *   - Mutation-runner statistics and the reproducible seed are printed inline.
 *   - Any finding (state divergence, unhandled rejection, unexpected
 *     decrypt success, crash) prints a counter-example bytes-sequence
 *     to stderr and exits non-zero.
 *
 * The fuzz target lives in tests/fuzz/decrypt-fuzz.js. See its header
 * for the invariants asserted per iteration.
 *
 * Set PINCHAT_FUZZ_SEED to replay a campaign with the same input stream.
 */

'use strict';

const { fuzz } = require('./fuzz/decrypt-fuzz');

async function runCampaign(seconds, requestedSeed) {
    if (!(seconds > 0)) throw new RangeError('Fuzz duration must be positive');
    const seed = Number.isInteger(requestedSeed) ? requestedSeed >>> 0 : Date.now() >>> 0;
    let prngState = seed || 0x9e3779b9;
    const nextU32 = () => {
        // xorshift32: fast and deterministic; cryptographic randomness is not
        // needed for fuzz input generation.
        prngState ^= prngState << 13;
        prngState ^= prngState >>> 17;
        prngState ^= prngState << 5;
        return prngState >>> 0;
    };
    const nextInput = (iteration) => {
        // Regularly force boundary lengths; otherwise explore the complete
        // 0..512-byte range and mutate every byte from the seeded stream.
        const boundaries = [0, 1, 2, 27, 28, 64, 65, 255, 256, 511, 512];
        const length = iteration % 16 === 0
            ? boundaries[(iteration / 16) % boundaries.length]
            : nextU32() % 513;
        const data = Buffer.alloc(length);
        for (let i = 0; i < data.length; i++) data[i] = nextU32() & 0xff;
        return data;
    };

    const started = Date.now();
    const deadline = started + (seconds * 1000);
    let iterations = 0;
    do {
        const data = nextInput(iterations);
        try {
            await fuzz(data);
        } catch (error) {
            error.fuzzIteration = iterations;
            error.fuzzInput = data.toString('base64url');
            error.fuzzSeed = seed;
            throw error;
        }
        iterations++;
    } while (Date.now() < deadline);

    const elapsedSeconds = Math.max((Date.now() - started) / 1000, 0.001);
    return { seed, iterations, perSecond: Math.round(iterations / elapsedSeconds) };
}

async function main() {
    const seconds = parseInt(process.argv[2] || '10', 10);
    if (!(seconds > 0)) {
        console.error('Usage: node tests/run-fuzz.js [seconds]');
        process.exitCode = 2;
        return;
    }
    const configuredSeed = Number.parseInt(process.env.PINCHAT_FUZZ_SEED || '', 10);
    const requestedSeed = Number.isInteger(configuredSeed) ? configuredSeed : undefined;

    console.log('PinChat decrypt-path fuzz campaign');
    console.log(`  Target:   tests/fuzz/decrypt-fuzz.js (fuzz)`);
    console.log(`  Duration: ${seconds}s`);
    try {
        const result = await runCampaign(seconds, requestedSeed);
        console.log(`  Seed:     ${result.seed}`);
        console.log('');
        console.log(`stat::number_of_executed_units: ${result.iterations}`);
        console.log(`stat::average_exec_per_sec: ${result.perSecond}`);
        console.log('');
        console.log(`Fuzz campaign completed cleanly after ${seconds}s — no findings.`);
    } catch (err) {
        console.error('');
        console.error('FUZZ FINDING (or fatal error):');
        console.error(`Replay with: PINCHAT_FUZZ_SEED=${err.fuzzSeed} node tests/run-fuzz.js ${seconds}`);
        if (err && err.fuzzIteration !== undefined) console.error(`Iteration: ${err.fuzzIteration}`);
        if (err && err.fuzzInput !== undefined) console.error(`Input (base64url): ${err.fuzzInput}`);
        console.error(err && err.stack ? err.stack : err);
        process.exitCode = 1;
    }
}

if (require.main === module) main();

module.exports = { runCampaign };
