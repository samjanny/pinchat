#!/usr/bin/env node

/**
 * Wycheproof test-vector harness for PinChat's WebCrypto wrappers.
 *
 * Coverage:
 *   - ECDSA P-256 / SHA-256 with P1363 (raw r||s) signature format.
 *     Drives `IdentityKeyManager.verify` against 260 Wycheproof cases
 *     covering: valid signatures, malleability/high-s, arithmetic edge
 *     cases, integer overflow attempts, malformed encodings, point at
 *     infinity, special-case public keys, …
 *   - HKDF-SHA256 against 86 Wycheproof cases covering: RFC 5869 KAT,
 *     empty salt, empty info, maximal output size, size-too-large
 *     (must reject), output collision sanity.
 *
 * Why this exists (audit-3 M-03 + the "validate the wrapper not the
 * primitive" point):
 *   WebCrypto is exercised by browser vendors; we don't re-test it. We
 *   test that OUR wrapper (`IdentityKeyManager.verify` and the HKDF
 *   path used by `DoubleRatchet.hkdf`) feeds inputs and reads outputs
 *   correctly across the full range of edge cases Wycheproof curates.
 *   A bug in encoding, hash algorithm choice, public-key format, or
 *   signature format would show up here as a single-vector failure.
 *
 * Result semantics per Wycheproof:
 *   - "valid"      → MUST verify. Failure is a wrapper bug.
 *   - "invalid"    → MUST NOT verify. Acceptance is a wrapper bug.
 *   - "acceptable" → implementation-defined. Either result is OK; we
 *                    record the actual outcome for visibility.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const assert = require('assert');

const VECTORS_DIR = path.join(__dirname, 'vectors', 'wycheproof');

// Silence the production modules' debug helpers.
global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};
global.PINCHAT_PROTOCOL_VERSION = 1;

// Load the real production modules — we test the wrapper, not a copy.
require('../static/js/crypto.js');
const { IdentityKeyManager } = require('../static/js/identity.js');

// ── helpers ─────────────────────────────────────────────────────────────

function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) {
        throw new Error(`Invalid hex string: ${hex}`);
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
}

function bytesToHex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function loadVectors(filename) {
    const full = path.join(VECTORS_DIR, filename);
    return JSON.parse(fs.readFileSync(full, 'utf8'));
}

// ── ECDSA P-256 / SHA-256 / P1363 ───────────────────────────────────────
//
// Per-group setup: import the public key as a non-extractable ECDSA verify
// key — same path the production `importPeerIdentityPublicKey` takes. Each
// test then drives `IdentityKeyManager.verify` with the message bytes and
// the signature bytes, comparing the WebCrypto result against the
// Wycheproof expectation.
//
// The wrapper's contract is: throw on invalid, return true on valid. We
// inverse that here to compute a boolean and compare with the expectation,
// because Wycheproof represents both outcomes as a single field.

async function runEcdsaWycheproof() {
    const vectors = loadVectors('ecdsa_secp256r1_sha256_p1363_test.json');
    if (vectors.algorithm !== 'ECDSA') {
        throw new Error(`Unexpected algorithm: ${vectors.algorithm}`);
    }

    let totalValid = 0, passedValid = 0;
    let totalInvalid = 0, passedInvalid = 0;
    let totalAcceptable = 0, acceptableTrue = 0, acceptableFalse = 0;
    const failures = [];

    for (const group of vectors.testGroups) {
        // Wycheproof gives the public key in several encodings. We use the
        // raw uncompressed form (65 bytes prefixed with 0x04) because that
        // matches what the production code receives over the wire (peer
        // identity raw export) and feeds into `importPeerIdentityPublicKey`.
        const pubRaw = hexToBytes(group.publicKey.uncompressed);
        let pubKey;
        try {
            pubKey = await webcrypto.subtle.importKey(
                'raw',
                pubRaw,
                { name: 'ECDSA', namedCurve: 'P-256' },
                false,
                ['verify'],
            );
        } catch (err) {
            // Some Wycheproof groups carry intentionally-malformed public
            // keys (point not on curve, point at infinity). If importKey
            // rejects, every test in the group is automatically "invalid"
            // from our side — but Wycheproof may still mark individual
            // tests as "valid" against that key. We record the rejection
            // and continue; this is a known divergence between Wycheproof's
            // group-level public key and WebCrypto's import-time validation.
            for (const t of group.tests) {
                if (t.result === 'valid') {
                    failures.push({
                        tcId: t.tcId,
                        comment: t.comment,
                        expected: 'valid',
                        actual: 'public-key-import-rejected',
                        flags: t.flags,
                    });
                }
            }
            continue;
        }

        const mgr = new IdentityKeyManager();
        mgr.peerIdentityPublicKey = pubKey;
        mgr.peerIdentityPublicKeyRaw = pubRaw;

        for (const t of group.tests) {
            const msg = hexToBytes(t.msg);
            const sig = hexToBytes(t.sig);
            let verified = false;
            try {
                await mgr.verify(msg, sig);
                verified = true;
            } catch (_) {
                verified = false;
            }

            if (t.result === 'valid') {
                totalValid++;
                if (verified) passedValid++;
                else failures.push({
                    tcId: t.tcId, comment: t.comment, expected: 'valid',
                    actual: 'rejected', flags: t.flags,
                });
            } else if (t.result === 'invalid') {
                totalInvalid++;
                if (!verified) passedInvalid++;
                else failures.push({
                    tcId: t.tcId, comment: t.comment, expected: 'invalid',
                    actual: 'accepted', flags: t.flags,
                });
            } else if (t.result === 'acceptable') {
                totalAcceptable++;
                if (verified) acceptableTrue++;
                else acceptableFalse++;
            } else {
                throw new Error(`Unknown result label: ${t.result}`);
            }
        }
    }

    return {
        totalValid, passedValid,
        totalInvalid, passedInvalid,
        totalAcceptable, acceptableTrue, acceptableFalse,
        failures,
    };
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────────────
//
// The production `DoubleRatchet.hkdf(ikm, salt, info_string, length)`
// helper encodes `info` as UTF-8 internally. Wycheproof's vectors pass
// `info` as arbitrary bytes — including non-UTF8 sequences — so we cannot
// always go through the string-typed wrapper. We mirror the wrapper's
// WebCrypto sequence here exactly: `importKey('raw', ikm, 'HKDF', false,
// ['deriveBits'])` + `deriveBits({HKDF, SHA-256, salt, info}, ikmKey,
// bits)`. That is the same code path the production wrapper takes; the
// only difference is `info` is passed through as bytes instead of being
// re-encoded from a string.

async function deriveHkdf(ikm, salt, info, sizeBytes) {
    const ikmKey = await webcrypto.subtle.importKey(
        'raw',
        ikm,
        'HKDF',
        false,
        ['deriveBits'],
    );
    const bits = await webcrypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info,
        },
        ikmKey,
        sizeBytes * 8,
    );
    return new Uint8Array(bits);
}

async function runHkdfWycheproof() {
    const vectors = loadVectors('hkdf_sha256_test.json');
    if (vectors.algorithm !== 'HKDF-SHA-256') {
        throw new Error(`Unexpected algorithm: ${vectors.algorithm}`);
    }

    let totalValid = 0, passedValid = 0;
    let totalInvalid = 0, passedInvalid = 0;
    let totalAcceptable = 0, acceptableTrue = 0, acceptableFalse = 0;
    const failures = [];

    for (const group of vectors.testGroups) {
        for (const t of group.tests) {
            const ikm = hexToBytes(t.ikm);
            const salt = hexToBytes(t.salt);
            const info = hexToBytes(t.info);
            const size = t.size;
            const expectedOkm = t.okm.toLowerCase();

            let actualHex = null;
            let threw = false;
            try {
                const out = await deriveHkdf(ikm, salt, info, size);
                actualHex = bytesToHex(out);
            } catch (_) {
                threw = true;
            }

            if (t.result === 'valid') {
                totalValid++;
                if (!threw && actualHex === expectedOkm) {
                    passedValid++;
                } else {
                    failures.push({
                        tcId: t.tcId, comment: t.comment, expected: 'valid',
                        actual: threw ? 'threw' : `output-mismatch (got ${actualHex}, want ${expectedOkm})`,
                        flags: t.flags,
                    });
                }
            } else if (t.result === 'invalid') {
                totalInvalid++;
                // Wycheproof's "invalid" HKDF cases are SizeTooLarge (size
                // > 255 × hash output length) — RFC 5869 mandates rejection
                // and WebCrypto throws. Anything else is a wrapper bug.
                if (threw) {
                    passedInvalid++;
                } else {
                    failures.push({
                        tcId: t.tcId, comment: t.comment, expected: 'invalid',
                        actual: 'accepted', flags: t.flags,
                    });
                }
            } else if (t.result === 'acceptable') {
                totalAcceptable++;
                if (!threw && actualHex === expectedOkm) acceptableTrue++;
                else acceptableFalse++;
            } else {
                throw new Error(`Unknown result label: ${t.result}`);
            }
        }
    }

    return {
        totalValid, passedValid,
        totalInvalid, passedInvalid,
        totalAcceptable, acceptableTrue, acceptableFalse,
        failures,
    };
}

// ── reporting ───────────────────────────────────────────────────────────

function printSummary(label, r) {
    console.log(`\n${label}:`);
    console.log(`  valid:      ${r.passedValid}/${r.totalValid}`);
    console.log(`  invalid:    ${r.passedInvalid}/${r.totalInvalid}`);
    console.log(`  acceptable: ${r.totalAcceptable}  (true:${r.acceptableTrue} false:${r.acceptableFalse})`);
    if (r.failures.length === 0) {
        console.log(`  ✅ no failures`);
    } else {
        console.log(`  ❌ ${r.failures.length} failure(s):`);
        for (const f of r.failures.slice(0, 20)) {
            console.log(`    tcId=${f.tcId}  expected=${f.expected}  actual=${f.actual}  flags=[${(f.flags || []).join(',')}]`);
            if (f.comment) console.log(`      "${f.comment}"`);
        }
        if (r.failures.length > 20) {
            console.log(`    … and ${r.failures.length - 20} more`);
        }
    }
}

// ── runner ──────────────────────────────────────────────────────────────

(async () => {
    console.log('Wycheproof test-vector harness:');
    console.log('  Vectors source: tests/vectors/wycheproof/ (see README.md for commit)');
    let allOk = true;

    const ecdsa = await runEcdsaWycheproof();
    printSummary('ECDSA P-256 / SHA-256 (P1363)', ecdsa);
    if (ecdsa.failures.length > 0) allOk = false;
    // Sanity: at least some valid tests must have been run.
    assert.ok(ecdsa.totalValid > 0, 'ECDSA suite produced zero valid-class tests');
    assert.ok(ecdsa.totalInvalid > 0, 'ECDSA suite produced zero invalid-class tests');

    const hkdf = await runHkdfWycheproof();
    printSummary('HKDF-SHA256', hkdf);
    if (hkdf.failures.length > 0) allOk = false;
    assert.ok(hkdf.totalValid > 0, 'HKDF suite produced zero valid-class tests');

    console.log('');
    if (allOk) {
        console.log('All Wycheproof suites PASSED.');
        process.exit(0);
    } else {
        console.log('SOME Wycheproof tests FAILED — see failure listing above.');
        process.exit(1);
    }
})().catch(err => {
    console.error('Fatal harness error:', err && err.stack ? err.stack : err);
    process.exit(1);
});
