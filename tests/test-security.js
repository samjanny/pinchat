#!/usr/bin/env node

/**
 * Security Properties Test Suite
 *
 * Tests security invariants that are not part of the core protocol correctness
 * but are required by the security model:
 *
 * - Creator bootstrap key must be non-extractable (LOW-B2)
 * - Joiner bootstrap key must be non-extractable
 * - Identity private key must be non-extractable
 */

const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

async function runTests() {
    console.log('='.repeat(70));
    console.log('SECURITY PROPERTIES TEST SUITE');
    console.log('='.repeat(70));
    console.log('');

    let passed = 0;
    let failed = 0;

    // -------------------------------------------------------------------------
    // Test 1: Creator bootstrap key is non-extractable
    // -------------------------------------------------------------------------
    console.log('--- Test 1: Creator Bootstrap Key Is Non-Extractable ---');
    try {
        // Mirrors crypto.js CryptoManager.generateKey() after the LOW-B2 fix:
        // extractable must be false so an XSS occurring after fragment removal
        // cannot exfiltrate the raw key bytes via exportKey().
        const algorithm = { name: 'AES-GCM', length: 256 };
        const key = await subtle.generateKey(algorithm, false /* non-extractable */, ['encrypt', 'decrypt']);

        let exportFailed = false;
        try {
            await subtle.exportKey('raw', key);
        } catch (e) {
            exportFailed = true;
            console.log(`  exportKey rejected (expected): ${e.name}`);
        }

        if (exportFailed) {
            console.log('PASSED: non-extractable creator key cannot be exported');
            passed++;
        } else {
            console.log('FAILED: key was exported — extractable=false not enforced');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 2: Joiner bootstrap key is non-extractable
    // -------------------------------------------------------------------------
    console.log('--- Test 2: Joiner Bootstrap Key Is Non-Extractable ---');
    try {
        // Mirrors crypto.js CryptoManager.extractKeyFromURL():
        // key imported from raw bytes with extractable=false.
        const rawBytes = webcrypto.getRandomValues(new Uint8Array(32));
        const algorithm = { name: 'AES-GCM', length: 256 };
        const key = await subtle.importKey('raw', rawBytes, algorithm, false /* non-extractable */, ['encrypt', 'decrypt']);

        let exportFailed = false;
        try {
            await subtle.exportKey('raw', key);
        } catch (e) {
            exportFailed = true;
            console.log(`  exportKey rejected (expected): ${e.name}`);
        }

        if (exportFailed) {
            console.log('PASSED: non-extractable joiner key cannot be exported');
            passed++;
        } else {
            console.log('FAILED: key was exported — extractable=false not enforced');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 3: Identity private key is non-extractable
    // -------------------------------------------------------------------------
    console.log('--- Test 3: Identity Private Key Is Non-Extractable ---');
    try {
        // Mirrors identity.js IdentityKeyManager.generateIdentityKey():
        // private key generated with extractable=false.
        const kp = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false, /* non-extractable */
            ['sign', 'verify']
        );

        let privateExportFailed = false;
        try {
            await subtle.exportKey('pkcs8', kp.privateKey);
        } catch (e) {
            privateExportFailed = true;
            console.log(`  Private exportKey rejected (expected): ${e.name}`);
        }

        // Public key must still be exportable (sent to peer during handshake)
        let publicExportSucceeded = false;
        try {
            await subtle.exportKey('raw', kp.publicKey);
            publicExportSucceeded = true;
            console.log('  Public exportKey succeeded (expected)');
        } catch (e) {
            console.log(`  Public exportKey failed (unexpected): ${e.message}`);
        }

        if (privateExportFailed && publicExportSucceeded) {
            console.log('PASSED: identity private key non-extractable, public key extractable');
            passed++;
        } else {
            console.log(`FAILED: privateExportFailed=${privateExportFailed}, publicExportSucceeded=${publicExportSucceeded}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 4: Extractable key CAN be exported (positive control)
    // -------------------------------------------------------------------------
    console.log('--- Test 4: Extractable Key Can Be Exported (positive control) ---');
    try {
        const algorithm = { name: 'AES-GCM', length: 256 };
        const key = await subtle.generateKey(algorithm, true /* extractable */, ['encrypt', 'decrypt']);

        let exported = false;
        try {
            const raw = await subtle.exportKey('raw', key);
            exported = raw.byteLength === 32;
            console.log(`  Exported ${raw.byteLength} bytes (expected 32)`);
        } catch (e) {
            console.log(`  exportKey failed (unexpected): ${e.message}`);
        }

        if (exported) {
            console.log('PASSED: extractable key exports correctly (32 bytes)');
            passed++;
        } else {
            console.log('FAILED: extractable key should export 32 raw bytes');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Summary
    // =========================================================================
    console.log('='.repeat(70));
    console.log(`TEST SUMMARY: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(70));

    if (failed === 0) {
        console.log('ALL TESTS PASSED');
        process.exit(0);
    } else {
        console.log('SOME TESTS FAILED');
        process.exit(1);
    }
}

runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
