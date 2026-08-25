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
const assert = require('assert');
const fs = require('fs');
const path = require('path');

// Required globals for production modules under Node.
global.debugLog = () => {};
global.debugError = () => {};
global.debugWarn = () => {};

// crypto.js must be required first so it promotes the AAD globals before
// downstream modules evaluate. We don't use CryptoManager directly here
// but loading identity.js as the real production module is the point of
// the F-02 regression test below.
require('../static/js/crypto.js');
const { IdentityKeyManager } = require('../static/js/identity.js');

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

    // -------------------------------------------------------------------------
    // Test 5: F-02 regression — IdentityKeyManager production path
    // -------------------------------------------------------------------------
    // Test 3 above verifies the GENERIC pattern (generateKey(false, ...) yields
    // a non-extractable private key). Test 5 exercises the REAL production
    // class `IdentityKeyManager.generateIdentityKeypair()`. Before v0.2.5 the
    // class used a three-step round-trip (extractable=true → exportKey('pkcs8')
    // → importKey(false) → fill(0)) that briefly placed the raw private key
    // bytes in the JS heap. F-02 collapsed it to a single non-extractable
    // generateKey. This test exists to catch any future regression that
    // re-introduces an extractable intermediate.
    console.log('--- Test 5: IdentityKeyManager produces non-extractable private (F-02) ---');
    try {
        const mgr = new IdentityKeyManager();
        const kp = await mgr.generateIdentityKeypair();

        // The class either restored a persisted keypair from IndexedDB (not
        // available under Node, so we always hit the freshly-minted branch)
        // or generated one. Either way, the private side must be unreadable.
        let privateExportFailed = false;
        try {
            await subtle.exportKey('pkcs8', kp.privateKey);
        } catch (e) {
            privateExportFailed = true;
            console.log(`  Private exportKey rejected (expected): ${e.name}`);
        }

        // Public side must still export (used by exportIdentityPublicKey + SAS).
        let publicExportSucceeded = false;
        try {
            const pub = await subtle.exportKey('raw', kp.publicKey);
            publicExportSucceeded = pub.byteLength === 65; // uncompressed P-256
            console.log(`  Public exportKey succeeded: ${pub.byteLength} bytes`);
        } catch (e) {
            console.log(`  Public exportKey failed (unexpected): ${e.message}`);
        }

        // Sign+verify roundtrip exercises the actual usages array on the keypair.
        let signVerifyOk = false;
        let failedImportWasAtomic = false;
        try {
            const data = new TextEncoder().encode('F-02 regression payload');
            const sig = await mgr.sign(data);
            await mgr.importPeerIdentityPublicKey(await subtle.exportKey('raw', kp.publicKey));
            await mgr.verify(data, sig);
            signVerifyOk = true;
            console.log('  sign+verify roundtrip OK');

            const previousKey = mgr.peerIdentityPublicKey;
            const previousRaw = new Uint8Array(mgr.peerIdentityPublicKeyRaw);
            const offCurve = new Uint8Array(65);
            offCurve[0] = 0x04;
            let rejected = false;
            try {
                await mgr.importPeerIdentityPublicKey(offCurve);
            } catch (_) {
                rejected = true;
            }
            failedImportWasAtomic = rejected
                && mgr.peerIdentityPublicKey === previousKey
                && Buffer.from(mgr.peerIdentityPublicKeyRaw).equals(Buffer.from(previousRaw));
            console.log(`  failed peer-key import left prior state unchanged: ${failedImportWasAtomic}`);
        } catch (e) {
            console.log(`  sign+verify failed (unexpected): ${e.message}`);
        }

        if (privateExportFailed && publicExportSucceeded && signVerifyOk && failedImportWasAtomic) {
            console.log('PASSED: F-02 — non-extractable identity + transactional peer import');
            passed++;
        } else {
            console.log(`FAILED: privateExportFailed=${privateExportFailed}, publicExportSucceeded=${publicExportSucceeded}, signVerifyOk=${signVerifyOk}, failedImportWasAtomic=${failedImportWasAtomic}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 6: Extension release pins match the signed manifest generation
    // -------------------------------------------------------------------------
    console.log('--- Test 6: Extension release pins match signed manifest ---');
    try {
        const root = path.join(__dirname, '..');
        const signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
        const chromeBackground = fs.readFileSync(path.join(root, 'extensions/chrome/background.js'), 'utf8');
        const firefoxBackground = fs.readFileSync(path.join(root, 'extensions/firefox/background.js'), 'utf8');
        const chromeManifest = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/manifest.json'), 'utf8'));
        const firefoxManifest = JSON.parse(fs.readFileSync(path.join(root, 'extensions/firefox/manifest.json'), 'utf8'));
        const readPin = (source, name) => {
            const match = source.match(new RegExp(`const ${name} = (?:'([^']+)'|([0-9]+));`));
            if (!match) throw new Error(`${name} not found`);
            return match[1] === undefined ? Number(match[2]) : match[1];
        };
        const chromeTag = readPin(chromeBackground, 'GITHUB_TAG');
        const firefoxTag = readPin(firefoxBackground, 'GITHUB_TAG');
        const chromeFloor = readPin(chromeBackground, 'MIN_KNOWN_SEQUENCE');
        const firefoxFloor = readPin(firefoxBackground, 'MIN_KNOWN_SEQUENCE');
        const readPublicKey = (source) => {
            const match = source.match(/const PINCHAT_PUBLIC_KEY = `([\s\S]*?)`;/);
            if (!match) throw new Error('PINCHAT_PUBLIC_KEY not found');
            return match[1];
        };

        const pinsOk = chromeTag === 'v0.7.0'
            && firefoxTag === chromeTag
            && chromeFloor === signed.data.sequence
            && firefoxFloor === chromeFloor
            && chromeManifest.version === '1.2.1'
            && firefoxManifest.version === chromeManifest.version
            && readPublicKey(chromeBackground) === readPublicKey(firefoxBackground);
        if (!pinsOk) {
            throw new Error(
                `tag chrome/firefox=${chromeTag}/${firefoxTag}, `
                + `floor=${chromeFloor}/${firefoxFloor}, signed=${signed.data.sequence}, `
                + `extension=${chromeManifest.version}/${firefoxManifest.version}`,
            );
        }
        console.log(`  Release ${chromeTag}, sequence floor ${chromeFloor}, extension ${chromeManifest.version}`);
        console.log('PASSED: Chrome and Firefox release pins are aligned');
        passed++;
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 7: Extension CSP is preventive, pinned, and deterministic
    // -------------------------------------------------------------------------
    console.log('--- Test 7: Extension enforces signed script hashes before execution ---');
    try {
        const root = path.join(__dirname, '..');
        const signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
        const chromeManifest = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/manifest.json'), 'utf8'));
        const firefoxManifest = JSON.parse(fs.readFileSync(path.join(root, 'extensions/firefox/manifest.json'), 'utf8'));
        const chromeRules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/rules.json'), 'utf8'));
        const firefoxRules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/firefox/rules.json'), 'utf8'));
        const { buildRules } = require('../extensions/generate-csp-rules');
        const expectedRules = buildRules(signed);

        for (const manifest of [chromeManifest, firefoxManifest]) {
            assert(manifest.permissions.includes('declarativeNetRequestWithHostAccess'));
            assert.strictEqual(manifest.declarative_net_request.rule_resources[0].enabled, true);
            assert.strictEqual(manifest.declarative_net_request.rule_resources[0].path, 'rules.json');
        }
        assert.deepStrictEqual(chromeRules, expectedRules);
        assert.deepStrictEqual(firefoxRules, expectedRules);
        assert(chromeRules[0].action.responseHeaders[0].value.includes("script-src 'none'"));
        for (const rule of chromeRules.slice(1)) {
            const csp = rule.action.responseHeaders[0].value;
            assert(!/script-src[^;]*'self'/.test(csp), 'script-src must not trust the origin');
            assert(csp.includes("'sha256-"), 'page rule must pin at least one signed script');
        }

        console.log('PASSED: packaged DNR rules replace origin trust with per-page signed hashes');
        passed++;
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
