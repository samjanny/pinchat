#!/usr/bin/env node

/**
 * Cross-check the MLS §5 labeled KDF / hash operations against the
 * IETF crypto-basics.json reference vectors for cipher_suite = 2.
 *
 * Covers:
 *   - DeriveSecret        → against crypto-basics.derive_secret
 *   - ExpandWithLabel     → against crypto-basics.expand_with_label
 *   - RefHash             → against crypto-basics.ref_hash
 *
 * The SignWithLabel and EncryptWithLabel fields of crypto-basics.json
 * are verified in the modules that own their primitives (signature,
 * labeled-hpke) once those land.
 */

const path = require('path');
const KS = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-schedule.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'crypto-basics.json'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  — ${detail}` : ''}`);
        failed += 1;
    }
}

function hexDecode(h) {
    const clean = h.replace(/\s+/g, '');
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.substr(i * 2, 2), 16);
    return out;
}

function hex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
    const v = VECTORS.find((x) => x.cipher_suite === 2);
    if (!v) {
        console.log('  FAIL no cipher_suite=2 entry');
        process.exit(1);
    }

    console.log(`# crypto-basics — cipher_suite=2`);

    // --- DeriveSecret ---
    {
        const secret = hexDecode(v.derive_secret.secret);
        const out = await KS.deriveSecret(secret, v.derive_secret.label);
        assert(hex(out) === v.derive_secret.out.toLowerCase(),
            `DeriveSecret("${v.derive_secret.label}")`,
            `got ${hex(out)} want ${v.derive_secret.out}`);
    }

    // --- ExpandWithLabel ---
    {
        const secret = hexDecode(v.expand_with_label.secret);
        const context = hexDecode(v.expand_with_label.context);
        const out = await KS.expandWithLabel(
            secret, v.expand_with_label.label, context, v.expand_with_label.length);
        assert(hex(out) === v.expand_with_label.out.toLowerCase(),
            `ExpandWithLabel("${v.expand_with_label.label}", len=${v.expand_with_label.length})`,
            `got ${hex(out)} want ${v.expand_with_label.out}`);
    }

    // --- RefHash ---
    {
        const value = hexDecode(v.ref_hash.value);
        const out = await Labeled.refHash(v.ref_hash.label, value);
        assert(hex(out) === v.ref_hash.out.toLowerCase(),
            `RefHash("${v.ref_hash.label}")`,
            `got ${hex(out)} want ${v.ref_hash.out}`);
    }

    console.log('');
    console.log(`crypto-basics: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
