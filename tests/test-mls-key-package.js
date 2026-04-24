#!/usr/bin/env node

/**
 * MLS KeyPackage test.
 *
 * Coverage:
 *   - MLSMessage framing: welcome.json stores `key_package` as an
 *     MLSMessage(mls_key_package). We parse the framing and verify the
 *     wire_format and version.
 *   - KeyPackage struct round-trip: bytes → struct → bytes must match.
 *   - KeyPackage signature: the signature carried in the KeyPackage is a
 *     SignWithLabel("KeyPackageTBS", …) produced by the leaf's
 *     signature_key; importing that signature key and verifying must
 *     return true.
 *   - keyPackageRef: RefHash("MLS 1.0 KeyPackage Reference", kp_bytes) is
 *     32 bytes of SHA-256, confirmed non-null and deterministic.
 *
 * GroupContext round-trip is also verified here against the
 * key-schedule.json vectors (5 epochs × cs=2) to ground the new
 * group-context module in IETF vectors before later modules consume it.
 */

const path = require('path');
const KP = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const GroupContext = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group-context.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));

const WELCOME_VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'welcome.json'));
const KEY_SCHEDULE_VECTORS = require(path.join(__dirname, 'vectors', 'mls', 'key-schedule.json'));

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
    const b = Buffer.from(h, 'hex');
    return new Uint8Array(b.buffer, b.byteOffset, b.length);
}

function hex(u8) {
    return Buffer.from(u8).toString('hex');
}

async function main() {
    // ---------------------------------------------------------------------
    // KeyPackage from welcome.json (cipher_suite=2)
    // ---------------------------------------------------------------------
    console.log('# KeyPackage — welcome.json cs=2');
    {
        const v = WELCOME_VECTORS.find((x) => x.cipher_suite === 2);
        const wrapped = hexDecode(v.key_package);

        const { version, wireFormat, body } = MLSMessage.parseMLSMessage(wrapped);
        assert(version === 0x0001, 'MLSMessage version == mls10');
        assert(
            wireFormat === MLSMessage.WireFormat.MLS_KEY_PACKAGE,
            `MLSMessage wire_format == mls_key_package (0x0005)`
        );

        // Re-wrap check
        const rewrapped = MLSMessage.serializeMLSMessage(wireFormat, body);
        assert(hex(rewrapped) === hex(wrapped), 'MLSMessage round-trip');

        const kp = KP.parseKeyPackage(body);
        assert(kp.version === 0x0001, 'KeyPackage.version == mls10');
        assert(kp.cipherSuite === 0x0002, 'KeyPackage.cipher_suite == 0x0002');
        assert(kp.initKey.length === 65, 'init_key is 65 bytes (P-256 uncompressed)');
        assert(kp.leafNode.signatureKey.length === 65, 'leaf.signature_key is 65 bytes');
        assert(kp.extensions.length === 0, 'no top-level extensions in vector');

        const round = KP.keyPackageBytes(kp);
        assert(hex(round) === hex(body), 'KeyPackage struct round-trip');

        // Verify SignWithLabel("KeyPackageTBS", tbs).
        const sigPub = await Signature.importPublicKey(kp.leafNode.signatureKey);
        const tbs = KP.keyPackageTbsBytes(kp);
        const verified = await Labeled.verifyWithLabel(sigPub, 'KeyPackageTBS', tbs, kp.signature);
        assert(verified === true, 'KeyPackageTBS signature verifies');

        // keyPackageRef is a 32-byte SHA-256 that must be deterministic.
        const ref1 = await KP.keyPackageRef(body);
        const ref2 = await KP.keyPackageRef(body);
        assert(ref1.length === 32, 'keyPackageRef is 32 bytes');
        assert(hex(ref1) === hex(ref2), 'keyPackageRef deterministic');
    }

    // ---------------------------------------------------------------------
    // GroupContext round-trip vs key-schedule.json (cs=2)
    // ---------------------------------------------------------------------
    console.log('# GroupContext — key-schedule.json cs=2');
    {
        const v = KEY_SCHEDULE_VECTORS.find((x) => x.cipher_suite === 2);
        for (let i = 0; i < v.epochs.length; i += 1) {
            const bytes = hexDecode(v.epochs[i].group_context);
            const ctx = GroupContext.parseGroupContext(bytes);
            const round = GroupContext.groupContextBytes(ctx);
            assert(
                hex(round) === v.epochs[i].group_context.toLowerCase(),
                `epoch ${i} GroupContext round-trip`
            );
            assert(ctx.version === 0x0001, `epoch ${i} GroupContext.version == mls10`);
            assert(ctx.cipherSuite === 0x0002, `epoch ${i} GroupContext.cipher_suite == 0x0002`);
        }
    }

    console.log('');
    console.log(`key-package: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
