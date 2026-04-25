#!/usr/bin/env node

/**
 * MLS Group — 3-leaf flow exercising commitAddMember + processCommit.
 *
 * Sequence:
 *   1. Alice creates a group.
 *   2. Bob (joiner #1) builds a KeyPackage → Alice commits Add → Bob
 *      Welcomes in. Both at epoch 1, 2-leaf tree.
 *   3. Carol (joiner #2) builds a KeyPackage → Alice commits Add →
 *      broadcasts Commit + Welcome. Bob processes the Commit (NOT the
 *      Welcome — it's not for him), Carol processes the Welcome. Alice,
 *      Bob, and Carol must all converge to identical epoch-2 secrets,
 *      a 3-leaf tree, and the ability to exchange application messages
 *      pairwise.
 *
 * The point of this test is the new processCommit decryption path
 * (existing member receives a Commit, walks UpdatePath, recovers the
 * shared epoch keys) and the generalised joinFromWelcomeWithTree
 * (auto-detect own leaf + walk path_secret up to root for any tree
 * shape ≥ 2 leaves).
 */

const path = require('path');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));

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

async function freshIdentity() {
    const kp = await Signature.generateKeyPair();
    return {
        signaturePrivateKey: kp.privateKey,
        signaturePublicKeyBytes: kp.publicKeyBytes,
    };
}

async function buildKeyPackage() {
    const identity = await freshIdentity();
    const initKp = await HPKE.generateKeyPair();
    const leaf = Group.buildSelfLeaf({
        encryptionKeyBytes: initKp.publicKeyBytes,
        signatureKeyBytes: identity.signaturePublicKeyBytes,
        credentialIdentity: identity.signaturePublicKeyBytes,
        leafNodeSource: Nodes.LeafNodeSource.KEY_PACKAGE,
    });
    leaf.signature = await Group.signLeafNodeForKeyPackage(
        identity.signaturePrivateKey, leaf,
    );
    const kp = {
        version: 0x0001,
        cipherSuite: 0x0002,
        initKey: initKp.publicKeyBytes,
        leafNode: leaf,
        extensions: [],
        signature: new Uint8Array(0),
    };
    const tbs = KeyPackage.keyPackageTbsBytes(kp);
    kp.signature = await Labeled.signWithLabel(
        identity.signaturePrivateKey, 'KeyPackageTBS', tbs,
    );
    const bytes = KeyPackage.keyPackageBytes(kp);
    return { identity, initKp, leaf, keyPackage: kp, keyPackageBytes: bytes };
}

function hex(u8) { return Buffer.from(u8).toString('hex'); }

async function main() {
    console.log('# Group — 3-leaf Add/Commit/Welcome');

    // ----- Epoch 0 → 1: Alice + Bob -----
    const aliceId = await freshIdentity();
    const alice = await Group.Group.create({ identity: aliceId });
    const bob = await buildKeyPackage();
    const r1 = await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });
    const tree1Bytes = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const bobGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r1.welcomeMessage,
        keyPackageBytes: bob.keyPackageBytes,
        initPrivateKey: bob.initKp.privateKey,
        identity: bob.identity,
        leafEncKeyPair: bob.initKp,
        ratchetTreeBytes: tree1Bytes,
    });
    assert(alice.epoch === 1n && bobGroup.epoch === 1n,
        'Alice and Bob at epoch 1 after first Add');
    assert(alice.nLeaves === 2 && bobGroup.nLeaves === 2,
        'Both see 2-leaf tree at epoch 1');

    // ----- Epoch 1 → 2: add Carol -----
    const carol = await buildKeyPackage();
    const r2 = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
    assert(alice.epoch === 2n, 'Alice advanced to epoch 2');
    assert(alice.nLeaves === 3, 'Alice has 3 leaves');

    // Bob processes the Commit broadcast.
    const bobResult = await bobGroup.processCommit(r2.commitMessage);
    assert(bobResult.addedLeafIndex === 2, 'Bob saw addedLeafIndex=2');
    assert(bobGroup.epoch === 2n, 'Bob advanced to epoch 2');
    assert(bobGroup.nLeaves === 3, 'Bob sees 3 leaves after processCommit');

    // Carol joins via Welcome.
    const tree2Bytes = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const carolGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r2.welcomeMessage,
        keyPackageBytes: carol.keyPackageBytes,
        initPrivateKey: carol.initKp.privateKey,
        identity: carol.identity,
        leafEncKeyPair: carol.initKp,
        ratchetTreeBytes: tree2Bytes,
    });
    assert(carolGroup.epoch === 2n && carolGroup.nLeaves === 3,
        'Carol joined into 3-leaf tree at epoch 2');
    assert(carolGroup.myLeafIndex === 2, 'Carol is leaf 2');

    // All three share encryption_secret at epoch 2.
    const aHex = hex(alice.epochSecrets.encryptionSecret);
    const bHex = hex(bobGroup.epochSecrets.encryptionSecret);
    const cHex = hex(carolGroup.epochSecrets.encryptionSecret);
    assert(aHex === bHex && bHex === cHex,
        'Alice, Bob, Carol share encryption_secret at epoch 2',
        aHex !== bHex ? `A=${aHex.slice(0, 16)} B=${bHex.slice(0, 16)} C=${cHex.slice(0, 16)}` : null);

    // Pairwise application messages at epoch 2.
    const wireAB = await alice.encryptApplicationMessage('hello bob');
    assert(new TextDecoder().decode(await bobGroup.decryptApplicationMessage(wireAB)) === 'hello bob',
        'Alice → Bob app msg at epoch 2');

    const wireAC = await alice.encryptApplicationMessage('hello carol');
    assert(new TextDecoder().decode(await carolGroup.decryptApplicationMessage(wireAC)) === 'hello carol',
        'Alice → Carol app msg at epoch 2');

    const wireBC = await bobGroup.encryptApplicationMessage('hi carol from bob');
    assert(new TextDecoder().decode(await carolGroup.decryptApplicationMessage(wireBC)) === 'hi carol from bob',
        'Bob → Carol app msg at epoch 2');

    const wireCA = await carolGroup.encryptApplicationMessage('hi alice from carol');
    assert(new TextDecoder().decode(await alice.decryptApplicationMessage(wireCA)) === 'hi alice from carol',
        'Carol → Alice app msg at epoch 2');

    const wireCB = await carolGroup.encryptApplicationMessage('hi bob from carol');
    assert(new TextDecoder().decode(await bobGroup.decryptApplicationMessage(wireCB)) === 'hi bob from carol',
        'Carol → Bob app msg at epoch 2');

    // ----- Epoch 2 → 3: add Dave -----
    const dave = await buildKeyPackage();
    const r3 = await alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes });
    assert(alice.epoch === 3n, 'Alice advanced to epoch 3');
    assert(alice.nLeaves === 4, 'Alice has 4 leaves');

    // Existing members process the Commit.
    await bobGroup.processCommit(r3.commitMessage);
    await carolGroup.processCommit(r3.commitMessage);
    assert(bobGroup.epoch === 3n && carolGroup.epoch === 3n,
        'Bob and Carol advanced to epoch 3');
    assert(bobGroup.nLeaves === 4 && carolGroup.nLeaves === 4,
        'Bob and Carol see 4 leaves');

    const tree3Bytes = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const daveGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r3.welcomeMessage,
        keyPackageBytes: dave.keyPackageBytes,
        initPrivateKey: dave.initKp.privateKey,
        identity: dave.identity,
        leafEncKeyPair: dave.initKp,
        ratchetTreeBytes: tree3Bytes,
    });
    assert(daveGroup.myLeafIndex === 3, 'Dave is leaf 3');
    assert(daveGroup.epoch === 3n && daveGroup.nLeaves === 4,
        'Dave joined into 4-leaf tree at epoch 3');

    // All four converge.
    const aHex3 = hex(alice.epochSecrets.encryptionSecret);
    const bHex3 = hex(bobGroup.epochSecrets.encryptionSecret);
    const cHex3 = hex(carolGroup.epochSecrets.encryptionSecret);
    const dHex3 = hex(daveGroup.epochSecrets.encryptionSecret);
    assert(aHex3 === bHex3 && bHex3 === cHex3 && cHex3 === dHex3,
        'A/B/C/D share encryption_secret at epoch 3');

    // Round-trip every pair Alice ↔ {Bob, Carol, Dave}.
    for (const [from, to, name] of [
        [alice, bobGroup, 'Alice→Bob'],
        [alice, carolGroup, 'Alice→Carol'],
        [alice, daveGroup, 'Alice→Dave'],
        [bobGroup, daveGroup, 'Bob→Dave'],
        [carolGroup, daveGroup, 'Carol→Dave'],
        [daveGroup, alice, 'Dave→Alice'],
        [daveGroup, bobGroup, 'Dave→Bob'],
        [daveGroup, carolGroup, 'Dave→Carol'],
    ]) {
        const w = await from.encryptApplicationMessage(`hi from ${name}`);
        const pt = await to.decryptApplicationMessage(w);
        assert(new TextDecoder().decode(pt) === `hi from ${name}`,
            `${name} app msg at epoch 3`);
    }

    // ---- Tampered KeyPackage rejection -----------------------------------
    // A relay that flips a single byte of any signed field — leafNode
    // encryption_key, leafNode signature_key, or the outer KeyPackage
    // signature itself — must be rejected by commitAddMember. Without
    // these checks an attacker could splice attacker-controlled leaves
    // into the tree.
    console.log('# KeyPackage tamper rejection');
    {
        const kpVictim = await buildKeyPackage();
        const aliceClean = await Group.Group.create({ identity: aliceId });
        // Sanity: clean KP accepted by a fresh group.
        await aliceClean.commitAddMember({ keyPackageBytes: kpVictim.keyPackageBytes });
        assert(aliceClean.nLeaves === 2, 'sanity: clean KP accepted');

        // Flip a bit in the LeafNode encryption_key (KeyPackage TBS bytes).
        const tamperedEncKey = kpVictim.keyPackageBytes.slice();
        // Find the encryption_key bytes (first 65-byte uncompressed point
        // after the LeafNode prefix). Easier: just flip a byte well inside
        // the structure. We pick a byte that's part of the signed body —
        // bytes 100..200 are LeafNode territory in our typical encoding.
        tamperedEncKey[120] ^= 0x01;
        const aliceA = await Group.Group.create({ identity: await freshIdentity() });
        let threw = false;
        try {
            await aliceA.commitAddMember({ keyPackageBytes: tamperedEncKey });
        } catch (_) {
            threw = true;
        }
        assert(threw, 'tampered KeyPackage TBS body rejected');

        // Flip the trailing KeyPackage signature byte directly.
        const tamperedSig = kpVictim.keyPackageBytes.slice();
        tamperedSig[tamperedSig.length - 1] ^= 0x01;
        const aliceB = await Group.Group.create({ identity: await freshIdentity() });
        let threw2 = false;
        try {
            await aliceB.commitAddMember({ keyPackageBytes: tamperedSig });
        } catch (_) {
            threw2 = true;
        }
        assert(threw2, 'tampered KeyPackage signature rejected');
    }

    console.log('');
    console.log(`group-add-3leaf: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
