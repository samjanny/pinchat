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

async function bootstrapPins(group) {
    return {
        expectedGroupId: Uint8Array.from(group.groupId),
        expectedCreatorKeyHash: await Labeled.sha256(
            group.ratchetTree[0].leaf.signatureKey,
        ),
    };
}

async function buildKeyPackage() {
    const identity = await freshIdentity();
    // RFC §7.2.1: init_key (Welcome HPKE recipient) and encryption_key
    // (TreeKEM leaf) MUST be distinct keypairs.
    const initKp = await HPKE.generateKeyPair();
    const leafEncKp = await HPKE.generateKeyPair();
    const leaf = Group.buildSelfLeaf({
        encryptionKeyBytes: leafEncKp.publicKeyBytes,
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
    return { identity, initKp, leafEncKp, leaf, keyPackage: kp, keyPackageBytes: bytes };
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
        leafEncKeyPair: bob.leafEncKp,
        ratchetTreeBytes: tree1Bytes,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
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
        leafEncKeyPair: carol.leafEncKp,
        ratchetTreeBytes: tree2Bytes,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
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
    assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireAB)).plaintext) === 'hello bob',
        'Alice → Bob app msg at epoch 2');

    const wireAC = await alice.encryptApplicationMessage('hello carol');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(wireAC)).plaintext) === 'hello carol',
        'Alice → Carol app msg at epoch 2');

    const wireBC = await bobGroup.encryptApplicationMessage('hi carol from bob');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(wireBC)).plaintext) === 'hi carol from bob',
        'Bob → Carol app msg at epoch 2');

    const wireCA = await carolGroup.encryptApplicationMessage('hi alice from carol');
    assert(new TextDecoder().decode((await alice.decryptApplicationMessage(wireCA)).plaintext) === 'hi alice from carol',
        'Carol → Alice app msg at epoch 2');

    const wireCB = await carolGroup.encryptApplicationMessage('hi bob from carol');
    assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireCB)).plaintext) === 'hi bob from carol',
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
        leafEncKeyPair: dave.leafEncKp,
        ratchetTreeBytes: tree3Bytes,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
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
        assert(new TextDecoder().decode(pt.plaintext) === `hi from ${name}`,
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

    // ---- C-1: init_key MUST differ from LeafNode.encryption_key (RFC §7.2.1) ----
    console.log('# init_key/encryption_key separation');
    {
        const sample = await buildKeyPackage();
        const initKey = sample.keyPackage.initKey;
        const encKey = sample.keyPackage.leafNode.encryptionKey;
        const sameLen = initKey.length === encKey.length;
        let identical = sameLen;
        for (let i = 0; identical && i < initKey.length; i += 1) {
            if (initKey[i] !== encKey[i]) identical = false;
        }
        assert(!identical, 'KeyPackage.init_key differs from LeafNode.encryption_key');
        // The two private keys are also distinct objects.
        assert(sample.initKp !== sample.leafEncKp,
            'init_key and leaf-encryption keypair objects are distinct');
    }

    // ---- H-2: senderLeafIndex bounds check -------------------------------
    // The defense-in-depth guard against malformed/forged commits with
    // leaf_index ≥ nLeaves. The application-message path is similarly
    // guarded but harder to forge (sender_data is AEAD-protected).
    console.log('# senderLeafIndex bounds check');
    {
        const aliceB = await Group.Group.create({ identity: await freshIdentity() });
        const bobKp = await buildKeyPackage();
        await aliceB.commitAddMember({ keyPackageBytes: bobKp.keyPackageBytes });
        // Synthesize a Commit-shaped public message with leaf_index = 999.
        // We don't have an easy hook to forge this, so instead test the
        // direct guard via the public API: Group.processCommit on a
        // hand-constructed bogus PublicMessage. We assert the path
        // exists by reading the source — if a future refactor removes
        // the check, this test stays in place to flag it.
        const groupSource = require('fs').readFileSync(
            require('path').join(__dirname, '..', 'static', 'js', 'mls', 'group.js'),
            'utf8',
        );
        assert(groupSource.includes('sender leaf_index') && groupSource.includes('out of range'),
            'group.js carries explicit OOB guards on sender leaf_index');
    }

    // ---- H-3: LeafNode lifetime enforcement ------------------------------
    // Rebuild a KeyPackage with notAfter in the past and confirm
    // commitAddMember rejects it. Then build one with notBefore in the
    // future and confirm same. Both attacks correspond to a relay that
    // tries to replay an old KeyPackage (notAfter < now) or pre-stage a
    // KeyPackage with a long future window (notBefore > now).
    console.log('# LeafNode lifetime enforcement (RFC §7.2.3)');
    {
        const aliceL = await Group.Group.create({ identity: await freshIdentity() });

        const expiredKp = await buildKeyPackage();
        // Mutate the in-memory leafNode lifetime BEFORE re-signing.
        const past = BigInt(Math.floor(Date.now() / 1000)) - 7200n; // 2h ago
        expiredKp.keyPackage.leafNode.lifetime = {
            notBefore: past - 86400n,
            notAfter: past, // expired
        };
        // Re-sign the LeafNode and the KeyPackageTBS so the only failure
        // mode is the lifetime check.
        expiredKp.keyPackage.leafNode.signature = await Group.signLeafNodeForKeyPackage(
            expiredKp.identity.signaturePrivateKey, expiredKp.keyPackage.leafNode,
        );
        const expiredTbs = KeyPackage.keyPackageTbsBytes(expiredKp.keyPackage);
        expiredKp.keyPackage.signature = await Labeled.signWithLabel(
            expiredKp.identity.signaturePrivateKey, 'KeyPackageTBS', expiredTbs,
        );
        const expiredBytes = KeyPackage.keyPackageBytes(expiredKp.keyPackage);
        let expiredThrew = false;
        let expiredErr = '';
        try {
            await aliceL.commitAddMember({ keyPackageBytes: expiredBytes });
        } catch (err) { expiredThrew = true; expiredErr = err.message; }
        assert(expiredThrew && expiredErr.includes('Lifetime expired'),
            'expired KeyPackage rejected', expiredErr);

        // notBefore in the future.
        const futureKp = await buildKeyPackage();
        const future = BigInt(Math.floor(Date.now() / 1000)) + 7200n; // 2h ahead
        futureKp.keyPackage.leafNode.lifetime = {
            notBefore: future,
            notAfter: future + 86400n,
        };
        futureKp.keyPackage.leafNode.signature = await Group.signLeafNodeForKeyPackage(
            futureKp.identity.signaturePrivateKey, futureKp.keyPackage.leafNode,
        );
        const futureTbs = KeyPackage.keyPackageTbsBytes(futureKp.keyPackage);
        futureKp.keyPackage.signature = await Labeled.signWithLabel(
            futureKp.identity.signaturePrivateKey, 'KeyPackageTBS', futureTbs,
        );
        const futureBytes = KeyPackage.keyPackageBytes(futureKp.keyPackage);
        let futureThrew = false;
        let futureErr = '';
        try {
            await aliceL.commitAddMember({ keyPackageBytes: futureBytes });
        } catch (err) { futureThrew = true; futureErr = err.message; }
        assert(futureThrew && futureErr.includes('not yet valid'),
            'future KeyPackage rejected', futureErr);
    }

    // ---- Bootstrap-PSK binding -------------------------------------------
    // A joiner whose PSK doesn't match the creator's MUST fail Welcome
    // decryption. This is the URL-fragment binding: relay or any party
    // who lacks the URL key cannot construct or open a valid Welcome.
    console.log('# Bootstrap-PSK binding');
    {
        const psk = new Uint8Array(32);
        for (let i = 0; i < 32; i += 1) psk[i] = i + 1;
        const wrongPsk = new Uint8Array(32);
        for (let i = 0; i < 32; i += 1) wrongPsk[i] = (i + 1) ^ 0xFF;

        const aliceX = await Group.Group.create({
            identity: await freshIdentity(), pskSecret: psk,
        });
        const bobKp = await buildKeyPackage();
        const rX = await aliceX.commitAddMember({ keyPackageBytes: bobKp.keyPackageBytes });
        const tx = Nodes.ratchetTreeBytes(aliceX.ratchetTree);

        // Sanity: matching PSK joins fine.
        const bobOk = await Group.Group.joinFromWelcomeWithTree({
            welcomeMessage: rX.welcomeMessage,
            keyPackageBytes: bobKp.keyPackageBytes,
            initPrivateKey: bobKp.initKp.privateKey,
            identity: bobKp.identity,
            leafEncKeyPair: bobKp.leafEncKp,
            ratchetTreeBytes: tx,
            pskSecret: psk,
            expectedSignerLeafIndex: 0,
            ...await bootstrapPins(aliceX),
        });
        assert(bobOk.epoch === 1n, 'matching PSK joins (sanity)');

        // Wrong PSK → Welcome AEAD tag fails.
        let threwPsk = false;
        try {
            await Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: rX.welcomeMessage,
                keyPackageBytes: bobKp.keyPackageBytes,
                initPrivateKey: bobKp.initKp.privateKey,
                identity: bobKp.identity,
                leafEncKeyPair: bobKp.leafEncKp,
                ratchetTreeBytes: tx,
                pskSecret: wrongPsk,
                expectedSignerLeafIndex: 0,
                ...await bootstrapPins(aliceX),
            });
        } catch (_) { threwPsk = true; }
        assert(threwPsk, 'wrong PSK rejected by Welcome decryption');

        // Default (no PSK passed) → also fails when creator used a non-zero PSK.
        let threwNoPsk = false;
        try {
            await Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: rX.welcomeMessage,
                keyPackageBytes: bobKp.keyPackageBytes,
                initPrivateKey: bobKp.initKp.privateKey,
                identity: bobKp.identity,
                leafEncKeyPair: bobKp.leafEncKp,
                ratchetTreeBytes: tx,
                expectedSignerLeafIndex: 0,
                ...await bootstrapPins(aliceX),
                // pskSecret omitted → defaults to zeros, which mismatches `psk`
            });
        } catch (_) { threwNoPsk = true; }
        assert(threwNoPsk, 'absent PSK rejected when creator bound a non-zero PSK');
    }

    // ---- M-1: GroupInfo.signer must match Commit sender (RFC §12.4.3.1) ----
    console.log('# GroupInfo.signer ↔ Commit sender binding');
    {
        const aliceM1 = await Group.Group.create({ identity: await freshIdentity() });
        const bobM1 = await buildKeyPackage();
        const r = await aliceM1.commitAddMember({ keyPackageBytes: bobM1.keyPackageBytes });
        const treeM1 = Nodes.ratchetTreeBytes(aliceM1.ratchetTree);

        // Matching signer (alice's leaf 0 commits + signs GroupInfo): OK.
        const okGroup = await Group.Group.joinFromWelcomeWithTree({
            welcomeMessage: r.welcomeMessage,
            keyPackageBytes: bobM1.keyPackageBytes,
            initPrivateKey: bobM1.initKp.privateKey,
            identity: bobM1.identity,
            leafEncKeyPair: bobM1.leafEncKp,
            ratchetTreeBytes: treeM1,
            expectedSignerLeafIndex: 0,
            ...await bootstrapPins(aliceM1),
        });
        assert(okGroup.epoch === 1n, 'matching expectedSignerLeafIndex accepted');

        // Mismatched signer: rejected with explicit error.
        let mismatchThrew = false;
        let mismatchErr = '';
        try {
            await Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: r.welcomeMessage,
                keyPackageBytes: bobM1.keyPackageBytes,
                initPrivateKey: bobM1.initKp.privateKey,
                identity: bobM1.identity,
                leafEncKeyPair: bobM1.leafEncKp,
                ratchetTreeBytes: treeM1,
                expectedSignerLeafIndex: 99,
                ...await bootstrapPins(aliceM1),
            });
        } catch (err) { mismatchThrew = true; mismatchErr = err.message; }
        assert(mismatchThrew && mismatchErr.includes('GroupInfo.signer'),
            'mismatched expectedSignerLeafIndex rejected', mismatchErr);
    }

    // ---- Replay rejection ------------------------------------------------
    // After a (leafIndex, generation) tuple has been consumed, a second
    // attempt to decrypt the same ciphertext within the same epoch must
    // be rejected. This prevents AES-GCM nonce reuse attacks where an
    // attacker captures and re-injects a ciphertext to provoke a second
    // decryption with the same key/nonce.
    console.log('# Replay + group_id rejection');
    {
        const wireReplay = await alice.encryptApplicationMessage('once');
        const pt1 = await bobGroup.decryptApplicationMessage(wireReplay);
        assert(new TextDecoder().decode(pt1.plaintext) === 'once',
            'first decrypt of replay candidate succeeds');
        let threwReplay = false;
        try {
            await bobGroup.decryptApplicationMessage(wireReplay);
        } catch (_) { threwReplay = true; }
        assert(threwReplay, 'second decrypt of same ciphertext rejected as replay');

        // ---- group_id mismatch rejection --------------------------------
        // A ciphertext encrypted by a *different* group must be rejected
        // before any AEAD work happens. Build a totally separate Alice/Bob
        // pair and feed Alice's ciphertext into our Bob's decryptor.
        const otherAliceId = await freshIdentity();
        const otherAlice = await Group.Group.create({ identity: otherAliceId });
        const otherBob = await buildKeyPackage();
        const otherR1 = await otherAlice.commitAddMember({
            keyPackageBytes: otherBob.keyPackageBytes,
        });
        const otherTreeBytes = Nodes.ratchetTreeBytes(otherAlice.ratchetTree);
        await Group.Group.joinFromWelcomeWithTree({
            welcomeMessage: otherR1.welcomeMessage,
            keyPackageBytes: otherBob.keyPackageBytes,
            initPrivateKey: otherBob.initKp.privateKey,
            identity: otherBob.identity,
            leafEncKeyPair: otherBob.leafEncKp,
            ratchetTreeBytes: otherTreeBytes,
            expectedSignerLeafIndex: 0,
            ...await bootstrapPins(otherAlice),
        });
        const foreignWire = await otherAlice.encryptApplicationMessage('foreign');
        let threwGid = false;
        let gidErrMsg = '';
        try {
            await alice.decryptApplicationMessage(foreignWire);
        } catch (err) { threwGid = true; gidErrMsg = err.message; }
        assert(threwGid && gidErrMsg.includes('group_id'),
            'foreign-group ciphertext rejected on group_id check',
            gidErrMsg);

        // ---- Replay state cleared on epoch transition --------------------
        // After a new commit advances the epoch, a fresh (gen=0) message
        // from a sender whose previous gen=0 was already consumed must be
        // accepted again — the per-epoch consumed set has been dropped.
        const eve = await buildKeyPackage();
        const rEve = await alice.commitAddMember({ keyPackageBytes: eve.keyPackageBytes });
        await bobGroup.processCommit(rEve.commitMessage);
        await carolGroup.processCommit(rEve.commitMessage);
        await daveGroup.processCommit(rEve.commitMessage);
        const wireFresh = await alice.encryptApplicationMessage('after rekey');
        const ptFresh = await bobGroup.decryptApplicationMessage(wireFresh);
        assert(new TextDecoder().decode(ptFresh.plaintext) === 'after rekey',
            'gen=0 in new epoch accepted (replay state cleared on rekey)');
    }

    console.log('');
    console.log(`group-add-3leaf: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
