#!/usr/bin/env node

/**
 * MLS Group — Remove flow.
 *
 * Sequence:
 *   1. Alice creates a group.
 *   2. Bob and Carol join via successive commitAddMember + Welcome.
 *      Members at epoch 2: Alice (0), Bob (1), Carol (2).
 *   3. Alice commitRemoveMember(Bob). Carol applies via processCommit.
 *      Tree blanks Bob's leaf and the parents on his direct path; Alice
 *      and Carol re-key on Alice's direct path.
 *   4. After the Remove:
 *        - Alice and Carol share epoch-3 secrets.
 *        - Bob's epoch-2 state cannot decrypt epoch-3 application msgs.
 *        - Bob's processCommit on the Remove throws "removed from group".
 *   5. Alice can still add a new member (Dave) at epoch 4 with the
 *      blanked Bob slot still in place.
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
    console.log('# Group — Remove flow');

    const aliceId = await freshIdentity();
    const alice = await Group.Group.create({ identity: aliceId });

    // Add Bob → epoch 1.
    const bob = await buildKeyPackage();
    const r1 = await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });
    const tree1 = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const bobGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r1.welcomeMessage,
        keyPackageBytes: bob.keyPackageBytes,
        initPrivateKey: bob.initKp.privateKey,
        identity: bob.identity,
        leafEncKeyPair: bob.leafEncKp,
        ratchetTreeBytes: tree1,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
    });

    // Add Carol → epoch 2.
    const carol = await buildKeyPackage();
    const r2 = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
    await bobGroup.processCommit(r2.commitMessage);
    const tree2 = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const carolGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r2.welcomeMessage,
        keyPackageBytes: carol.keyPackageBytes,
        initPrivateKey: carol.initKp.privateKey,
        identity: carol.identity,
        leafEncKeyPair: carol.leafEncKp,
        ratchetTreeBytes: tree2,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
    });
    assert(alice.epoch === 2n && bobGroup.epoch === 2n && carolGroup.epoch === 2n,
        'A/B/C all at epoch 2 after second Add');

    // Sanity at epoch 2: Bob can decrypt.
    const wireA = await alice.encryptApplicationMessage('hello at epoch 2');
    assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireA)).plaintext) === 'hello at epoch 2',
        'Bob decrypts Alice at epoch 2');

    // ---- Remove Bob (leaf 1) ----
    const rmRes = await alice.commitRemoveMember({ removedLeafIndex: 1 });
    assert(alice.epoch === 3n, 'Alice advanced to epoch 3 after Remove');

    // Carol (still in tree) processes the Remove commit.
    const carolResult = await carolGroup.processCommit(rmRes.commitMessage);
    assert(carolResult.removedLeafIndex === 1, 'Carol observed removedLeafIndex=1');
    assert(carolGroup.epoch === 3n, 'Carol advanced to epoch 3');
    assert(hex(alice.epochSecrets.epochAuthenticator)
        === hex(carolGroup.epochSecrets.epochAuthenticator),
    'Alice and Carol share epoch_authenticator at epoch 3');
    assert(alice._chainStates.size === 4 && carolGroup._chainStates.size === 4,
        'removed blank leaf has no retained application or handshake roots');

    // Bob's leaf in both trees is now blank.
    const bobLeafNode = 2; // leafToNode(1) = 2
    assert(alice.ratchetTree[bobLeafNode] === null, 'Bob leaf blank in Alice tree');
    assert(carolGroup.ratchetTree[bobLeafNode] === null, 'Bob leaf blank in Carol tree');

    // Application message at epoch 3: Carol decrypts Alice.
    const wireA3 = await alice.encryptApplicationMessage('only us now');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(wireA3)).plaintext) === 'only us now',
        'Alice → Carol app msg at epoch 3');

    // Bob (still at epoch 2) cannot decrypt epoch 3 traffic.
    let bobThrew = false;
    try {
        await bobGroup.decryptApplicationMessage(wireA3);
    } catch (_) { bobThrew = true; }
    assert(bobThrew, 'Removed Bob cannot decrypt epoch-3 traffic with stale state');

    // Bob's processCommit on the Remove commit explicitly fails with
    // "removed from group" so the orchestrator can clean up.
    let bobProcessThrew = false;
    let bobErrMsg = '';
    try {
        await bobGroup.processCommit(rmRes.commitMessage);
    } catch (err) { bobProcessThrew = true; bobErrMsg = err.message; }
    assert(bobProcessThrew && bobErrMsg.includes('removed'),
        'Bob.processCommit signals removal explicitly', bobErrMsg);

    // Self-remove must throw.
    let selfRmThrew = false;
    try {
        await alice.commitRemoveMember({ removedLeafIndex: alice.myLeafIndex });
    } catch (_) { selfRmThrew = true; }
    assert(selfRmThrew, 'commitRemoveMember rejects self-remove');

    // Out-of-range index must throw.
    let oobThrew = false;
    try {
        await alice.commitRemoveMember({ removedLeafIndex: 99 });
    } catch (_) { oobThrew = true; }
    assert(oobThrew, 'commitRemoveMember rejects out-of-range leaf');

    // Already-blank leaf must throw.
    let alreadyBlankThrew = false;
    try {
        await alice.commitRemoveMember({ removedLeafIndex: 1 });
    } catch (_) { alreadyBlankThrew = true; }
    assert(alreadyBlankThrew, 'commitRemoveMember rejects already-blank leaf');

    // ---- Add Dave AFTER the Remove (Bob's slot is still blank) ----
    const dave = await buildKeyPackage();
    const r4 = await alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes });
    await carolGroup.processCommit(r4.commitMessage);
    assert(alice.epoch === 4n && carolGroup.epoch === 4n,
        'Alice and Carol advanced to epoch 4 after add-after-remove');
    assert(alice.nLeaves === 4, 'Alice tree has 4 leaves (Bob slot still occupied by blank)');

    const tree4 = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const daveGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r4.welcomeMessage,
        keyPackageBytes: dave.keyPackageBytes,
        initPrivateKey: dave.initKp.privateKey,
        identity: dave.identity,
        leafEncKeyPair: dave.leafEncKp,
        ratchetTreeBytes: tree4,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
    });
    assert(daveGroup.myLeafIndex === 3, 'Dave joined at leaf 3 (after blank Bob slot)');

    const wireA4 = await alice.encryptApplicationMessage('post-remove epoch');
    assert(new TextDecoder().decode((await daveGroup.decryptApplicationMessage(wireA4)).plaintext) === 'post-remove epoch',
        'Alice → Dave app msg at epoch 4');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(
        await daveGroup.encryptApplicationMessage('hi from dave'),
    )).plaintext) === 'hi from dave',
        'Dave → Carol app msg at epoch 4');

    console.log('');
    console.log(`group-remove: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
