#!/usr/bin/env node

/**
 * MLS Group - Remove flow.
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
 *        - Bob's processCommit returns an authenticated terminal result and
 *          erases its stale epoch capabilities.
 *   5. Alice can still add a new member (Dave) at epoch 4 by reusing
 *      Bob's blanked leaf index.
 */

const path = require('path');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));
const RatchetTree = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'ratchet-tree.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));

let passed = 0;
let failed = 0;
function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  - ${detail}` : ''}`);
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

function previousEpochReceiveSnapshot(previousEpoch) {
    const chains = [...previousEpoch.chainStates.entries()]
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([id, st]) => ({
            id,
            nextGeneration: st.nextGeneration,
            secret: hex(st.secret),
            skipped: [...st.skipped.entries()]
                .sort(([a], [b]) => a - b)
                .map(([generation, value]) => ({
                    generation,
                    key: hex(value.key),
                    nonce: hex(value.nonce),
                })),
        }));
    const consumed = [...previousEpoch.consumedByLeaf.entries()]
        .sort(([a], [b]) => a - b)
        .map(([leafIndex, generations]) => [
            leafIndex, [...generations].sort((a, b) => a - b),
        ]);
    const allowed = [...previousEpoch.allowedSenderLeafIndices]
        .sort((a, b) => a - b);
    return JSON.stringify({ chains, consumed, allowed });
}

function groupSecretRefs(group) {
    const refs = [
        ...Object.values(group.epochSecrets || {}),
        group.pskSecret,
        ...[...(group._chainStates || new Map()).values()]
            .flatMap((state) => [
                state.secret,
                ...[...state.skipped.values()].flatMap((value) => [
                    value.key, value.nonce,
                ]),
            ]),
    ];
    if (group._prevEpoch) {
        refs.push(group._prevEpoch.senderDataSecret);
        for (const state of group._prevEpoch.chainStates.values()) {
            refs.push(state.secret);
            for (const value of state.skipped.values()) {
                refs.push(value.key, value.nonce);
            }
        }
    }
    return refs.filter((value) => value instanceof Uint8Array);
}

async function joinWith(committer, member, welcomeMessage) {
    return Group.Group.joinFromWelcomeWithTree({
        welcomeMessage,
        keyPackageBytes: member.keyPackageBytes,
        initPrivateKey: member.initKp.privateKey,
        identity: member.identity,
        leafEncKeyPair: member.leafEncKp,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(committer.ratchetTree),
        expectedSignerLeafIndex: 0,
        expectedCommitEpoch: committer.epoch - 1n,
        ...await bootstrapPins(committer),
    });
}

/**
 * M-08: RFC 9420 trees are full. Three members live in a 4-leaf tree, a
 * Remove that empties the right subtree halves the tree, and removing the
 * last member leaves the creator alone in a 1-leaf tree with an empty
 * direct path. Every member must reach the same tree hash at each step.
 */
async function fullTreeShape() {
    console.log('# Group - RFC 9420 full-tree extend and truncate');
    const alice = await Group.Group.create({ identity: await freshIdentity() });
    const bob = await buildKeyPackage();
    const r1 = await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });
    const bobGroup = await joinWith(alice, bob, r1.welcomeMessage);
    const carol = await buildKeyPackage();
    const r2 = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
    await bobGroup.processCommit(r2.commitMessage);
    const carolGroup = await joinWith(alice, carol, r2.welcomeMessage);
    assert(alice.nLeaves === 4 && alice.ratchetTree.length === 7
        && bobGroup.nLeaves === 4 && carolGroup.nLeaves === 4,
    'three members share a full 4-leaf tree (left-balanced math would use 3)');
    assert(TreeMath.directPathWithRoot(TreeMath.leafToNode(2), 4).join(',') === '5,3'
        && alice.ratchetTree[5] === null,
    'Carol at leaf 2 sits under the blank parent 5, as in RFC 9420');
    assert(Nodes.parseRatchetTree(
        Nodes.ratchetTreeBytes(alice.ratchetTree),
    ).length === 5,
    'Welcome ratchet_tree omits the two trailing blank nodes (RFC 9420 section 12.4.3.3)');

    const r3 = await alice.commitRemoveMember({ removedLeafIndex: 2 });
    await bobGroup.processCommit(r3.commitMessage);
    assert(alice.nLeaves === 2 && alice.ratchetTree.length === 3
        && bobGroup.nLeaves === 2
        && hex(alice.treeHash) === hex(bobGroup.treeHash),
    'Remove of the only right-subtree member truncates the tree to 2 leaves');
    assert(!bobGroup.parentKeyPairs.has(3) && bobGroup.parentKeyPairs.has(1),
        'truncation drops the parent key pair of the discarded root');

    const dave = await buildKeyPackage();
    const r4 = await alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes });
    await bobGroup.processCommit(r4.commitMessage);
    const daveGroup = await joinWith(alice, dave, r4.welcomeMessage);
    assert(alice.nLeaves === 4 && daveGroup.myLeafIndex === 2
        && hex(daveGroup.treeHash) === hex(bobGroup.treeHash),
    'the next Add extends the tree again and reuses leaf 2');

    const r5 = await alice.commitRemoveMember({ removedLeafIndex: 2 });
    await bobGroup.processCommit(r5.commitMessage);
    const r6 = await alice.commitRemoveMember({ removedLeafIndex: 1 });
    const bobRemoved = await bobGroup.processCommit(r6.commitMessage);
    assert(alice.nLeaves === 1 && alice.ratchetTree.length === 1
        && bobRemoved.removedSelf === true,
    'removing the last member leaves the creator in a 1-leaf tree');
    const erin = await buildKeyPackage();
    const r7 = await alice.commitAddMember({ keyPackageBytes: erin.keyPackageBytes });
    const erinGroup = await joinWith(alice, erin, r7.welcomeMessage);
    const wire = await alice.encryptApplicationMessage('after the 1-leaf epoch');
    assert(alice.nLeaves === 2 && erinGroup.myLeafIndex === 1
        && new TextDecoder().decode(
            (await erinGroup.decryptApplicationMessage(wire)).plaintext,
        ) === 'after the 1-leaf epoch',
    'a creator left alone can admit a new member afterwards');

    // A ratchet_tree that keeps its trailing blank nodes is not the RFC
    // wire form and is refused at join.
    const frank = await buildKeyPackage();
    const r8 = await alice.commitAddMember({ keyPackageBytes: frank.keyPackageBytes });
    const enc = new Codec.Encoder();
    Nodes.writeRatchetTree(enc, alice.ratchetTree);
    let trailingRefused = false;
    try {
        await Group.Group.joinFromWelcomeWithTree({
            welcomeMessage: r8.welcomeMessage,
            keyPackageBytes: frank.keyPackageBytes,
            initPrivateKey: frank.initKp.privateKey,
            identity: frank.identity,
            leafEncKeyPair: frank.leafEncKp,
            ratchetTreeBytes: enc.bytes(),
            expectedSignerLeafIndex: 0,
            expectedCommitEpoch: alice.epoch - 1n,
            ...await bootstrapPins(alice),
        });
    } catch (err) {
        trailingRefused = err.message.includes('blank node');
    }
    assert(alice.ratchetTree[alice.ratchetTree.length - 1] === null && trailingRefused,
        'a ratchet_tree that ends with a blank node is refused');
}

async function main() {
    console.log('# Group - Remove flow');

    const aliceId = await freshIdentity();
    const alice = await Group.Group.create({ identity: aliceId });

    // Add Bob -> epoch 1.
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
        expectedCommitEpoch: alice.epoch - 1n,
        ...await bootstrapPins(alice),
    });

    // Add Carol -> epoch 2.
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
        expectedCommitEpoch: alice.epoch - 1n,
        ...await bootstrapPins(alice),
    });
    assert(alice.epoch === 2n && bobGroup.epoch === 2n && carolGroup.epoch === 2n,
        'A/B/C all at epoch 2 after second Add');

    // Sanity at epoch 2: Bob can decrypt.
    const wireA = await alice.encryptApplicationMessage('hello at epoch 2');
    assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireA)).plaintext) === 'hello at epoch 2',
        'Bob decrypts Alice at epoch 2');

    // ---- Remove Bob (leaf 1) ----
    // This message was genuinely sent before the Remove and must remain
    // deliverable through the grace context because Alice survives.
    const survivingInFlight = await alice.encryptApplicationMessage(
        'survivor in flight before remove',
    );
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
    assert(!alice._prevEpoch.allowedSenderLeafIndices.has(1)
        && !carolGroup._prevEpoch.allowedSenderLeafIndices.has(1)
        && alice._prevEpoch.allowedSenderLeafIndices.has(0)
        && carolGroup._prevEpoch.allowedSenderLeafIndices.has(0),
    'previous-epoch grace authorizes surviving leaves but revokes Bob immediately');

    const survivingLate = await carolGroup.decryptApplicationMessage(
        survivingInFlight,
    );
    assert(new TextDecoder().decode(survivingLate.plaintext)
        === 'survivor in flight before remove',
    'in-flight previous-epoch message from a surviving leaf is still accepted');

    // Bob can still form an epoch-2 ciphertext locally after observing the
    // transition, but recipients must reject it before advancing any retained
    // receive chain. This closes the revocation-lag window without sacrificing
    // late delivery for members that remain in the group.
    const revokedOldEpoch = await bobGroup.encryptApplicationMessage(
        'revoked sender after remove',
    );
    const carolPreviousEpoch = carolGroup._prevEpoch;
    const previousChains = carolPreviousEpoch.chainStates;
    const previousConsumed = carolPreviousEpoch.consumedByLeaf;
    const previousBeforeReject = previousEpochReceiveSnapshot(carolPreviousEpoch);
    let revokedRejected = false;
    let revokedError = '';
    try {
        await carolGroup.decryptApplicationMessage(revokedOldEpoch);
    } catch (err) {
        revokedRejected = true;
        revokedError = err.message;
    }
    assert(revokedRejected && revokedError.includes('was removed'),
        'valid old-epoch ciphertext from removed Bob is rejected immediately',
        revokedError);
    assert(carolGroup._prevEpoch === carolPreviousEpoch
        && carolPreviousEpoch.chainStates === previousChains
        && carolPreviousEpoch.consumedByLeaf === previousConsumed
        && previousEpochReceiveSnapshot(carolPreviousEpoch) === previousBeforeReject,
    'revoked old-epoch ciphertext leaves grace ratchet and replay state unchanged');

    // Bob's leaf in both trees is now blank.
    const bobLeafNode = 2; // leafToNode(1) = 2
    assert(alice.ratchetTree[bobLeafNode] === null, 'Bob leaf blank in Alice tree');
    assert(carolGroup.ratchetTree[bobLeafNode] === null, 'Bob leaf blank in Carol tree');

    // Application message at epoch 3: Carol decrypts Alice.
    const wireA3 = await alice.encryptApplicationMessage('only us now');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(wireA3)).plaintext) === 'only us now',
        'Alice -> Carol app msg at epoch 3');

    // Bob (still at epoch 2) cannot decrypt epoch 3 traffic.
    let bobThrew = false;
    try {
        await bobGroup.decryptApplicationMessage(wireA3);
    } catch (_) { bobThrew = true; }
    assert(bobThrew, 'Removed Bob cannot decrypt epoch-3 traffic with stale state');

    // Bob authenticates every public component of the Remove, receives a
    // typed terminal result, and destroys its stale epoch capabilities.
    const bobSecretBytes = groupSecretRefs(bobGroup);
    const bobRemoval = await bobGroup.processCommit(rmRes.commitMessage);
    assert(bobRemoval.removedSelf === true
        && bobRemoval.removedLeafIndex === 1
        && bobRemoval.epoch === 3n,
    'Bob.processCommit returns an authenticated terminal removal result');
    assert(Object.keys(bobGroup.epochSecrets).length === 0
        && bobGroup._chainStates.size === 0
        && bobGroup._prevEpoch === null
        && bobGroup.pskSecret === null
        && bobGroup.leafKeyPair === null
        && bobGroup.identity === null
        && bobGroup.parentKeyPairs.size === 0
        && bobSecretBytes.every((bytes) => bytes.every((byte) => byte === 0)),
    'authenticated self-removal erases all retained Group secret material');

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

    // ---- Add Dave AFTER the Remove (reuse Bob's blank slot) ----
    const dave = await buildKeyPackage();
    const r4 = await alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes });
    await carolGroup.processCommit(r4.commitMessage);
    assert(alice.epoch === 4n && carolGroup.epoch === 4n,
        'Alice and Carol advanced to epoch 4 after add-after-remove');
    assert(alice.nLeaves === 4,
        'Alice tree reuses Bob\'s blank leaf without growing');

    const tree4 = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const daveGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: r4.welcomeMessage,
        keyPackageBytes: dave.keyPackageBytes,
        initPrivateKey: dave.initKp.privateKey,
        identity: dave.identity,
        leafEncKeyPair: dave.leafEncKp,
        ratchetTreeBytes: tree4,
        expectedSignerLeafIndex: 0,
        expectedCommitEpoch: alice.epoch - 1n,
        ...await bootstrapPins(alice),
    });
    assert(daveGroup.myLeafIndex === 1,
        'Dave joins in the leftmost blank leaf');

    const wireA4 = await alice.encryptApplicationMessage('post-remove epoch');
    assert(new TextDecoder().decode((await daveGroup.decryptApplicationMessage(wireA4)).plaintext) === 'post-remove epoch',
        'Alice -> Dave app msg at epoch 4');
    assert(new TextDecoder().decode((await carolGroup.decryptApplicationMessage(
        await daveGroup.encryptApplicationMessage('hi from dave'),
    )).plaintext) === 'hi from dave',
        'Dave -> Carol app msg at epoch 4');

    const cappedCandidate = alice.forkForPendingCommit();
    const existingLeaf = RatchetTree.leafFor(
        cappedCandidate.ratchetTree, 0,
    );
    // 20 members occupy leaves 0..19 of the full 32-leaf tree; leaves
    // 20..31 stay blank, yet the member cap still refuses a 21st member.
    cappedCandidate.nLeaves = Group.MAX_TREE_LEAVES;
    cappedCandidate.ratchetTree = new Array(
        TreeMath.nodeWidth(Group.MAX_TREE_LEAVES),
    ).fill(null);
    for (let leafIndex = 0;
        leafIndex < Group.MAX_GROUP_LEAVES;
        leafIndex += 1) {
        cappedCandidate.ratchetTree[TreeMath.leafToNode(leafIndex)] = {
            nodeType: Nodes.NodeType.LEAF,
            leaf: existingLeaf,
        };
    }
    const overflowMember = await buildKeyPackage();
    let leafCapRejected = false;
    try {
        await cappedCandidate.commitAddMember({
            keyPackageBytes: overflowMember.keyPackageBytes,
        });
    } catch (error) {
        leafCapRejected = error.message.includes('20-member limit');
    } finally {
        cappedCandidate.destroySecrets();
    }
    assert(leafCapRejected,
        'cryptographic Add path enforces the 20-member profile cap');

    await fullTreeShape();

    console.log('');
    console.log(`group-remove: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
