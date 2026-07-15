#!/usr/bin/env node
/**
 * Welcome ratchet-tree validation (RFC 9420 §§7.3, 7.9, 12.4.3.1).
 *
 * These are malicious-committer tests, not relay-tamper tests: the
 * committer deliberately builds a malformed tree, then computes a matching
 * tree_hash, signs GroupInfo, and emits an otherwise valid Welcome. The
 * joiner must still reject before deriving epoch secrets.
 */
const path = require('path');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const Proposal = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'proposal.js'));

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

async function expectReject(promise, expectedText, name) {
    let message = '';
    try {
        await promise;
    } catch (err) {
        message = err.message;
    }
    assert(message.includes(expectedText), name, message || 'did not reject');
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
    const keyPackage = {
        version: 0x0001,
        cipherSuite: 0x0002,
        initKey: initKp.publicKeyBytes,
        leafNode: leaf,
        extensions: [],
        signature: new Uint8Array(0),
    };
    keyPackage.signature = await Labeled.signWithLabel(
        identity.signaturePrivateKey,
        'KeyPackageTBS',
        KeyPackage.keyPackageTbsBytes(keyPackage),
    );
    return {
        identity,
        initKp,
        leafEncKp,
        leaf,
        keyPackage,
        keyPackageBytes: KeyPackage.keyPackageBytes(keyPackage),
    };
}

async function replaceKeyPackageLeafEncryptionKey(bundle, encryptionKey) {
    bundle.leaf.encryptionKey = Uint8Array.from(encryptionKey);
    bundle.leaf.signature = await Group.signLeafNodeForKeyPackage(
        bundle.identity.signaturePrivateKey, bundle.leaf,
    );
    bundle.keyPackage.signature = await Labeled.signWithLabel(
        bundle.identity.signaturePrivateKey,
        'KeyPackageTBS',
        KeyPackage.keyPackageTbsBytes(bundle.keyPackage),
    );
    bundle.keyPackageBytes = KeyPackage.keyPackageBytes(bundle.keyPackage);
}

function joinFrom(committer, result, joiner, expectedSignerLeafIndex = committer.myLeafIndex) {
    return Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: result.welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKp.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafEncKp,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(committer.ratchetTree),
        expectedSignerLeafIndex,
    });
}

async function addAndJoin(committer, joiner, existingMembers = []) {
    const result = await committer.commitAddMember({
        keyPackageBytes: joiner.keyPackageBytes,
    });
    for (const member of existingMembers) {
        await member.processCommit(result.commitMessage);
    }
    const joined = await joinFrom(committer, result, joiner);
    return { result, joined };
}

async function main() {
    console.log('# Imported Welcome tree validation');

    // ---- G-2: GroupInfo.signer binding is mandatory ---------------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const result = await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });
        const args = {
            welcomeMessage: result.welcomeMessage,
            keyPackageBytes: bob.keyPackageBytes,
            initPrivateKey: bob.initKp.privateKey,
            identity: bob.identity,
            leafEncKeyPair: bob.leafEncKp,
            ratchetTreeBytes: Nodes.ratchetTreeBytes(alice.ratchetTree),
        };
        await expectReject(
            Group.Group.joinFromWelcomeWithTree(args),
            'missing Commit sender',
            'Welcome without observable Commit is rejected fail-closed',
        );
        const joined = await Group.Group.joinFromWelcomeWithTree({
            ...args, expectedSignerLeafIndex: 0,
        });
        assert(joined.epoch === 1n, 'same Welcome joins when Commit sender is bound');
    }

    // ---- G-1(a): every non-blank leaf signature is checked --------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await addAndJoin(alice, bob);

        // Bob is not the next committer or GroupInfo signer. Corrupt only
        // his inner LeafNode signature, then let Alice build and sign the
        // next tree exactly as a malicious committer could.
        const bobLeaf = alice.ratchetTree[2].leaf;
        bobLeaf.signature = Uint8Array.from(bobLeaf.signature);
        bobLeaf.signature[0] ^= 0x01;

        const carol = await buildKeyPackage();
        const result = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
        await expectReject(
            joinFrom(alice, result, carol),
            'leaf 1 LeafNode signature invalid',
            'invalid non-signer KEY_PACKAGE LeafNode rejected at join',
        );
    }

    // ---- Key uniqueness: duplicate signature_key -----------------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });

        // Make Bob's leaf self-consistent under Alice's signing key so the
        // rejection is specifically the duplicate-key invariant.
        const bobLeaf = alice.ratchetTree[2].leaf;
        bobLeaf.signatureKey = Uint8Array.from(alice.identity.signaturePublicKeyBytes);
        bobLeaf.credential = {
            ...bobLeaf.credential,
            identity: Uint8Array.from(alice.identity.signaturePublicKeyBytes),
        };
        bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
            alice.identity.signaturePrivateKey, bobLeaf,
        );

        const carol = await buildKeyPackage();
        const result = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
        await expectReject(
            joinFrom(alice, result, carol),
            'duplicate signature_key',
            'duplicate leaf signature_key rejected at join',
        );
    }

    // ---- Key uniqueness: duplicate leaf encryption_key -----------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await alice.commitAddMember({ keyPackageBytes: bob.keyPackageBytes });
        const carol = await buildKeyPackage();

        // Re-sign Bob's leaf after assigning Carol's future leaf key. The
        // two LeafNodes are independently signature-valid but violate §7.3.
        const bobLeaf = alice.ratchetTree[2].leaf;
        bobLeaf.encryptionKey = Uint8Array.from(carol.leaf.encryptionKey);
        bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
            bob.identity.signaturePrivateKey, bobLeaf,
        );

        const result = await alice.commitAddMember({ keyPackageBytes: carol.keyPackageBytes });
        await expectReject(
            joinFrom(alice, result, carol),
            'duplicate encryption_key',
            'duplicate leaf encryption_key rejected at join',
        );
    }

    // ---- UPDATE-source TBS uses group_id + leaf_index -------------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);
        const { pendingLeafKeyPair, pendingLeafNode } = await bobGroup.proposeUpdate();
        const update = await alice.commitUpdate({
            updateProposals: [{
                proposal: {
                    proposalType: Proposal.ProposalType.UPDATE,
                    leafNode: pendingLeafNode,
                },
                senderLeafIndex: 1,
            }],
        });
        await bobGroup.processCommit(update.commitMessage, {
            pendingSelfUpdate: pendingLeafKeyPair,
        });

        const carol = await buildKeyPackage();
        const { joined: carolGroup } = await addAndJoin(alice, carol, [bobGroup]);
        assert(carolGroup.epoch === alice.epoch,
            'valid UPDATE-source leaf verifies with group-bound TBS');

        const bobLeaf = alice.ratchetTree[2].leaf;
        bobLeaf.signature = Uint8Array.from(bobLeaf.signature);
        bobLeaf.signature[0] ^= 0x01;
        const dave = await buildKeyPackage();
        const result = await alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes });
        await expectReject(
            joinFrom(alice, result, dave),
            'leaf 1 LeafNode signature invalid',
            'invalid non-signer UPDATE LeafNode rejected at join',
        );
    }

    // ---- Steady-state Add processing enforces key uniqueness ------------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);

        // Positive control: an ordinary Add must still advance an existing
        // member after the whole-tree uniqueness check is introduced.
        const carol = await buildKeyPackage();
        const normalAdd = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
        const normalResult = await bobGroup.processCommit(normalAdd.commitMessage);
        assert(normalResult.addedLeafIndex === 2 && bobGroup.epoch === 2n,
            'normal non-colliding Add succeeds in processCommit');

        // Build an independently signed KeyPackage whose leaf HPKE key is a
        // byte-for-byte copy of Bob's existing leaf key. The committer can
        // construct and authenticate this Commit, but existing members must
        // reject it before advancing their epoch.
        const dave = await buildKeyPackage();
        await replaceKeyPackageLeafEncryptionKey(
            dave, bob.leaf.encryptionKey,
        );
        const collidingAdd = await alice.commitAddMember({
            keyPackageBytes: dave.keyPackageBytes,
        });
        const bobEpochBefore = bobGroup.epoch;
        await expectReject(
            bobGroup.processCommit(collidingAdd.commitMessage),
            'duplicate encryption_key',
            'processCommit rejects Add with duplicate leaf encryption_key',
        );
        assert(bobGroup.epoch === bobEpochBefore,
            'rejected colliding Add does not advance recipient epoch');
    }

    // ---- G-1(b): every parent, including off-signer-path, is valid ------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);
        const carol = await buildKeyPackage();
        const { joined: carolGroup } = await addAndJoin(alice, carol, [bobGroup]);
        const dave = await buildKeyPackage();
        const { joined: daveGroup } = await addAndJoin(
            alice, dave, [bobGroup, carolGroup],
        );

        // Construct a standards-valid historical right-hand path locally on
        // Dave's state. PinChat's creator-only application policy prevents
        // the other members from accepting Dave's Commit, but the imported
        // tree validator remains responsible for checking arbitrary valid
        // MLS tree shapes independently of that authorization policy.
        await daveGroup.commitUpdate();

        await Group.verifyImportedTree(
            daveGroup.ratchetTree, daveGroup.nLeaves, daveGroup.groupId,
        );
        assert(true,
            'valid tree with multiple historical committer paths is accepted');

        // A parent HPKE key may not collide with any other tree node key.
        const collisionTree = Nodes.parseRatchetTree(
            Nodes.ratchetTreeBytes(daveGroup.ratchetTree),
        );
        collisionTree[2].leaf.encryptionKey = Uint8Array.from(
            collisionTree[5].parent.encryptionKey,
        );
        collisionTree[2].leaf.signature = await Group.signLeafNodeForKeyPackage(
            bob.identity.signaturePrivateKey, collisionTree[2].leaf,
        );
        await expectReject(
            Group.verifyImportedTree(collisionTree, 4, daveGroup.groupId),
            'duplicate encryption_key',
            'parent/leaf HPKE encryption_key collision rejected',
        );

        // Corrupt the off-path parent's upward link. A signer-path-only
        // import check would miss this historical branch.
        const offPathParent = daveGroup.ratchetTree[5].parent;
        offPathParent.parentHash = Uint8Array.from(offPathParent.parentHash);
        offPathParent.parentHash[0] ^= 0x01;

        await expectReject(
            Group.verifyImportedTree(
                daveGroup.ratchetTree, daveGroup.nLeaves, daveGroup.groupId,
            ),
            'parent 5 is not parent-hash valid',
            'invalid off-signer-path parent-hash chain rejected on import',
        );
    }

    console.log('');
    console.log(`imported-tree: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
