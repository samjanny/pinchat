#!/usr/bin/env node

/**
 * MLS Group — Add + Commit + Welcome flow (2-leaf MVP).
 *
 * End-to-end: Alice creates a group, generates a Welcome+Commit that
 * adds Bob, and Bob joins from the Welcome. After that both members
 * exchange application messages encrypted under epoch 1.
 *
 * The flow we exercise:
 *   1. Alice: Group.create
 *   2. Bob  : generates identity + an HPKE init keypair + a signed
 *             KeyPackage (basic credential).
 *   3. Alice: commitAddMember({ keyPackageBytes: bobKeyPackageBytes })
 *             → { commitMessage, welcomeMessage }
 *             Alice's state advances to epoch 1 with a 2-leaf tree.
 *   4. Bob  : Group.joinFromWelcomeWithTree — parses the Welcome,
 *             decrypts GroupSecrets under his init_priv, decrypts
 *             the GroupInfo AEAD, verifies the GroupInfo signature
 *             against Alice's leaf signature key, then derives the
 *             epoch-1 secrets and confirms the confirmation_tag
 *             against confirmed_transcript_hash.
 *   5. Both : encrypt / decrypt application messages at epoch 1.
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

async function buildBobKeyPackage() {
    const identity = await freshIdentity();
    const initKp = await HPKE.generateKeyPair();

    // Leaf with source = KEY_PACKAGE (we'll be added, not committing).
    const leaf = Group.buildSelfLeaf({
        encryptionKeyBytes: initKp.publicKeyBytes, // leaf.encryption_key reuses init_key
        signatureKeyBytes: identity.signaturePublicKeyBytes,
        credentialIdentity: identity.signaturePublicKeyBytes,
        leafNodeSource: Nodes.LeafNodeSource.KEY_PACKAGE,
    });
    leaf.signature = await Group.signLeafNodeForKeyPackage(
        identity.signaturePrivateKey, leaf,
    );

    // Build KeyPackage.
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

async function main() {
    console.log('# Group — Add/Commit/Welcome (2-leaf MVP)');

    // 1. Alice creates the group.
    const aliceId = await freshIdentity();
    const alice = await Group.Group.create({ identity: aliceId });
    assert(alice.nLeaves === 1, 'Alice starts as 1-leaf group');

    // 2. Bob builds a KeyPackage.
    const bob = await buildBobKeyPackage();

    // 3. Alice commits Add(Bob) → generates commit + welcome.
    const { commitMessage, welcomeMessage } = await alice.commitAddMember({
        keyPackageBytes: bob.keyPackageBytes,
    });
    assert(alice.nLeaves === 2, 'Alice now has 2 leaves after commit');
    assert(alice.epoch === 1n, 'Alice advanced to epoch 1');
    assert(welcomeMessage instanceof Uint8Array && welcomeMessage.length > 0,
        'welcomeMessage produced');
    assert(commitMessage instanceof Uint8Array && commitMessage.length > 0,
        'commitMessage produced');

    // 4. Bob joins via Welcome. Needs out-of-band ratchet_tree (our MVP).
    const ratchetTreeBytes = Nodes.ratchetTreeBytes(alice.ratchetTree);
    const bobGroup = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage,
        keyPackageBytes: bob.keyPackageBytes,
        initPrivateKey: bob.initKp.privateKey,
        identity: bob.identity,
        leafEncKeyPair: bob.initKp,
        ratchetTreeBytes,
        expectedSignerLeafIndex: 0,
        ...await bootstrapPins(alice),
    });
    assert(bobGroup.nLeaves === 2, 'Bob sees 2-leaf tree');
    assert(bobGroup.epoch === 1n, 'Bob at epoch 1');
    assert(bobGroup.myLeafIndex === 1, 'Bob is leaf 1');
    assert(
        Buffer.from(bobGroup.epochSecrets.encryptionSecret).toString('hex')
        === Buffer.from(alice.epochSecrets.encryptionSecret).toString('hex'),
        'Bob and Alice share encryption_secret at epoch 1'
    );
    assert(
        Buffer.from(bobGroup.epochSecrets.confirmationKey).toString('hex')
        === Buffer.from(alice.epochSecrets.confirmationKey).toString('hex'),
        'Bob and Alice share confirmation_key at epoch 1'
    );

    // 5. Exchange application messages at epoch 1.
    const wire1 = await alice.encryptApplicationMessage('ciao bob, eccoci');
    const pt1 = await bobGroup.decryptApplicationMessage(wire1);
    assert(new TextDecoder().decode(pt1.plaintext) === 'ciao bob, eccoci',
        'Alice → Bob application message at epoch 1 decrypts');

    const wire2 = await bobGroup.encryptApplicationMessage('ciao alice!');
    const pt2 = await alice.decryptApplicationMessage(wire2);
    assert(new TextDecoder().decode(pt2.plaintext) === 'ciao alice!',
        'Bob → Alice application message at epoch 1 decrypts');

    // 6. Path-only Update commit: PCS rotation without membership change.
    const secretBefore = Buffer.from(alice.epochSecrets.encryptionSecret).toString('hex');
    const { commitMessage: updCommit } = await alice.commitUpdate();
    await bobGroup.processCommit(updCommit);
    assert(alice.epoch === 2n && bobGroup.epoch === 2n,
        'Update commit advances both members to epoch 2');
    assert(
        Buffer.from(alice.epochSecrets.encryptionSecret).toString('hex')
            === Buffer.from(bobGroup.epochSecrets.encryptionSecret).toString('hex'),
        'epoch 2 encryption_secret converges after Update commit'
    );
    assert(
        Buffer.from(alice.epochSecrets.encryptionSecret).toString('hex') !== secretBefore,
        'Update commit rotates the encryption_secret'
    );
    const wireU1 = await alice.encryptApplicationMessage('post-update alice');
    assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireU1)).plaintext)
        === 'post-update alice', 'Alice -> Bob message at epoch 2 decrypts');
    const wireU2 = await bobGroup.encryptApplicationMessage('post-update bob');
    assert(new TextDecoder().decode((await alice.decryptApplicationMessage(wireU2)).plaintext)
        === 'post-update bob', 'Bob -> Alice message at epoch 2 decrypts');

    // 7. Previous-epoch grace window: a message encrypted under epoch 2
    // and delivered after the receiver advanced to epoch 3 must still
    // decrypt, exactly once, until the window expires.
    const inFlight = await bobGroup.encryptApplicationMessage('sent at epoch 2');
    const { commitMessage: updCommit2 } = await alice.commitUpdate();  // alice -> epoch 3
    assert(alice.epoch === 3n && bobGroup.epoch === 2n,
        'alice at epoch 3, bob still at epoch 2 (commit in flight)');
    const late = await alice.decryptApplicationMessage(inFlight);
    assert(new TextDecoder().decode(late.plaintext) === 'sent at epoch 2',
        'in-flight epoch-2 message decrypts via the grace window');
    let threwGraceReplay = false;
    try {
        await alice.decryptApplicationMessage(inFlight);
    } catch (_e) { threwGraceReplay = true; }
    assert(threwGraceReplay, 'replay through the grace window rejected');

    // Force the window shut: an old-epoch message is now rejected.
    const inFlight2 = await bobGroup.encryptApplicationMessage('too late');
    alice._prevEpoch.expiresAt = Date.now() - 1;
    let threwExpired = false;
    try {
        await alice.decryptApplicationMessage(inFlight2);
    } catch (_e) { threwExpired = true; }
    assert(threwExpired, 'old-epoch message after grace expiry rejected');
    assert(alice._prevEpoch === null, 'expired grace context dropped and zeroed');

    // Bob catches up and the group converges at epoch 3.
    await bobGroup.processCommit(updCommit2);
    assert(bobGroup.epoch === 3n, 'bob converges to epoch 3');
    const wireF = await bobGroup.encryptApplicationMessage('all caught up');
    assert(new TextDecoder().decode((await alice.decryptApplicationMessage(wireF)).plaintext)
        === 'all caught up', 'post-convergence message decrypts at epoch 3');

    // 8. Member-initiated Update proposal (per-member PCS). Bob (leaf 1)
    // re-keys its OWN leaf; Alice (creator, leaf 0) folds the proposal
    // into a Commit. This is what heals a compromised member leaf key:
    // Bob's fresh encryption key is not derivable from the old one.
    console.log('# Member-initiated Update proposal (per-member PCS)');
    {
        const bobOldLeaf = require('../static/js/mls/ratchet-tree.js')
            .leafFor(bobGroup.ratchetTree, bobGroup.myLeafIndex);
        const bobOldEncKey = Buffer.from(bobOldLeaf.encryptionKey).toString('hex');

        // Bob proposes; keeps the pending keypair to swap in on commit.
        const { proposalMessage, pendingLeafKeyPair } = await bobGroup.proposeUpdate();
        assert(proposalMessage instanceof Uint8Array && proposalMessage.length > 0,
            'Bob produced an Update proposal message');

        // Alice parses the proposal off the wire and folds it into a
        // Commit (mirrors what mls-session does).
        const MLSMessage = require('../static/js/mls/mls-message.js');
        const PublicMessage = require('../static/js/mls/public-message.js');
        const Proposal = require('../static/js/mls/proposal.js');
        const Framing = require('../static/js/mls/framing.js');
        const pframe = MLSMessage.parseMLSMessage(proposalMessage);
        const ppm = PublicMessage.parsePublicMessage(pframe.body, (dec, ct) =>
            (ct === Framing.ContentType.PROPOSAL ? Proposal.readProposal(dec) : null));
        assert(ppm.content.parsed.proposalType === Proposal.ProposalType.UPDATE,
            'proposal parses as UPDATE');
        const proposerLeaf = ppm.content.sender.leafIndex;
        assert(proposerLeaf === 1, 'proposal sender is Bob (leaf 1)');

        const beforeEpoch = alice.epoch;
        const { commitMessage: updCommit3 } = await alice.commitUpdate({
            updateProposals: [{ proposal: ppm.content.parsed, senderLeafIndex: proposerLeaf }],
        });
        assert(alice.epoch === beforeEpoch + 1n, 'folded-Update commit advances Alice');
        const aliceBobLeaf = require('../static/js/mls/ratchet-tree.js')
            .leafFor(alice.ratchetTree, 1);
        assert(Buffer.from(aliceBobLeaf.encryptionKey).toString('hex') !== bobOldEncKey,
            'Bob leaf encryption_key rotated in Alice tree');
        assert(Buffer.from(aliceBobLeaf.encryptionKey).toString('hex')
            === Buffer.from(pendingLeafKeyPair.publicKeyBytes).toString('hex'),
            'Alice tree carries exactly Bob proposed key');

        // Bob processes the Commit with the pending self-update; his
        // keypair swaps in and the group converges.
        const res = await bobGroup.processCommit(updCommit3, { pendingSelfUpdate: pendingLeafKeyPair });
        assert(res.selfUpdated === true, 'processCommit reports Bob self-updated');
        assert(bobGroup.epoch === alice.epoch, 'Bob converges after folded Update');
        assert(
            Buffer.from(bobGroup.epochSecrets.encryptionSecret).toString('hex')
                === Buffer.from(alice.epochSecrets.encryptionSecret).toString('hex'),
            'encryption_secret converges after member Update'
        );
        assert(Buffer.from(bobGroup.leafKeyPair.publicKeyBytes).toString('hex')
            === Buffer.from(pendingLeafKeyPair.publicKeyBytes).toString('hex'),
            'Bob adopted the fresh leaf keypair');

        // Post-rotation traffic decrypts both ways.
        const wireM1 = await bobGroup.encryptApplicationMessage('bob after self-rekey');
        assert(new TextDecoder().decode((await alice.decryptApplicationMessage(wireM1)).plaintext)
            === 'bob after self-rekey', 'Bob -> Alice decrypts after member Update');
        const wireM2 = await alice.encryptApplicationMessage('alice ack');
        assert(new TextDecoder().decode((await bobGroup.decryptApplicationMessage(wireM2)).plaintext)
            === 'alice ack', 'Alice -> Bob decrypts after member Update');
    }

    console.log('');
    console.log(`group-add: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
