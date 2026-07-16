#!/usr/bin/env node

/**
 * PinChat MLS single-admin policy.
 *
 * MLS permits any member to create a Commit. PinChat's creator-centric MVP
 * deliberately narrows that protocol capability to the authenticated member
 * at leaf 0, while retaining non-creator Update proposals.
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

function assert(condition, name, detail = '') {
    if (condition) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
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
        keyPackageBytes: KeyPackage.keyPackageBytes(keyPackage),
    };
}

async function addAndJoin(creator, joiner, existingMembers = []) {
    const result = await creator.commitAddMember({
        keyPackageBytes: joiner.keyPackageBytes,
    });
    for (const member of existingMembers) {
        await member.processCommit(result.commitMessage);
    }
    return Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: result.welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKp.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafEncKp,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(creator.ratchetTree),
        expectedSignerLeafIndex: 0,
        expectedCommitEpoch: creator.epoch - 1n,
        ...await bootstrapPins(creator),
    });
}

function equalBytes(a, b) {
    return Buffer.from(a).equals(Buffer.from(b));
}

async function main() {
    console.log('# MLS creator-only Commit policy');

    // The join path must enforce the same creator-only rule as
    // processCommit.  Make leaf 1 produce an internally consistent Add +
    // Welcome and pass the matching Commit sender explicitly; the legacy
    // signer/committer binding therefore succeeds, so rejection exercises
    // only the creator-at-leaf-0 policy.
    {
        const welcomeCreator = await Group.Group.create({
            identity: await freshIdentity(),
        });
        const nonCreatorGroup = await addAndJoin(
            welcomeCreator, await buildKeyPackage(),
        );
        const target = await buildKeyPackage();
        const unauthorizedWelcome = await nonCreatorGroup.commitAddMember({
            keyPackageBytes: target.keyPackageBytes,
        });
        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: unauthorizedWelcome.welcomeMessage,
                keyPackageBytes: target.keyPackageBytes,
                initPrivateKey: target.initKp.privateKey,
                identity: target.identity,
                leafEncKeyPair: target.leafEncKp,
                ratchetTreeBytes: Nodes.ratchetTreeBytes(
                    nonCreatorGroup.ratchetTree,
                ),
                expectedSignerLeafIndex: 1,
                expectedCommitEpoch: nonCreatorGroup.epoch - 1n,
                ...await bootstrapPins(nonCreatorGroup),
            }),
            'only creator leaf 0 may sign GroupInfo',
            'Welcome signed by authenticated non-creator leaf is rejected',
        );
    }

    const alice = await Group.Group.create({ identity: await freshIdentity() });
    const bobGroup = await addAndJoin(alice, await buildKeyPackage());
    const carolGroup = await addAndJoin(
        alice, await buildKeyPackage(), [bobGroup],
    );
    assert(alice.myLeafIndex === 0 && bobGroup.myLeafIndex === 1,
        'creator is leaf 0 and non-creator is leaf 1');

    await expectReject(
        bobGroup.commitRemoveMember({ removedLeafIndex: 0 }),
        'creator leaf 0 cannot be removed',
        'Remove targeting creator leaf 0 is rejected',
    );

    // Bob can construct a cryptographically valid MLS Commit with the
    // low-level Group API, but PinChat recipients must reject it on policy.
    const unauthorized = await bobGroup.commitUpdate();
    const carolEpochBefore = carolGroup.epoch;
    await expectReject(
        carolGroup.processCommit(unauthorized.commitMessage),
        'only creator leaf 0 may commit',
        'Commit from authenticated non-creator member is rejected',
    );
    assert(carolGroup.epoch === carolEpochBefore,
        'rejected non-creator Commit does not advance recipient epoch');

    const authorized = await alice.commitUpdate();
    const accepted = await carolGroup.processCommit(authorized.commitMessage);
    assert(accepted.committerLeafIndex === 0,
        'Commit from creator leaf 0 is accepted');
    assert(carolGroup.epoch === alice.epoch,
        'recipient advances on creator Commit');
    assert(equalBytes(
        carolGroup.epochSecrets.epochAuthenticator,
        alice.epochSecrets.epochAuthenticator,
    ), 'creator and recipient converge after authorized Commit');

    console.log('');
    console.log(`mls-creator-policy: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
