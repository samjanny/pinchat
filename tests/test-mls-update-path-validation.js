#!/usr/bin/env node
/**
 * UpdatePath encrypted_path_secret cardinality (RFC 9420 §7.6).
 *
 * The malicious messages below are re-signed by the real creator and carry
 * a valid membership_tag for the recipient's current epoch. processCommit
 * must reject them specifically at the whole-path layout gate, before using
 * a recipient-specific ciphertext or mutating MLS state.
 */
const path = require('path');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));

let passed = 0;
let failed = 0;

function assert(condition, name, detail) {
    if (condition) {
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

function bytesTag(bytes) {
    return Buffer.from(bytes || []).toString('base64url');
}

function captureGroupState(group) {
    return {
        epoch: group.epoch,
        nLeaves: group.nLeaves,
        tree: bytesTag(Nodes.ratchetTreeBytes(group.ratchetTree)),
        treeHash: bytesTag(group.treeHash),
        confirmedTranscriptHash: bytesTag(group.confirmedTranscriptHash),
        interimTranscriptHash: bytesTag(group.interimTranscriptHash),
        senderRatchetGeneration: group.senderRatchetGeneration,
        epochSecrets: Object.fromEntries(Object.entries(group.epochSecrets)
            .map(([name, value]) => [name, bytesTag(value)])),
        leafPrivateKey: group.leafKeyPair.privateKey,
        leafPublicKey: group.leafKeyPair.publicKey,
        leafPublicKeyBytes: bytesTag(group.leafKeyPair.publicKeyBytes),
        parentKeyPairs: group.parentKeyPairs,
        chainStates: group._chainStates,
        consumedByLeaf: group.consumedByLeaf,
        previousEpoch: group._prevEpoch,
    };
}

function groupStateMatches(group, before) {
    const after = captureGroupState(group);
    return after.epoch === before.epoch
        && after.nLeaves === before.nLeaves
        && after.tree === before.tree
        && after.treeHash === before.treeHash
        && after.confirmedTranscriptHash === before.confirmedTranscriptHash
        && after.interimTranscriptHash === before.interimTranscriptHash
        && after.senderRatchetGeneration === before.senderRatchetGeneration
        && JSON.stringify(after.epochSecrets) === JSON.stringify(before.epochSecrets)
        && after.leafPrivateKey === before.leafPrivateKey
        && after.leafPublicKey === before.leafPublicKey
        && after.leafPublicKeyBytes === before.leafPublicKeyBytes
        && after.parentKeyPairs === before.parentKeyPairs
        && after.chainStates === before.chainStates
        && after.consumedByLeaf === before.consumedByLeaf
        && after.previousEpoch === before.previousEpoch;
}

async function freshIdentity() {
    const keyPair = await Signature.generateKeyPair();
    return {
        signaturePrivateKey: keyPair.privateKey,
        signaturePublicKeyBytes: keyPair.publicKeyBytes,
    };
}

async function buildKeyPackage() {
    const identity = await freshIdentity();
    const initKeyPair = await HPKE.generateKeyPair();
    const leafKeyPair = await HPKE.generateKeyPair();
    const leaf = Group.buildSelfLeaf({
        encryptionKeyBytes: leafKeyPair.publicKeyBytes,
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
        initKey: initKeyPair.publicKeyBytes,
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
        initKeyPair,
        leafKeyPair,
        keyPackageBytes: KeyPackage.keyPackageBytes(keyPackage),
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

async function addAndJoin(creator, joiner, existingMembers = []) {
    const result = await creator.commitAddMember({
        keyPackageBytes: joiner.keyPackageBytes,
    });
    for (const member of existingMembers) {
        await member.processCommit(result.commitMessage);
    }
    const joined = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: result.welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKeyPair.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafKeyPair,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(creator.ratchetTree),
        expectedSignerLeafIndex: 0,
        expectedCommitEpoch: creator.epoch - 1n,
        ...await bootstrapPins(creator),
    });
    return { result, joined };
}

function parseCommitMessage(commitMessage) {
    const frame = MLSMessage.parseMLSMessage(commitMessage);
    return PublicMessage.parsePublicMessage(frame.body, (decoder, contentType) => {
        if (contentType === Framing.ContentType.COMMIT) return Commit.readCommit(decoder);
        throw new Error(`test: expected Commit, got content_type ${contentType}`);
    });
}

/**
 * Mutate an UpdatePath and re-authenticate the resulting Commit with the real
 * creator identity and the recipient's current membership key. The original
 * confirmation_tag is retained because the new layout gate must reject first.
 */
async function rewriteUpdatePath(commitMessage, mutatePath, creator, recipient) {
    const pm = parseCommitMessage(commitMessage);
    mutatePath(pm.content.parsed.path);
    pm.content.payload = Commit.commitBytes(pm.content.parsed);
    const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
    const groupContext = recipient._buildGroupContextStruct();
    pm.auth.signature = await PublicMessage.signFramedContent(
        creator.identity.signaturePrivateKey,
        wireFormat,
        pm.content,
        groupContext,
    );
    pm.membershipTag = await PublicMessage.computeMembershipTag(
        recipient.epochSecrets.membershipKey,
        wireFormat,
        pm.content,
        pm.auth,
        groupContext,
    );
    return MLSMessage.serializeMLSMessage(
        wireFormat, PublicMessage.publicMessageBytes(pm),
    );
}

async function main() {
    console.log('# UpdatePath ciphertext-layout validation (RFC 9420 §7.6)');

    // Four live leaves make Alice's direct path contain two levels. Bob
    // decrypts from level 0; level 1 targets Carol and Dave and was therefore
    // previously invisible to Bob's recipient-specific lookup.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bobBundle = await buildKeyPackage();
        const { joined: bob } = await addAndJoin(alice, bobBundle);
        const carolBundle = await buildKeyPackage();
        const { joined: carol } = await addAndJoin(alice, carolBundle, [bob]);
        const daveBundle = await buildKeyPackage();
        await addAndJoin(alice, daveBundle, [bob, carol]);

        const { commitMessage } = await alice.commitUpdate();
        const parsed = parseCommitMessage(commitMessage);
        const pathNodes = parsed.content.parsed.path.nodes;
        assert(pathNodes.length === 2
            && pathNodes[0].encryptedPathSecret.length === 1
            && pathNodes[1].encryptedPathSecret.length === 2,
            'honest four-leaf UpdatePath matches both copath resolutions');

        const aliceDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(0), 4,
        );
        const bobLca = TreeMath.commonAncestor(
            TreeMath.leafToNode(0), TreeMath.leafToNode(1), 4,
        );
        assert(aliceDirectPath.indexOf(bobLca) === 0,
            'Bob decrypts at level 0, leaving level 1 as an off-recipient check');

        const missingCiphertext = await rewriteUpdatePath(
            commitMessage,
            (updatePath) => {
                updatePath.nodes[1].encryptedPathSecret =
                    updatePath.nodes[1].encryptedPathSecret.slice(0, -1);
            },
            alice,
            bob,
        );
        const beforeMissing = captureGroupState(bob);
        await expectReject(
            bob.processCommit(missingCiphertext),
            'UpdatePath node 1 (tree node 3) encrypted_path_secret length 1 != filtered copath resolution 2',
            'missing off-recipient path ciphertext is rejected',
        );
        assert(groupStateMatches(bob, beforeMissing),
            'missing-ciphertext rejection leaves recipient state unchanged');

        const extraCiphertext = await rewriteUpdatePath(
            commitMessage,
            (updatePath) => {
                const source = updatePath.nodes[1].encryptedPathSecret[0];
                updatePath.nodes[1].encryptedPathSecret.push({
                    kemOutput: Uint8Array.from(source.kemOutput),
                    ciphertext: Uint8Array.from(source.ciphertext),
                });
            },
            alice,
            bob,
        );
        const beforeExtra = captureGroupState(bob);
        await expectReject(
            bob.processCommit(extraCiphertext),
            'UpdatePath node 1 (tree node 3) encrypted_path_secret length 3 != filtered copath resolution 2',
            'extra off-recipient path ciphertext is rejected',
        );
        assert(groupStateMatches(bob, beforeExtra),
            'extra-ciphertext rejection leaves recipient state unchanged');

        const invalidPathPublicKey = await rewriteUpdatePath(
            commitMessage,
            (updatePath) => {
                updatePath.nodes[1].encryptionKey = new Uint8Array(HPKE.Npk);
            },
            alice,
            bob,
        );
        const beforeBadPathKeyBob = captureGroupState(bob);
        const beforeBadPathKeyCarol = captureGroupState(carol);
        await expectReject(
            bob.processCommit(invalidPathPublicKey),
            'UpdatePath node 1 encryption_key invalid',
            'invalid off-recipient UpdatePath public key is rejected by Bob',
        );
        await expectReject(
            carol.processCommit(invalidPathPublicKey),
            'UpdatePath node 1 encryption_key invalid',
            'same malformed path key is uniformly rejected by Carol',
        );
        assert(groupStateMatches(bob, beforeBadPathKeyBob)
                && groupStateMatches(carol, beforeBadPathKeyCarol),
            'off-recipient path-key rejection leaves both recipients unchanged');

        const invalidKemOutput = await rewriteUpdatePath(
            commitMessage,
            (updatePath) => {
                updatePath.nodes[1].encryptedPathSecret[0].kemOutput =
                    new Uint8Array(HPKE.Npk);
            },
            alice,
            bob,
        );
        const beforeBadKem = captureGroupState(bob);
        await expectReject(
            bob.processCommit(invalidKemOutput),
            'ciphertext 0 kem_output invalid',
            'invalid off-recipient KEM output is rejected',
        );
        assert(groupStateMatches(bob, beforeBadKem),
            'invalid KEM output leaves recipient state unchanged');

        const invalidCiphertextLength = await rewriteUpdatePath(
            commitMessage,
            (updatePath) => {
                updatePath.nodes[1].encryptedPathSecret[0].ciphertext =
                    updatePath.nodes[1].encryptedPathSecret[0]
                        .ciphertext.slice(0, -1);
            },
            alice,
            bob,
        );
        const beforeBadCiphertext = captureGroupState(bob);
        await expectReject(
            bob.processCommit(invalidCiphertextLength),
            'ciphertext must be 48 bytes',
            'wrong-length off-recipient HPKE ciphertext is rejected',
        );
        assert(groupStateMatches(bob, beforeBadCiphertext),
            'wrong-length HPKE ciphertext leaves recipient state unchanged');

        await bob.processCommit(commitMessage);
        await carol.processCommit(commitMessage);
        assert(bob.epoch === alice.epoch,
            'untampered UpdatePath still advances the recipient');
    }

    // In a three-leaf Add, the root copath contains only the newly added
    // member. That leaf MUST be excluded, so the corresponding vector is
    // empty. An injected ciphertext proves the exclusion is checked.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bobBundle = await buildKeyPackage();
        const { joined: bob } = await addAndJoin(alice, bobBundle);
        const carolBundle = await buildKeyPackage();
        const addResult = await alice.commitAddMember({
            keyPackageBytes: carolBundle.keyPackageBytes,
        });
        const parsedAdd = parseCommitMessage(addResult.commitMessage);
        const pathNodes = parsedAdd.content.parsed.path.nodes;
        assert(pathNodes.length === 2
            && pathNodes[1].encryptedPathSecret.length === 0,
            'new Add leaf is excluded from the root copath resolution');

        const addedLeafCiphertext = await rewriteUpdatePath(
            addResult.commitMessage,
            (updatePath) => {
                updatePath.nodes[1].encryptedPathSecret.push({
                    kemOutput: new Uint8Array(65),
                    ciphertext: new Uint8Array(48),
                });
            },
            alice,
            bob,
        );
        const beforeAddedLeaf = captureGroupState(bob);
        await expectReject(
            bob.processCommit(addedLeafCiphertext),
            'UpdatePath node 1 (tree node 3) encrypted_path_secret length 1 != filtered copath resolution 0',
            'ciphertext addressed only to a newly added leaf is rejected',
        );
        assert(groupStateMatches(bob, beforeAddedLeaf),
            'new-leaf exclusion rejection leaves recipient state unchanged');

        await bob.processCommit(addResult.commitMessage);
        assert(bob.epoch === alice.epoch,
            'untampered Add UpdatePath still advances an existing member');
    }

    console.log('');
    console.log(`update-path-validation: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
