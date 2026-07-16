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
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Welcome = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'welcome.js'));
const GroupInfo = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group-info.js'));
const TreeHash = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-hash.js'));

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

function bytesTag(bytes) {
    return Buffer.from(bytes || []).toString('base64url');
}

function captureGroupState(group) {
    return {
        reference: group,
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
    return after.reference === before.reference
        && after.epoch === before.epoch
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

async function expectReject(promise, expectedText, name) {
    let message = '';
    try {
        await promise;
    } catch (err) {
        message = err.message;
    }
    assert(message.includes(expectedText), name, message || 'did not reject');
}

async function expectJoinReject(args, expectedText, name) {
    let message = '';
    let joined = null;
    try {
        joined = await Group.Group.joinFromWelcomeWithTree(args);
    } catch (err) {
        message = err.message;
    }
    assert(message.includes(expectedText), name, message || 'did not reject');
    assert(joined === null, `${name} creates no joined Group state`);
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
        leaf,
        keyPackage,
        keyPackageBytes: KeyPackage.keyPackageBytes(keyPackage),
    };
}

async function resignKeyPackage(bundle) {
    bundle.keyPackage.leafNode.signature = await Group.signLeafNodeForKeyPackage(
        bundle.identity.signaturePrivateKey,
        bundle.keyPackage.leafNode,
    );
    bundle.keyPackage.signature = await Labeled.signWithLabel(
        bundle.identity.signaturePrivateKey,
        'KeyPackageTBS',
        KeyPackage.keyPackageTbsBytes(bundle.keyPackage),
    );
    bundle.keyPackageBytes = KeyPackage.keyPackageBytes(bundle.keyPackage);
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

async function replaceKeyPackageLeafSignatureIdentity(bundle, identity) {
    bundle.leaf.signatureKey = Uint8Array.from(identity.signaturePublicKeyBytes);
    bundle.leaf.credential = {
        ...bundle.leaf.credential,
        identity: Uint8Array.from(identity.signaturePublicKeyBytes),
    };
    bundle.leaf.signature = await Group.signLeafNodeForKeyPackage(
        identity.signaturePrivateKey, bundle.leaf,
    );
    bundle.keyPackage.signature = await Labeled.signWithLabel(
        identity.signaturePrivateKey,
        'KeyPackageTBS',
        KeyPackage.keyPackageTbsBytes(bundle.keyPackage),
    );
    bundle.keyPackageBytes = KeyPackage.keyPackageBytes(bundle.keyPackage);
}

async function maliciousCommitAddWithoutFinalTreeGate(group, keyPackageBytes) {
    group._verifyFinalTreeKeyUniqueness = () => {};
    try {
        return await group.commitAddMember({ keyPackageBytes });
    } finally {
        delete group._verifyFinalTreeKeyUniqueness;
    }
}

function inlineProposal(proposal) {
    return {
        type: Proposal.ProposalOrRefType.PROPOSAL,
        proposal,
    };
}

function referencedProposal(entry) {
    return {
        type: Proposal.ProposalOrRefType.REFERENCE,
        reference: Uint8Array.from(entry.reference),
    };
}

function resolvedProposalReference(entry) {
    return {
        ...referencedProposal(entry),
        proposal: entry.proposal,
        proposalSenderLeafIndex: entry.senderLeafIndex,
    };
}

function proposalStore(...entries) {
    return new Map(entries.map((entry) => [
        Group.proposalReferenceKey(entry.reference), entry,
    ]));
}

/**
 * Replace only a Commit's proposal vector, then authenticate the altered
 * FramedContent with the real creator key and the recipient's current
 * membership key. The original path/confirmation tag intentionally remain
 * untouched: proposal-list validation must reject before either is used.
 */
async function rewriteCommitProposalList(
    commitMessage,
    proposalOrRefs,
    signerIdentity,
    recipientGroup,
) {
    const frame = MLSMessage.parseMLSMessage(commitMessage);
    const pm = PublicMessage.parsePublicMessage(frame.body, (decoder, contentType) => {
        if (contentType === Framing.ContentType.COMMIT) return Commit.readCommit(decoder);
        throw new Error(`test: expected Commit, got content_type ${contentType}`);
    });
    const rewrittenCommit = {
        ...pm.content.parsed,
        proposals: proposalOrRefs,
    };
    const content = {
        ...pm.content,
        payload: Commit.commitBytes(rewrittenCommit),
        parsed: rewrittenCommit,
    };
    const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
    const groupContext = recipientGroup._buildGroupContextStruct();
    const auth = {
        ...pm.auth,
        signature: await PublicMessage.signFramedContent(
            signerIdentity.signaturePrivateKey,
            wireFormat,
            content,
            groupContext,
        ),
    };
    const membershipTag = await PublicMessage.computeMembershipTag(
        recipientGroup.epochSecrets.membershipKey,
        wireFormat,
        content,
        auth,
        groupContext,
    );
    return MLSMessage.serializeMLSMessage(
        wireFormat,
        PublicMessage.publicMessageBytes({ content, auth, membershipTag }),
    );
}

async function tamperCommitConfirmationTag(commitMessage, recipientGroup) {
    const frame = MLSMessage.parseMLSMessage(commitMessage);
    const pm = PublicMessage.parsePublicMessage(frame.body, (decoder, contentType) => {
        if (contentType === Framing.ContentType.COMMIT) return Commit.readCommit(decoder);
        throw new Error(`test: expected Commit, got content_type ${contentType}`);
    });
    const auth = {
        ...pm.auth,
        confirmationTag: Uint8Array.from(pm.auth.confirmationTag),
    };
    auth.confirmationTag[0] ^= 0x01;
    const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
    const membershipTag = await PublicMessage.computeMembershipTag(
        recipientGroup.epochSecrets.membershipKey,
        wireFormat,
        pm.content,
        auth,
        recipientGroup._buildGroupContextStruct(),
    );
    return MLSMessage.serializeMLSMessage(
        wireFormat,
        PublicMessage.publicMessageBytes({
            content: pm.content,
            auth,
            membershipTag,
        }),
    );
}

async function rewriteWelcome({
    result,
    joiner,
    signerIdentity,
    mutateGroupSecrets = async () => {},
    mutateGroupInfo = async () => {},
}) {
    const frame = MLSMessage.parseMLSMessage(result.welcomeMessage);
    const welcome = Welcome.parseWelcome(frame.body);
    if (welcome.secrets.length !== 1) {
        throw new Error(`test: expected one Welcome secret, got ${welcome.secrets.length}`);
    }

    const entry = welcome.secrets[0];
    const groupSecrets = await Welcome.decryptGroupSecrets(
        entry.encryptedGroupSecrets,
        joiner.initKp.privateKey,
        joiner.keyPackage.initKey,
        welcome.encryptedGroupInfo,
    );
    const pskSecret = new Uint8Array(HPKE.Nh);
    const originalWelcomeSecret = await Welcome.deriveWelcomeSecret(
        groupSecrets.joinerSecret, pskSecret,
    );
    const originalKeyNonce = await Welcome.welcomeKeyNonce(originalWelcomeSecret);
    const originalGroupInfoBytes = await Welcome.openEncryptedGroupInfo(
        originalKeyNonce.key,
        originalKeyNonce.nonce,
        welcome.encryptedGroupInfo,
    );
    const groupInfo = GroupInfo.parseGroupInfo(originalGroupInfoBytes);
    originalWelcomeSecret.fill(0);
    originalKeyNonce.key.fill(0);
    originalKeyNonce.nonce.fill(0);
    originalGroupInfoBytes.fill(0);

    await mutateGroupInfo(groupInfo);
    groupInfo.signature = await Labeled.signWithLabel(
        signerIdentity.signaturePrivateKey,
        'GroupInfoTBS',
        GroupInfo.groupInfoTbsBytes(groupInfo),
    );
    await mutateGroupSecrets(groupSecrets);

    const rewrittenWelcomeSecret = await Welcome.deriveWelcomeSecret(
        groupSecrets.joinerSecret, pskSecret,
    );
    const rewrittenKeyNonce = await Welcome.welcomeKeyNonce(rewrittenWelcomeSecret);
    const rewrittenGroupInfoBytes = GroupInfo.groupInfoBytes(groupInfo);
    const encryptedGroupInfo = await Welcome.sealEncryptedGroupInfo(
        rewrittenKeyNonce.key,
        rewrittenKeyNonce.nonce,
        rewrittenGroupInfoBytes,
    );
    const groupSecretsBytes = Welcome.groupSecretsBytes(groupSecrets);
    const encryptedGroupSecrets = await Labeled.encryptWithLabel(
        joiner.keyPackage.initKey,
        'Welcome',
        encryptedGroupInfo,
        groupSecretsBytes,
    );
    rewrittenWelcomeSecret.fill(0);
    rewrittenKeyNonce.key.fill(0);
    rewrittenKeyNonce.nonce.fill(0);
    rewrittenGroupInfoBytes.fill(0);
    groupSecretsBytes.fill(0);

    const rewritten = {
        cipherSuite: welcome.cipherSuite,
        secrets: [{
            newMember: Uint8Array.from(entry.newMember),
            encryptedGroupSecrets,
        }],
        encryptedGroupInfo,
    };
    return MLSMessage.serializeMLSMessage(
        MLSMessage.WireFormat.MLS_WELCOME,
        Welcome.welcomeBytes(rewritten),
    );
}

async function joinArguments(
    committer,
    result,
    joiner,
    expectedSignerLeafIndex = committer.myLeafIndex,
) {
    return {
        welcomeMessage: result.welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKp.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafEncKp,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(committer.ratchetTree),
        expectedSignerLeafIndex,
        expectedCommitEpoch: committer.epoch - 1n,
        ...await bootstrapPins(committer),
    };
}

async function joinFrom(
    committer, result, joiner,
    expectedSignerLeafIndex = committer.myLeafIndex,
) {
    return Group.Group.joinFromWelcomeWithTree(
        await joinArguments(committer, result, joiner, expectedSignerLeafIndex),
    );
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
        const baseArgs = {
            welcomeMessage: result.welcomeMessage,
            keyPackageBytes: bob.keyPackageBytes,
            initPrivateKey: bob.initKp.privateKey,
            identity: bob.identity,
            leafEncKeyPair: bob.leafEncKp,
            ratchetTreeBytes: Nodes.ratchetTreeBytes(alice.ratchetTree),
            expectedCommitEpoch: alice.epoch - 1n,
        };
        const args = { ...baseArgs, ...await bootstrapPins(alice) };
        await expectReject(
            Group.Group.joinFromWelcomeWithTree(args),
            'missing Commit sender',
            'Welcome without observable Commit is rejected fail-closed',
        );
        const {
            expectedCommitEpoch: _omittedCommitEpoch,
            ...missingCommitEpochArgs
        } = args;
        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                ...missingCommitEpochArgs,
                expectedSignerLeafIndex: 0,
            }),
            'expectedCommitEpoch must be a uint64 BigInt',
            'Welcome without the correlated Commit epoch is rejected fail-closed',
        );
        const joined = await Group.Group.joinFromWelcomeWithTree({
            ...args, expectedSignerLeafIndex: 0,
        });
        assert(joined.epoch === 1n, 'same Welcome joins when Commit sender is bound');

        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                ...args,
                identity: await freshIdentity(),
                expectedSignerLeafIndex: 0,
            }),
            'local identity does not match KeyPackage signature_key',
            'Welcome is bound to the local KeyPackage signature identity',
        );

        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                ...args,
                leafEncKeyPair: await HPKE.generateKeyPair(),
                expectedSignerLeafIndex: 0,
            }),
            'local leaf private key does not match KeyPackage encryption_key',
            'Welcome is bound to the local TreeKEM leaf keypair',
        );

        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                ...baseArgs, expectedSignerLeafIndex: 0,
            }),
            'group_id bootstrap pin',
            'Welcome without invite identity pins is rejected fail-closed',
        );

        const wrongGroupId = Uint8Array.from(alice.groupId);
        wrongGroupId[0] ^= 0x01;
        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                ...baseArgs,
                expectedSignerLeafIndex: 0,
                expectedGroupId: wrongGroupId,
                expectedCreatorKeyHash: (await bootstrapPins(alice))
                    .expectedCreatorKeyHash,
            }),
            'group_id does not match invite bootstrap pin',
            'Welcome for a different group_id is rejected by invite pin',
        );

        // Even if an alternative leaf-0 group deliberately reuses the pinned
        // group_id and the same PSK, it cannot reproduce the creator's signing
        // key fingerprint from the invite.
        const imposter = await Group.Group.create({
            identity: await freshIdentity(),
            groupId: Uint8Array.from(alice.groupId),
        });
        const target = await buildKeyPackage();
        const imposterWelcome = await imposter.commitAddMember({
            keyPackageBytes: target.keyPackageBytes,
        });
        await expectReject(
            Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: imposterWelcome.welcomeMessage,
                keyPackageBytes: target.keyPackageBytes,
                initPrivateKey: target.initKp.privateKey,
                identity: target.identity,
                leafEncKeyPair: target.leafEncKp,
                ratchetTreeBytes: Nodes.ratchetTreeBytes(imposter.ratchetTree),
                expectedSignerLeafIndex: 0,
                expectedCommitEpoch: imposter.epoch - 1n,
                ...await bootstrapPins(alice),
            }),
            'creator signature_key does not match invite bootstrap pin',
            'same-group-id alternative creator is rejected by key pin',
        );
    }

    // ---- Welcome/imported-tree ciphersuite profile strictness ----------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const result = await alice.commitAddMember({
            keyPackageBytes: bob.keyPackageBytes,
        });
        const baseArgs = await joinArguments(alice, result, bob);
        const malformedSecretCases = [
            {
                expected: 'joiner_secret must be 32 bytes',
                name: 'Welcome with a non-Nh joiner_secret is rejected',
                mutateGroupSecrets: async (groupSecrets) => {
                    groupSecrets.joinerSecret = new Uint8Array(HPKE.Nh - 1);
                },
            },
            {
                expected: 'path_secret must be 32 bytes',
                name: 'Welcome with a non-Nh path_secret is rejected',
                mutateGroupSecrets: async (groupSecrets) => {
                    groupSecrets.pathSecret = new Uint8Array(HPKE.Nh - 1);
                },
            },
            {
                expected: 'confirmed_transcript_hash must be 32 bytes',
                name: 'Welcome with a non-Nh confirmed transcript hash is rejected',
                mutateGroupInfo: async (groupInfo) => {
                    groupInfo.groupContext.confirmedTranscriptHash =
                        new Uint8Array(HPKE.Nh - 1);
                },
            },
            {
                expected: 'confirmation_tag must be 32 bytes',
                name: 'Welcome with a non-Nh confirmation tag is rejected',
                mutateGroupInfo: async (groupInfo) => {
                    groupInfo.confirmationTag = new Uint8Array(HPKE.Nh - 1);
                },
            },
        ];

        for (const testCase of malformedSecretCases) {
            const welcomeMessage = await rewriteWelcome({
                result,
                joiner: bob,
                signerIdentity: alice.identity,
                mutateGroupSecrets: testCase.mutateGroupSecrets,
                mutateGroupInfo: testCase.mutateGroupInfo,
            });
            await expectJoinReject(
                { ...baseArgs, welcomeMessage },
                testCase.expected,
                testCase.name,
            );
        }

        // Exercise a historical parent outside the new joiner's direct path.
        // A path-only validator would never import this key. Use a
        // correctly-prefixed but off-curve P-256 point so rejection also
        // depends on ciphersuite key deserialization, not merely byte length.
        const aliceFour = await Group.Group.create({
            identity: await freshIdentity(),
        });
        const bobFour = await buildKeyPackage();
        const { joined: bobFourGroup } =
            await addAndJoin(aliceFour, bobFour);
        const carolFour = await buildKeyPackage();
        await addAndJoin(aliceFour, carolFour, [bobFourGroup]);
        const daveFour = await buildKeyPackage();
        const resultFour = await aliceFour.commitAddMember({
            keyPackageBytes: daveFour.keyPackageBytes,
        });
        const baseArgsFour =
            await joinArguments(aliceFour, resultFour, daveFour);
        const malformedTree = Nodes.parseRatchetTree(
            Nodes.ratchetTreeBytes(aliceFour.ratchetTree),
        );
        const parentIndex = 1;
        const invalidOffCurvePoint = new Uint8Array(65);
        invalidOffCurvePoint[0] = 0x04;
        malformedTree[parentIndex].parent.encryptionKey =
            invalidOffCurvePoint;
        const invalidParentWelcome = await rewriteWelcome({
            result: resultFour,
            joiner: daveFour,
            signerIdentity: aliceFour.identity,
            mutateGroupInfo: async (groupInfo) => {
                groupInfo.groupContext.treeHash =
                    await TreeHash.hashRoot(malformedTree);
            },
        });
        await expectJoinReject(
            {
                ...baseArgsFour,
                welcomeMessage: invalidParentWelcome,
                ratchetTreeBytes: Nodes.ratchetTreeBytes(malformedTree),
            },
            `parent ${parentIndex} encryption_key invalid`,
            'Welcome with an invalid parent HPKE public key is rejected',
        );
    }

    // ---- RFC §§7.3/10.1: complete KeyPackage semantic validation -------
    // Every sample below is re-signed after mutation. The rejection must
    // therefore come from the semantic KeyPackage gate, not from a damaged
    // LeafNode or KeyPackage signature.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });

        async function rejectKeyPackage(mutate, expectedText, name) {
            const bundle = await buildKeyPackage();
            await mutate(bundle);
            await resignKeyPackage(bundle);
            const before = captureGroupState(alice);
            await expectReject(
                alice.commitAddMember({ keyPackageBytes: bundle.keyPackageBytes }),
                expectedText,
                name,
            );
            assert(groupStateMatches(alice, before),
                `${name} leaves creator state unchanged`);
        }

        await rejectKeyPackage(
            async (bundle) => {
                bundle.keyPackage.initKey = Uint8Array.from(
                    bundle.keyPackage.leafNode.encryptionKey,
                );
            },
            'init_key must differ from LeafNode encryption_key',
            'fully signed KeyPackage with reused HPKE key is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => { bundle.keyPackage.version = 0x0002; },
            'protocol version 2 does not match MLS 1.0',
            'fully signed KeyPackage with a mismatched version is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => {
                bundle.keyPackage.leafNode.capabilities.cipherSuites = [];
            },
            'does not support ciphersuite',
            'LeafNode missing the group ciphersuite capability is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => {
                bundle.keyPackage.leafNode.credential.identity = new Uint8Array([1]);
            },
            'basic credential identity must equal signature_key',
            'self-signed but misbound PinChat basic credential is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => {
                bundle.keyPackage.initKey = new Uint8Array(65);
            },
            'init_key invalid',
            'fully signed KeyPackage with an invalid HPKE init_key is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => {
                bundle.keyPackage.extensions = [{
                    extensionType: 0x4242,
                    extensionData: new Uint8Array([1]),
                }];
            },
            'KeyPackage extensions contain unadvertised extension',
            'unadvertised KeyPackage extension is rejected',
        );

        await rejectKeyPackage(
            async (bundle) => {
                const now = BigInt(Math.floor(Date.now() / 1000));
                bundle.keyPackage.leafNode.lifetime = {
                    notBefore: now - 1n,
                    notAfter: now + 86400n,
                };
            },
            'Lifetime exceeds the 24-hour profile maximum',
            'overlong KeyPackage lifetime is rejected',
        );
    }

    // Imported historical KeyPackage leaves keep the bounded PinChat
    // Lifetime profile, but are not required to remain current forever.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await addAndJoin(alice, bob);
        const bobLeaf = alice.ratchetTree[2].leaf;
        const now = BigInt(Math.floor(Date.now() / 1000));
        bobLeaf.lifetime = {
            notBefore: now - 1n,
            notAfter: now + 86400n,
        };
        bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
            bob.identity.signaturePrivateKey, bobLeaf,
        );

        const carol = await buildKeyPackage();
        const result = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
        await expectJoinReject(
            await joinArguments(alice, result, carol),
            'Lifetime exceeds the 24-hour profile maximum',
            'overlong historical KeyPackage Lifetime is rejected on import',
        );
    }

    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await addAndJoin(alice, bob);
        const bobLeaf = alice.ratchetTree[2].leaf;
        const now = BigInt(Math.floor(Date.now() / 1000));
        bobLeaf.lifetime = {
            notBefore: now - 100n,
            notAfter: now - 1n,
        };
        bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
            bob.identity.signaturePrivateKey, bobLeaf,
        );

        const carol = await buildKeyPackage();
        const result = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
        const joined = await joinFrom(alice, result, carol);
        assert(
            joined.epoch === alice.epoch,
            'expired historical KeyPackage Lifetime remains valid on tree import',
        );
    }

    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        await addAndJoin(alice, bob);
        const bobLeaf = alice.ratchetTree[2].leaf;
        const now = BigInt(Math.floor(Date.now() / 1000));
        bobLeaf.lifetime = {
            notBefore: now + 100n,
            notAfter: now + 200n,
        };
        bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
            bob.identity.signaturePrivateKey, bobLeaf,
        );

        const carol = await buildKeyPackage();
        const result = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
        await expectJoinReject(
            await joinArguments(alice, result, carol),
            'Lifetime not yet valid',
            'future-dated historical KeyPackage Lifetime is rejected on import',
        );
    }

    // A malicious creator can bypass its local KeyPackage gate. Existing
    // members must independently reject the same fully authenticated Add
    // before advancing any epoch or candidate-tree state.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);
        const carol = await buildKeyPackage();
        const validAdd = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
        carol.keyPackage.initKey = Uint8Array.from(
            carol.keyPackage.leafNode.encryptionKey,
        );
        await resignKeyPackage(carol);
        const invalidAdd = await rewriteCommitProposalList(
            validAdd.commitMessage,
            [inlineProposal({
                proposalType: Proposal.ProposalType.ADD,
                keyPackage: carol.keyPackage,
            })],
            alice.identity,
            bobGroup,
        );
        const before = captureGroupState(bobGroup);
        await expectReject(
            bobGroup.processCommit(invalidAdd),
            'init_key must differ from LeafNode encryption_key',
            'processCommit rejects authenticated Add with a reused HPKE key',
        );
        assert(groupStateMatches(bobGroup, before),
            'malformed Add rejection leaves recipient state byte-for-byte unchanged');
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
        const result = await alice.commitAddMember({
            keyPackageBytes: carol.keyPackageBytes,
        });
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
        const result = await maliciousCommitAddWithoutFinalTreeGate(
            alice, carol.keyPackageBytes,
        );
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

        const result = await maliciousCommitAddWithoutFinalTreeGate(
            alice, carol.keyPackageBytes,
        );
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
        const proposed = await bobGroup.proposeUpdate();
        const { pendingLeafKeyPair } = proposed;
        const authenticatedProposal = await alice.verifyUpdateProposal(
            proposed.proposalMessage,
        );
        const update = await alice.commitUpdate({
            updateProposals: [authenticatedProposal],
        });
        await bobGroup.processCommit(update.commitMessage, {
            pendingSelfUpdate: pendingLeafKeyPair,
            proposalStore: proposalStore(proposed),
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
        // byte-for-byte copy of Bob's existing leaf key. An honest committer
        // must now reject it before hashing a candidate tree or mutating any
        // live epoch state.
        const dave = await buildKeyPackage();
        await replaceKeyPackageLeafEncryptionKey(
            dave, bob.leaf.encryptionKey,
        );
        const aliceBeforeCollision = captureGroupState(alice);
        await expectReject(
            alice.commitAddMember({ keyPackageBytes: dave.keyPackageBytes }),
            'duplicate encryption_key',
            'creator rejects Add with duplicate leaf encryption_key',
        );
        assert(groupStateMatches(alice, aliceBeforeCollision),
            'rejected colliding Add leaves creator state byte-for-byte unchanged');

        const erin = await buildKeyPackage();
        await replaceKeyPackageLeafSignatureIdentity(erin, alice.identity);
        const aliceBeforeSignatureCollision = captureGroupState(alice);
        await expectReject(
            alice.commitAddMember({ keyPackageBytes: erin.keyPackageBytes }),
            'duplicate signature_key',
            'creator rejects Add with duplicate leaf signature_key',
        );
        assert(groupStateMatches(alice, aliceBeforeSignatureCollision),
            'signature-colliding Add also leaves creator state unchanged');

        // A group member is adversarial and can run a modified client which
        // removes its own guard. Model that explicitly so processCommit's
        // independent receiver-side gate remains covered as well.
        const collidingAdd = await maliciousCommitAddWithoutFinalTreeGate(
            alice, dave.keyPackageBytes,
        );
        const bobEpochBefore = bobGroup.epoch;
        await expectReject(
            bobGroup.processCommit(collidingAdd.commitMessage),
            'duplicate encryption_key',
            'processCommit rejects Add with duplicate leaf encryption_key',
        );
        assert(bobGroup.epoch === bobEpochBefore,
            'rejected colliding Add does not advance recipient epoch');
    }

    // ---- Commit proposal-list validation and phased application ---------
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);
        const proposed = await bobGroup.proposeUpdate();
        const updateEntry = await alice.verifyUpdateProposal(
            proposed.proposalMessage,
        );
        const updateProposal = updateEntry.proposal;

        const aliceBeforeDuplicate = captureGroupState(alice);
        await expectReject(
            alice.commitUpdate({ updateProposals: [updateEntry, updateEntry] }),
            'duplicate ProposalRef',
            'creator rejects duplicate Update proposals for one leaf',
        );
        assert(groupStateMatches(alice, aliceBeforeDuplicate),
            'duplicate Update rejection leaves creator state unchanged');

        // A valid Commit supplies an authenticated outer frame and path. We
        // then let a malicious creator replace its proposal vector and
        // re-authenticate the frame, so these are processCommit rejections,
        // not parser-only tests.
        const validUpdate = await alice.commitUpdate({
            updateProposals: [updateEntry],
        });
        const invalidConfirmationCommit = await tamperCommitConfirmationTag(
            validUpdate.commitMessage, bobGroup,
        );
        const bobBeforeInvalidConfirmation = captureGroupState(bobGroup);
        await expectReject(
            bobGroup.processCommit(invalidConfirmationCommit, {
                pendingSelfUpdate: proposed.pendingLeafKeyPair,
                proposalStore: proposalStore(proposed),
            }),
            'confirmation_tag mismatch',
            'referenced self-Update with invalid confirmation tag is rejected',
        );
        assert(groupStateMatches(bobGroup, bobBeforeInvalidConfirmation),
            'failed self-Update confirmation leaves private key and epoch state unchanged');

        const duplicateUpdateCommit = await rewriteCommitProposalList(
            validUpdate.commitMessage,
            [referencedProposal(updateEntry), referencedProposal(updateEntry)],
            alice.identity,
            bobGroup,
        );
        const bobBeforeDuplicate = captureGroupState(bobGroup);
        await expectReject(
            bobGroup.processCommit(duplicateUpdateCommit, {
                proposalStore: proposalStore(proposed),
            }),
            'duplicate ProposalRef',
            'processCommit rejects authenticated duplicate Update proposals',
        );
        assert(groupStateMatches(bobGroup, bobBeforeDuplicate),
            'duplicate Update rejection leaves recipient state unchanged');

        const removeBob = {
            proposalType: Proposal.ProposalType.REMOVE,
            removed: 1,
        };
        const updateAndRemoveCommit = await rewriteCommitProposalList(
            validUpdate.commitMessage,
            [referencedProposal(updateEntry), inlineProposal(removeBob)],
            alice.identity,
            bobGroup,
        );
        const bobBeforeConflict = captureGroupState(bobGroup);
        await expectReject(
            bobGroup.processCommit(updateAndRemoveCommit, {
                proposalStore: proposalStore(proposed),
            }),
            'multiple Update and/or Remove proposals target leaf 1',
            'processCommit rejects Update+Remove conflict on one leaf',
        );
        assert(groupStateMatches(bobGroup, bobBeforeConflict),
            'Update+Remove rejection leaves recipient state unchanged');

        // The RFC constrains application phases, not the vector's wire order.
        // An Add before an Update on the wire is accepted by the validator,
        // while the returned plan places the Update phase first.
        const carol = await buildKeyPackage();
        const interleavedPlan = bobGroup._validateCommitProposalList([
            inlineProposal({
                proposalType: Proposal.ProposalType.ADD,
                keyPackage: carol.keyPackage,
            }),
            resolvedProposalReference(updateEntry),
        ], 0, 'testProposalOrder');
        assert(interleavedPlan.updates.length === 1
            && interleavedPlan.updates[0].wireIndex === 1
            && interleavedPlan.adds.length === 1
            && interleavedPlan.adds[0].wireIndex === 0,
            'wire-interleaved proposals produce Update-before-Add application phases');
    }

    // Duplicate Removes are also rejected globally before candidate state or
    // path processing, including when the authenticated Commit targets some
    // other member than the recipient.
    {
        const alice = await Group.Group.create({ identity: await freshIdentity() });
        const bob = await buildKeyPackage();
        const { joined: bobGroup } = await addAndJoin(alice, bob);
        const carol = await buildKeyPackage();
        await addAndJoin(alice, carol, [bobGroup]);

        const validRemove = await alice.commitRemoveMember({ removedLeafIndex: 2 });
        const removeCarol = {
            proposalType: Proposal.ProposalType.REMOVE,
            removed: 2,
        };
        const duplicateRemoveCommit = await rewriteCommitProposalList(
            validRemove.commitMessage,
            [inlineProposal(removeCarol), inlineProposal(removeCarol)],
            alice.identity,
            bobGroup,
        );
        const bobBeforeRemove = captureGroupState(bobGroup);
        await expectReject(
            bobGroup.processCommit(duplicateRemoveCommit),
            'multiple Update and/or Remove proposals target leaf 2',
            'processCommit rejects authenticated duplicate Remove proposals',
        );
        assert(groupStateMatches(bobGroup, bobBeforeRemove),
            'duplicate Remove rejection leaves recipient state unchanged');
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
