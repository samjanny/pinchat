#!/usr/bin/env node

/**
 * PinChat MLS ECDSA signature profile.
 *
 * A mathematically equivalent high-S ECDSA signature is re-authenticated
 * with a valid membership_tag and delivered through Group.processCommit().
 * The Commit must be rejected at the FramedContent signature boundary, the
 * recipient state must remain unchanged, and the original low-S Commit must
 * remain usable afterwards.
 */

const path = require('path');
const { webcrypto } = require('crypto');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));

const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

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

function bytesTag(bytes) {
    return Buffer.from(bytes || []).toString('base64url');
}

function bytesToBigInt(bytes) {
    let value = 0n;
    for (const byte of bytes) value = (value << 8n) | BigInt(byte);
    return value;
}

function bigIntToFixed(value, length) {
    const out = new Uint8Array(length);
    let remaining = value;
    for (let i = length - 1; i >= 0; i -= 1) {
        out[i] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }
    if (remaining !== 0n) throw new Error('test scalar overflow');
    return out;
}

// Independent canonical DER encoder that deliberately preserves high-S.
function rawToDerPreservingS(raw) {
    function integer(bytes) {
        let start = 0;
        while (start < bytes.length - 1 && bytes[start] === 0) start += 1;
        const value = bytes.subarray(start);
        const padded = (value[0] & 0x80) !== 0;
        const out = new Uint8Array(2 + value.length + (padded ? 1 : 0));
        out[0] = 0x02;
        out[1] = out.length - 2;
        out.set(value, padded ? 3 : 2);
        return out;
    }
    const r = integer(raw.subarray(0, 32));
    const s = integer(raw.subarray(32));
    const out = new Uint8Array(2 + r.length + s.length);
    out[0] = 0x30;
    out[1] = out.length - 2;
    out.set(r, 2);
    out.set(s, 2 + r.length);
    return out;
}

function captureGroupState(group) {
    return {
        bytes: JSON.stringify({
            epoch: group.epoch.toString(),
            nLeaves: group.nLeaves,
            tree: bytesTag(Nodes.ratchetTreeBytes(group.ratchetTree)),
            treeHash: bytesTag(group.treeHash),
            confirmedTranscriptHash: bytesTag(group.confirmedTranscriptHash),
            interimTranscriptHash: bytesTag(group.interimTranscriptHash),
            senderRatchetGeneration: group.senderRatchetGeneration,
            epochSecrets: Object.fromEntries(Object.entries(group.epochSecrets)
                .map(([name, value]) => [name, bytesTag(value)])),
        }),
        leafPrivateKey: group.leafKeyPair.privateKey,
        leafPublicKey: group.leafKeyPair.publicKey,
        parentKeyPairs: group.parentKeyPairs,
        chainStates: group._chainStates,
        consumedByLeaf: group.consumedByLeaf,
        previousEpoch: group._prevEpoch,
    };
}

function groupStateMatches(group, before) {
    const after = captureGroupState(group);
    return after.bytes === before.bytes
        && after.leafPrivateKey === before.leafPrivateKey
        && after.leafPublicKey === before.leafPublicKey
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

async function addAndJoin(creator, joiner) {
    const result = await creator.commitAddMember({
        keyPackageBytes: joiner.keyPackageBytes,
    });
    return Group.Group.joinFromWelcomeWithTree({
        welcomeMessage: result.welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKeyPair.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafKeyPair,
        ratchetTreeBytes: Nodes.ratchetTreeBytes(creator.ratchetTree),
        expectedSignerLeafIndex: 0,
        expectedGroupId: Uint8Array.from(creator.groupId),
        expectedCreatorKeyHash: await Labeled.sha256(
            creator.ratchetTree[0].leaf.signatureKey,
        ),
    });
}

function parseCommitMessage(commitMessage) {
    const frame = MLSMessage.parseMLSMessage(commitMessage);
    const publicMessage = PublicMessage.parsePublicMessage(
        frame.body,
        (decoder, contentType) => {
            if (contentType !== Framing.ContentType.COMMIT) {
                throw new Error(`test: expected Commit, got ${contentType}`);
            }
            return Commit.readCommit(decoder);
        },
    );
    return { frame, publicMessage };
}

async function main() {
    console.log('# MLS canonical low-S signature enforcement');

    const lifecycleKeyPair = await Signature.generateKeyPair();
    assert(lifecycleKeyPair.privateKey.extractable === false,
        'generated signature private key is non-extractable');
    assert(lifecycleKeyPair.publicKey.extractable === true,
        'generated signature public key remains exportable');
    let privateExportRejected = false;
    try {
        await webcrypto.subtle.exportKey('jwk', lifecycleKeyPair.privateKey);
    } catch (_err) {
        privateExportRejected = true;
    }
    assert(privateExportRejected,
        'WebCrypto rejects export of generated signature private key');

    const alice = await Group.Group.create({ identity: await freshIdentity() });
    const bob = await addAndJoin(alice, await buildKeyPackage());
    const { commitMessage } = await alice.commitUpdate();
    const { frame, publicMessage } = parseCommitMessage(commitMessage);

    const lowRaw = Signature.derToRaw(publicMessage.auth.signature);
    const lowS = bytesToBigInt(lowRaw.subarray(32));
    const highRaw = Uint8Array.from(lowRaw);
    highRaw.set(bigIntToFixed(P256_ORDER - lowS, 32), 32);
    const highDer = rawToDerPreservingS(highRaw);

    const groupContext = bob._buildGroupContextStruct();
    const framedContentTbs = PublicMessage.framedContentTbsBytes(
        frame.wireFormat, publicMessage.content, groupContext,
    );
    const signedContent = Labeled.signContentBytes(
        'FramedContentTBS', framedContentTbs,
    );
    const creatorPublicKey = await Signature.importPublicKey(
        bob.ratchetTree[0].leaf.signatureKey,
    );
    const mathematicallyValid = await webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        creatorPublicKey,
        highRaw,
        signedContent,
    );
    assert(mathematicallyValid,
        'high-S Commit signature is mathematically valid ECDSA');

    publicMessage.auth.signature = highDer;
    publicMessage.membershipTag = await PublicMessage.computeMembershipTag(
        bob.epochSecrets.membershipKey,
        frame.wireFormat,
        publicMessage.content,
        publicMessage.auth,
        groupContext,
    );
    const highSCommit = MLSMessage.serializeMLSMessage(
        frame.wireFormat,
        PublicMessage.publicMessageBytes(publicMessage),
    );

    const before = captureGroupState(bob);
    let rejection = '';
    try {
        await bob.processCommit(highSCommit);
    } catch (err) {
        rejection = err.message;
    }
    assert(rejection.includes('FramedContent signature invalid'),
        'processCommit rejects authenticated canonical high-S signature',
        rejection || 'did not reject');
    assert(groupStateMatches(bob, before),
        'high-S rejection leaves recipient state byte-for-byte unchanged');

    await bob.processCommit(commitMessage);
    assert(bob.epoch === alice.epoch,
        'original low-S Commit remains usable after rejection');
    assert(bytesTag(bob.epochSecrets.epochAuthenticator)
        === bytesTag(alice.epochSecrets.epochAuthenticator),
    'original low-S Commit converges recipient state');

    console.log('');
    console.log(`mls-signature-canonical: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
