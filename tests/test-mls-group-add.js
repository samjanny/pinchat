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

    console.log('');
    console.log(`group-add: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
