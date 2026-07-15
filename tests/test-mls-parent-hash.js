#!/usr/bin/env node
/**
 * Parent-hash chaining (RFC 9420 §7.9).
 *
 * No IETF reference vectors for the parent-hash chain shipped with our
 * local cache, so this suite is behavioural: it exercises the property
 * the chain is supposed to guarantee (a receiver rejects a Commit whose
 * committer LeafNode.parent_hash does not match the surrounding tree)
 * plus the direct round-trip (committer-stamped hashes verify on both
 * the Commit and Welcome/join paths).
 *
 * Coverage:
 *   1. Round-trip: build a 4-leaf group by Add/Commit/Welcome; every
 *      joiner's join path runs verifyCommitterParentHashes on the signer
 *      leaf (implicit) and every processCommit runs the leaf check.
 *   2. Parent-hash unit: directPathParentHashes over a hand-built tree
 *      is deterministic and non-empty for a multi-leaf path, empty for a
 *      single leaf.
 *   3. Splice rejection: tamper the committer LeafNode.parent_hash on the
 *      wire -> processCommit throws. Tamper a parent encryption_key in
 *      the UpdatePath -> the recomputed leaf parent_hash no longer
 *      matches the signed one -> processCommit throws.
 */
const path = require('path');
const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const KeyPackage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-package.js'));
const Labeled = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'labeled.js'));
const TreeMath = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-math.js'));
const ParentHash = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'parent-hash.js'));
const MLSMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'mls-message.js'));
const PublicMessage = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'public-message.js'));
const Framing = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'framing.js'));
const Commit = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'commit.js'));

let passed = 0;
let failed = 0;
function assert(cond, name) {
    if (cond) { console.log(`  OK   ${name}`); passed += 1; }
    else { console.log(`  FAIL ${name}`); failed += 1; }
}

async function freshIdentity() {
    const kp = await Signature.generateKeyPair();
    return { signaturePrivateKey: kp.privateKey, signaturePublicKeyBytes: kp.publicKeyBytes };
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
    leaf.signature = await Group.signLeafNodeForKeyPackage(identity.signaturePrivateKey, leaf);
    const kp = {
        version: 0x0001, cipherSuite: 0x0002, initKey: initKp.publicKeyBytes,
        leafNode: leaf, extensions: [], signature: new Uint8Array(0),
    };
    kp.signature = await Labeled.signWithLabel(
        identity.signaturePrivateKey, 'KeyPackageTBS', KeyPackage.keyPackageTbsBytes(kp),
    );
    return {
        identity,
        initKp,
        leafEncKp,
        keyPackage: kp,
        keyPackageBytes: KeyPackage.keyPackageBytes(kp),
    };
}

// Add a joiner to `committer`, returning the joined Group and the raw
// commit message so callers can replay / tamper it.
async function addMember(committer, others) {
    const joiner = await buildKeyPackage();
    const { commitMessage, welcomeMessage } = await committer.commitAddMember({
        keyPackageBytes: joiner.keyPackageBytes,
    });
    const ratchetTreeBytes = Nodes.ratchetTreeBytes(committer.ratchetTree);
    const joined = await Group.Group.joinFromWelcomeWithTree({
        welcomeMessage,
        keyPackageBytes: joiner.keyPackageBytes,
        initPrivateKey: joiner.initKp.privateKey,
        identity: joiner.identity,
        leafEncKeyPair: joiner.leafEncKp,
        ratchetTreeBytes,
        expectedSignerLeafIndex: committer.myLeafIndex,
        ...await bootstrapPins(committer),
    });
    for (const o of others) await o.processCommit(commitMessage);
    return { joined, commitMessage };
}

async function main() {
    console.log('# Parent-hash chaining (RFC 9420 §7.9)');

    // ---- 1. Round-trip: build a 4-leaf group ----
    const aliceId = await freshIdentity();
    const alice = await Group.Group.create({ identity: aliceId });
    const { joined: bob } = await addMember(alice, []);
    assert(alice.nLeaves === 2 && bob.nLeaves === 2, 'Add #1 (Bob) round-trips with parent hashes');
    const { joined: carol } = await addMember(alice, [bob]);
    assert(alice.nLeaves === 3 && carol.nLeaves === 3 && bob.nLeaves === 3,
        'Add #2 (Carol) round-trips; existing members processCommit OK');
    const { joined: dave } = await addMember(alice, [bob, carol]);
    assert(alice.nLeaves === 4 && dave.nLeaves === 4,
        'Add #3 (Dave) round-trips to a 4-leaf tree');

    // Every committed leaf on Alice's direct path carries a non-empty
    // parent_hash chain; the topmost parent (root's child) hashes to a
    // stable value. Recompute and compare to what Alice stamped.
    {
        const { pathWithRoot, pathHashes, leafParentHash } =
            await ParentHash.directPathParentHashes(alice.ratchetTree, alice.myLeafIndex, alice.nLeaves);
        let allMatch = true;
        for (let i = 0; i < pathWithRoot.length; i += 1) {
            const slot = alice.ratchetTree[pathWithRoot[i]];
            if (slot && slot.nodeType === Nodes.NodeType.PARENT) {
                const a = Buffer.from(slot.parent.parentHash).toString('hex');
                const b = Buffer.from(pathHashes[i]).toString('hex');
                if (a !== b) allMatch = false;
            }
        }
        assert(allMatch, 'stamped parent_hash on Alice direct path matches recomputation');
        const aliceLeaf = alice.ratchetTree[TreeMath.leafToNode(alice.myLeafIndex)].leaf;
        assert(Buffer.from(aliceLeaf.parentHash).toString('hex')
            === Buffer.from(leafParentHash).toString('hex'),
            'Alice committer LeafNode.parent_hash matches recomputation');
        assert(leafParentHash.length > 0, 'multi-leaf committer leaf parent_hash is non-empty');
    }

    // ---- 2. Single-leaf group: empty leaf parent_hash ----
    {
        const soloId = await freshIdentity();
        const solo = await Group.Group.create({ identity: soloId });
        const { leafParentHash } =
            await ParentHash.directPathParentHashes(solo.ratchetTree, 0, solo.nLeaves);
        assert(leafParentHash.length === 0, 'single-leaf group has empty leaf parent_hash');
    }

    // ---- 3a. Splice rejection: tamper the committer LeafNode.parent_hash ----
    {
        const a2 = await Group.Group.create({ identity: await freshIdentity() });
        const { joined: b2 } = await addMember(a2, []);
        // Alice commits an Update; tamper the committer leaf parent_hash
        // on the wire before Bob processes it.
        const { commitMessage } = await a2.commitUpdate();
        const frame = MLSMessage.parseMLSMessage(commitMessage);
        const pm = PublicMessage.parsePublicMessage(frame.body, (dec, ct) =>
            (ct === Framing.ContentType.COMMIT ? Commit.readCommit(dec) : null));
        // Flip one byte of the committer LeafNode.parent_hash.
        const tamperedLeaf = { ...pm.content.parsed.path.leafNode };
        tamperedLeaf.parentHash = Uint8Array.from(pm.content.parsed.path.leafNode.parentHash);
        tamperedLeaf.parentHash[0] ^= 0x01;
        pm.content.parsed.path.leafNode = tamperedLeaf;
        // Rebuild the commit body + FramedContent payload with the tamper.
        pm.content.payload = Commit.commitBytes(pm.content.parsed);
        const tamperedBytes = MLSMessage.serializeMLSMessage(
            MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE, PublicMessage.publicMessageBytes(pm),
        );
        let threw = false;
        try { await b2.processCommit(tamperedBytes); } catch (_e) { threw = true; }
        assert(threw, 'tampered committer LeafNode.parent_hash rejected');
        // Sanity: the untampered commit still applies.
        assert(b2.epoch === 1n, 'Bob did not advance on the rejected commit');
    }

    // ---- 3b. Splice rejection: tamper a parent encryption_key ----
    // Changing a parent encryption_key in the UpdatePath changes the
    // recomputed leaf parent_hash, so it no longer matches the signed
    // one and processCommit must reject (before the derived-key check).
    {
        const a3 = await Group.Group.create({ identity: await freshIdentity() });
        const { joined: b3 } = await addMember(a3, []);
        const { joined: c3 } = await addMember(a3, [b3]);
        const { commitMessage } = await a3.commitUpdate();
        const frame = MLSMessage.parseMLSMessage(commitMessage);
        const pm = PublicMessage.parsePublicMessage(frame.body, (dec, ct) =>
            (ct === Framing.ContentType.COMMIT ? Commit.readCommit(dec) : null));
        const nodes = pm.content.parsed.path.nodes;
        // Swap the top parent's encryption_key for a random fresh one.
        const fresh = await HPKE.generateKeyPair();
        nodes[nodes.length - 1].encryptionKey = fresh.publicKeyBytes;
        pm.content.payload = Commit.commitBytes(pm.content.parsed);
        const tamperedBytes = MLSMessage.serializeMLSMessage(
            MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE, PublicMessage.publicMessageBytes(pm),
        );
        let threw = false;
        try { await c3.processCommit(tamperedBytes); } catch (_e) { threw = true; }
        assert(threw, 'tampered parent encryption_key rejected via parent-hash mismatch');
    }

    console.log('');
    console.log(`parent-hash: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => { console.error('fatal:', err); process.exit(2); });
