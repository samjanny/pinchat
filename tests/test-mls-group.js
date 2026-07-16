#!/usr/bin/env node

/**
 * MLS Group orchestrator — steady-state application message flow.
 *
 * This commit lands Group.create + encrypt/decrypt but not yet the
 * Add/Commit/Welcome epoch-transition path, so two-member tests need to
 * *synthesise* a shared state between Alice and Bob. We do that by:
 *
 *   1. Alice calls Group.create() as leaf 0.
 *   2. We synthetically add Bob's LeafNode at index 1 in Alice's
 *      ratchet tree (skipping UpdatePath cryptography), then derive the
 *      epoch-0 secrets one more time so Alice is aware of the 2-leaf
 *      shape.
 *   3. Bob gets the same state via Group.fromState() — this mirrors
 *      what a Welcome would give him once the Add/Commit/Welcome flow
 *      lands. The init_secret used for derivation has to match on both
 *      sides, so we capture Alice's and reuse it for Bob.
 *
 * Then:
 *   - Alice encrypts an application message; Bob decrypts it.
 *   - Bob encrypts a reply; Alice decrypts it.
 *   - Alice encrypts several messages in sequence; Bob decrypts them in
 *     order (the per-sender generation chain advances monotonically).
 *   - A tampered ciphertext must fail authentication.
 *
 * This covers everything in group.js except the epoch-transition path.
 */

const path = require('path');

const Group = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'group.js'));
const Signature = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'signature.js'));
const HPKE = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'hpke.js'));
const Nodes = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'nodes.js'));
const TreeHash = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'tree-hash.js'));
const KeySchedule = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'key-schedule.js'));

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

function hex(u8) { return Buffer.from(u8).toString('hex'); }

function receiveStateSnapshot(group) {
    const chains = [...group._chainStates.entries()]
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
    const consumed = [...group.consumedByLeaf.entries()]
        .sort(([a], [b]) => a - b)
        .map(([leafIndex, generations]) => [
            leafIndex, [...generations].sort((a, b) => a - b),
        ]);
    return JSON.stringify({ chains, consumed });
}

async function freshIdentity() {
    const kp = await Signature.generateKeyPair();
    return {
        signaturePrivateKey: kp.privateKey,
        signaturePublicKeyBytes: kp.publicKeyBytes,
    };
}

async function buildSynthetic2LeafGroup() {
    // Alice creates a 1-leaf group.
    const aliceId = await freshIdentity();
    const bobId = await freshIdentity();
    const bobEncKp = await HPKE.generateKeyPair();

    const initialAlice = await Group.Group.create({ identity: aliceId });

    // Build Bob's LeafNode and insert it at node index 2 (leaf 1 in a
    // 2-leaf tree). We need a parent node at index 1 to make the tree
    // valid; we leave it blanked (null) which is fine for the secret-
    // tree ratchet and for tree_hash as long as both members agree.
    const bobLeaf = Group.buildSelfLeaf({
        encryptionKeyBytes: bobEncKp.publicKeyBytes,
        signatureKeyBytes: bobId.signaturePublicKeyBytes,
        credentialIdentity: bobId.signaturePublicKeyBytes,
        leafNodeSource: Nodes.LeafNodeSource.KEY_PACKAGE,
    });
    bobLeaf.signature = await Group.signLeafNodeForKeyPackage(
        bobId.signaturePrivateKey, bobLeaf,
    );

    // Grow Alice's tree: width goes from 1 → 3 (leaf 0, parent 1, leaf 2).
    initialAlice.ratchetTree = [
        initialAlice.ratchetTree[0], // leaf 0 — Alice
        null,                        // parent 1 — blank (would be set by Commit)
        { nodeType: Nodes.NodeType.LEAF, leaf: bobLeaf },
    ];
    initialAlice.nLeaves = 2;
    initialAlice.treeHash = await TreeHash.hashRoot(initialAlice.ratchetTree);

    // Re-derive epoch 0 with the new group_context (tree_hash changed).
    // init_secret, commit_secret, psk_secret are all zero here — the
    // point is just that Alice and Bob end up with identical epoch
    // secrets, so any shared-zero seed works.
    const initSecretSeed = new Uint8Array(HPKE.Nh);
    const epochOut = await KeySchedule.deriveEpoch({
        initSecretPrev: initSecretSeed,
        commitSecret: new Uint8Array(HPKE.Nh),
        pskSecret: new Uint8Array(HPKE.Nh),
        groupContext: initialAlice._groupContextBytes(),
    });

    const commonState = {
        cipherSuite: initialAlice.cipherSuite,
        groupId: initialAlice.groupId,
        epoch: initialAlice.epoch,
        ratchetTree: initialAlice.ratchetTree,
        nLeaves: initialAlice.nLeaves,
        interimTranscriptHash: initialAlice.interimTranscriptHash,
        confirmedTranscriptHash: initialAlice.confirmedTranscriptHash,
        treeHash: initialAlice.treeHash,
        epochSecrets: epochOut,
        pskSecret: initialAlice.pskSecret,
    };

    const alice = await Group.Group.fromState({
        ...commonState,
        myLeafIndex: 0,
        identity: aliceId,
        leafKeyPair: initialAlice.leafKeyPair,
        parentKeyPairs: initialAlice.parentKeyPairs,
        senderRatchetGeneration: 0,
    });

    // Bob gets the mirror state. Bob's view differs from Alice's in
    // identity / leafKeyPair / myLeafIndex / senderRatchetGeneration,
    // but shares ratchetTree + epochSecrets + groupId + epoch.
    const bob = await Group.Group.fromState({
        ...commonState,
        myLeafIndex: 1,
        identity: bobId,
        leafKeyPair: bobEncKp,
        parentKeyPairs: new Map(),
        senderRatchetGeneration: 0,
    });

    // fromState clones the schedule before consuming it, so explicitly
    // erase the raw fixture and the superseded one-leaf Group state too.
    for (const value of Object.values(epochOut)) {
        if (value instanceof Uint8Array) value.fill(0);
    }
    initialAlice.destroySecrets();

    return { alice, bob };
}

async function main() {
    console.log('# Group.create — single-leaf group basic sanity');
    {
        const identity = await freshIdentity();
        const group = await Group.Group.create({ identity });
        assert(group.nLeaves === 1, 'fresh group has 1 leaf');
        assert(group.myLeafIndex === 0, 'creator is leaf 0');
        assert(group.epoch === 0n, 'fresh group is at epoch 0');
        assert(group.groupId instanceof Uint8Array && group.groupId.length === 32,
            'groupId defaulted to 32 random bytes');
        assert(group.epochSecrets.epochAuthenticator.length === 32,
            'epoch 0 steady-state secrets derived');
        assert(
            ['joinerSecret', 'welcomeSecret', 'epochSecret',
                'encryptionSecret', 'confirmationKey']
                .every((name) => group.epochSecrets[name] === undefined),
            'one-shot epoch secrets are not retained',
        );
        assert(group._chainStates.size === 2
            && group._chainStates.has('0:application')
            && group._chainStates.has('0:handshake'),
        'SecretTree roots are pre-derived for the live leaf');
        // A single-member group can still encrypt to itself (loopback).
        // With the stateful forward-secret chains the SENDER consumes its
        // own generation at encrypt time, so self-decrypt on the same
        // instance is (correctly) rejected as a replay. Decrypt through a
        // state clone, which re-roots its own chains.
        const receiver = await Group.Group.fromState({ ...group });
        const consumedChainSecret = group._chainStates.get('0:application').secret;
        const ct = await group.encryptApplicationMessage('hello self');
        assert(ct instanceof Uint8Array && ct.length > 0, 'encrypt returns bytes');
        assert(consumedChainSecret.every((byte) => byte === 0)
            && group._chainStates.get('0:application').secret !== consumedChainSecret,
        'sending erases the superseded generation secret');
        const pt = (await receiver.decryptApplicationMessage(ct)).plaintext;
        assert(
            new TextDecoder().decode(pt) === 'hello self',
            'single-leaf loopback encrypt → decrypt'
        );
    }

    console.log('# Group — send ratchet advances only after encryption succeeds');
    {
        const { alice } = await buildSynthetic2LeafGroup();
        const before = receiveStateSnapshot(alice);
        const beforeGeneration = alice.senderRatchetGeneration;
        const senderDataSecret = alice.epochSecrets.senderDataSecret;
        alice.epochSecrets.senderDataSecret = {};
        let rejected = false;
        try {
            await alice.encryptApplicationMessage(
                'must not consume a generation',
            );
        } catch (_err) {
            rejected = true;
        } finally {
            alice.epochSecrets.senderDataSecret = senderDataSecret;
        }
        assert(rejected, 'post-ratchet sender-data encryption failure is rejected');
        assert(alice.senderRatchetGeneration === beforeGeneration
            && receiveStateSnapshot(alice) === before,
        'failed encryption leaves send ratchet byte-for-byte unchanged');
        const recovered = await alice.encryptApplicationMessage(
            'same generation remains usable',
        );
        assert(recovered instanceof Uint8Array
            && alice.senderRatchetGeneration === beforeGeneration + 1,
        'successful retry consumes the original generation exactly once');
    }

    console.log('# Group — Alice ↔ Bob application messages (synthesised 2-leaf)');
    {
        const { alice, bob } = await buildSynthetic2LeafGroup();

        assert(
            hex(alice.epochSecrets.epochAuthenticator)
                === hex(bob.epochSecrets.epochAuthenticator),
            'Alice and Bob share epoch_authenticator'
        );

        // Alice → Bob
        const m1 = 'hey bob from alice';
        const wire1 = await alice.encryptApplicationMessage(m1);
        const got1 = new TextDecoder().decode((await bob.decryptApplicationMessage(wire1)).plaintext);
        assert(got1 === m1, 'Alice → Bob message 0 decrypts');

        // Bob → Alice
        const m2 = 'hey alice from bob';
        const wire2 = await bob.encryptApplicationMessage(m2);
        const got2 = new TextDecoder().decode((await alice.decryptApplicationMessage(wire2)).plaintext);
        assert(got2 === m2, 'Bob → Alice message 0 decrypts');

        // Sequential messages — generation chain advances.
        const messages = ['one', 'two', 'three', 'four'];
        const wires = [];
        for (const m of messages) {
            wires.push(await alice.encryptApplicationMessage(m));
        }
        // All four must decrypt in order.
        for (let i = 0; i < wires.length; i += 1) {
            const pt = new TextDecoder().decode((await bob.decryptApplicationMessage(wires[i])).plaintext);
            assert(pt === messages[i], `sequential message ${i} decrypts`);
        }

        // Tamper with a ciphertext: must throw.
        const tampered = new Uint8Array(wire1);
        tampered[tampered.length - 5] ^= 0x01;
        let threw = false;
        try {
            await bob.decryptApplicationMessage(tampered);
        } catch (_e) {
            threw = true;
        }
        assert(threw, 'tampered ciphertext rejected');
    }

    console.log('# Group: forward-secret chains, out-of-order + replay + attribution');
    {
        const { alice, bob } = await buildSynthetic2LeafGroup();
        const w0 = await alice.encryptApplicationMessage('m0');
        const w1 = await alice.encryptApplicationMessage('m1');
        const w2 = await alice.encryptApplicationMessage('m2');

        // Deliver gen 2 first: bob's chain for alice's leaf jumps ahead,
        // caching single-use keys for generations 0 and 1.
        assert(new TextDecoder().decode((await bob.decryptApplicationMessage(w2)).plaintext) === 'm2',
            'out-of-order head (gen 2) decrypts');
        assert(new TextDecoder().decode((await bob.decryptApplicationMessage(w0)).plaintext) === 'm0',
            'late gen 0 decrypts from skipped-key cache');
        assert(new TextDecoder().decode((await bob.decryptApplicationMessage(w1)).plaintext) === 'm1',
            'late gen 1 decrypts from skipped-key cache');

        // Replays: cached keys are single-use and chain positions are
        // consumed, so every replay must be rejected.
        for (const [w, name] of [[w0, 'gen 0'], [w1, 'gen 1'], [w2, 'gen 2']]) {
            let threwReplay = false;
            try { await bob.decryptApplicationMessage(w); } catch (_e) { threwReplay = true; }
            assert(threwReplay, `replayed ${name} rejected (key deleted)`);
        }

        // The authenticated sender leaf is surfaced for E2E attribution.
        const w3 = await alice.encryptApplicationMessage('m3');
        const res3 = await bob.decryptApplicationMessage(w3);
        assert(res3.senderLeafIndex === alice.myLeafIndex,
            'decrypt surfaces the authenticated sender leaf index');
        assert(hex(res3.senderSignatureKey)
            === hex(alice.ratchetTree[0].leaf.signatureKey),
        'decrypt surfaces the exact signature key that authenticated the sender');
    }

    console.log('# Group: receive ratchet advances only after full authentication');
    {
        const { alice, bob } = await buildSynthetic2LeafGroup();
        const delayed0 = await alice.encryptApplicationMessage('delayed zero');
        const delayed1 = await alice.encryptApplicationMessage('delayed one');
        const valid = await alice.encryptApplicationMessage('valid generation two');
        const tampered = Uint8Array.from(valid);
        // The tail is within the encrypted content (well beyond the
        // sender-data sample), so sender_data and the generation key are
        // derived before content AEAD authentication rejects this frame.
        // Generation 2 also forces the tentative ratchet to derive and
        // cache generations 0 and 1; none of that staged work may leak into
        // the live state on failure.
        tampered[tampered.length - 5] ^= 0x01;

        const chainRef = bob._chainStates;
        const consumedRef = bob.consumedByLeaf;
        const before = receiveStateSnapshot(bob);
        let aeadRejected = false;
        try {
            await bob.decryptApplicationMessage(tampered);
        } catch (_err) {
            aeadRejected = true;
        }
        assert(aeadRejected, 'tampered content AEAD is rejected');
        assert(bob._chainStates === chainRef
            && bob.consumedByLeaf === consumedRef
            && receiveStateSnapshot(bob) === before,
        'AEAD failure leaves ratchet and replay state byte-for-byte unchanged');
        const recovered = await bob.decryptApplicationMessage(valid);
        assert(new TextDecoder().decode(recovered.plaintext) === 'valid generation two',
            'original jumped generation still decrypts after tampered ciphertext');
        assert(new TextDecoder().decode(
            (await bob.decryptApplicationMessage(delayed0)).plaintext,
        ) === 'delayed zero', 'rollback preserves later out-of-order generation 0');
        assert(new TextDecoder().decode(
            (await bob.decryptApplicationMessage(delayed1)).plaintext,
        ) === 'delayed one', 'rollback preserves later out-of-order generation 1');
    }
    {
        const { alice, bob } = await buildSynthetic2LeafGroup();
        // Create two independent send candidates at the same generation.
        // The malicious one has the epoch keys (so AEAD is valid) but signs
        // with a key that does not match leaf 0. The honest candidate must
        // remain decryptable after that inner-signature rejection.
        const maliciousAlice = alice.forkForPendingCommit();
        const wrongIdentity = await freshIdentity();
        maliciousAlice.identity = {
            ...maliciousAlice.identity,
            signaturePrivateKey: wrongIdentity.signaturePrivateKey,
        };
        const invalidSignature = await maliciousAlice.encryptApplicationMessage(
            'AEAD valid, signature invalid',
        );
        const valid = await alice.encryptApplicationMessage('valid after bad signature');

        const chainRef = bob._chainStates;
        const consumedRef = bob.consumedByLeaf;
        const before = receiveStateSnapshot(bob);
        let signatureRejected = false;
        let signatureError = '';
        try {
            await bob.decryptApplicationMessage(invalidSignature);
        } catch (err) {
            signatureRejected = true;
            signatureError = err.message;
        }
        assert(signatureRejected && signatureError.includes('signature invalid'),
            'AEAD-valid message with wrong FramedContent signature is rejected',
            signatureError);
        assert(bob._chainStates === chainRef
            && bob.consumedByLeaf === consumedRef
            && receiveStateSnapshot(bob) === before,
        'signature failure leaves ratchet and replay state byte-for-byte unchanged');
        const recovered = await bob.decryptApplicationMessage(valid);
        assert(new TextDecoder().decode(recovered.plaintext) === 'valid after bad signature',
            'same generation remains usable after signature rejection');
    }

    console.log('');
    console.log(`group: ${passed} passed, ${failed} failed`);
    process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
    console.error('fatal:', err);
    process.exit(2);
});
