/**
 * PinChat MLS — stateful Group orchestrator (RFC 9420 §§8, 12, 6.3).
 *
 * This module ties together the bottom-layer primitives into a
 * member-facing API:
 *
 *   Group.create({ identity, groupId? })                 → Group
 *   Group.joinFromEpochState(state)                       → Group
 *   group.encryptApplicationMessage(plaintext)            → MLSMessage bytes
 *   group.decryptApplicationMessage(mlsMessageBytes)      → plaintext
 *
 * Scope
 * -----
 * This commit lands the *steady-state* part: creating a 1-leaf group,
 * ingesting an externally-built state, and encrypting / decrypting
 * application messages against the current epoch. The Add+Commit+Welcome
 * flow (which advances the epoch) is implemented in a follow-up — it
 * needs UpdatePath encryption cryptography that is substantial enough
 * to keep separate.
 *
 * State
 * -----
 *   cipherSuite         : locked to 0x0002
 *   groupId             : opaque<V>
 *   epoch               : uint64
 *   ratchetTree         : padded array<optional<Node>>  (nodeWidth(nLeaves))
 *   nLeaves             : current number of leaves
 *   myLeafIndex         : our leaf position
 *   identity            : { signaturePrivateKey, signaturePublicKeyBytes }
 *   leafKeyPair         : our leaf's HPKE init keypair (from the
 *                         KeyPackage we published — used for Welcome
 *                         decryption; not rotated per message)
 *   senderRatchetGeneration
 *                       : next app-message generation to send, per
 *                         "application" chain
 *   epochSecrets        : { encryptionSecret, senderDataSecret,
 *                           membershipKey, confirmationKey,
 *                           initSecret, epochAuthenticator, ... }
 *   groupContext        : serialized bytes for signature domain
 *                         separation (recomputed on every epoch change)
 *   interimTranscriptHash
 *
 * Random sources
 * --------------
 * All "random" inputs (group_id default, reuse_guard, etc.) flow from
 * WebCrypto's crypto.getRandomValues — the same CSPRNG the 1:1
 * protocol already relies on.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./hpke.js'),
            require('./signature.js'),
            require('./nodes.js'),
            require('./ratchet-tree.js'),
            require('./tree-math.js'),
            require('./tree-hash.js'),
            require('./group-context.js'),
            require('./key-schedule.js'),
            require('./framing.js'),
            require('./private-message.js'),
            require('./mls-message.js'),
            require('./public-message.js'),
            require('./labeled.js'),
            require('./key-package.js'),
            require('./proposal.js'),
            require('./commit.js'),
            require('./tree-kem.js'),
            require('./welcome.js'),
            require('./group-info.js'),
            require('./transcript-hashes.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Group = factory(
            root.MLS.Codec, root.MLS.HPKE, root.MLS.Signature,
            root.MLS.Nodes, root.MLS.RatchetTree, root.MLS.TreeMath,
            root.MLS.TreeHash, root.MLS.GroupContext, root.MLS.KeySchedule,
            root.MLS.Framing, root.MLS.PrivateMessage, root.MLS.MLSMessage,
            root.MLS.PublicMessage, root.MLS.Labeled,
            root.MLS.KeyPackage, root.MLS.Proposal, root.MLS.Commit,
            root.MLS.TreeKEM, root.MLS.Welcome, root.MLS.GroupInfo,
            root.MLS.TranscriptHashes,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (
    Codec, HPKE, Signature, Nodes, RatchetTree, TreeMath,
    TreeHash, GroupContext, KeySchedule, Framing, PrivateMessage,
    MLSMessage, PublicMessage, Labeled,
    KeyPackage, Proposal, Commit, TreeKEM, Welcome, GroupInfo,
    TranscriptHashes,
) {
    'use strict';

    const PROTOCOL_VERSION = 0x0001;
    const CIPHERSUITE = 0x0002;

    function getCrypto() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto) return globalThis.crypto;
        // eslint-disable-next-line global-require
        return require('crypto').webcrypto;
    }

    function randomBytes(n) {
        const out = new Uint8Array(n);
        getCrypto().getRandomValues(out);
        return out;
    }

    // --- Group class ------------------------------------------------------

    class Group {
        constructor(state) {
            Object.assign(this, state);
        }

        // ------------------------------------------------------------------
        // Creation: fresh 1-leaf group with the caller as sole member.
        // ------------------------------------------------------------------

        /**
         * Create a fresh group with the caller as leaf 0. Inputs:
         *   identity : { signaturePrivateKey, signaturePublicKeyBytes }
         *   groupId? : 32 bytes (fresh if omitted)
         *   credentialIdentity? : Uint8Array identity blob for the
         *                         Credential(basic) field (defaults to
         *                         signaturePublicKeyBytes)
         */
        static async create({ identity, groupId, credentialIdentity }) {
            const gid = groupId || randomBytes(32);
            const encKeyPair = await HPKE.generateKeyPair();

            const leaf = buildSelfLeaf({
                encryptionKeyBytes: encKeyPair.publicKeyBytes,
                signatureKeyBytes: identity.signaturePublicKeyBytes,
                credentialIdentity: credentialIdentity || identity.signaturePublicKeyBytes,
                leafNodeSource: Nodes.LeafNodeSource.KEY_PACKAGE,
            });
            leaf.signature = await signLeafNodeForKeyPackage(
                identity.signaturePrivateKey, leaf,
            );

            const ratchetTree = [{ nodeType: Nodes.NodeType.LEAF, leaf }];
            const nLeaves = 1;
            const treeHashBytes = await TreeHash.hashRoot(ratchetTree);
            const initSecret = randomBytes(HPKE.Nh);

            const state = {
                cipherSuite: CIPHERSUITE,
                groupId: gid,
                epoch: 0n,
                ratchetTree,
                nLeaves,
                myLeafIndex: 0,
                identity,
                leafKeyPair: encKeyPair,
                senderRatchetGeneration: 0,
                interimTranscriptHash: new Uint8Array(0),
                confirmedTranscriptHash: new Uint8Array(0),
                treeHash: treeHashBytes,
            };
            const group = new Group(state);

            // Derive epoch 0 secrets. commit_secret and psk_secret are
            // zero for the initial epoch; init_secret_[-1] is freshly
            // random as §12.3 prescribes.
            await group._deriveEpoch({
                initSecretPrev: initSecret,
                commitSecret: new Uint8Array(HPKE.Nh),
                pskSecret: new Uint8Array(HPKE.Nh),
            });
            return group;
        }

        /**
         * Ingest an externally-constructed group state (testing + future
         * Welcome path). Inputs must already be a complete, consistent
         * state object. This is the escape hatch that lets tests build
         * two synchronised members without going through a full
         * Commit+Welcome round-trip.
         */
        static fromState(state) {
            return new Group(state);
        }

        // ------------------------------------------------------------------
        // Key-schedule + GroupContext helpers.
        // ------------------------------------------------------------------

        async _recomputeTreeHash() {
            this.treeHash = await TreeHash.hashRoot(this.ratchetTree);
        }

        _buildGroupContextStruct() {
            return {
                version: PROTOCOL_VERSION,
                cipherSuite: this.cipherSuite,
                groupId: this.groupId,
                epoch: this.epoch,
                treeHash: this.treeHash,
                confirmedTranscriptHash: this.confirmedTranscriptHash,
                extensions: [],
            };
        }

        _groupContextBytes() {
            return GroupContext.groupContextBytes(this._buildGroupContextStruct());
        }

        async _deriveEpoch({ initSecretPrev, commitSecret, pskSecret }) {
            const groupContextBytes = this._groupContextBytes();
            const out = await KeySchedule.deriveEpoch({
                initSecretPrev,
                commitSecret,
                pskSecret,
                groupContext: groupContextBytes,
            });
            this.epochSecrets = out;
        }

        // ------------------------------------------------------------------
        // Application message encryption / decryption.
        // ------------------------------------------------------------------

        /**
         * Encrypt a plaintext application message into a full MLSMessage
         * (mls_private_message) ready for the server relay.
         *
         * Payload is signed with our leaf's signature_key under the
         * GroupContext; sender_data carries (leaf_index, generation,
         * reuse_guard) AEAD-encrypted under sender_data_secret.
         */
        async encryptApplicationMessage(plaintext) {
            if (this.myLeafIndex === undefined || this.myLeafIndex === null) {
                throw new Error('group: observer cannot send application messages');
            }
            const wireFormat = MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE;
            const generation = this.senderRatchetGeneration;
            this.senderRatchetGeneration += 1;

            const content = {
                groupId: this.groupId,
                epoch: this.epoch,
                sender: { senderType: Framing.SenderType.MEMBER, leafIndex: this.myLeafIndex },
                authenticatedData: new Uint8Array(0),
                contentType: Framing.ContentType.APPLICATION,
                payload: plaintext instanceof Uint8Array
                    ? plaintext
                    : new TextEncoder().encode(String(plaintext)),
            };

            const signature = await PublicMessage.signFramedContent(
                this.identity.signaturePrivateKey,
                wireFormat, content, this._buildGroupContextStruct(),
            );
            const auth = { signature };

            const senderData = {
                leafIndex: this.myLeafIndex,
                generation,
                reuseGuard: randomBytes(4),
            };

            const pm = await PrivateMessage.encryptPrivateMessage({
                groupId: this.groupId,
                epoch: this.epoch,
                contentType: Framing.ContentType.APPLICATION,
                authenticatedData: new Uint8Array(0),
                payloadBytes: content.payload,
                auth,
                senderData,
                paddingLen: 0,
                senderDataSecret: this.epochSecrets.senderDataSecret,
                encryptionSecret: this.epochSecrets.encryptionSecret,
                nLeaves: this.nLeaves,
            });
            const pmBytes = PrivateMessage.privateMessageBytes(pm);
            return MLSMessage.serializeMLSMessage(wireFormat, pmBytes);
        }

        /**
         * Decrypt an incoming MLSMessage(mls_private_message) carrying an
         * application payload. Verifies the sender's signature against
         * their LeafNode's signature_key, rejects wrong-epoch or
         * non-application messages.
         */
        async decryptApplicationMessage(mlsMessageBytes) {
            const frame = MLSMessage.parseMLSMessage(mlsMessageBytes);
            if (frame.wireFormat !== MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE) {
                throw new Error(`group: expected mls_private_message, got ${frame.wireFormat}`);
            }
            const pm = PrivateMessage.parsePrivateMessage(frame.body);
            if (pm.contentType !== Framing.ContentType.APPLICATION) {
                throw new Error(`group: expected application content, got ${pm.contentType}`);
            }
            if (pm.epoch !== this.epoch) {
                throw new Error(`group: wrong epoch (got ${pm.epoch}, expected ${this.epoch})`);
            }

            const out = await PrivateMessage.decryptPrivateMessage({
                pm,
                senderDataSecret: this.epochSecrets.senderDataSecret,
                encryptionSecret: this.epochSecrets.encryptionSecret,
                nLeaves: this.nLeaves,
            });

            const senderLeafIndex = out.senderData.leafIndex;
            const senderLeaf = RatchetTree.leafFor(this.ratchetTree, senderLeafIndex);
            if (!senderLeaf) {
                throw new Error(`group: unknown sender leaf_index ${senderLeafIndex}`);
            }

            const sigPub = await Signature.importPublicKey(senderLeaf.signatureKey);
            const content = {
                groupId: pm.groupId,
                epoch: pm.epoch,
                sender: { senderType: Framing.SenderType.MEMBER, leafIndex: senderLeafIndex },
                authenticatedData: pm.authenticatedData,
                contentType: pm.contentType,
                payload: out.content.payloadBytes,
            };
            const sigOk = await PublicMessage.verifyFramedContent(
                sigPub,
                MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE,
                content,
                this._buildGroupContextStruct(),
                out.content.auth.signature,
            );
            if (!sigOk) {
                throw new Error('group: application message signature invalid');
            }

            return out.content.payloadBytes;
        }
    }

    // ------------------------------------------------------------------
    // Add/Commit/Welcome flow — scoped to 2-leaf groups.
    //
    // The committer (existing member, leaf 0) invokes
    //   alice.commitAddMember({ keyPackageBytes }) → { commitMessage,
    //                                                 welcomeMessage }
    // New member invokes
    //   Group.joinFromWelcome({ welcomeMessage, keyPackageBytes,
    //                           initPrivateKey, identity })
    // to enter epoch 1 with Alice.
    //
    // Scope limit: this implementation handles committer == leaf 0 and
    // adds the new member at leaf 1 (tree width 1 → 3). For deeper
    // trees the filtered direct path / copath resolution logic
    // generalises cleanly — just not in this commit.
    // ------------------------------------------------------------------

    Group.prototype.commitAddMember = async function commitAddMember({ keyPackageBytes }) {
        if (this.myLeafIndex !== 0 || this.nLeaves !== 1) {
            throw new Error('group: commitAddMember is 2-leaf-only (MVP scope)');
        }
        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
        if (kp.cipherSuite !== CIPHERSUITE) {
            throw new Error(`group: KeyPackage cipher_suite mismatch (got ${kp.cipherSuite})`);
        }
        const newLeafIndex = 1;

        // ---- 1. Generate committer's new leaf_secret and path chain ----
        //
        // The path secrets chain walks from the committer's leaf up to
        // the root. For a 2-leaf tree the committer's direct path (with
        // root) is just [root=1], so there's exactly one chain entry.
        const leafSecret = randomBytes(HPKE.Nh);
        const leafNodePair = await TreeKEM.leafKeyPairFromSecret(leafSecret, this.myLeafIndex);
        const chain = await TreeKEM.pathSecretChain(leafSecret, this.myLeafIndex, 2);
        // chain.length === 1 for 2-leaf tree; root entry.
        if (chain.length !== 1) {
            throw new Error(`group: expected chain.length === 1 for 2-leaf, got ${chain.length}`);
        }
        const rootEntry = chain[0];

        // ---- 2. Build provisional ratchet tree + new GroupContext ----
        //
        // After applying: leaves 0 (Alice updated) and 1 (Bob new),
        // parent node 1 (encryption_key derived from rootEntry).
        const bobLeaf = kp.leafNode;
        const aliceNewLeafPreSign = buildSelfLeaf({
            encryptionKeyBytes: leafNodePair.keyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.COMMIT,
        });
        // For commit-source leaves, parent_hash binds the new leaf to
        // the freshly-computed root. We use an empty parent_hash for
        // this MVP: full parent-hash chaining lands with §7.9 later.
        aliceNewLeafPreSign.parentHash = new Uint8Array(0);

        // Sign the committer's updated LeafNode. §7.4.2 mandates the
        // LeafNodeTBS for commit-source leaves include the group_id and
        // leaf_index after the LeafNode fields — we honour that.
        aliceNewLeafPreSign.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey,
            aliceNewLeafPreSign,
            this.groupId,
            this.myLeafIndex,
        );

        // Replace Alice's leaf, blank her direct-path parents, and add
        // Bob at leaf 1. Build new parent node at index 1 (the root
        // for 2-leaf trees).
        const newTree = [
            { nodeType: Nodes.NodeType.LEAF, leaf: aliceNewLeafPreSign },
            {
                nodeType: Nodes.NodeType.PARENT,
                parent: {
                    encryptionKey: rootEntry.keyPair.publicKeyBytes,
                    parentHash: new Uint8Array(0),
                    unmergedLeaves: [],
                },
            },
            { nodeType: Nodes.NodeType.LEAF, leaf: bobLeaf },
        ];
        const newTreeHash = await TreeHash.hashRoot(newTree);

        const newEpoch = this.epoch + 1n;
        const provisionalGroupContext = {
            version: PROTOCOL_VERSION,
            cipherSuite: CIPHERSUITE,
            groupId: this.groupId,
            epoch: newEpoch,
            treeHash: newTreeHash,
            confirmedTranscriptHash: this.confirmedTranscriptHash,
            extensions: [],
        };
        const provisionalGroupContextBytes =
            GroupContext.groupContextBytes(provisionalGroupContext);

        // ---- 3. Encrypt path_secret[root] to Bob via EncryptWithLabel ----
        const { kemOutput, ciphertext } = await Labeled.encryptWithLabel(
            bobLeaf.encryptionKey,
            'UpdatePathNode',
            provisionalGroupContextBytes,
            rootEntry.pathSecret,
        );

        const updatePathNode = {
            encryptionKey: rootEntry.keyPair.publicKeyBytes,
            encryptedPathSecret: [{ kemOutput, ciphertext }],
        };
        const updatePath = {
            leafNode: aliceNewLeafPreSign,
            nodes: [updatePathNode],
        };

        // ---- 4. Build Commit struct: Add proposal + UpdatePath ----
        const addProposal = { proposalType: Proposal.ProposalType.ADD, keyPackage: kp };
        const commitStruct = {
            proposals: [{
                type: Proposal.ProposalOrRefType.PROPOSAL,
                proposal: addProposal,
            }],
            path: updatePath,
        };
        const commitBodyBytes = Commit.commitBytes(commitStruct);

        // ---- 5. FramedContent(commit) + signature ----
        const content = {
            groupId: this.groupId,
            epoch: this.epoch,  // signed under OLD group_context
            sender: { senderType: Framing.SenderType.MEMBER, leafIndex: this.myLeafIndex },
            authenticatedData: new Uint8Array(0),
            contentType: Framing.ContentType.COMMIT,
            payload: commitBodyBytes,
        };
        const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
        const signature = await PublicMessage.signFramedContent(
            this.identity.signaturePrivateKey,
            wireFormat, content, this._buildGroupContextStruct(),
        );

        // ---- 6. Advance transcripts + derive new epoch secrets ----
        //
        // ConfirmedTranscriptHashInput = serialize(wire_format ||
        //                     FramedContent || opaque<V>(signature))
        const cthInput = new Codec.Encoder();
        cthInput.writeU16(wireFormat);
        Framing.writeFramedContent(cthInput, content);
        cthInput.writeOpaque(signature);
        const newConfirmedTranscriptHash = await TranscriptHashes.confirmedTranscriptHash(
            this.interimTranscriptHash, cthInput.bytes(),
        );

        const epochGroupContext = {
            ...provisionalGroupContext,
            confirmedTranscriptHash: newConfirmedTranscriptHash,
        };
        const epochGroupContextBytes = GroupContext.groupContextBytes(epochGroupContext);

        const epochSecrets = await KeySchedule.deriveEpoch({
            initSecretPrev: this.epochSecrets.initSecret,
            commitSecret: await TreeKEM.commitSecret(rootEntry.pathSecret),
            pskSecret: new Uint8Array(HPKE.Nh),
            groupContext: epochGroupContextBytes,
        });

        const confirmationTag = await TranscriptHashes.confirmationTag(
            epochSecrets.confirmationKey, newConfirmedTranscriptHash,
        );
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            newConfirmedTranscriptHash, confirmationTag,
        );

        const auth = { signature, confirmationTag };

        // ---- 7. PublicMessage with membership_tag ----
        const pmGroupContext = {
            ...epochGroupContext,
            confirmedTranscriptHash: newConfirmedTranscriptHash,
        };
        const membershipTag = await PublicMessage.computeMembershipTag(
            epochSecrets.membershipKey, wireFormat, content, auth, this._buildGroupContextStruct(),
        );
        const pm = {
            content, auth, membershipTag,
        };
        const pmBytes = PublicMessage.publicMessageBytes(pm);
        const commitMessage = MLSMessage.serializeMLSMessage(wireFormat, pmBytes);

        // ---- 8. Build GroupInfo + AES-GCM encrypt for Welcome ----
        const groupInfoPreSign = {
            groupContext: epochGroupContext,
            extensions: [],
            confirmationTag,
            signer: this.myLeafIndex,
            signature: new Uint8Array(0),
        };
        const giTbs = GroupInfo.groupInfoTbsBytes(groupInfoPreSign);
        const giSignature = await Labeled.signWithLabel(
            this.identity.signaturePrivateKey, 'GroupInfoTBS', giTbs,
        );
        const groupInfo = { ...groupInfoPreSign, signature: giSignature };
        const giBytes = GroupInfo.groupInfoBytes(groupInfo);

        const welcomeSecret = await Welcome.deriveWelcomeSecret(
            epochSecrets.joinerSecret, new Uint8Array(HPKE.Nh),
        );
        const { key: wKey, nonce: wNonce } = await Welcome.welcomeKeyNonce(welcomeSecret);
        const encryptedGroupInfo = await Welcome.sealEncryptedGroupInfo(wKey, wNonce, giBytes);

        // ---- 9. Encrypt GroupSecrets for Bob ----
        // path_secret for Bob is the path_secret at the LCA of Alice's
        // leaf (0) and Bob's leaf (2). For a 2-leaf tree, LCA = root
        // (node 1), so path_secret is rootEntry.pathSecret.
        const groupSecrets = {
            joinerSecret: epochSecrets.joinerSecret,
            pathSecret: rootEntry.pathSecret,
            psks: [],
        };
        const gsBytes = Welcome.groupSecretsBytes(groupSecrets);
        const ref = await KeyPackage.keyPackageRef(keyPackageBytes);
        const { kemOutput: gsKem, ciphertext: gsCt } = await Labeled.encryptWithLabel(
            kp.initKey, 'Welcome', encryptedGroupInfo, gsBytes,
        );
        const welcomeStruct = {
            cipherSuite: CIPHERSUITE,
            secrets: [{
                newMember: ref,
                encryptedGroupSecrets: { kemOutput: gsKem, ciphertext: gsCt },
            }],
            encryptedGroupInfo,
        };
        const welcomeBytes = Welcome.welcomeBytes(welcomeStruct);
        const welcomeMessage = MLSMessage.serializeMLSMessage(
            MLSMessage.WireFormat.MLS_WELCOME, welcomeBytes,
        );

        // ---- 10. Apply commit to our own state ----
        this.ratchetTree = newTree;
        this.nLeaves = 2;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = epochSecrets;
        this.senderRatchetGeneration = 0;
        this.leafKeyPair = {
            privateKey: leafNodePair.keyPair.privateKey,
            publicKey: leafNodePair.keyPair.publicKey,
            publicKeyBytes: leafNodePair.keyPair.publicKeyBytes,
        };

        return { commitMessage, welcomeMessage };
    };

    /**
     * Process a Welcome and join the group as the new member. Inputs:
     *   welcomeMessage    : MLSMessage bytes (wire_format = mls_welcome)
     *   keyPackageBytes   : our published KeyPackage's serialised bytes
     *   initPrivateKey    : ECDH CryptoKey matching keyPackage.init_key
     *   identity          : our signature identity (as in Group.create)
     *   leafEncKeyPair    : the full HPKE keypair for the leaf (the
     *                       init_key from the KeyPackage; we reuse it as
     *                       the leaf's encryption_key until we rotate).
     *
     * Scope limit: assumes exactly one new member (ourselves) and a
     * 2-leaf resulting tree. Leaf_index == 1.
     */
    Group.joinFromWelcome = async function joinFromWelcome({
        welcomeMessage, keyPackageBytes, initPrivateKey, identity, leafEncKeyPair,
    }) {
        const frame = MLSMessage.parseMLSMessage(welcomeMessage);
        if (frame.wireFormat !== MLSMessage.WireFormat.MLS_WELCOME) {
            throw new Error(`group.join: expected mls_welcome, got ${frame.wireFormat}`);
        }
        const welcome = Welcome.parseWelcome(frame.body);
        if (welcome.cipherSuite !== CIPHERSUITE) {
            throw new Error(`group.join: cipher_suite mismatch (got ${welcome.cipherSuite})`);
        }

        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
        const myRef = await KeyPackage.keyPackageRef(keyPackageBytes);
        const entry = welcome.secrets.find((s) => {
            if (s.newMember.length !== myRef.length) return false;
            for (let i = 0; i < myRef.length; i += 1) {
                if (s.newMember[i] !== myRef[i]) return false;
            }
            return true;
        });
        if (!entry) throw new Error('group.join: no EncryptedGroupSecrets for our KeyPackage');

        // Decrypt GroupSecrets.
        const gs = await Welcome.decryptGroupSecrets(
            entry.encryptedGroupSecrets, initPrivateKey, kp.initKey, welcome.encryptedGroupInfo,
        );
        if (!gs.pathSecret) {
            throw new Error('group.join: no path_secret in GroupSecrets (MVP assumes Add+path)');
        }

        // Derive welcome_secret → welcome_key/nonce → decrypt GroupInfo.
        const welcomeSecret = await Welcome.deriveWelcomeSecret(
            gs.joinerSecret, new Uint8Array(HPKE.Nh),
        );
        const { key: wKey, nonce: wNonce } = await Welcome.welcomeKeyNonce(welcomeSecret);
        const giBytes = await Welcome.openEncryptedGroupInfo(wKey, wNonce, welcome.encryptedGroupInfo);
        const groupInfo = GroupInfo.parseGroupInfo(giBytes);

        // Verify GroupInfo signature with the signer's signature_key. The
        // signer is a leaf index; we need their LeafNode. Since our MVP
        // assumes a 2-leaf tree with the signer at leaf 0, we'll locate
        // them after reconstructing the tree below.
        //
        // Reconstruct the ratchet tree. MVP: we synthesise the 2-leaf
        // shape (signer at leaf 0, new member at leaf 1). A full
        // implementation would load the ratchet_tree extension.
        const signerLeafIndex = groupInfo.signer;
        if (signerLeafIndex !== 0) {
            throw new Error('group.join: MVP scope — signer must be leaf 0');
        }

        // The committer's LeafNode is not directly in GroupInfo; we
        // recover it by decrypting the path_secret and walking from
        // the LCA down. But for tree-hash + sig-verify we also need
        // the signer's LeafNode up front.
        //
        // For a 2-leaf group, a dedicated ratchet_tree extension (or
        // side-channel) carries the full tree. Our MVP wire contract:
        // the caller can fetch it from the server relay. Here we
        // require callers to supply it so the joiner can validate
        // against groupInfo.group_context.tree_hash.

        throw new Error(
            'group.join: MVP requires out-of-band ratchet_tree bytes; '
            + 'call Group.joinFromWelcomeWithTree(...) instead.'
        );
    };

    /**
     * Variant that takes the ratchet_tree explicitly (serialised via
     * Nodes.ratchetTreeBytes). Committer should ship it alongside the
     * Welcome for now, until the `ratchet_tree` GroupInfo extension
     * path lands.
     */
    Group.joinFromWelcomeWithTree = async function joinFromWelcomeWithTree({
        welcomeMessage, keyPackageBytes, initPrivateKey, identity,
        leafEncKeyPair, ratchetTreeBytes,
    }) {
        const frame = MLSMessage.parseMLSMessage(welcomeMessage);
        const welcome = Welcome.parseWelcome(frame.body);

        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
        const myRef = await KeyPackage.keyPackageRef(keyPackageBytes);
        const entry = welcome.secrets.find((s) =>
            s.newMember.length === myRef.length
            && s.newMember.every((b, i) => b === myRef[i])
        );
        if (!entry) throw new Error('group.join: no EncryptedGroupSecrets for our KeyPackage');

        const gs = await Welcome.decryptGroupSecrets(
            entry.encryptedGroupSecrets, initPrivateKey, kp.initKey, welcome.encryptedGroupInfo,
        );
        const welcomeSecret = await Welcome.deriveWelcomeSecret(
            gs.joinerSecret, new Uint8Array(HPKE.Nh),
        );
        const { key: wKey, nonce: wNonce } = await Welcome.welcomeKeyNonce(welcomeSecret);
        const giBytes = await Welcome.openEncryptedGroupInfo(wKey, wNonce, welcome.encryptedGroupInfo);
        const groupInfo = GroupInfo.parseGroupInfo(giBytes);

        const parsedTree = Nodes.parseRatchetTree(ratchetTreeBytes);
        const tree = Nodes.padRatchetTree(parsedTree, 3); // 2-leaf width
        const nLeaves = 2;

        // Verify GroupInfo signature with the signer's signature_key.
        const signerLeaf = RatchetTree.leafFor(tree, groupInfo.signer);
        if (!signerLeaf) throw new Error('group.join: signer leaf not present');
        const signerSigPub = await Signature.importPublicKey(signerLeaf.signatureKey);
        const sigOk = await Labeled.verifyWithLabel(
            signerSigPub, 'GroupInfoTBS',
            GroupInfo.groupInfoTbsBytes(groupInfo),
            groupInfo.signature,
        );
        if (!sigOk) throw new Error('group.join: GroupInfo signature invalid');

        // Verify tree_hash matches what the GroupInfo claims.
        const computedTreeHash = await TreeHash.hashRoot(tree);
        if (computedTreeHash.length !== groupInfo.groupContext.treeHash.length
            || !computedTreeHash.every((b, i) => b === groupInfo.groupContext.treeHash[i])) {
            throw new Error('group.join: tree_hash mismatch');
        }

        // Derive epoch secrets using gs.joinerSecret as the joiner_secret.
        // We bypass the full deriveEpoch path because GroupSecrets
        // already carries joiner_secret; the derivation just splits it
        // into welcome/epoch + downstream secrets.
        const memberSecret = await HPKE.hkdfExtract(
            gs.joinerSecret, new Uint8Array(HPKE.Nh),
        );
        const epochSecretRaw = await KeySchedule.expandWithLabel(
            memberSecret, 'epoch',
            GroupContext.groupContextBytes(groupInfo.groupContext),
            HPKE.Nh,
        );
        const senderDataSecret = await KeySchedule.deriveSecret(epochSecretRaw, 'sender data');
        const encryptionSecret = await KeySchedule.deriveSecret(epochSecretRaw, 'encryption');
        const exporterSecret = await KeySchedule.deriveSecret(epochSecretRaw, 'exporter');
        const externalSecret = await KeySchedule.deriveSecret(epochSecretRaw, 'external');
        const confirmationKey = await KeySchedule.deriveSecret(epochSecretRaw, 'confirm');
        const membershipKey = await KeySchedule.deriveSecret(epochSecretRaw, 'membership');
        const resumptionPsk = await KeySchedule.deriveSecret(epochSecretRaw, 'resumption');
        const epochAuthenticator = await KeySchedule.deriveSecret(epochSecretRaw, 'authentication');
        const initSecret = await KeySchedule.deriveSecret(epochSecretRaw, 'init');

        const epochSecrets = {
            joinerSecret: gs.joinerSecret,
            welcomeSecret,
            epochSecret: epochSecretRaw,
            senderDataSecret,
            encryptionSecret,
            exporterSecret,
            externalSecret,
            confirmationKey,
            membershipKey,
            resumptionPsk,
            epochAuthenticator,
            initSecret,
        };

        // Verify confirmation_tag against confirmed_transcript_hash.
        const expectedConfTag = await TranscriptHashes.confirmationTag(
            confirmationKey, groupInfo.groupContext.confirmedTranscriptHash,
        );
        if (expectedConfTag.length !== groupInfo.confirmationTag.length
            || !expectedConfTag.every((b, i) => b === groupInfo.confirmationTag[i])) {
            throw new Error('group.join: confirmation_tag mismatch');
        }

        const state = {
            cipherSuite: CIPHERSUITE,
            groupId: groupInfo.groupContext.groupId,
            epoch: groupInfo.groupContext.epoch,
            ratchetTree: tree,
            nLeaves,
            myLeafIndex: 1, // MVP scope
            identity,
            leafKeyPair: leafEncKeyPair,
            senderRatchetGeneration: 0,
            interimTranscriptHash: await TranscriptHashes.interimTranscriptHash(
                groupInfo.groupContext.confirmedTranscriptHash, expectedConfTag,
            ),
            confirmedTranscriptHash: groupInfo.groupContext.confirmedTranscriptHash,
            treeHash: groupInfo.groupContext.treeHash,
            epochSecrets,
        };
        return new Group(state);
    };

    // --- Internal helpers ------------------------------------------------

    function buildSelfLeaf({ encryptionKeyBytes, signatureKeyBytes, credentialIdentity, leafNodeSource }) {
        return {
            encryptionKey: encryptionKeyBytes,
            signatureKey: signatureKeyBytes,
            credential: {
                credentialType: Nodes.CredentialType.BASIC,
                identity: credentialIdentity,
            },
            capabilities: {
                versions: [PROTOCOL_VERSION],
                cipherSuites: [CIPHERSUITE],
                extensions: [],
                proposals: [],
                credentials: [Nodes.CredentialType.BASIC],
            },
            leafNodeSource,
            // KEY_PACKAGE variant needs a Lifetime; the in-tree group
            // operations don't pin an absolute clock, so we advertise
            // a window of ± ~34 years around epoch zero (i.e. "always
            // valid"). Ephemeral rooms enforce lifetime via TTL at the
            // relay, not via Lifetime.
            lifetime: leafNodeSource === Nodes.LeafNodeSource.KEY_PACKAGE
                ? { notBefore: 0n, notAfter: 0xffffffffffffffffn }
                : undefined,
            extensions: [],
            signature: new Uint8Array(0),
        };
    }

    async function signLeafNodeForKeyPackage(signaturePrivateKey, leaf) {
        const tbs = Nodes.leafNodeTbsBytes(leaf);
        return Labeled.signWithLabel(signaturePrivateKey, 'LeafNodeTBS', tbs);
    }

    /**
     * LeafNodeTBS for commit-source leaves includes group_id and
     * leaf_index after the LeafNode prefix (RFC 9420 §7.4.2).
     */
    async function signLeafNodeInCommit(signaturePrivateKey, leaf, groupId, leafIndex) {
        const encoder = new Codec.Encoder();
        Nodes.writeLeafNodeTbs(encoder, leaf);
        encoder.writeOpaque(groupId);
        encoder.writeU32(leafIndex);
        return Labeled.signWithLabel(signaturePrivateKey, 'LeafNodeTBS', encoder.bytes());
    }

    return Object.freeze({
        Group,
        PROTOCOL_VERSION,
        CIPHERSUITE,
        // Exposed for tests / future add-member path
        buildSelfLeaf,
        signLeafNodeForKeyPackage,
        signLeafNodeInCommit,
    });
});
