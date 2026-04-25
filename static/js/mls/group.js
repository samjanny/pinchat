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

    function equalBytes(a, b) {
        if (!a || !b) return false;
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
        return diff === 0;
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
    // Add/Commit/Welcome flow — generic for N-leaf groups.
    //
    // The committer invokes
    //   alice.commitAddMember({ keyPackageBytes }) → { commitMessage,
    //                                                 welcomeMessage }
    // New member invokes
    //   Group.joinFromWelcomeWithTree({ welcomeMessage, ... })
    // to enter the next epoch.
    //
    // Existing members process the broadcast Commit via
    //   alice.processCommit(commitMessageBytes)
    // which decrypts the appropriate path_secret out of the UpdatePath,
    // walks it up to root, and advances the local epoch state.
    //
    // Tree growth: new members are always appended at the next free leaf
    // (newLeafIndex = nLeaves). The ratchet tree is padded to the new
    // node-width on each Add. Parent nodes that are NOT on the
    // committer's direct path stay blank — TreeKEM resolution recurses
    // through them automatically.
    //
    // Parent-hash chaining (§7.9) is intentionally skipped; commit-source
    // leaves carry an empty parent_hash byte string. Signatures still
    // verify because we encode and verify the same field consistently
    // on both sides. Adding stricter parent-hash validation is a
    // post-MVP hardening item.
    // ------------------------------------------------------------------

    Group.prototype.commitAddMember = async function commitAddMember({ keyPackageBytes }) {
        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
        if (kp.cipherSuite !== CIPHERSUITE) {
            throw new Error(`group: KeyPackage cipher_suite mismatch (got ${kp.cipherSuite})`);
        }

        // ---- 1. Compute new tree shape, insert new leaf ----
        const newLeafIndex = this.nLeaves;
        const newNLeaves = this.nLeaves + 1;
        const newWidth = TreeMath.nodeWidth(newNLeaves);
        const newTree = Nodes.padRatchetTree(this.ratchetTree, newWidth);
        newTree[TreeMath.leafToNode(newLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: kp.leafNode,
        };

        // ---- 2. Generate fresh leaf_secret + path-secret chain ----
        const leafSecret = randomBytes(HPKE.Nh);
        const leafNodePair = await TreeKEM.leafKeyPairFromSecret(leafSecret, this.myLeafIndex);
        const chain = await TreeKEM.pathSecretChain(leafSecret, this.myLeafIndex, newNLeaves);
        const committerDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(this.myLeafIndex), newNLeaves,
        );
        if (chain.length !== committerDirectPath.length) {
            throw new Error(
                `commitAddMember: chain length ${chain.length} != direct path ${committerDirectPath.length}`,
            );
        }

        // ---- 3. Build NEW committer leaf (commit-source) and place it ----
        const committerNewLeafPreSign = buildSelfLeaf({
            encryptionKeyBytes: leafNodePair.keyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.COMMIT,
        });
        committerNewLeafPreSign.parentHash = new Uint8Array(0);
        committerNewLeafPreSign.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey,
            committerNewLeafPreSign,
            this.groupId,
            this.myLeafIndex,
        );
        newTree[TreeMath.leafToNode(this.myLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: committerNewLeafPreSign,
        };

        // ---- 4. Set new parent encryption_keys on direct path ----
        // §5.3.1: intermediate nodes intersected by an UpdatePath have
        // empty unmerged_leaves.
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            newTree[committerDirectPath[i]] = {
                nodeType: Nodes.NodeType.PARENT,
                parent: {
                    encryptionKey: chain[i].keyPair.publicKeyBytes,
                    parentHash: new Uint8Array(0),
                    unmergedLeaves: [],
                },
            };
        }

        // ---- 5. Compute new tree hash + provisional GroupContext ----
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

        // ---- 6. Encrypt each path_secret to resolution(copath_sibling) ----
        // For each parent on the committer's direct path, encrypt that
        // parent's path_secret to every node in the resolution of the
        // copath sibling. The new member's leaf is excluded — they
        // receive their copy via the Welcome's group_secrets.path_secret
        // at the LCA between the committer and their leaf.
        const newLeafNodeIdx = TreeMath.leafToNode(newLeafIndex);
        const updatePathNodes = [];
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            const childOnPath = i === 0
                ? TreeMath.leafToNode(this.myLeafIndex)
                : committerDirectPath[i - 1];
            const copathSibling = TreeMath.sibling(childOnPath, newNLeaves);
            const res = RatchetTree.resolution(newTree, copathSibling);
            const filtered = res.filter((n) => n !== newLeafNodeIdx);
            const ciphertexts = [];
            for (const targetNode of filtered) {
                const targetSlot = newTree[targetNode];
                if (!targetSlot) {
                    throw new Error(`commitAddMember: resolution target ${targetNode} unexpectedly blank`);
                }
                const encKey = targetSlot.nodeType === Nodes.NodeType.LEAF
                    ? targetSlot.leaf.encryptionKey
                    : targetSlot.parent.encryptionKey;
                const { kemOutput, ciphertext } = await Labeled.encryptWithLabel(
                    encKey, 'UpdatePathNode',
                    provisionalGroupContextBytes, chain[i].pathSecret,
                );
                ciphertexts.push({ kemOutput, ciphertext });
            }
            updatePathNodes.push({
                encryptionKey: chain[i].keyPair.publicKeyBytes,
                encryptedPathSecret: ciphertexts,
            });
        }
        const updatePath = {
            leafNode: committerNewLeafPreSign,
            nodes: updatePathNodes,
        };

        // ---- 7. Commit struct: Add proposal + UpdatePath ----
        const addProposal = { proposalType: Proposal.ProposalType.ADD, keyPackage: kp };
        const commitStruct = {
            proposals: [{
                type: Proposal.ProposalOrRefType.PROPOSAL,
                proposal: addProposal,
            }],
            path: updatePath,
        };
        const commitBodyBytes = Commit.commitBytes(commitStruct);

        // ---- 8. FramedContent(commit) + signature (under OLD context) ----
        const content = {
            groupId: this.groupId,
            epoch: this.epoch,
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

        // ---- 9. Transcript hashes + new epoch secrets ----
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

        const rootChainEntry = chain[chain.length - 1];
        const epochSecrets = await KeySchedule.deriveEpoch({
            initSecretPrev: this.epochSecrets.initSecret,
            commitSecret: await TreeKEM.commitSecret(rootChainEntry.pathSecret),
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

        // ---- 10. PublicMessage with membership_tag (under OLD context) ----
        const membershipTag = await PublicMessage.computeMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, auth,
            this._buildGroupContextStruct(),
        );
        const pm = { content, auth, membershipTag };
        const pmBytes = PublicMessage.publicMessageBytes(pm);
        const commitMessage = MLSMessage.serializeMLSMessage(wireFormat, pmBytes);

        // ---- 11. GroupInfo + Welcome for the new member ----
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

        // The path_secret to ship in the Welcome is the chain entry at
        // the LCA of the committer and the new leaf — i.e. the lowest
        // direct-path entry whose subtree contains the new leaf.
        let lcaIndexForNewMember = -1;
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            const descendants = TreeMath.leafDescendants(
                committerDirectPath[i], newNLeaves,
            );
            if (descendants.includes(newLeafIndex)) {
                lcaIndexForNewMember = i;
                break;
            }
        }
        if (lcaIndexForNewMember === -1) {
            throw new Error('commitAddMember: cannot locate new member ancestor');
        }
        const groupSecrets = {
            joinerSecret: epochSecrets.joinerSecret,
            pathSecret: chain[lcaIndexForNewMember].pathSecret,
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

        // ---- 12. Apply commit to local state ----
        this.ratchetTree = newTree;
        this.nLeaves = newNLeaves;
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
        if (!this.parentKeyPairs) this.parentKeyPairs = new Map();
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            this.parentKeyPairs.set(committerDirectPath[i], chain[i].keyPair);
        }

        return { commitMessage, welcomeMessage };
    };

    /**
     * Process a Commit broadcast by another member. Inputs:
     *   commitMessageBytes : MLSMessage(mls_public_message) bytes
     *
     * Verifies the FramedContent signature + membership_tag, applies
     * Add proposals, walks the UpdatePath to recover our share of the
     * new path_secret chain, and advances the local epoch state.
     *
     * Scope:
     *   - Inline proposals only (Add). Proposal-by-reference (which
     *     would require a local proposal cache) is not implemented.
     *   - Single Add per commit. Multi-Add commits are accepted by the
     *     parser but only the last new leaf index is reported back —
     *     more than one would still apply correctly in tree terms but
     *     hasn't been verified end-to-end yet.
     */
    Group.prototype.processCommit = async function processCommit(commitMessageBytes) {
        const frame = MLSMessage.parseMLSMessage(commitMessageBytes);
        if (frame.wireFormat !== MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE) {
            throw new Error(`processCommit: expected mls_public_message, got ${frame.wireFormat}`);
        }
        const pm = PublicMessage.parsePublicMessage(frame.body, (decoder, ct) => {
            if (ct === Framing.ContentType.COMMIT) return Commit.readCommit(decoder);
            throw new Error(`processCommit: unexpected content_type ${ct}`);
        });
        const content = pm.content;
        if (content.contentType !== Framing.ContentType.COMMIT) {
            throw new Error(`processCommit: expected commit, got ${content.contentType}`);
        }
        if (content.epoch !== this.epoch) {
            throw new Error(`processCommit: wrong epoch (got ${content.epoch}, expected ${this.epoch})`);
        }
        if (content.sender.senderType !== Framing.SenderType.MEMBER) {
            throw new Error('processCommit: non-member sender not supported');
        }
        const senderLeafIndex = content.sender.leafIndex;
        if (senderLeafIndex === this.myLeafIndex) {
            throw new Error('processCommit: own commit echo (filter upstream)');
        }
        const senderLeaf = RatchetTree.leafFor(this.ratchetTree, senderLeafIndex);
        if (!senderLeaf) {
            throw new Error(`processCommit: unknown sender leaf ${senderLeafIndex}`);
        }

        const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
        const senderSigPub = await Signature.importPublicKey(senderLeaf.signatureKey);
        const sigOk = await PublicMessage.verifyFramedContent(
            senderSigPub, wireFormat, content,
            this._buildGroupContextStruct(), pm.auth.signature,
        );
        if (!sigOk) throw new Error('processCommit: FramedContent signature invalid');

        const membOk = await PublicMessage.verifyMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, pm.auth,
            this._buildGroupContextStruct(), pm.membershipTag,
        );
        if (!membOk) throw new Error('processCommit: membership_tag invalid');

        const commit = content.parsed;

        // ---- Apply Add proposals (insert new leaves) ----
        let newTree = this.ratchetTree.slice();
        let newNLeaves = this.nLeaves;
        let lastAddedLeafIndex = null;
        for (const por of commit.proposals) {
            if (por.type !== Proposal.ProposalOrRefType.PROPOSAL) {
                throw new Error('processCommit: proposal-by-reference not supported');
            }
            const proposal = por.proposal;
            if (proposal.proposalType !== Proposal.ProposalType.ADD) {
                throw new Error(`processCommit: unsupported proposal_type ${proposal.proposalType}`);
            }
            const addLeafIndex = newNLeaves;
            newNLeaves += 1;
            const newWidth = TreeMath.nodeWidth(newNLeaves);
            newTree = Nodes.padRatchetTree(newTree, newWidth);
            newTree[TreeMath.leafToNode(addLeafIndex)] = {
                nodeType: Nodes.NodeType.LEAF, leaf: proposal.keyPackage.leafNode,
            };
            lastAddedLeafIndex = addLeafIndex;
        }

        // ---- Apply UpdatePath ----
        const updatePath = commit.path;
        if (!updatePath) {
            throw new Error('processCommit: commit without path is not supported (Add+Path only)');
        }
        const committerDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(senderLeafIndex), newNLeaves,
        );
        if (updatePath.nodes.length !== committerDirectPath.length) {
            throw new Error(
                `processCommit: UpdatePath nodes ${updatePath.nodes.length} != direct path ${committerDirectPath.length}`,
            );
        }

        // Replace committer's leaf and stamp parent encryption_keys.
        newTree[TreeMath.leafToNode(senderLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: updatePath.leafNode,
        };
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            newTree[committerDirectPath[i]] = {
                nodeType: Nodes.NodeType.PARENT,
                parent: {
                    encryptionKey: updatePath.nodes[i].encryptionKey,
                    parentHash: new Uint8Array(0),
                    unmergedLeaves: [],
                },
            };
        }

        // Provisional group context for HPKE info string.
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

        // ---- Find LCA and decrypt our share of path_secret ----
        let lcaIdxInPath = -1;
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            const descendants = TreeMath.leafDescendants(
                committerDirectPath[i], newNLeaves,
            );
            if (descendants.includes(this.myLeafIndex)) {
                lcaIdxInPath = i;
                break;
            }
        }
        if (lcaIdxInPath === -1) {
            throw new Error(`processCommit: my leaf ${this.myLeafIndex} not under any committer ancestor`);
        }

        // Resolution of committer's copath sibling at the LCA level.
        const childOnPathAtLca = lcaIdxInPath === 0
            ? TreeMath.leafToNode(senderLeafIndex)
            : committerDirectPath[lcaIdxInPath - 1];
        const copathSibling = TreeMath.sibling(childOnPathAtLca, newNLeaves);
        const resolution = RatchetTree.resolution(newTree, copathSibling);
        const filtered = lastAddedLeafIndex !== null
            ? resolution.filter((n) => n !== TreeMath.leafToNode(lastAddedLeafIndex))
            : resolution;

        const myLeafNodeIdx = TreeMath.leafToNode(this.myLeafIndex);
        let myCtIndex = -1;
        let myPrivateKey = null;
        let myPublicKeyBytes = null;
        for (let j = 0; j < filtered.length; j += 1) {
            const n = filtered[j];
            if (n === myLeafNodeIdx) {
                myCtIndex = j;
                myPrivateKey = this.leafKeyPair.privateKey;
                myPublicKeyBytes = this.leafKeyPair.publicKeyBytes;
                break;
            }
            if (this.parentKeyPairs && this.parentKeyPairs.has(n)) {
                const pk = this.parentKeyPairs.get(n);
                myCtIndex = j;
                myPrivateKey = pk.privateKey;
                myPublicKeyBytes = pk.publicKeyBytes;
                break;
            }
        }
        if (myCtIndex === -1) {
            throw new Error(
                `processCommit: cannot locate my key in resolution at LCA index ${lcaIdxInPath}`,
            );
        }

        const ct = updatePath.nodes[lcaIdxInPath].encryptedPathSecret[myCtIndex];
        if (!ct) {
            throw new Error(
                `processCommit: missing ciphertext at index ${myCtIndex} for LCA node`,
            );
        }
        const lcaPathSecret = await Labeled.decryptWithLabel(
            myPrivateKey, myPublicKeyBytes, 'UpdatePathNode',
            provisionalGroupContextBytes, ct.kemOutput, ct.ciphertext,
        );

        // Walk path_secret from LCA up to root, deriving keypairs and
        // checking each against the encryption_key the committer
        // advertised. Track derived keypairs so we can decrypt later
        // commits from any committer whose copath sibling resolution
        // lands on one of these nodes.
        const newParentKeyPairs = new Map();
        let cur = lcaPathSecret;
        for (let i = lcaIdxInPath; i < committerDirectPath.length; i += 1) {
            if (i > lcaIdxInPath) {
                cur = await KeySchedule.deriveSecret(cur, 'path');
            }
            const nodeIdx = committerDirectPath[i];
            const nodeSecret = await KeySchedule.deriveSecret(cur, 'node');
            const kpDerived = await HPKE.deriveKeyPair(nodeSecret);
            const expectedPub = updatePath.nodes[i].encryptionKey;
            if (!equalBytes(kpDerived.publicKeyBytes, expectedPub)) {
                throw new Error(
                    `processCommit: derived public key mismatch at node ${nodeIdx} (i=${i})`,
                );
            }
            newParentKeyPairs.set(nodeIdx, kpDerived);
        }

        // commit_secret = DeriveSecret(path_secret_root, "path")
        const commitSecretBytes = await TreeKEM.commitSecret(cur);

        // ---- Transcript hashes + new epoch secrets ----
        const cthInput = new Codec.Encoder();
        cthInput.writeU16(wireFormat);
        Framing.writeFramedContent(cthInput, content);
        cthInput.writeOpaque(pm.auth.signature);
        const newConfirmedTranscriptHash = await TranscriptHashes.confirmedTranscriptHash(
            this.interimTranscriptHash, cthInput.bytes(),
        );
        const epochGroupContext = {
            ...provisionalGroupContext,
            confirmedTranscriptHash: newConfirmedTranscriptHash,
        };
        const epochGroupContextBytes = GroupContext.groupContextBytes(epochGroupContext);

        const newEpochSecrets = await KeySchedule.deriveEpoch({
            initSecretPrev: this.epochSecrets.initSecret,
            commitSecret: commitSecretBytes,
            pskSecret: new Uint8Array(HPKE.Nh),
            groupContext: epochGroupContextBytes,
        });

        const expectedConfTag = await TranscriptHashes.confirmationTag(
            newEpochSecrets.confirmationKey, newConfirmedTranscriptHash,
        );
        if (!equalBytes(expectedConfTag, pm.auth.confirmationTag)) {
            throw new Error('processCommit: confirmation_tag mismatch');
        }
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            newConfirmedTranscriptHash, expectedConfTag,
        );

        // ---- Commit the new state ----
        this.ratchetTree = newTree;
        this.nLeaves = newNLeaves;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = newEpochSecrets;
        this.senderRatchetGeneration = 0;
        if (!this.parentKeyPairs) this.parentKeyPairs = new Map();
        for (const [nodeIdx, pk] of newParentKeyPairs) {
            this.parentKeyPairs.set(nodeIdx, pk);
        }

        return {
            addedLeafIndex: lastAddedLeafIndex,
            committerLeafIndex: senderLeafIndex,
        };
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

        // Parse the ratchet tree. The committer always serialises with
        // node_width(nLeaves) entries (no trailing-blank truncation), so
        // the wire length tells us nLeaves directly.
        const parsedTree = Nodes.parseRatchetTree(ratchetTreeBytes);
        const nLeaves = TreeMath.numLeaves(parsedTree.length);
        const tree = Nodes.padRatchetTree(parsedTree, TreeMath.nodeWidth(nLeaves));

        // Locate our own leaf by matching the encryption_key against our
        // KeyPackage's leaf-node encryption_key (the committer copies it
        // into the tree verbatim on Add).
        const myEncKey = kp.leafNode.encryptionKey;
        let myLeafIndex = -1;
        for (let li = 0; li < nLeaves; li += 1) {
            const leaf = RatchetTree.leafFor(tree, li);
            if (leaf && equalBytes(leaf.encryptionKey, myEncKey)) {
                myLeafIndex = li;
                break;
            }
        }
        if (myLeafIndex === -1) {
            throw new Error('group.join: cannot locate our leaf in the ratchet_tree');
        }

        // Verify GroupInfo signature with the signer's signature_key.
        const signerLeafIndex = groupInfo.signer;
        const signerLeaf = RatchetTree.leafFor(tree, signerLeafIndex);
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
        if (!equalBytes(computedTreeHash, groupInfo.groupContext.treeHash)) {
            throw new Error('group.join: tree_hash mismatch');
        }

        // Walk our path_secret (gs.pathSecret = path_secret[LCA]) up the
        // direct path to root, deriving keypairs and verifying each
        // matches the encryption_key the committer placed in the tree.
        // This both validates the GroupSecrets we received AND populates
        // our parentKeyPairs map for future commits.
        if (!gs.pathSecret) {
            throw new Error('group.join: missing path_secret in GroupSecrets');
        }
        const myDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(myLeafIndex), nLeaves,
        );
        let lcaIdx = -1;
        for (let i = 0; i < myDirectPath.length; i += 1) {
            const descendants = TreeMath.leafDescendants(myDirectPath[i], nLeaves);
            if (descendants.includes(signerLeafIndex)) {
                lcaIdx = i;
                break;
            }
        }
        if (lcaIdx === -1) {
            throw new Error('group.join: signer leaf not under any of our ancestors');
        }
        const parentKeyPairs = new Map();
        let cur = gs.pathSecret;
        for (let i = lcaIdx; i < myDirectPath.length; i += 1) {
            if (i > lcaIdx) {
                cur = await KeySchedule.deriveSecret(cur, 'path');
            }
            const nodeIdx = myDirectPath[i];
            const nodeSecret = await KeySchedule.deriveSecret(cur, 'node');
            const kpDerived = await HPKE.deriveKeyPair(nodeSecret);
            const slot = tree[nodeIdx];
            if (!slot || slot.nodeType !== Nodes.NodeType.PARENT) {
                throw new Error(`group.join: parent node ${nodeIdx} unexpectedly blank/non-parent`);
            }
            if (!equalBytes(kpDerived.publicKeyBytes, slot.parent.encryptionKey)) {
                throw new Error(`group.join: derived public key mismatch at node ${nodeIdx}`);
            }
            parentKeyPairs.set(nodeIdx, kpDerived);
        }

        // Derive epoch secrets using gs.joinerSecret as the joiner_secret.
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
        if (!equalBytes(expectedConfTag, groupInfo.confirmationTag)) {
            throw new Error('group.join: confirmation_tag mismatch');
        }

        const state = {
            cipherSuite: CIPHERSUITE,
            groupId: groupInfo.groupContext.groupId,
            epoch: groupInfo.groupContext.epoch,
            ratchetTree: tree,
            nLeaves,
            myLeafIndex,
            identity,
            leafKeyPair: leafEncKeyPair,
            parentKeyPairs,
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
