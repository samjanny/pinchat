/**
 * PinChat MLS — stateful Group orchestrator (RFC 9420 §§8, 12, 6.3).
 *
 * This module ties together the bottom-layer primitives into a
 * member-facing API:
 *
 *   Group.create({ identity, groupId? })                 → Group
 *   Group.joinFromEpochState(state)                       → Group
 *   group.encryptApplicationMessage(plaintext)            → MLSMessage bytes
 *   group.decryptApplicationMessage(mlsMessageBytes)      → { plaintext,
 *                                                             senderLeafIndex }
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
            require('./secret-tree.js'),
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
            require('./parent-hash.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Group = factory(
            root.MLS.Codec, root.MLS.HPKE, root.MLS.Signature,
            root.MLS.Nodes, root.MLS.RatchetTree, root.MLS.TreeMath,
            root.MLS.TreeHash, root.MLS.GroupContext, root.MLS.KeySchedule,
            root.MLS.Framing, root.MLS.PrivateMessage, root.MLS.SecretTree,
            root.MLS.MLSMessage,
            root.MLS.PublicMessage, root.MLS.Labeled,
            root.MLS.KeyPackage, root.MLS.Proposal, root.MLS.Commit,
            root.MLS.TreeKEM, root.MLS.Welcome, root.MLS.GroupInfo,
            root.MLS.TranscriptHashes, root.MLS.ParentHash,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (
    Codec, HPKE, Signature, Nodes, RatchetTree, TreeMath,
    TreeHash, GroupContext, KeySchedule, Framing, PrivateMessage,
    SecretTree, MLSMessage, PublicMessage, Labeled,
    KeyPackage, Proposal, Commit, TreeKEM, Welcome, GroupInfo,
    TranscriptHashes, ParentHash,
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

    // Out-of-order tolerance bounds for the stateful secret-tree chains.
    // A forward jump larger than MAX_GENERATION_SKIP is rejected (DoS
    // bound on chain derivations); at most MAX_SKIPPED_PER_CHAIN cached
    // keys are kept per sender chain, FIFO-evicted and zeroed.
    const MAX_GENERATION_SKIP = 256;
    const MAX_SKIPPED_PER_CHAIN = 256;

    // How long the previous epoch's decrypt-only context is retained
    // after a Commit, so application messages already in flight when
    // the epoch turned still decrypt instead of being lost. Bounded FS
    // cost: the retained chains keep deleting keys as they are used,
    // and the whole context is zeroed at expiry or on the next Commit.
    const PREV_EPOCH_GRACE_MS = 60 * 1000;

    // --- Group class ------------------------------------------------------

    class Group {
        constructor(state) {
            Object.assign(this, state);
            // Replay protection: per-epoch set of (leafIndex, generation)
            // pairs we have already accepted. Reset on every epoch
            // transition; cap per-leaf to bound memory growth. With the
            // stateful chains below this is defense-in-depth: the chain
            // state itself rejects replays because consumed keys are
            // deleted and cannot be re-derived.
            this.consumedByLeaf = new Map();
            // Stateful per-sender secret-tree chains (intra-epoch forward
            // secrecy). Keyed by `${leafIndex}:${which}`; each entry holds
            // only the CURRENT chain position's secret, which is
            // overwritten as the chain advances, plus a bounded cache of
            // single-use keys for skipped generations. Reset (and zeroed)
            // on every epoch transition.
            this._chainStates = new Map();
            // Decrypt-only context of the previous epoch (grace window
            // for in-flight messages across a Commit). See
            // _snapshotPrevEpoch / _decryptFromPreviousEpoch.
            this._prevEpoch = null;
        }

        _markGenerationConsumed(leafIndex, generation) {
            let set = this.consumedByLeaf.get(leafIndex);
            if (!set) {
                set = new Set();
                this.consumedByLeaf.set(leafIndex, set);
            }
            // Hard cap: if a sender exhausts more than 4096 distinct
            // generations within one epoch, drop the oldest (smallest)
            // entries. In practice we're nowhere near this — generations
            // are reset on every commit.
            if (set.size >= 4096) {
                const sorted = [...set].sort((a, b) => a - b);
                for (let i = 0; i < sorted.length / 2; i += 1) set.delete(sorted[i]);
            }
            set.add(generation);
        }

        _isGenerationConsumed(leafIndex, generation) {
            const set = this.consumedByLeaf.get(leafIndex);
            return set ? set.has(generation) : false;
        }

        /**
         * Zero and drop all stateful chain material. Called on every
         * epoch transition: the next epoch's chains re-root from the new
         * encryption_secret on first use.
         */
        _resetChainStates() {
            if (!this._chainStates) {
                this._chainStates = new Map();
                return;
            }
            for (const st of this._chainStates.values()) {
                if (st.secret) st.secret.fill(0);
                for (const v of st.skipped.values()) {
                    v.key.fill(0);
                    v.nonce.fill(0);
                }
                st.skipped.clear();
            }
            this._chainStates = new Map();
        }

        /**
         * Retain a bounded decrypt-only context for the epoch we are
         * about to leave, so application messages already in flight when
         * the Commit landed still decrypt instead of being lost. MUST be
         * called BEFORE the epoch fields are overwritten. Replaces (and
         * zeroes) any older retained context: at most ONE previous epoch
         * is kept, for at most PREV_EPOCH_GRACE_MS.
         */
        _snapshotPrevEpoch() {
            this._dropPrevEpoch();
            this._prevEpoch = {
                epoch: this.epoch,
                nLeaves: this.nLeaves,
                ratchetTree: this.ratchetTree,
                groupContext: this._buildGroupContextStruct(),
                senderDataSecret: this.epochSecrets.senderDataSecret,
                encryptionSecret: this.epochSecrets.encryptionSecret,
                chainStates: this._chainStates,
                consumedByLeaf: this.consumedByLeaf,
                expiresAt: Date.now() + PREV_EPOCH_GRACE_MS,
            };
            // Chain-state ownership moved into the snapshot; the new
            // epoch starts fresh (re-rooted on first use).
            this._chainStates = new Map();
        }

        /**
         * Zero and drop the retained previous-epoch context.
         */
        _dropPrevEpoch() {
            if (!this._prevEpoch) return;
            for (const st of this._prevEpoch.chainStates.values()) {
                if (st.secret) st.secret.fill(0);
                for (const v of st.skipped.values()) {
                    v.key.fill(0);
                    v.nonce.fill(0);
                }
                st.skipped.clear();
            }
            this._prevEpoch = null;
        }

        /**
         * Stateful key/nonce provider for PrivateMessage encrypt/decrypt
         * (intra-epoch forward secrecy, RFC 9420 §9.2 deletion schedule).
         *
         * Invariants:
         *   - the stored secret is always at position `nextGeneration`;
         *     old positions are overwritten (fill(0)) as the chain moves,
         *     so past generations cannot be re-derived from live state;
         *   - keys for skipped generations are cached single-use and
         *     zeroed on eviction;
         *   - a generation below the chain position with no cached key
         *     is a replay (or fell out of the skip window) and throws.
         *
         * Note: the key is consumed at derivation time, BEFORE the AEAD
         * runs. A tampered ciphertext therefore burns its generation and
         * the original cannot be decrypted afterwards; that is equivalent
         * to the relay dropping the message, which it can always do.
         */
        async _chainKeyNonce(leafIndex, which, generation) {
            return this._chainKeyNonceIn(
                this._chainStates, this.epochSecrets.encryptionSecret,
                this.nLeaves, leafIndex, which, generation,
            );
        }

        async _chainKeyNonceIn(chainStates, encryptionSecret, nLeaves, leafIndex, which, generation) {
            const id = `${leafIndex}:${which}`;
            let st = chainStates.get(id);
            if (!st) {
                const leafSec = await SecretTree.leafSecret(
                    encryptionSecret, leafIndex, nLeaves,
                );
                const chainRoot = await SecretTree.leafChainRoot(leafSec, which);
                st = { nextGeneration: 0, secret: chainRoot, skipped: new Map() };
                chainStates.set(id, st);
            }
            if (generation < st.nextGeneration) {
                const cached = st.skipped.get(generation);
                if (!cached) {
                    throw new Error(
                        `group: replayed or expired application message (leaf=${leafIndex}, gen=${generation})`,
                    );
                }
                st.skipped.delete(generation);
                return cached;
            }
            if (generation - st.nextGeneration > MAX_GENERATION_SKIP) {
                throw new Error(
                    `group: generation jump too large (leaf=${leafIndex}, `
                    + `gen=${generation}, next=${st.nextGeneration}, max skip=${MAX_GENERATION_SKIP})`,
                );
            }
            // Advance to `generation`, caching (bounded) skipped keys so
            // out-of-order arrivals within the window still decrypt.
            let secret = st.secret;
            for (let g = st.nextGeneration; g < generation; g += 1) {
                const step = await SecretTree.keyNonceStep(secret, g);
                st.skipped.set(g, { key: step.key, nonce: step.nonce });
                if (st.skipped.size > MAX_SKIPPED_PER_CHAIN) {
                    const oldest = st.skipped.keys().next().value;
                    const evicted = st.skipped.get(oldest);
                    evicted.key.fill(0);
                    evicted.nonce.fill(0);
                    st.skipped.delete(oldest);
                }
                secret.fill(0);
                secret = step.nextSecret;
            }
            const fin = await SecretTree.keyNonceStep(secret, generation);
            secret.fill(0);
            st.secret = fin.nextSecret;
            st.nextGeneration = generation + 1;
            return { key: fin.key, nonce: fin.nonce };
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
        static async create({ identity, groupId, credentialIdentity, pskSecret }) {
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

            // PSK injected into every epoch transition. Defaults to zeros
            // for backwards compatibility / unit tests; for production we
            // derive it from the URL fragment so an attacker without the
            // invite cannot craft a valid Welcome or Commit even with a
            // compromised relay.
            const psk = pskSecret || new Uint8Array(HPKE.Nh);
            if (psk.length !== HPKE.Nh) {
                throw new Error(`group: pskSecret must be ${HPKE.Nh} bytes (got ${psk.length})`);
            }

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
                pskSecret: psk,
            };
            const group = new Group(state);

            // Derive epoch 0 secrets. commit_secret is zero for the
            // initial epoch (no UpdatePath has run yet); init_secret_[-1]
            // is freshly random as §12.3 prescribes. psk_secret carries
            // the URL-fragment binding when set.
            await group._deriveEpoch({
                initSecretPrev: initSecret,
                commitSecret: new Uint8Array(HPKE.Nh),
                pskSecret: psk,
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
                keyNonceProvider: (li, which, gen) => this._chainKeyNonce(li, which, gen),
            });
            const pmBytes = PrivateMessage.privateMessageBytes(pm);
            return MLSMessage.serializeMLSMessage(wireFormat, pmBytes);
        }

        /**
         * Decrypt an incoming MLSMessage(mls_private_message) carrying an
         * application payload. Verifies the sender's signature against
         * their LeafNode's signature_key, rejects wrong-epoch or
         * non-application messages.
         *
         * Returns { plaintext, senderLeafIndex }: the leaf index is the
         * CRYPTOGRAPHICALLY authenticated sender (signature verified
         * against that leaf's signature_key in the tree), as opposed to
         * the relay envelope's unauthenticated sender_id. Callers doing
         * sender attribution MUST use this value.
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
            if (!equalBytes(pm.groupId, this.groupId)) {
                throw new Error('group: group_id mismatch on incoming application message');
            }
            if (pm.epoch !== this.epoch) {
                // Grace window: a message encrypted under the epoch we
                // just left may still be in flight when the Commit lands.
                return this._decryptFromPreviousEpoch(pm);
            }

            const out = await PrivateMessage.decryptPrivateMessage({
                pm,
                senderDataSecret: this.epochSecrets.senderDataSecret,
                encryptionSecret: this.epochSecrets.encryptionSecret,
                nLeaves: this.nLeaves,
                keyNonceProvider: (li, which, gen) => this._chainKeyNonce(li, which, gen),
            });

            const senderLeafIndex = out.senderData.leafIndex;
            const generation = out.senderData.generation;
            // Defense-in-depth bounds check before tree lookup. Even
            // though leafFor returns falsy for OOB, an explicit guard
            // makes a future port (e.g. typed-array-backed RatchetTree)
            // memory-safe by construction.
            if (!Number.isInteger(senderLeafIndex) || senderLeafIndex < 0
                || senderLeafIndex >= this.nLeaves) {
                throw new Error(
                    `group: sender leaf_index ${senderLeafIndex} out of range [0,${this.nLeaves})`,
                );
            }
            // Replay protection: reject (leafIndex, generation) duplicates
            // within the current epoch. Reset on every epoch transition.
            // The legitimate sender increments senderRatchetGeneration once
            // per send, so seeing the same (leaf, gen) twice means either
            // a relay-level retransmission or an attacker replaying a
            // captured ciphertext — both must be dropped to preserve
            // AES-GCM nonce uniqueness guarantees.
            if (this._isGenerationConsumed(senderLeafIndex, generation)) {
                throw new Error(
                    `group: replayed application message (leaf=${senderLeafIndex}, gen=${generation})`,
                );
            }

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

            this._markGenerationConsumed(senderLeafIndex, generation);

            return { plaintext: out.content.payloadBytes, senderLeafIndex };
        }

        /**
         * Decrypt an application message from the PREVIOUS epoch using
         * the retained grace-window context. Same verification chain as
         * the current-epoch path (bounds, replay, signature under the
         * OLD group context and OLD tree); the retained chains delete
         * consumed keys exactly like the live ones.
         */
        async _decryptFromPreviousEpoch(pm) {
            const pe = this._prevEpoch;
            if (!pe || pm.epoch !== pe.epoch) {
                throw new Error(`group: wrong epoch (got ${pm.epoch}, expected ${this.epoch})`);
            }
            if (Date.now() > pe.expiresAt) {
                this._dropPrevEpoch();
                throw new Error('group: previous-epoch grace window expired');
            }

            const out = await PrivateMessage.decryptPrivateMessage({
                pm,
                senderDataSecret: pe.senderDataSecret,
                encryptionSecret: pe.encryptionSecret,
                nLeaves: pe.nLeaves,
                keyNonceProvider: (li, which, gen) => this._chainKeyNonceIn(
                    pe.chainStates, pe.encryptionSecret, pe.nLeaves, li, which, gen,
                ),
            });

            const senderLeafIndex = out.senderData.leafIndex;
            const generation = out.senderData.generation;
            if (!Number.isInteger(senderLeafIndex) || senderLeafIndex < 0
                || senderLeafIndex >= pe.nLeaves) {
                throw new Error(
                    `group: sender leaf_index ${senderLeafIndex} out of range [0,${pe.nLeaves}) (prev epoch)`,
                );
            }
            let consumedSet = pe.consumedByLeaf.get(senderLeafIndex);
            if (consumedSet && consumedSet.has(generation)) {
                throw new Error(
                    `group: replayed application message (leaf=${senderLeafIndex}, gen=${generation}, prev epoch)`,
                );
            }

            const senderLeaf = RatchetTree.leafFor(pe.ratchetTree, senderLeafIndex);
            if (!senderLeaf) {
                throw new Error(`group: unknown sender leaf_index ${senderLeafIndex} (prev epoch)`);
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
                pe.groupContext,
                out.content.auth.signature,
            );
            if (!sigOk) {
                throw new Error('group: application message signature invalid (prev epoch)');
            }

            if (!consumedSet) {
                consumedSet = new Set();
                pe.consumedByLeaf.set(senderLeafIndex, consumedSet);
            }
            consumedSet.add(generation);

            return { plaintext: out.content.payloadBytes, senderLeafIndex };
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

        // ---- 0. Verify the joiner's KeyPackage and inner LeafNode ----
        // Without this, a malicious relay could substitute leafNode fields
        // (encryption_key, signature_key, credential) and have us insert
        // an attacker-controlled leaf into the tree. The signing key is
        // taken from kp.leafNode.signatureKey because our credential model
        // ties identity to the signature key directly.
        await verifyKeyPackageBindings(kp);

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

        // ---- 3. Build NEW committer leaf (commit-source), unsigned ----
        const committerNewLeafPreSign = buildSelfLeaf({
            encryptionKeyBytes: leafNodePair.keyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.COMMIT,
        });
        newTree[TreeMath.leafToNode(this.myLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: committerNewLeafPreSign,
        };

        // ---- 4. Set new parent encryption_keys on direct path ----
        // §5.3.1: intermediate nodes intersected by an UpdatePath have
        // empty unmerged_leaves. parent_hash is a placeholder here and
        // is filled by the §7.9 chain computation below.
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

        // ---- 4b. Parent-hash chaining (§7.9): stamp the direct path and
        // bind the committer's LeafNode.parent_hash, THEN sign the leaf. ----
        committerNewLeafPreSign.parentHash = await stampCommitterParentHashes(
            newTree, this.myLeafIndex, newNLeaves,
        );
        committerNewLeafPreSign.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey,
            committerNewLeafPreSign,
            this.groupId,
            this.myLeafIndex,
        );

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
            pskSecret: this.pskSecret,
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
            epochSecrets.joinerSecret, this.pskSecret,
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
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch();
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
        // Replace parent keypairs wholesale with the freshly-derived
        // entries — anything not on our new direct path is unreachable
        // and only weakens forward secrecy by lingering in memory.
        this.parentKeyPairs = new Map();
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            this.parentKeyPairs.set(committerDirectPath[i], chain[i].keyPair);
        }
        // Replay protection state is per-epoch — every commit advances
        // the epoch and re-keys the secret tree, so old generations no
        // longer collide with anything new. The old consumed set and
        // chain states now live in the grace-window snapshot; fresh
        // maps start the new epoch.
        this.consumedByLeaf = new Map();

        return { commitMessage, welcomeMessage };
    };

    /**
     * Commit a Remove proposal: blank the target leaf, blank every
     * parent on its direct path, then re-key the committer's direct
     * path so the removed member can no longer derive any subsequent
     * epoch secret. Returns { commitMessage } (no Welcome — Remove
     * doesn't admit anyone). The removed leaf's index slot stays in
     * place (we don't prune the tree); other members converge to the
     * same blanked-tree shape via processCommit.
     */
    Group.prototype.commitRemoveMember = async function commitRemoveMember({ removedLeafIndex }) {
        if (typeof removedLeafIndex !== 'number' || removedLeafIndex < 0
            || removedLeafIndex >= this.nLeaves) {
            throw new Error(`commitRemoveMember: invalid leaf_index ${removedLeafIndex}`);
        }
        if (removedLeafIndex === this.myLeafIndex) {
            throw new Error('commitRemoveMember: cannot remove self');
        }
        const removedLeafNode = TreeMath.leafToNode(removedLeafIndex);
        if (!this.ratchetTree[removedLeafNode]
            || this.ratchetTree[removedLeafNode].nodeType !== Nodes.NodeType.LEAF) {
            throw new Error(`commitRemoveMember: leaf ${removedLeafIndex} already blank or non-leaf`);
        }

        // ---- 1. Build new tree: blank the removed leaf and its ancestors ----
        const newNLeaves = this.nLeaves;
        const newWidth = TreeMath.nodeWidth(newNLeaves);
        const newTree = Nodes.padRatchetTree(this.ratchetTree.slice(), newWidth);
        newTree[removedLeafNode] = null;
        const removedDirectPath = TreeMath.directPathWithRoot(removedLeafNode, newNLeaves);
        for (const nodeIdx of removedDirectPath) {
            newTree[nodeIdx] = null;
        }

        // ---- 2. Generate fresh leaf_secret + path-secret chain for committer ----
        const leafSecret = randomBytes(HPKE.Nh);
        const leafNodePair = await TreeKEM.leafKeyPairFromSecret(leafSecret, this.myLeafIndex);
        const chain = await TreeKEM.pathSecretChain(leafSecret, this.myLeafIndex, newNLeaves);
        const committerDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(this.myLeafIndex), newNLeaves,
        );
        if (chain.length !== committerDirectPath.length) {
            throw new Error(
                `commitRemoveMember: chain length ${chain.length} != direct path ${committerDirectPath.length}`,
            );
        }

        // ---- 3. Build NEW committer leaf (commit-source), unsigned ----
        const committerNewLeafPreSign = buildSelfLeaf({
            encryptionKeyBytes: leafNodePair.keyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.COMMIT,
        });
        newTree[TreeMath.leafToNode(this.myLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: committerNewLeafPreSign,
        };

        // ---- 4. Set new parent encryption_keys on committer's direct path ----
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

        // ---- 4b. Parent-hash chaining (§7.9). ----
        committerNewLeafPreSign.parentHash = await stampCommitterParentHashes(
            newTree, this.myLeafIndex, newNLeaves,
        );
        committerNewLeafPreSign.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey,
            committerNewLeafPreSign,
            this.groupId,
            this.myLeafIndex,
        );

        // ---- 5. New tree hash + provisional GroupContext ----
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

        // ---- 6. Encrypt path_secrets to filtered resolution(copath_sibling) ----
        // The removed leaf is now blank, so it naturally falls out of every
        // resolution that would have included it. The remaining members in
        // the copath subtree still receive their share.
        const updatePathNodes = [];
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            const childOnPath = i === 0
                ? TreeMath.leafToNode(this.myLeafIndex)
                : committerDirectPath[i - 1];
            const copathSibling = TreeMath.sibling(childOnPath, newNLeaves);
            const res = RatchetTree.resolution(newTree, copathSibling);
            const ciphertexts = [];
            for (const targetNode of res) {
                const targetSlot = newTree[targetNode];
                if (!targetSlot) {
                    throw new Error(
                        `commitRemoveMember: resolution target ${targetNode} unexpectedly blank`,
                    );
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

        // ---- 7. Commit struct: Remove proposal + UpdatePath ----
        const removeProposal = {
            proposalType: Proposal.ProposalType.REMOVE,
            removed: removedLeafIndex,
        };
        const commitStruct = {
            proposals: [{
                type: Proposal.ProposalOrRefType.PROPOSAL,
                proposal: removeProposal,
            }],
            path: updatePath,
        };
        const commitBodyBytes = Commit.commitBytes(commitStruct);

        // ---- 8. FramedContent + signature (under OLD context) ----
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

        // ---- 9. Transcript + new epoch secrets ----
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
            pskSecret: this.pskSecret,
            groupContext: epochGroupContextBytes,
        });

        const confirmationTag = await TranscriptHashes.confirmationTag(
            epochSecrets.confirmationKey, newConfirmedTranscriptHash,
        );
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            newConfirmedTranscriptHash, confirmationTag,
        );
        const auth = { signature, confirmationTag };

        // ---- 10. PublicMessage with membership_tag ----
        const membershipTag = await PublicMessage.computeMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, auth,
            this._buildGroupContextStruct(),
        );
        const pm = { content, auth, membershipTag };
        const pmBytes = PublicMessage.publicMessageBytes(pm);
        const commitMessage = MLSMessage.serializeMLSMessage(wireFormat, pmBytes);

        // ---- 11. Apply commit to local state ----
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch();
        this.ratchetTree = newTree;
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
        this.parentKeyPairs = new Map();
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            this.parentKeyPairs.set(committerDirectPath[i], chain[i].keyPair);
        }
        this.consumedByLeaf = new Map();

        return { commitMessage };
    };

    /**
     * Member-initiated Update proposal (RFC 9420 §12.1.2). Generates a
     * FRESH leaf HPKE keypair, builds a source=UPDATE LeafNode signed
     * with our identity key, and returns a signed PublicMessage(proposal)
     * to broadcast plus the pending private keypair the caller must swap
     * in once the committing member folds this proposal into a Commit.
     *
     * This is what closes per-member PCS in the single-committer model:
     * a member whose leaf ENCRYPTION key was compromised picks a new one
     * the attacker does not hold (its signature/identity key, kept
     * separate, still authenticates the proposal), and the committer
     * re-keys the tree so the old leaf key stops decrypting anything.
     *
     * Returns { proposalMessage, pendingLeafKeyPair, pendingLeafNode }.
     * The caller (mls-session) holds pendingLeafKeyPair until it sees the
     * Commit that carries this proposal land, then calls
     * applyPendingSelfUpdate().
     */
    Group.prototype.proposeUpdate = async function proposeUpdate() {
        if (this.myLeafIndex === undefined || this.myLeafIndex === null) {
            throw new Error('proposeUpdate: observer cannot propose');
        }
        // Fresh leaf encryption keypair (the whole point of PCS).
        const newLeafKeyPair = await HPKE.generateKeyPair();
        const leaf = buildSelfLeaf({
            encryptionKeyBytes: newLeafKeyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.UPDATE,
        });
        // §7.6: a source=UPDATE LeafNode is signed over LeafNodeTBS with
        // group_id and leaf_index appended (same TBS shape as commit).
        leaf.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey, leaf, this.groupId, this.myLeafIndex,
        );

        const proposal = { proposalType: Proposal.ProposalType.UPDATE, leafNode: leaf };
        const proposalBodyBytes = Proposal.proposalBytes(proposal);
        const content = {
            groupId: this.groupId,
            epoch: this.epoch,
            sender: { senderType: Framing.SenderType.MEMBER, leafIndex: this.myLeafIndex },
            authenticatedData: new Uint8Array(0),
            contentType: Framing.ContentType.PROPOSAL,
            payload: proposalBodyBytes,
        };
        const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
        const signature = await PublicMessage.signFramedContent(
            this.identity.signaturePrivateKey, wireFormat, content,
            this._buildGroupContextStruct(),
        );
        const auth = { signature };
        const membershipTag = await PublicMessage.computeMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, auth,
            this._buildGroupContextStruct(),
        );
        const pm = { content, auth, membershipTag };
        const pmBytes = PublicMessage.publicMessageBytes(pm);
        const proposalMessage = MLSMessage.serializeMLSMessage(wireFormat, pmBytes);

        return { proposalMessage, pendingLeafKeyPair: newLeafKeyPair, pendingLeafNode: leaf };
    };

    /**
     * Swap in the leaf keypair we generated in proposeUpdate() once the
     * Commit carrying that proposal has been applied. The updated leaf's
     * public key is already in the tree (installed by processCommit);
     * this makes our private state match it. Idempotent-safe: verifies
     * the tree actually carries our proposed public key before swapping.
     */
    Group.prototype.applyPendingSelfUpdate = function applyPendingSelfUpdate(pendingLeafKeyPair) {
        const myLeaf = RatchetTree.leafFor(this.ratchetTree, this.myLeafIndex);
        if (!myLeaf || !equalBytes(myLeaf.encryptionKey, pendingLeafKeyPair.publicKeyBytes)) {
            // The commit did not carry our update (superseded / dropped);
            // keep the existing leafKeyPair untouched.
            return false;
        }
        this.leafKeyPair = {
            privateKey: pendingLeafKeyPair.privateKey,
            publicKey: pendingLeafKeyPair.publicKey,
            publicKeyBytes: pendingLeafKeyPair.publicKeyBytes,
        };
        return true;
    };

    /**
     * Path-only Commit (RFC 9420 allows a Commit with an empty proposal
     * list as long as it carries an UpdatePath): re-key the committer's
     * leaf and direct path and advance the epoch WITHOUT membership
     * change. Used for the periodic PCS rotation in membership-stable
     * groups.
     *
     * `updateProposals` (optional): an array of
     * { proposal, senderLeafIndex } Update proposals to fold into this
     * Commit. Each installs the proposer's fresh leaf and blanks that
     * leaf's direct path BEFORE the committer builds its own UpdatePath,
     * so the committer's re-key routes new path secrets to the updated
     * members' new keys.
     *
     * Scope note: this heals leakage of the current epoch secrets (an
     * attacker holding epoch n secrets cannot follow into epoch n+1
     * without the committer's fresh path secret). It does NOT heal a
     * compromised MEMBER leaf private key: the ciphertext addressed to
     * that leaf remains decryptable by whoever holds it. Full PCS for
     * member compromise needs member-initiated Update proposals, which
     * are still post-MVP.
     *
     * Returns { commitMessage }.
     */
    Group.prototype.commitUpdate = async function commitUpdate({ updateProposals = [] } = {}) {
        const newNLeaves = this.nLeaves;
        const newWidth = TreeMath.nodeWidth(newNLeaves);
        const newTree = Nodes.padRatchetTree(this.ratchetTree.slice(), newWidth);

        // ---- 0. Apply Update proposals: install each proposer's fresh
        // leaf and blank its direct path (RFC §12.4.2). Verify each
        // proposal's LeafNode signature against the CURRENT leaf's
        // signature key (no identity rotation in this MVP). Skip a
        // proposal for a leaf we're not tracking or whose signer changed.
        const proposalOrRefs = [];
        for (const up of updateProposals) {
            const li = up.senderLeafIndex;
            if (li === this.myLeafIndex) {
                throw new Error('commitUpdate: committer must use its own path re-key, not an Update proposal');
            }
            const curLeaf = RatchetTree.leafFor(this.ratchetTree, li);
            if (!curLeaf) continue;
            await verifyUpdateLeafBinding(
                up.proposal.leafNode, curLeaf.signatureKey, this.groupId, li,
            );
            newTree[TreeMath.leafToNode(li)] = {
                nodeType: Nodes.NodeType.LEAF, leaf: up.proposal.leafNode,
            };
            for (const ancestor of TreeMath.directPathWithRoot(TreeMath.leafToNode(li), newNLeaves)) {
                newTree[ancestor] = null;
            }
            proposalOrRefs.push({
                type: Proposal.ProposalOrRefType.PROPOSAL,
                proposal: up.proposal,
            });
        }

        // ---- 1. Fresh leaf_secret + path-secret chain for committer ----
        const leafSecret = randomBytes(HPKE.Nh);
        const leafNodePair = await TreeKEM.leafKeyPairFromSecret(leafSecret, this.myLeafIndex);
        const chain = await TreeKEM.pathSecretChain(leafSecret, this.myLeafIndex, newNLeaves);
        const committerDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(this.myLeafIndex), newNLeaves,
        );
        if (chain.length !== committerDirectPath.length) {
            throw new Error(
                `commitUpdate: chain length ${chain.length} != direct path ${committerDirectPath.length}`,
            );
        }

        // ---- 2. New committer leaf (commit-source), unsigned ----
        const committerNewLeafPreSign = buildSelfLeaf({
            encryptionKeyBytes: leafNodePair.keyPair.publicKeyBytes,
            signatureKeyBytes: this.identity.signaturePublicKeyBytes,
            credentialIdentity: this.identity.signaturePublicKeyBytes,
            leafNodeSource: Nodes.LeafNodeSource.COMMIT,
        });
        newTree[TreeMath.leafToNode(this.myLeafIndex)] = {
            nodeType: Nodes.NodeType.LEAF, leaf: committerNewLeafPreSign,
        };

        // ---- 3. New parent encryption_keys on committer's direct path ----
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

        // ---- 3b. Parent-hash chaining (§7.9). ----
        committerNewLeafPreSign.parentHash = await stampCommitterParentHashes(
            newTree, this.myLeafIndex, newNLeaves,
        );
        committerNewLeafPreSign.signature = await signLeafNodeInCommit(
            this.identity.signaturePrivateKey,
            committerNewLeafPreSign,
            this.groupId,
            this.myLeafIndex,
        );

        // ---- 4. New tree hash + provisional GroupContext ----
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

        // ---- 5. Encrypt path_secrets to resolution(copath_sibling) ----
        const updatePathNodes = [];
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            const childOnPath = i === 0
                ? TreeMath.leafToNode(this.myLeafIndex)
                : committerDirectPath[i - 1];
            const copathSibling = TreeMath.sibling(childOnPath, newNLeaves);
            const res = RatchetTree.resolution(newTree, copathSibling);
            const ciphertexts = [];
            for (const targetNode of res) {
                const targetSlot = newTree[targetNode];
                if (!targetSlot) {
                    throw new Error(
                        `commitUpdate: resolution target ${targetNode} unexpectedly blank`,
                    );
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

        // ---- 6. Commit struct: folded Update proposals + UpdatePath ----
        const commitStruct = { proposals: proposalOrRefs, path: updatePath };
        const commitBodyBytes = Commit.commitBytes(commitStruct);

        // ---- 7. FramedContent + signature (under OLD context) ----
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

        // ---- 8. Transcript + new epoch secrets ----
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
            pskSecret: this.pskSecret,
            groupContext: epochGroupContextBytes,
        });

        const confirmationTag = await TranscriptHashes.confirmationTag(
            epochSecrets.confirmationKey, newConfirmedTranscriptHash,
        );
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            newConfirmedTranscriptHash, confirmationTag,
        );
        const auth = { signature, confirmationTag };

        // ---- 9. PublicMessage with membership_tag ----
        const membershipTag = await PublicMessage.computeMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, auth,
            this._buildGroupContextStruct(),
        );
        const pm = { content, auth, membershipTag };
        const pmBytes = PublicMessage.publicMessageBytes(pm);
        const commitMessage = MLSMessage.serializeMLSMessage(wireFormat, pmBytes);

        // ---- 10. Apply commit to local state ----
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch();
        this.ratchetTree = newTree;
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
        this.parentKeyPairs = new Map();
        for (let i = 0; i < committerDirectPath.length; i += 1) {
            this.parentKeyPairs.set(committerDirectPath[i], chain[i].keyPair);
        }
        this.consumedByLeaf = new Map();

        return { commitMessage };
    };

    /**
     * Process a Commit broadcast by another member. Inputs:
     *   commitMessageBytes : MLSMessage(mls_public_message) bytes
     *
     * Verifies the FramedContent signature + membership_tag, applies
     * inline Add/Remove proposals, walks the UpdatePath to recover our
     * share of the new path_secret chain, and advances the local epoch
     * state.
     *
     * Scope:
     *   - Inline proposals only (Add, Remove). Proposal-by-reference is
     *     not implemented.
     *   - Update proposals are not yet handled.
     */
    Group.prototype.processCommit = async function processCommit(commitMessageBytes, opts = {}) {
        // pendingSelfUpdate: the { publicKeyBytes, privateKey, ... } keypair
        // we generated for an Update proposal that may be folded into this
        // Commit. If the Commit installs our new leaf, we must decrypt the
        // committer's UpdatePath with the NEW private key (the committer
        // encrypted to it), so we swap leafKeyPair before the resolution
        // walk. Ignored if this Commit does not carry our update.
        const pendingSelfUpdate = opts.pendingSelfUpdate || null;
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
        if (!equalBytes(content.groupId, this.groupId)) {
            throw new Error('processCommit: group_id mismatch');
        }
        if (content.epoch !== this.epoch) {
            throw new Error(`processCommit: wrong epoch (got ${content.epoch}, expected ${this.epoch})`);
        }
        if (content.sender.senderType !== Framing.SenderType.MEMBER) {
            throw new Error('processCommit: non-member sender not supported');
        }
        const senderLeafIndex = content.sender.leafIndex;
        if (!Number.isInteger(senderLeafIndex) || senderLeafIndex < 0
            || senderLeafIndex >= this.nLeaves) {
            throw new Error(
                `processCommit: sender leaf_index ${senderLeafIndex} out of range [0,${this.nLeaves})`,
            );
        }
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

        // ---- Apply Add / Remove proposals ----
        // Adds insert at the next free leaf and grow the tree; Removes
        // blank the target leaf AND every parent on its direct path so
        // the removed member can no longer derive any subsequent epoch
        // secret. nLeaves stays unchanged on Remove (we don't prune).
        let newTree = this.ratchetTree.slice();
        let newNLeaves = this.nLeaves;
        let lastAddedLeafIndex = null;
        let lastRemovedLeafIndex = null;
        // Leaves updated by a folded Update proposal, used below so the
        // committing member can swap in its own pending keypair.
        const updatedLeafIndices = [];
        for (const por of commit.proposals) {
            if (por.type !== Proposal.ProposalOrRefType.PROPOSAL) {
                throw new Error('processCommit: proposal-by-reference not supported');
            }
            const proposal = por.proposal;
            if (proposal.proposalType === Proposal.ProposalType.ADD) {
                const addLeafIndex = newNLeaves;
                newNLeaves += 1;
                const newWidth = TreeMath.nodeWidth(newNLeaves);
                newTree = Nodes.padRatchetTree(newTree, newWidth);
                newTree[TreeMath.leafToNode(addLeafIndex)] = {
                    nodeType: Nodes.NodeType.LEAF, leaf: proposal.keyPackage.leafNode,
                };
                lastAddedLeafIndex = addLeafIndex;
            } else if (proposal.proposalType === Proposal.ProposalType.UPDATE) {
                // Member-initiated re-key (RFC §12.4.2): the proposal
                // must have come from a member (its own leaf); the
                // committer applies the new LeafNode and blanks that
                // leaf's direct path. We cannot recover the leaf_index
                // from the inline proposal alone, so we match the new
                // LeafNode's signature key against an existing leaf (no
                // identity rotation in this MVP) and verify the
                // UPDATE-source LeafNode signature over that index.
                const newLeaf = proposal.leafNode;
                if (newLeaf.leafNodeSource !== Nodes.LeafNodeSource.UPDATE) {
                    throw new Error('processCommit: Update proposal leaf not source=update');
                }
                let updLeafIndex = -1;
                for (let li = 0; li < newNLeaves; li += 1) {
                    const existing = RatchetTree.leafFor(newTree, li);
                    if (existing && equalBytes(existing.signatureKey, newLeaf.signatureKey)) {
                        updLeafIndex = li;
                        break;
                    }
                }
                if (updLeafIndex === -1) {
                    throw new Error('processCommit: Update proposal for an unknown member');
                }
                if (updLeafIndex === senderLeafIndex) {
                    throw new Error('processCommit: committer must re-key via its own path, not an Update');
                }
                await verifyUpdateLeafBinding(
                    newLeaf, newLeaf.signatureKey, this.groupId, updLeafIndex,
                );
                newTree[TreeMath.leafToNode(updLeafIndex)] = {
                    nodeType: Nodes.NodeType.LEAF, leaf: newLeaf,
                };
                for (const ancestor of TreeMath.directPathWithRoot(
                    TreeMath.leafToNode(updLeafIndex), newNLeaves,
                )) {
                    newTree[ancestor] = null;
                }
                updatedLeafIndices.push(updLeafIndex);
            } else if (proposal.proposalType === Proposal.ProposalType.REMOVE) {
                const rmIdx = proposal.removed;
                if (typeof rmIdx !== 'number' || rmIdx < 0 || rmIdx >= newNLeaves) {
                    throw new Error(`processCommit: invalid removed leaf_index ${rmIdx}`);
                }
                if (rmIdx === senderLeafIndex) {
                    throw new Error('processCommit: committer cannot remove themself');
                }
                const rmNode = TreeMath.leafToNode(rmIdx);
                if (!newTree[rmNode] || newTree[rmNode].nodeType !== Nodes.NodeType.LEAF) {
                    throw new Error(`processCommit: leaf ${rmIdx} already blank`);
                }
                newTree[rmNode] = null;
                for (const ancestor of TreeMath.directPathWithRoot(rmNode, newNLeaves)) {
                    newTree[ancestor] = null;
                }
                lastRemovedLeafIndex = rmIdx;
            } else {
                throw new Error(`processCommit: unsupported proposal_type ${proposal.proposalType}`);
            }
        }

        // ---- Apply UpdatePath ----
        // If WE are the leaf being removed, our key material is no longer
        // useful — surface a distinct error so the orchestrator can tear
        // the session down rather than chase phantom decrypt failures.
        if (lastRemovedLeafIndex === this.myLeafIndex) {
            throw new Error('processCommit: removed from group');
        }
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

        // Verify the committer's NEW LeafNode is properly signed by the
        // same identity key that signed the FramedContent. Without this
        // check, a malicious party who somehow holds the committer's
        // signing key (or a relay that forged FramedContentTBS — already
        // rejected above) could splice in a leaf with an attacker-
        // controlled encryption_key.
        await verifyCommitLeafBinding(
            updatePath.leafNode,
            senderLeaf.signatureKey,
            this.groupId,
            senderLeafIndex,
        );

        // Apply Add proposals' KeyPackages: each leafNode the committer
        // is inserting must itself carry valid signatures (otherwise the
        // committer could smuggle attacker-controlled leaves through Adds).
        for (const por of commit.proposals) {
            if (por.type === Proposal.ProposalOrRefType.PROPOSAL
                && por.proposal.proposalType === Proposal.ProposalType.ADD) {
                await verifyKeyPackageBindings(por.proposal.keyPackage);
            }
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

        // Parent-hash chaining (§7.9). The UpdatePath carries only the
        // parent encryption_keys, not their parent_hash values, so we
        // recompute the chain from the tree we hold post-apply (stamping
        // the parent nodes, exactly as the committer did) and confirm the
        // committer's SIGNED LeafNode carries the expected leaf
        // parent_hash. The signature over updatePath.leafNode was already
        // verified (verifyCommitLeafBinding), so a matching parent_hash
        // ties that signature to the full surrounding subtree shape and
        // defeats subtree splicing. A mismatch aborts before we advance
        // the epoch.
        const expectedLeafParentHash = await stampCommitterParentHashes(
            newTree, senderLeafIndex, newNLeaves,
        );
        if (!equalBytes(
            updatePath.leafNode.parentHash || new Uint8Array(0),
            expectedLeafParentHash,
        )) {
            throw new Error('parent-hash: committer LeafNode.parent_hash mismatch');
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

        // If a folded Update proposal re-keyed OUR leaf, adopt the
        // pending private key now: the committer's UpdatePath below is
        // encrypted to our NEW leaf encryption key, and the tree already
        // carries the matching public key.
        let selfUpdated = false;
        if (pendingSelfUpdate && updatedLeafIndices.includes(this.myLeafIndex)) {
            const myLeaf = RatchetTree.leafFor(newTree, this.myLeafIndex);
            if (myLeaf && equalBytes(myLeaf.encryptionKey, pendingSelfUpdate.publicKeyBytes)) {
                this.leafKeyPair = {
                    privateKey: pendingSelfUpdate.privateKey,
                    publicKey: pendingSelfUpdate.publicKey,
                    publicKeyBytes: pendingSelfUpdate.publicKeyBytes,
                };
                selfUpdated = true;
            }
        }

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
            pskSecret: this.pskSecret,
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
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch();
        this.ratchetTree = newTree;
        this.nLeaves = newNLeaves;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = newEpochSecrets;
        this.senderRatchetGeneration = 0;
        // Forward secrecy: keep only entries that are on our direct
        // path in the new tree. Any prior entry not in this set was
        // either a node-of-no-current-relevance (tree grew past it) or
        // got re-keyed in this commit — either way, the old keypair
        // shouldn't survive the epoch transition.
        const myNewDirectPath = TreeMath.directPathWithRoot(
            TreeMath.leafToNode(this.myLeafIndex), newNLeaves,
        );
        const survivors = new Map();
        for (const nodeIdx of myNewDirectPath) {
            if (newParentKeyPairs.has(nodeIdx)) {
                survivors.set(nodeIdx, newParentKeyPairs.get(nodeIdx));
            } else if (this.parentKeyPairs && this.parentKeyPairs.has(nodeIdx)) {
                // Below LCA — committer didn't re-key this node, but it's
                // still on our path so we need the previously-known key.
                survivors.set(nodeIdx, this.parentKeyPairs.get(nodeIdx));
            }
        }
        this.parentKeyPairs = survivors;
        // Replay protection state is per-epoch — drop the consumed
        // generations now that we've advanced past the epoch they
        // applied to. The old consumed set and chain states now live in
        // the grace-window snapshot; fresh maps start the new epoch.
        this.consumedByLeaf = new Map();

        return {
            addedLeafIndex: lastAddedLeafIndex,
            removedLeafIndex: lastRemovedLeafIndex,
            updatedLeafIndices,
            selfUpdated,
            committerLeafIndex: senderLeafIndex,
        };
    };

    /**
     * Process a Welcome and join the group as the new member. The
     * ratchet_tree travels as a side-channel on the welcome envelope
     * (committer serialises via Nodes.ratchetTreeBytes) until the
     * `ratchet_tree` GroupInfo extension path lands.
     *
     * Inputs:
     *   welcomeMessage    : MLSMessage bytes (wire_format = mls_welcome)
     *   keyPackageBytes   : our published KeyPackage's serialised bytes
     *   initPrivateKey    : ECDH CryptoKey matching keyPackage.init_key
     *   identity          : our signature identity (as in Group.create)
     *   leafEncKeyPair    : the full HPKE keypair for the leaf — the
     *                       init_key from the KeyPackage, reused as the
     *                       leaf's encryption_key until we rotate
     *   ratchetTreeBytes  : serialised tree (out-of-band from Welcome)
     */
    Group.joinFromWelcomeWithTree = async function joinFromWelcomeWithTree({
        welcomeMessage, keyPackageBytes, initPrivateKey, identity,
        leafEncKeyPair, ratchetTreeBytes, pskSecret,
        expectedSignerLeafIndex,
    }) {
        const psk = pskSecret || new Uint8Array(HPKE.Nh);
        if (psk.length !== HPKE.Nh) {
            throw new Error(`group.join: pskSecret must be ${HPKE.Nh} bytes (got ${psk.length})`);
        }

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
        // Welcome AEAD is keyed off (joiner_secret, psk_secret). A joiner
        // with the wrong PSK will fail the AES-GCM auth tag here, which
        // is exactly the bootstrap-key gating we want.
        const welcomeSecret = await Welcome.deriveWelcomeSecret(
            gs.joinerSecret, psk,
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
        if (!Number.isInteger(signerLeafIndex) || signerLeafIndex < 0
            || signerLeafIndex >= nLeaves) {
            throw new Error(
                `group.join: signer leaf_index ${signerLeafIndex} out of range [0,${nLeaves})`,
            );
        }
        // M-1 (RFC §12.4.3.1): GroupInfo MUST be signed by the
        // member that committed the epoch this Welcome introduces.
        // The orchestrator extracts the Commit's FramedContent
        // sender_leaf_index and passes it as expectedSignerLeafIndex;
        // a null value means the orchestrator couldn't observe a
        // Commit (degraded mode) and the binding is not enforced.
        if (expectedSignerLeafIndex !== null
            && expectedSignerLeafIndex !== undefined
            && expectedSignerLeafIndex !== signerLeafIndex) {
            throw new Error(
                `group.join: GroupInfo.signer ${signerLeafIndex} != Commit sender ${expectedSignerLeafIndex}`,
            );
        }
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

        // Parent-hash chaining verification (§7.9). The GroupInfo signer
        // is the member that committed the epoch this Welcome introduces,
        // so its leaf is commit-source and its direct path carries the
        // parent-hash chain. Recompute it from the received tree and
        // confirm the signer's LeafNode.parent_hash matches, which binds
        // the signer's already-verified signature to the surrounding tree
        // shape, so a relay cannot hand us a spliced ratchet_tree.
        const signerLeafForPh = RatchetTree.leafFor(tree, signerLeafIndex);
        if (signerLeafForPh
            && signerLeafForPh.leafNodeSource === Nodes.LeafNodeSource.COMMIT) {
            await verifyCommitterParentHashes(
                tree, signerLeafIndex, signerLeafForPh, nLeaves,
            );
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
        // psk_secret is the URL-fragment-derived PSK (zeros in tests).
        const memberSecret = await HPKE.hkdfExtract(
            gs.joinerSecret, psk,
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
            pskSecret: psk,
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
            // KEY_PACKAGE variant needs a Lifetime per RFC §7.2.3.
            // We bind it to a 24-hour window around publication; the
            // recipient validates `now ∈ [notBefore, notAfter)` so an
            // old or replayed KeyPackage is rejected even if its
            // signature is intact. Rooms have a hard TTL ≤ 24h so
            // this matches the operational lifetime of any valid
            // KeyPackage in flight.
            lifetime: leafNodeSource === Nodes.LeafNodeSource.KEY_PACKAGE
                ? (() => {
                    const nowSecs = BigInt(Math.floor(Date.now() / 1000));
                    return {
                        notBefore: nowSecs - 60n,           // 1 min clock-skew
                        notAfter: nowSecs + 24n * 60n * 60n, // 24h
                    };
                })()
                : undefined,
            extensions: [],
            signature: new Uint8Array(0),
        };
    }

    /**
     * Verify a KeyPackage's two signatures: the inner LeafNode (signed
     * with source = KEY_PACKAGE, so the TBS is just the LeafNode bytes)
     * and the outer KeyPackageTBS. Both use the leaf's signature_key —
     * our credential model identifies a member by their signature key,
     * so a forgery would have to forge ECDSA-P-256.
     *
     * Throws on any mismatch; returns void on success.
     */
    async function verifyKeyPackageBindings(kp) {
        if (kp.leafNode.leafNodeSource !== Nodes.LeafNodeSource.KEY_PACKAGE) {
            throw new Error(
                `verifyKeyPackage: expected source=KEY_PACKAGE, got ${kp.leafNode.leafNodeSource}`,
            );
        }
        // RFC §7.2.3: enforce now ∈ [notBefore, notAfter). Rejects
        // replayed KeyPackages from a former member trying to rejoin
        // off a captured invite.
        const lt = kp.leafNode.lifetime;
        if (!lt || typeof lt.notBefore !== 'bigint' || typeof lt.notAfter !== 'bigint') {
            throw new Error('verifyKeyPackage: missing or malformed Lifetime');
        }
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        if (nowSecs < lt.notBefore) {
            throw new Error(
                `verifyKeyPackage: Lifetime not yet valid (now=${nowSecs} < notBefore=${lt.notBefore})`,
            );
        }
        if (nowSecs >= lt.notAfter) {
            throw new Error(
                `verifyKeyPackage: Lifetime expired (now=${nowSecs} >= notAfter=${lt.notAfter})`,
            );
        }
        const sigPub = await Signature.importPublicKey(kp.leafNode.signatureKey);
        const leafTbs = Nodes.leafNodeTbsBytes(kp.leafNode);
        const leafOk = await Labeled.verifyWithLabel(
            sigPub, 'LeafNodeTBS', leafTbs, kp.leafNode.signature,
        );
        if (!leafOk) {
            throw new Error('verifyKeyPackage: inner LeafNode signature invalid');
        }
        const kpTbs = KeyPackage.keyPackageTbsBytes(kp);
        const kpOk = await Labeled.verifyWithLabel(
            sigPub, 'KeyPackageTBS', kpTbs, kp.signature,
        );
        if (!kpOk) {
            throw new Error('verifyKeyPackage: outer KeyPackage signature invalid');
        }
    }

    /**
     * Verify a COMMIT-source LeafNode: the TBS includes group_id and
     * leaf_index appended after the LeafNode body. The signing key in
     * the new leaf must match the OLD leaf's signing key (we don't
     * support identity rotation in this MVP) — that ties the commit's
     * new leaf back to the same member who signed the FramedContent.
     */
    async function verifyCommitLeafBinding(leaf, expectedSignatureKey, groupId, leafIndex) {
        if (leaf.leafNodeSource !== Nodes.LeafNodeSource.COMMIT) {
            throw new Error(
                `verifyCommitLeaf: expected source=COMMIT, got ${leaf.leafNodeSource}`,
            );
        }
        if (!equalBytes(leaf.signatureKey, expectedSignatureKey)) {
            throw new Error(
                'verifyCommitLeaf: signature_key rotation in commit not supported',
            );
        }
        const sigPub = await Signature.importPublicKey(leaf.signatureKey);
        const encoder = new Codec.Encoder();
        Nodes.writeLeafNodeTbs(encoder, leaf);
        encoder.writeOpaque(groupId);
        encoder.writeU32(leafIndex);
        const ok = await Labeled.verifyWithLabel(
            sigPub, 'LeafNodeTBS', encoder.bytes(), leaf.signature,
        );
        if (!ok) {
            throw new Error('verifyCommitLeaf: LeafNode signature invalid');
        }
    }

    /**
     * Verify an UPDATE-source LeafNode (member-initiated re-key). Same
     * TBS shape as commit-source (LeafNodeTBS || group_id || leaf_index),
     * and the new leaf must keep the member's existing signature key
     * (no identity rotation in this MVP), so the re-key is bound to the
     * same authenticated member.
     */
    async function verifyUpdateLeafBinding(leaf, expectedSignatureKey, groupId, leafIndex) {
        if (leaf.leafNodeSource !== Nodes.LeafNodeSource.UPDATE) {
            throw new Error(
                `verifyUpdateLeaf: expected source=UPDATE, got ${leaf.leafNodeSource}`,
            );
        }
        if (!equalBytes(leaf.signatureKey, expectedSignatureKey)) {
            throw new Error(
                'verifyUpdateLeaf: signature_key rotation in update not supported',
            );
        }
        const sigPub = await Signature.importPublicKey(leaf.signatureKey);
        const encoder = new Codec.Encoder();
        Nodes.writeLeafNodeTbs(encoder, leaf);
        encoder.writeOpaque(groupId);
        encoder.writeU32(leafIndex);
        const ok = await Labeled.verifyWithLabel(
            sigPub, 'LeafNodeTBS', encoder.bytes(), leaf.signature,
        );
        if (!ok) {
            throw new Error('verifyUpdateLeaf: LeafNode signature invalid');
        }
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

    /**
     * Committer side (RFC 9420 §7.9): after the committer's fresh parent
     * encryption_keys are placed on `tree` (with placeholder empty
     * parent_hash) and the committer's un-signed commit-source LeafNode
     * is installed at its leaf, compute the top-down parent-hash chain,
     * stamp each parent node's parent_hash, and return the value the
     * committer LeafNode must carry. Mutates `tree` in place.
     */
    async function stampCommitterParentHashes(tree, committerLeafIndex, nLeaves) {
        const { pathWithRoot, pathHashes, leafParentHash } =
            await ParentHash.directPathParentHashes(tree, committerLeafIndex, nLeaves);
        for (let i = 0; i < pathWithRoot.length; i += 1) {
            const nodeIdx = pathWithRoot[i];
            const slot = tree[nodeIdx];
            if (slot && slot.nodeType === Nodes.NodeType.PARENT) {
                slot.parent.parentHash = pathHashes[i];
            }
        }
        return leafParentHash;
    }

    /**
     * Receiver side (RFC 9420 §7.9): recompute the committer's direct-path
     * parent-hash chain from the tree we hold post-apply, and verify each
     * parent node carries the expected parent_hash and the committer's
     * LeafNode carries the expected leaf parent_hash. Throws on mismatch;
     * this is the check that turns parent hashes from decoration into a
     * defence against subtree splicing.
     */
    async function verifyCommitterParentHashes(tree, committerLeafIndex, committerLeaf, nLeaves) {
        const { pathWithRoot, pathHashes, leafParentHash } =
            await ParentHash.directPathParentHashes(tree, committerLeafIndex, nLeaves);
        for (let i = 0; i < pathWithRoot.length; i += 1) {
            const nodeIdx = pathWithRoot[i];
            const slot = tree[nodeIdx];
            if (!slot || slot.nodeType !== Nodes.NodeType.PARENT) continue;
            if (!equalBytes(slot.parent.parentHash, pathHashes[i])) {
                throw new Error(
                    `parent-hash: mismatch at node ${nodeIdx} on committer direct path`,
                );
            }
        }
        if (!equalBytes(committerLeaf.parentHash || new Uint8Array(0), leafParentHash)) {
            throw new Error('parent-hash: committer LeafNode.parent_hash mismatch');
        }
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
