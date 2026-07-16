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
 *   epochSecrets        : retained steady-state secrets only
 *                         ({ senderDataSecret, membershipKey, initSecret,
 *                            epochAuthenticator, ... }); one-shot schedule
 *                         values and the SecretTree root are consumed and
 *                         erased before the Group becomes usable
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
    const CREATOR_LEAF_INDEX = 0;
    const BOOTSTRAP_PIN_BYTES = 32;
    // PinChat's creator-centric group profile and relay admission layer are
    // both intentionally capped at 20 members. Enforce the same bound inside
    // the cryptographic state machine so a modified creator cannot hand an
    // honest member an arbitrarily large tree and force unbounded TreeKEM /
    // SecretTree work.
    const MAX_GROUP_LEAVES = 20;
    const MAX_KEY_PACKAGE_LIFETIME_SECONDS = 24n * 60n * 60n;

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

    /**
     * Stable Map key for an RFC 9420 ProposalRef. The active ciphersuite's
     * RefHash output is Nh bytes; rejecting every other length prevents an
     * attacker from populating ambiguous or unbounded reference keys.
     */
    function proposalReferenceKey(reference) {
        if (!(reference instanceof Uint8Array) || reference.length !== HPKE.Nh) {
            const length = reference && Number.isInteger(reference.length)
                ? reference.length : 'malformed';
            throw new Error(
                `proposal-ref: expected ${HPKE.Nh} bytes, got ${length}`,
            );
        }
        let out = '';
        for (let i = 0; i < reference.length; i += 1) {
            out += reference[i].toString(16).padStart(2, '0');
        }
        return out;
    }

    /**
     * Clone mutable MLS state while deliberately retaining WebCrypto key
     * handles. CryptoKey objects are immutable; byte arrays, tree nodes,
     * maps, sets, and their plain-object containers are not and must never
     * be shared between a live Group and a speculative PendingCommit.
     */
    function cloneMutableState(value, seen = new Map()) {
        if (value === null || value === undefined || typeof value !== 'object') {
            return value;
        }
        if (value instanceof Uint8Array) return Uint8Array.from(value);
        if (value instanceof ArrayBuffer) return value.slice(0);
        if (ArrayBuffer.isView(value)) {
            return new value.constructor(value);
        }
        if (seen.has(value)) return seen.get(value);
        if (Array.isArray(value)) {
            const copy = [];
            seen.set(value, copy);
            for (const item of value) copy.push(cloneMutableState(item, seen));
            return copy;
        }
        if (value instanceof Map) {
            const copy = new Map();
            seen.set(value, copy);
            for (const [key, item] of value) {
                copy.set(cloneMutableState(key, seen), cloneMutableState(item, seen));
            }
            return copy;
        }
        if (value instanceof Set) {
            const copy = new Set();
            seen.set(value, copy);
            for (const item of value) copy.add(cloneMutableState(item, seen));
            return copy;
        }
        // CryptoKey and other host objects have a non-plain prototype and
        // are immutable handles for our purposes. Sharing them cannot let a
        // candidate transition mutate the live epoch.
        const prototype = Object.getPrototypeOf(value);
        if (prototype !== Object.prototype && prototype !== null) return value;
        const copy = {};
        seen.set(value, copy);
        for (const [key, item] of Object.entries(value)) {
            copy[key] = cloneMutableState(item, seen);
        }
        return copy;
    }

    function wipeBytes(value) {
        if (value instanceof Uint8Array) value.fill(0);
    }

    function wipeTreeKemSecrets(leafSecret, leafNodePair, chain) {
        wipeBytes(leafSecret);
        if (leafNodePair) wipeBytes(leafNodePair.pathSecret);
        if (!Array.isArray(chain)) return;
        for (const entry of chain) {
            if (!entry) continue;
            wipeBytes(entry.pathSecret);
            wipeBytes(entry.nodeSecret); // Backward-compatible shape.
        }
    }

    const CONSUMED_EPOCH_SECRETS = new Set([
        'joinerSecret',
        'welcomeSecret',
        'epochSecret',
        'encryptionSecret',
        // confirmation_key authenticates the transition into this epoch and
        // has no steady-state use once that transition has been accepted.
        'confirmationKey',
    ]);

    /**
     * Convert the full key-schedule output into the minimum state retained
     * by an active Group. The encryption_secret is consumed into generation-0
     * application/handshake roots for every live leaf; root/intermediate
     * SecretTree material and one-shot epoch-transition secrets are erased.
     */
    async function prepareEpochSecretsForStorage(
        epochSecrets, ratchetTree, nLeaves,
    ) {
        if (!epochSecrets || typeof epochSecrets !== 'object') {
            throw new Error('group: missing epoch secret schedule');
        }
        const encryptionSecret = epochSecrets.encryptionSecret;
        let leafRatchetRoots;
        const activeLeafIndices = new Set();
        for (let leafIndex = 0; leafIndex < nLeaves; leafIndex += 1) {
            if (RatchetTree.leafFor(ratchetTree, leafIndex)) {
                activeLeafIndices.add(leafIndex);
            }
        }
        try {
            leafRatchetRoots = await SecretTree.consumeEncryptionSecret(
                encryptionSecret, nLeaves, activeLeafIndices,
            );
        } catch (err) {
            // A partially-derived schedule must never survive a failed
            // SecretTree initialization.
            for (const value of Object.values(epochSecrets)) wipeBytes(value);
            throw err;
        }
        const chainStates = new Map();

        try {
            for (let leafIndex = 0; leafIndex < nLeaves; leafIndex += 1) {
                const roots = leafRatchetRoots[leafIndex];
                if (!RatchetTree.leafFor(ratchetTree, leafIndex)) {
                    if (roots) {
                        throw new Error(
                            `group: SecretTree derived roots for blank leaf ${leafIndex}`,
                        );
                    }
                    continue;
                }
                if (!roots) {
                    throw new Error(
                        `group: SecretTree did not derive roots for leaf ${leafIndex}`,
                    );
                }
                chainStates.set(`${leafIndex}:application`, {
                    nextGeneration: 0,
                    secret: roots.application,
                    skipped: new Map(),
                });
                chainStates.set(`${leafIndex}:handshake`, {
                    nextGeneration: 0,
                    secret: roots.handshake,
                    skipped: new Map(),
                });
            }
        } catch (err) {
            for (const st of chainStates.values()) {
                wipeBytes(st.secret);
                for (const value of st.skipped.values()) {
                    wipeBytes(value.key);
                    wipeBytes(value.nonce);
                }
            }
            for (const roots of leafRatchetRoots) {
                if (!roots) continue;
                wipeBytes(roots.application);
                wipeBytes(roots.handshake);
            }
            for (const value of Object.values(epochSecrets)) wipeBytes(value);
            throw err;
        }

        const retainedEpochSecrets = {};
        for (const [name, value] of Object.entries(epochSecrets)) {
            if (CONSUMED_EPOCH_SECRETS.has(name)) {
                wipeBytes(value);
                continue;
            }
            retainedEpochSecrets[name] = value;
        }
        return { epochSecrets: retainedEpochSecrets, chainStates };
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
            if (!state || !Number.isInteger(state.nLeaves)
                || state.nLeaves < 1 || state.nLeaves > MAX_GROUP_LEAVES) {
                throw new Error(
                    `group: nLeaves must be in [1,${MAX_GROUP_LEAVES}]`,
                );
            }
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
         * Best-effort zeroisation for one map of stateful SecretTree
         * chains. The map itself may be a live epoch, a previous-epoch
         * grace context, or a tentative receive transaction.
         */
        _wipeChainStateMap(chainStates) {
            if (!(chainStates instanceof Map)) return;
            for (const st of chainStates.values()) {
                this._wipeChainState(st);
            }
            chainStates.clear();
        }

        _wipeChainState(st) {
            if (!st || typeof st !== 'object') return;
            if (st.secret instanceof Uint8Array) st.secret.fill(0);
            if (!(st.skipped instanceof Map)) return;
            for (const v of st.skipped.values()) {
                if (v.key instanceof Uint8Array) v.key.fill(0);
                if (v.nonce instanceof Uint8Array) v.nonce.fill(0);
            }
            st.skipped.clear();
        }

        /**
         * Zero and drop all stateful chain material. Called on every
         * epoch transition. The next epoch installs pre-derived generation-0
         * roots before it becomes active.
         */
        _resetChainStates() {
            if (!this._chainStates) {
                this._chainStates = new Map();
                return;
            }
            this._wipeChainStateMap(this._chainStates);
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
        _snapshotPrevEpoch(removedLeafIndices = []) {
            this._dropPrevEpoch();
            const outgoingEpochSecrets = this.epochSecrets;
            const removed = new Set(removedLeafIndices);
            const allowedSenderLeafIndices = new Set();
            for (let leafIndex = 0; leafIndex < this.nLeaves; leafIndex += 1) {
                if (RatchetTree.leafFor(this.ratchetTree, leafIndex)
                    && !removed.has(leafIndex)) {
                    allowedSenderLeafIndices.add(leafIndex);
                }
            }
            this._prevEpoch = {
                epoch: this.epoch,
                nLeaves: this.nLeaves,
                ratchetTree: this.ratchetTree,
                groupContext: this._buildGroupContextStruct(),
                senderDataSecret: outgoingEpochSecrets.senderDataSecret,
                chainStates: this._chainStates,
                consumedByLeaf: this.consumedByLeaf,
                // Old-epoch delivery tolerance must not extend a member's
                // authorization past a Remove. Surviving leaves may still
                // deliver messages that were already in flight; removed
                // leaves are rejected immediately after sender_data opens,
                // before their receive chain is touched.
                allowedSenderLeafIndices,
                expiresAt: Date.now() + PREV_EPOCH_GRACE_MS,
            };
            // sender_data_secret remains owned by the bounded grace context.
            // Everything else from the outgoing epoch has no remaining use.
            for (const [name, value] of Object.entries(outgoingEpochSecrets)) {
                if (name !== 'senderDataSecret') wipeBytes(value);
            }
            // Chain-state ownership moved into the snapshot; the new
            // epoch installs its already-derived roots after this snapshot.
            this._chainStates = new Map();
        }

        /**
         * Zero and drop the retained previous-epoch context.
         */
        _dropPrevEpoch() {
            if (!this._prevEpoch) return;
            wipeBytes(this._prevEpoch.senderDataSecret);
            this._wipeChainStateMap(this._prevEpoch.chainStates);
            if (this._prevEpoch.allowedSenderLeafIndices instanceof Set) {
                this._prevEpoch.allowedSenderLeafIndices.clear();
            }
            this._prevEpoch = null;
        }

        /**
         * Best-effort destruction of all extractable symmetric state owned
         * by this Group. Used when a speculative PendingCommit is abandoned
         * and when an accepted candidate supersedes the old live Group.
         * WebCrypto private-key handles cannot be overwritten from JavaScript;
         * all references are dropped below so the browser can release them.
         */
        destroySecrets() {
            if (this.epochSecrets && typeof this.epochSecrets === 'object') {
                for (const value of Object.values(this.epochSecrets)) wipeBytes(value);
                this.epochSecrets = {};
            }
            this._wipeChainStateMap(this._chainStates);
            this._chainStates = new Map();
            this._dropPrevEpoch();
            wipeBytes(this.pskSecret);
            this.pskSecret = null;
            if (this.consumedByLeaf instanceof Map) this.consumedByLeaf.clear();
            if (this.parentKeyPairs instanceof Map) this.parentKeyPairs.clear();
            this.parentKeyPairs = new Map();
            // CryptoKey handles cannot be overwritten, but dropping every
            // reference makes the browser eligible to release them. This is
            // especially important for an authenticated Remove, where the
            // session must become terminal rather than retain stale signing
            // or TreeKEM capabilities.
            this.leafKeyPair = null;
            this.identity = null;
            this.senderRatchetGeneration = 0;
            this._destroyed = true;
        }

        /**
         * Stage a receive-ratchet advance without touching live state.
         *
         * PrivateMessage must derive the content key before it can perform
         * AEAD authentication, and the FramedContent signature is inside
         * that ciphertext. Advancing the live chain at derivation time
         * would therefore let a corrupt ciphertext (or an AEAD-valid message
         * with an invalid signature) burn a generation. Instead, derive on a
         * deep copy and make the caller explicitly commit only after every
         * authentication and replay check succeeds.
         */
        _beginReceiveRatchetTransaction(chainStates, nLeaves) {
            // Copy the map container, then detach only the single sender
            // chain selected by decrypted sender_data. Cloning every other
            // sender's skipped-key cache for each message would turn the
            // authentication safeguard itself into an avoidable DoS cost.
            const stagedChainStates = new Map(chainStates);
            const ephemeralKeyNonces = [];
            let touchedChainId = null;
            let originalChainState = null;
            let stagedChainState = null;
            let settled = false;

            return {
                keyNonceProvider: async (leafIndex, which, generation) => {
                    if (touchedChainId !== null) {
                        throw new Error('group: receive transaction requested more than one chain');
                    }
                    touchedChainId = `${leafIndex}:${which}`;
                    originalChainState = chainStates.get(touchedChainId) || null;
                    if (originalChainState) {
                        stagedChainStates.set(
                            touchedChainId, cloneMutableState(originalChainState),
                        );
                    }
                    let keyNonce;
                    try {
                        keyNonce = await this._chainKeyNonceIn(
                            stagedChainStates, nLeaves,
                            leafIndex, which, generation,
                        );
                    } finally {
                        stagedChainState = stagedChainStates.get(touchedChainId) || null;
                    }
                    // The selected generation is no longer retained in the
                    // staged map. Track its one-shot key material so both
                    // commit and rollback can erase our last JS references.
                    ephemeralKeyNonces.push(keyNonce);
                    return keyNonce;
                },
                commit: () => {
                    if (settled) return null;
                    settled = true;
                    for (const value of ephemeralKeyNonces) {
                        if (value.key instanceof Uint8Array) value.key.fill(0);
                        if (value.nonce instanceof Uint8Array) value.nonce.fill(0);
                    }
                    ephemeralKeyNonces.length = 0;
                    if (originalChainState) this._wipeChainState(originalChainState);
                    // Unchanged chain objects are deliberately shared with
                    // stagedChainStates. Drop only the superseded map
                    // container; wiping it would destroy those accepted
                    // chains as well.
                    chainStates.clear();
                    return stagedChainStates;
                },
                rollback: () => {
                    if (settled) return;
                    settled = true;
                    for (const value of ephemeralKeyNonces) {
                        if (value.key instanceof Uint8Array) value.key.fill(0);
                        if (value.nonce instanceof Uint8Array) value.nonce.fill(0);
                    }
                    ephemeralKeyNonces.length = 0;
                    if (stagedChainState && stagedChainState !== originalChainState) {
                        this._wipeChainState(stagedChainState);
                    }
                    stagedChainStates.clear();
                },
            };
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
         * Sending consumes immediately after derivation. Receiving calls
         * this helper only against a tentative chain copy and installs that
         * copy after AEAD, replay, sender, and signature authentication.
         */
        async _chainKeyNonce(leafIndex, which, generation) {
            return this._chainKeyNonceIn(
                this._chainStates, this.nLeaves,
                leafIndex, which, generation,
            );
        }

        async _chainKeyNonceIn(chainStates, nLeaves, leafIndex, which, generation) {
            const id = `${leafIndex}:${which}`;
            let st = chainStates.get(id);
            if (!st) {
                throw new Error(
                    `group: no ${which} SecretTree ratchet for leaf ${leafIndex} `
                    + `(nLeaves=${nLeaves})`,
                );
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
            const basicCredentialIdentity = credentialIdentity
                || identity.signaturePublicKeyBytes;
            if (!equalBytes(
                basicCredentialIdentity, identity.signaturePublicKeyBytes,
            )) {
                throw new Error(
                    'group.create: basic credential identity must equal signature_key '
                    + 'in the PinChat profile',
                );
            }

            const leaf = buildSelfLeaf({
                encryptionKeyBytes: encKeyPair.publicKeyBytes,
                signatureKeyBytes: identity.signaturePublicKeyBytes,
                credentialIdentity: basicCredentialIdentity,
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
            // The Group owns and eventually erases this copy; never alias a
            // session/bootstrap buffer that another component may still use.
            const psk = pskSecret
                ? Uint8Array.from(pskSecret)
                : new Uint8Array(HPKE.Nh);
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
            const initialCommitSecret = new Uint8Array(HPKE.Nh);
            try {
                await group._deriveEpoch({
                    initSecretPrev: initSecret,
                    commitSecret: initialCommitSecret,
                    pskSecret: psk,
                });
            } finally {
                // Both inputs are consumed by the epoch-0 key schedule.
                initSecret.fill(0);
                initialCommitSecret.fill(0);
            }
            return group;
        }

        /**
         * Ingest an externally-constructed group state (testing + future
         * Welcome path). Inputs must already be a complete, consistent
         * state object. This is the escape hatch that lets tests build
         * two synchronised members without going through a full
         * Commit+Welcome round-trip.
         */
        static async fromState(state) {
            const copied = cloneMutableState(state);
            const suppliedChainStates = copied._chainStates;
            const suppliedConsumed = copied.consumedByLeaf;
            const suppliedPreviousEpoch = copied._prevEpoch;
            const group = new Group(copied);

            if (copied.epochSecrets && copied.epochSecrets.encryptionSecret) {
                const prepared = await prepareEpochSecretsForStorage(
                    copied.epochSecrets, copied.ratchetTree, copied.nLeaves,
                );
                group.epochSecrets = prepared.epochSecrets;
                group._chainStates = prepared.chainStates;
            } else if (suppliedChainStates instanceof Map) {
                // A clone of an already-live Group has no encryption_secret;
                // its stateful ratchets are the only valid continuation.
                group._chainStates = suppliedChainStates;
            } else {
                throw new Error(
                    'group.fromState: state has neither encryption_secret nor initialized ratchets',
                );
            }
            if (suppliedConsumed instanceof Map) {
                group.consumedByLeaf = suppliedConsumed;
            }
            if (suppliedPreviousEpoch) group._prevEpoch = suppliedPreviousEpoch;
            return group;
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

        /**
         * Produce an isolated candidate for one locally-authored Commit.
         * The existing commitAddMember / commitUpdate / commitRemoveMember
         * implementations may mutate this candidate normally, while the
         * live Group remains on the accepted epoch until the relay echoes
         * the exact Commit. The previous-previous epoch is intentionally
         * omitted: every successful transition drops it before snapshotting
         * the current epoch, so copying it would only retain obsolete key
         * material for longer.
         */
        forkForPendingCommit() {
            const state = {};
            for (const [key, value] of Object.entries(this)) {
                if (key === 'consumedByLeaf'
                    || key === '_chainStates'
                    || key === '_prevEpoch') continue;
                state[key] = cloneMutableState(value);
            }
            const candidate = new Group(state);
            candidate.consumedByLeaf = cloneMutableState(this.consumedByLeaf);
            candidate._chainStates = cloneMutableState(this._chainStates);
            candidate._prevEpoch = null;
            return candidate;
        }

        async _deriveEpoch({ initSecretPrev, commitSecret, pskSecret }) {
            const groupContextBytes = this._groupContextBytes();
            const out = await KeySchedule.deriveEpoch({
                initSecretPrev,
                commitSecret,
                pskSecret,
                groupContext: groupContextBytes,
            });
            const prepared = await prepareEpochSecretsForStorage(
                out, this.ratchetTree, this.nLeaves,
            );
            this.epochSecrets = prepared.epochSecrets;
            this._chainStates = prepared.chainStates;
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
         * Returns { plaintext, senderLeafIndex, senderSignatureKey }: the
         * leaf index and copied signature key identify the CRYPTOGRAPHICALLY
         * authenticated sender (the signature was verified against that
         * exact LeafNode), as opposed to the relay envelope's unauthenticated
         * sender_id. Callers doing sender attribution MUST derive it from
         * senderSignatureKey, not from transport metadata.
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

            const baseChainStates = this._chainStates;
            const ratchetTx = this._beginReceiveRatchetTransaction(
                baseChainStates, this.nLeaves,
            );
            try {
                const out = await PrivateMessage.decryptPrivateMessage({
                    pm,
                    senderDataSecret: this.epochSecrets.senderDataSecret,
                    nLeaves: this.nLeaves,
                    keyNonceProvider: ratchetTx.keyNonceProvider,
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

                // No asynchronous or fallible validation follows this point.
                // Swap the staged chain in one step, then destroy the
                // superseded representation and record replay acceptance.
                if (this._chainStates !== baseChainStates) {
                    throw new Error('group: concurrent receive-ratchet mutation');
                }
                const acceptedChainStates = ratchetTx.commit();
                this._chainStates = acceptedChainStates;
                this._markGenerationConsumed(senderLeafIndex, generation);

                return {
                    plaintext: out.content.payloadBytes,
                    senderLeafIndex,
                    senderSignatureKey: Uint8Array.from(senderLeaf.signatureKey),
                };
            } catch (err) {
                ratchetTx.rollback();
                throw err;
            }
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

            const baseChainStates = pe.chainStates;
            const ratchetTx = this._beginReceiveRatchetTransaction(
                baseChainStates, pe.nLeaves,
            );
            try {
                const out = await PrivateMessage.decryptPrivateMessage({
                    pm,
                    senderDataSecret: pe.senderDataSecret,
                    nLeaves: pe.nLeaves,
                    keyNonceProvider: async (leafIndex, which, generation) => {
                        if (!(pe.allowedSenderLeafIndices instanceof Set)
                            || !pe.allowedSenderLeafIndices.has(leafIndex)) {
                            throw new Error(
                                `group: previous-epoch sender leaf ${leafIndex} was removed`,
                            );
                        }
                        return ratchetTx.keyNonceProvider(
                            leafIndex, which, generation,
                        );
                    },
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

                if (this._prevEpoch !== pe || pe.chainStates !== baseChainStates) {
                    throw new Error('group: concurrent previous-epoch receive-ratchet mutation');
                }
                const acceptedChainStates = ratchetTx.commit();
                pe.chainStates = acceptedChainStates;
                if (!consumedSet) {
                    consumedSet = new Set();
                    pe.consumedByLeaf.set(senderLeafIndex, consumedSet);
                }
                consumedSet.add(generation);

                return {
                    plaintext: out.content.payloadBytes,
                    senderLeafIndex,
                    senderSignatureKey: Uint8Array.from(senderLeaf.signatureKey),
                };
            } catch (err) {
                ratchetTx.rollback();
                throw err;
            }
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
    // Every Commit stamps the committer's parent-hash chain (§7.9).
    // Existing members verify that newly applied path; a Welcome joiner
    // additionally validates every non-blank leaf and parent in the
    // imported tree before accepting epoch secrets.
    // ------------------------------------------------------------------

    /**
     * Single final-tree gate for every Commit transition. Keeping this as a
     * Group method gives the malicious-committer tests an explicit seam to
     * model a modified client which bypasses its own checks; honest receivers
     * still run their independent copy from processCommit().
     */
    Group.prototype._verifyFinalTreeKeyUniqueness =
        function _verifyFinalTreeKeyUniqueness(tree, operation) {
            verifyTreeKeyUniqueness(tree, operation);
        };

    function nextAddPosition(tree, nLeaves, operation) {
        for (let leafIndex = 0; leafIndex < nLeaves; leafIndex += 1) {
            if (!RatchetTree.leafFor(tree, leafIndex)) {
                return { leafIndex, nLeaves };
            }
        }
        if (nLeaves >= MAX_GROUP_LEAVES) {
            throw new Error(
                `${operation}: group is at the ${MAX_GROUP_LEAVES}-leaf limit`,
            );
        }
        return { leafIndex: nLeaves, nLeaves: nLeaves + 1 };
    }

    /**
     * Read-only admission gate used by MLSSession before it durably queues a
     * KeyPackage behind an in-flight PendingCommit. This validates every
     * deterministic property which could otherwise make the later Add fail:
     * KeyPackage/LeafNode bindings, the structural leaf cap, and collisions
     * with the current tree. The actual Commit still repeats these checks.
     */
    Group.prototype.validateKeyPackageForAdd =
        async function validateKeyPackageForAdd(keyPackageBytes) {
            const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
            await verifyKeyPackageBindings(kp, 'validateKeyPackageForAdd');
            const position = nextAddPosition(
                this.ratchetTree, this.nLeaves, 'validateKeyPackageForAdd',
            );
            const candidateTree = Nodes.padRatchetTree(
                this.ratchetTree.slice(),
                TreeMath.nodeWidth(position.nLeaves),
            );
            candidateTree[TreeMath.leafToNode(position.leafIndex)] = {
                nodeType: Nodes.NodeType.LEAF,
                leaf: kp.leafNode,
            };
            verifyTreeKeyUniqueness(
                candidateTree, 'validateKeyPackageForAdd',
            );
            return {
                keyPackage: kp,
                addedLeafIndex: position.leafIndex,
                nLeaves: position.nLeaves,
            };
        };

    /**
     * Validate the complete proposal list against the pre-Commit tree and
     * return the RFC 9420 §12.3 application phases.  The proposal vector's
     * wire order remains untouched (it is signed and transcript-bound); only
     * application is phased as Update -> Remove -> Add.  Keeping this as a
     * Group method also gives honest committers and independent receivers the
     * same fail-closed gate.
     */
    Group.prototype._validateCommitProposalList =
        function _validateCommitProposalList(proposalOrRefs, committerLeafIndex, operation) {
            return validateCommitProposalList(
                proposalOrRefs,
                this.ratchetTree,
                this.nLeaves,
                committerLeafIndex,
                operation,
            );
        };

    /**
     * Resolve every ProposalRef against this member's authenticated,
     * current-epoch proposal store. Store metadata is never trusted as the
     * proof: the exact standalone PublicMessage is parsed and all of its
     * epoch, signature, membership-tag, LeafNode-binding, and key-uniqueness
     * checks are repeated here before the proposal reaches candidate-tree
     * construction. Nothing is removed from the store on failure; the
     * orchestrator consumes the epoch store only after Commit acceptance.
     */
    Group.prototype._resolveCommitProposalList =
        async function _resolveCommitProposalList(
            proposalOrRefs, proposalStore, operation,
        ) {
            if (!Array.isArray(proposalOrRefs)) {
                throw new Error(`${operation}: malformed proposal list`);
            }
            const resolved = [];
            const seenReferences = new Set();
            for (let wireIndex = 0; wireIndex < proposalOrRefs.length; wireIndex += 1) {
                const por = proposalOrRefs[wireIndex];
                if (!por || !Number.isInteger(por.type)) {
                    throw new Error(`${operation}: malformed proposal at index ${wireIndex}`);
                }
                if (por.type === Proposal.ProposalOrRefType.PROPOSAL) {
                    resolved.push({
                        type: por.type,
                        proposal: por.proposal,
                        proposalSource: 'inline',
                    });
                    continue;
                }
                if (por.type !== Proposal.ProposalOrRefType.REFERENCE) {
                    throw new Error(
                        `${operation}: unsupported ProposalOrRef type ${por.type}`,
                    );
                }

                const referenceKey = proposalReferenceKey(por.reference);
                if (seenReferences.has(referenceKey)) {
                    throw new Error(
                        `${operation}: duplicate ProposalRef at index ${wireIndex}`,
                    );
                }
                seenReferences.add(referenceKey);
                if (!(proposalStore instanceof Map)) {
                    throw new Error(
                        `${operation}: ProposalRef requires an authenticated proposal store`,
                    );
                }
                const stored = proposalStore.get(referenceKey);
                if (!stored || !(stored.messageBytes instanceof Uint8Array)) {
                    throw new Error(
                        `${operation}: unknown ProposalRef at index ${wireIndex}`,
                    );
                }

                // allowOwnSender is required for the member whose own Update
                // is being committed. Network echoes are still rejected by
                // the ordinary receive path before storage.
                const verified = await this.verifyUpdateProposal(
                    stored.messageBytes, { allowOwnSender: true },
                );
                if (!equalBytes(verified.reference, por.reference)) {
                    throw new Error(
                        `${operation}: stored proposal does not match ProposalRef at index ${wireIndex}`,
                    );
                }
                resolved.push({
                    type: por.type,
                    reference: Uint8Array.from(por.reference),
                    proposal: verified.proposal,
                    proposalSenderLeafIndex: verified.senderLeafIndex,
                    proposalEpoch: verified.epoch,
                    proposalSource: 'reference',
                });
            }
            return resolved;
        };

    Group.prototype.commitAddMember = async function commitAddMember({ keyPackageBytes }) {
        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);

        // ---- 0. Verify the joiner's KeyPackage and inner LeafNode ----
        // Without this, a malicious relay could substitute leafNode fields
        // (encryption_key, signature_key, credential) and have us insert
        // an attacker-controlled leaf into the tree. The signing key is
        // taken from kp.leafNode.signatureKey because our credential model
        // ties identity to the signature key directly.
        await verifyKeyPackageBindings(kp, 'commitAddMember');

        // ---- 1. Compute new tree shape, insert new leaf ----
        // RFC tree slots are stable, but a blank leaf left by Remove is
        // immediately reusable. Reusing the leftmost blank prevents harmless
        // membership churn from growing the logical tree toward the profile
        // cap while preserving every still-live leaf index.
        const addPosition = nextAddPosition(
            this.ratchetTree, this.nLeaves, 'commitAddMember',
        );
        const newLeafIndex = addPosition.leafIndex;
        const newNLeaves = addPosition.nLeaves;
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

        // Reject a malicious KeyPackage which reuses any live signature or
        // HPKE key, and also guard against collisions involving the freshly
        // generated committer path. This runs before tree_hash, transcripts,
        // epoch-secret derivation, Welcome construction, or local mutation.
        this._verifyFinalTreeKeyUniqueness(newTree, 'commitAddMember');

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
        const commitSecretBytes = await TreeKEM.commitSecret(rootChainEntry.pathSecret);
        let epochSecrets;
        try {
            epochSecrets = await KeySchedule.deriveEpoch({
                initSecretPrev: this.epochSecrets.initSecret,
                commitSecret: commitSecretBytes,
                pskSecret: this.pskSecret,
                groupContext: epochGroupContextBytes,
            });
        } finally {
            commitSecretBytes.fill(0);
        }

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
        gsBytes.fill(0);
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
        welcomeSecret.fill(0);
        wKey.fill(0);
        wNonce.fill(0);

        const preparedEpoch = await prepareEpochSecretsForStorage(
            epochSecrets, newTree, newNLeaves,
        );
        const previousInitSecret = this.epochSecrets.initSecret;

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
        this.epochSecrets = preparedEpoch.epochSecrets;
        this._chainStates = preparedEpoch.chainStates;
        previousInitSecret.fill(0);
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
        wipeTreeKemSecrets(leafSecret, leafNodePair, chain);

        return { commitMessage, welcomeMessage, addedLeafIndex: newLeafIndex };
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
        if (removedLeafIndex === CREATOR_LEAF_INDEX) {
            throw new Error('commitRemoveMember: creator leaf 0 cannot be removed');
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

        // Remove cannot introduce an attacker-chosen leaf, but its fresh
        // committer leaf and path still form a new final tree and therefore
        // pass through the same invariant gate as every other Commit.
        this._verifyFinalTreeKeyUniqueness(newTree, 'commitRemoveMember');

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
        const commitSecretBytes = await TreeKEM.commitSecret(rootChainEntry.pathSecret);
        let epochSecrets;
        try {
            epochSecrets = await KeySchedule.deriveEpoch({
                initSecretPrev: this.epochSecrets.initSecret,
                commitSecret: commitSecretBytes,
                pskSecret: this.pskSecret,
                groupContext: epochGroupContextBytes,
            });
        } finally {
            commitSecretBytes.fill(0);
        }

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
        const preparedEpoch = await prepareEpochSecretsForStorage(
            epochSecrets, newTree, newNLeaves,
        );
        const previousInitSecret = this.epochSecrets.initSecret;

        // ---- 11. Apply commit to local state ----
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch([removedLeafIndex]);
        this.ratchetTree = newTree;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = preparedEpoch.epochSecrets;
        this._chainStates = preparedEpoch.chainStates;
        previousInitSecret.fill(0);
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
        wipeTreeKemSecrets(leafSecret, leafNodePair, chain);

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
     * Returns the complete authenticated proposal-store entry alongside the
     * pending private keypair. `reference` is computed over the serialized
     * AuthenticatedContent (wire_format + FramedContent + auth), excluding
     * both the PublicMessage membership_tag and the outer MLSMessage wrapper.
     * The caller (mls-session) retains pendingLeafKeyPair under this exact
     * reference and supplies it to processCommit(); the key is installed
     * only after the referenced Commit fully authenticates.
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
        const authenticatedContent = Framing.authenticatedContentBytes({
            wireFormat, content, auth,
        });
        const reference = await Commit.proposalRef(authenticatedContent);

        return {
            proposalMessage,
            messageBytes: Uint8Array.from(proposalMessage),
            reference,
            proposal,
            senderLeafIndex: this.myLeafIndex,
            epoch: this.epoch,
            pendingLeafKeyPair: newLeafKeyPair,
            pendingLeafNode: leaf,
        };
    };

    /**
     * Authenticate a standalone member Update proposal before an
     * orchestrator buffers it for a later Commit. The LeafNode signature
     * alone is not sufficient here: its TBS binds group_id + leaf_index but
     * not the epoch, so accepting only that signature would allow a relay to
     * replay an old, once-valid Update and roll a member back to an obsolete
     * HPKE leaf key. The surrounding PublicMessage signature and
     * membership_tag bind the proposal to the current GroupContext/epoch.
     *
     * This method is deliberately read-only. It returns the authenticated
     * proposal, its cryptographic sender leaf, its exact message bytes, and
     * its RFC ProposalRef for storage and later one-shot resolution.
     */
    Group.prototype.verifyUpdateProposal = async function verifyUpdateProposal(
        proposalMessageBytes,
        { allowOwnSender = false } = {},
    ) {
        const frame = MLSMessage.parseMLSMessage(proposalMessageBytes);
        if (frame.wireFormat !== MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE) {
            throw new Error(
                `verifyUpdateProposal: expected mls_public_message, got ${frame.wireFormat}`,
            );
        }
        const pm = PublicMessage.parsePublicMessage(frame.body, (decoder, contentType) => {
            if (contentType !== Framing.ContentType.PROPOSAL) {
                throw new Error(
                    `verifyUpdateProposal: expected proposal, got content_type ${contentType}`,
                );
            }
            return Proposal.readProposal(decoder);
        });
        const content = pm.content;
        if (content.contentType !== Framing.ContentType.PROPOSAL) {
            throw new Error(
                `verifyUpdateProposal: expected proposal, got ${content.contentType}`,
            );
        }
        if (!equalBytes(content.groupId, this.groupId)) {
            throw new Error('verifyUpdateProposal: group_id mismatch');
        }
        if (content.epoch !== this.epoch) {
            throw new Error(
                `verifyUpdateProposal: wrong epoch (got ${content.epoch}, expected ${this.epoch})`,
            );
        }
        if (!content.sender
            || content.sender.senderType !== Framing.SenderType.MEMBER) {
            throw new Error('verifyUpdateProposal: non-member sender not supported');
        }
        const senderLeafIndex = content.sender.leafIndex;
        if (!Number.isInteger(senderLeafIndex) || senderLeafIndex < 0
            || senderLeafIndex >= this.nLeaves) {
            throw new Error(
                `verifyUpdateProposal: sender leaf_index ${senderLeafIndex} out of range`,
            );
        }
        if (senderLeafIndex === this.myLeafIndex && !allowOwnSender) {
            throw new Error('verifyUpdateProposal: own proposal echo (filter upstream)');
        }
        const senderLeaf = RatchetTree.leafFor(this.ratchetTree, senderLeafIndex);
        if (!senderLeaf) {
            throw new Error(`verifyUpdateProposal: unknown sender leaf ${senderLeafIndex}`);
        }

        const wireFormat = MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE;
        const senderSigPub = await Signature.importPublicKey(senderLeaf.signatureKey);
        const sigOk = await PublicMessage.verifyFramedContent(
            senderSigPub, wireFormat, content,
            this._buildGroupContextStruct(), pm.auth.signature,
        );
        if (!sigOk) {
            throw new Error('verifyUpdateProposal: FramedContent signature invalid');
        }
        const membershipOk = await PublicMessage.verifyMembershipTag(
            this.epochSecrets.membershipKey, wireFormat, content, pm.auth,
            this._buildGroupContextStruct(), pm.membershipTag,
        );
        if (!membershipOk) {
            throw new Error('verifyUpdateProposal: membership_tag invalid');
        }

        const proposal = content.parsed;
        if (!proposal || proposal.proposalType !== Proposal.ProposalType.UPDATE) {
            throw new Error('verifyUpdateProposal: only Update proposals are supported');
        }
        await verifyUpdateLeafBinding(
            proposal.leafNode, senderLeaf.signatureKey, senderLeaf.encryptionKey,
            this.groupId, senderLeafIndex,
        );
        const candidateTree = this.ratchetTree.slice();
        const senderNodeIndex = TreeMath.leafToNode(senderLeafIndex);
        candidateTree[senderNodeIndex] = {
            nodeType: Nodes.NodeType.LEAF,
            leaf: proposal.leafNode,
        };
        for (const ancestor of TreeMath.directPathWithRoot(
            senderNodeIndex, this.nLeaves,
        )) {
            candidateTree[ancestor] = null;
        }
        verifyTreeKeyUniqueness(candidateTree, 'verifyUpdateProposal');
        const authenticatedContent = Framing.authenticatedContentBytes({
            wireFormat, content, auth: pm.auth,
        });
        const reference = await Commit.proposalRef(authenticatedContent);
        return {
            proposal,
            senderLeafIndex,
            epoch: content.epoch,
            reference,
            messageBytes: Uint8Array.from(proposalMessageBytes),
        };
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
     * `updateProposals` (optional): authenticated proposal-store entries
     * returned by verifyUpdateProposal(). The wire Commit carries only each
     * entry's ProposalRef; the standalone authenticated PublicMessage is
     * re-verified before its Update is applied. Each Update installs the
     * proposer's fresh leaf and blanks that leaf's direct path BEFORE the
     * committer builds its own UpdatePath, so the committer's re-key routes
     * new path secrets to the updated members' new keys.
     *
     * Scope note: this heals leakage of the current epoch secrets (an
     * attacker holding epoch n secrets cannot follow into epoch n+1
     * without the committer's fresh path secret). A compromised MEMBER leaf
     * private key is healed only when that member's authenticated Update
     * ProposalRef is folded into a Commit; the fresh member leaf and
     * committer path then advance the group beyond the compromised key.
     *
     * Returns { commitMessage }.
     */
    Group.prototype.commitUpdate = async function commitUpdate({ updateProposals = [] } = {}) {
        if (!Array.isArray(updateProposals)) {
            throw new Error('commitUpdate: updateProposals must be an array');
        }
        const newNLeaves = this.nLeaves;
        const newWidth = TreeMath.nodeWidth(newNLeaves);
        const newTree = Nodes.padRatchetTree(this.ratchetTree.slice(), newWidth);

        const proposalStore = new Map();
        const proposalOrRefs = updateProposals.map((up, index) => {
            if (!up || !(up.reference instanceof Uint8Array)
                || !(up.messageBytes instanceof Uint8Array)) {
                throw new Error(
                    `commitUpdate: proposal-store entry ${index} is incomplete`,
                );
            }
            const referenceKey = proposalReferenceKey(up.reference);
            if (!proposalStore.has(referenceKey)) proposalStore.set(referenceKey, up);
            return {
                type: Proposal.ProposalOrRefType.REFERENCE,
                reference: Uint8Array.from(up.reference),
            };
        });
        const resolvedProposals = await this._resolveCommitProposalList(
            proposalOrRefs, proposalStore, 'commitUpdate',
        );
        const proposalPlan = this._validateCommitProposalList(
            resolvedProposals, this.myLeafIndex, 'commitUpdate',
        );
        if (proposalPlan.updates.length !== proposalOrRefs.length) {
            throw new Error('commitUpdate: only Update proposals may be folded');
        }

        // ---- 0. Apply Update proposals: install each proposer's fresh
        // leaf and blank its direct path (RFC §12.4.2). Verify each
        // proposal's LeafNode signature against the CURRENT leaf's
        // signature key (no identity rotation in this MVP). The target is
        // the authenticated sender carried by the resolved ProposalRef,
        // never a signature-key scan over an unauthenticated inline leaf.
        for (const entry of proposalPlan.updates) {
            const li = entry.targetLeafIndex;
            const curLeaf = RatchetTree.leafFor(this.ratchetTree, li);
            await verifyUpdateLeafBinding(
                entry.proposal.leafNode,
                curLeaf.signatureKey,
                curLeaf.encryptionKey,
                this.groupId,
                li,
            );
            newTree[TreeMath.leafToNode(li)] = {
                nodeType: Nodes.NodeType.LEAF, leaf: entry.proposal.leafNode,
            };
            for (const ancestor of TreeMath.directPathWithRoot(TreeMath.leafToNode(li), newNLeaves)) {
                newTree[ancestor] = null;
            }
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

        // RFC 9420 §7.3: applying authenticated Update proposals must not
        // create duplicate leaf signature/encryption keys or duplicate HPKE
        // encryption keys anywhere in the resulting ratchet tree. Check on
        // the committer side before hashing the tree or deriving epoch state;
        // receivers enforce the same invariant in processCommit().
        this._verifyFinalTreeKeyUniqueness(newTree, 'commitUpdate');

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
        const commitSecretBytes = await TreeKEM.commitSecret(rootChainEntry.pathSecret);
        let epochSecrets;
        try {
            epochSecrets = await KeySchedule.deriveEpoch({
                initSecretPrev: this.epochSecrets.initSecret,
                commitSecret: commitSecretBytes,
                pskSecret: this.pskSecret,
                groupContext: epochGroupContextBytes,
            });
        } finally {
            commitSecretBytes.fill(0);
        }

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
        const preparedEpoch = await prepareEpochSecretsForStorage(
            epochSecrets, newTree, newNLeaves,
        );
        const previousInitSecret = this.epochSecrets.initSecret;

        // ---- 10. Apply commit to local state ----
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch();
        this.ratchetTree = newTree;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = preparedEpoch.epochSecrets;
        this._chainStates = preparedEpoch.chainStates;
        previousInitSecret.fill(0);
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
        wipeTreeKemSecrets(leafSecret, leafNodePair, chain);

        return { commitMessage };
    };

    /**
     * Process a Commit broadcast by another member. Inputs:
     *   commitMessageBytes : MLSMessage(mls_public_message) bytes
     *
     * Verifies the FramedContent signature + membership_tag, validates and
     * resolves authenticated Update ProposalRefs, applies Update/Remove/Add
     * proposals, walks the UpdatePath to recover our share of the new
     * path_secret chain, and advances the local epoch state.
     */
    Group.prototype.processCommit = async function processCommit(commitMessageBytes, opts = {}) {
        let authenticatedCreatorCommit = false;
        try {
        // pendingSelfUpdate: the { publicKeyBytes, privateKey, ... } keypair
        // we generated for an Update proposal that may be folded into this
        // Commit. If the Commit installs our new leaf, we decrypt the
        // committer's UpdatePath with the NEW private key but stage the swap
        // until all Commit authentication (including confirmation_tag) has
        // succeeded. Ignored if this Commit does not carry our update.
        const pendingSelfUpdate = opts.pendingSelfUpdate || null;
        const pendingSelfUpdates = opts.pendingSelfUpdates instanceof Map
            ? opts.pendingSelfUpdates : null;
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

        // PinChat's current group architecture has one permanent admin: the
        // creator at leaf 0. The signature and membership tag above bind this
        // authorization decision to leaf 0's authenticated identity. A future
        // multiple- or transferable-admin model must instead bind its admin
        // key set into the authenticated GroupContext.
        if (senderLeafIndex !== CREATOR_LEAF_INDEX) {
            throw new Error(
                `processCommit: only creator leaf 0 may commit (got leaf ${senderLeafIndex})`,
            );
        }
        // Everything below is controlled by a creator whose FramedContent
        // signature and membership_tag have both been verified for the
        // current group/epoch. Surface that distinction to the orchestration
        // layer: a deterministic unauthenticated forgery may be dropped, but
        // failure to apply an authenticated creator Commit means this member
        // can no longer safely advance its ordered control cursor.
        authenticatedCreatorCommit = true;

        const commit = content.parsed;
        const resolvedProposals = await this._resolveCommitProposalList(
            commit.proposals, opts.proposalStore, 'processCommit',
        );
        const proposalPlan = this._validateCommitProposalList(
            resolvedProposals, senderLeafIndex, 'processCommit',
        );

        // ---- Apply proposals in RFC 9420 §12.3 phases ----
        // The signed proposal vector need not itself be sorted. Updates are
        // applied first, then Removes, then Adds in their original relative
        // order. The validation pass above resolves every target against the
        // pre-Commit tree and rejects all same-leaf Update/Remove conflicts
        // before any candidate-tree work begins.
        let newTree = this.ratchetTree.slice();
        let newNLeaves = this.nLeaves;
        const addedLeafIndices = [];
        const removedLeafIndices = [];
        let lastAddedLeafIndex = null;
        let lastRemovedLeafIndex = null;
        // Leaves updated by a folded Update proposal, used below so the
        // committing member can swap in its own pending keypair.
        const updatedLeafIndices = [];

        for (const entry of proposalPlan.updates) {
            const newLeaf = entry.proposal.leafNode;
            const updLeafIndex = entry.targetLeafIndex;
            const currentUpdateLeaf = RatchetTree.leafFor(
                this.ratchetTree, updLeafIndex,
            );
            await verifyUpdateLeafBinding(
                newLeaf,
                currentUpdateLeaf.signatureKey,
                currentUpdateLeaf.encryptionKey,
                this.groupId,
                updLeafIndex,
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
        }

        for (const entry of proposalPlan.removes) {
            const rmIdx = entry.targetLeafIndex;
            const rmNode = TreeMath.leafToNode(rmIdx);
            newTree[rmNode] = null;
            for (const ancestor of TreeMath.directPathWithRoot(rmNode, newNLeaves)) {
                newTree[ancestor] = null;
            }
            removedLeafIndices.push(rmIdx);
            lastRemovedLeafIndex = rmIdx;
        }

        for (const entry of proposalPlan.adds) {
            await verifyKeyPackageBindings(
                entry.proposal.keyPackage, 'processCommit',
            );
            const addPosition = nextAddPosition(
                newTree, newNLeaves, 'processCommit',
            );
            const addLeafIndex = addPosition.leafIndex;
            newNLeaves = addPosition.nLeaves;
            const newWidth = TreeMath.nodeWidth(newNLeaves);
            newTree = Nodes.padRatchetTree(newTree, newWidth);
            newTree[TreeMath.leafToNode(addLeafIndex)] = {
                nodeType: Nodes.NodeType.LEAF,
                leaf: entry.proposal.keyPackage.leafNode,
            };
            addedLeafIndices.push(addLeafIndex);
            lastAddedLeafIndex = addLeafIndex;
        }

        // ---- Apply UpdatePath ----
        // A removed member cannot decrypt the new path, but it must not tear
        // itself down merely because an authenticated envelope contains a
        // Remove. Continue through every validation that is possible from the
        // old epoch (path layout, committer LeafNode, parent hashes, and final
        // tree uniqueness) before returning a typed terminal result below.
        const selfRemoved = removedLeafIndices.includes(this.myLeafIndex);
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
        const addedLeafNodes = new Set(
            addedLeafIndices.map((leafIndex) => TreeMath.leafToNode(leafIndex)),
        );
        const pathCopathResolutions = verifyUpdatePathCiphertextLayout(
            newTree,
            newNLeaves,
            senderLeafIndex,
            committerDirectPath,
            updatePath.nodes,
            addedLeafNodes,
            'processCommit',
        );

        // Verify the committer's NEW LeafNode is properly signed by the
        // same identity key that signed the FramedContent. Without this
        // check, a malicious party who somehow holds the committer's
        // signing key (or a relay that forged FramedContentTBS — already
        // rejected above) could splice in a leaf with an attacker-
        // controlled encryption_key.
        await verifyCommitLeafBinding(
            updatePath.leafNode,
            senderLeaf.signatureKey,
            senderLeaf.encryptionKey,
            this.groupId,
            senderLeafIndex,
        );

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

        // RFC 9420 §§7.3 and 7.8 require signature keys to be unique among
        // leaves and HPKE encryption keys to be unique across the complete
        // ratchet tree. Welcome import enforces the same invariant; check it
        // here as well so an Add cannot install a colliding key for members
        // that are processing the Commit in steady state.
        this._verifyFinalTreeKeyUniqueness(newTree, 'processCommit');

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

        if (selfRemoved) {
            // The old-epoch membership_tag already authenticates auth_data,
            // including confirmation_tag, and the creator's FramedContent
            // signature authorizes the Remove. A removed member deliberately
            // receives no path secret, so it cannot derive the new
            // confirmation_key. At this point every public component of the
            // candidate transition has nevertheless been validated. Destroy
            // the old capabilities and let MLSSession enter a terminal state.
            const result = {
                removedSelf: true,
                removedLeafIndex: this.myLeafIndex,
                removedLeafIndices,
                committerLeafIndex: senderLeafIndex,
                epoch: newEpoch,
            };
            this.destroySecrets();
            return result;
        }

        // If a referenced Update proposal re-keyed OUR leaf, stage the exact
        // pending private key selected by that ProposalRef. Do not mutate the
        // live leafKeyPair yet: AEAD/path, transcript, and confirmation-tag
        // validation below may still fail, and every failure must leave the
        // recipient state unchanged.
        let selfUpdated = false;
        let nextLeafKeyPair = this.leafKeyPair;
        const selfUpdateEntry = proposalPlan.updates.find(
            (entry) => entry.targetLeafIndex === this.myLeafIndex,
        );
        if (selfUpdateEntry) {
            let selectedPending = null;
            if (pendingSelfUpdates && selfUpdateEntry.reference) {
                const storedPending = pendingSelfUpdates.get(
                    proposalReferenceKey(selfUpdateEntry.reference),
                );
                selectedPending = storedPending && storedPending.keyPair
                    ? storedPending.keyPair : storedPending;
            }
            if (!selectedPending) selectedPending = pendingSelfUpdate;
            const myLeaf = RatchetTree.leafFor(newTree, this.myLeafIndex);
            if (!selectedPending || !myLeaf
                || !equalBytes(myLeaf.encryptionKey, selectedPending.publicKeyBytes)) {
                throw new Error(
                    'processCommit: missing private key for referenced self Update',
                );
            }
            nextLeafKeyPair = {
                privateKey: selectedPending.privateKey,
                publicKey: selectedPending.publicKey,
                publicKeyBytes: selectedPending.publicKeyBytes,
            };
            selfUpdated = true;
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

        // Reuse the exact filtered copath resolution whose cardinality was
        // validated for every UpdatePathNode above. This keeps ciphertext
        // indexing and structural validation on one canonical computation.
        const filtered = pathCopathResolutions[lcaIdxInPath];

        const myLeafNodeIdx = TreeMath.leafToNode(this.myLeafIndex);
        let myCtIndex = -1;
        let myPrivateKey = null;
        let myPublicKeyBytes = null;
        for (let j = 0; j < filtered.length; j += 1) {
            const n = filtered[j];
            if (n === myLeafNodeIdx) {
                myCtIndex = j;
                myPrivateKey = nextLeafKeyPair.privateKey;
                myPublicKeyBytes = nextLeafKeyPair.publicKeyBytes;
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
        let commitSecretBytes;
        try {
            for (let i = lcaIdxInPath; i < committerDirectPath.length; i += 1) {
                if (i > lcaIdxInPath) {
                    const next = await KeySchedule.deriveSecret(cur, 'path');
                    cur.fill(0);
                    cur = next;
                }
                const nodeIdx = committerDirectPath[i];
                const nodeSecret = await KeySchedule.deriveSecret(cur, 'node');
                let kpDerived;
                try {
                    kpDerived = await HPKE.deriveKeyPair(nodeSecret);
                } finally {
                    nodeSecret.fill(0);
                }
                const expectedPub = updatePath.nodes[i].encryptionKey;
                if (!equalBytes(kpDerived.publicKeyBytes, expectedPub)) {
                    throw new Error(
                        `processCommit: derived public key mismatch at node ${nodeIdx} (i=${i})`,
                    );
                }
                newParentKeyPairs.set(nodeIdx, kpDerived);
            }

            // commit_secret = DeriveSecret(path_secret_root, "path")
            commitSecretBytes = await TreeKEM.commitSecret(cur);
        } finally {
            wipeBytes(cur);
            wipeBytes(lcaPathSecret);
        }

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

        let newEpochSecrets;
        try {
            newEpochSecrets = await KeySchedule.deriveEpoch({
                initSecretPrev: this.epochSecrets.initSecret,
                commitSecret: commitSecretBytes,
                pskSecret: this.pskSecret,
                groupContext: epochGroupContextBytes,
            });
        } finally {
            commitSecretBytes.fill(0);
        }

        const expectedConfTag = await TranscriptHashes.confirmationTag(
            newEpochSecrets.confirmationKey, newConfirmedTranscriptHash,
        );
        if (!equalBytes(expectedConfTag, pm.auth.confirmationTag)) {
            for (const value of Object.values(newEpochSecrets)) wipeBytes(value);
            throw new Error('processCommit: confirmation_tag mismatch');
        }
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            newConfirmedTranscriptHash, expectedConfTag,
        );
        const preparedEpoch = await prepareEpochSecretsForStorage(
            newEpochSecrets, newTree, newNLeaves,
        );
        const previousInitSecret = this.epochSecrets.initSecret;

        // ---- Commit the new state ----
        // Retain the outgoing epoch's decrypt context first (grace
        // window for in-flight messages), then overwrite.
        this._snapshotPrevEpoch(removedLeafIndices);
        this.ratchetTree = newTree;
        this.nLeaves = newNLeaves;
        this.epoch = newEpoch;
        this.treeHash = newTreeHash;
        this.confirmedTranscriptHash = newConfirmedTranscriptHash;
        this.interimTranscriptHash = newInterimTranscriptHash;
        this.epochSecrets = preparedEpoch.epochSecrets;
        this._chainStates = preparedEpoch.chainStates;
        previousInitSecret.fill(0);
        this.senderRatchetGeneration = 0;
        if (selfUpdated) this.leafKeyPair = nextLeafKeyPair;
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
            addedLeafIndices,
            removedLeafIndex: lastRemovedLeafIndex,
            removedLeafIndices,
            updatedLeafIndices,
            selfUpdated,
            committerLeafIndex: senderLeafIndex,
            consumedProposalRefs: proposalPlan.updates.map(
                (entry) => Uint8Array.from(entry.reference),
            ),
        };
        } catch (err) {
            if (authenticatedCreatorCommit && err
                && (typeof err === 'object' || typeof err === 'function')) {
                err.authenticatedMlsControl = true;
            }
            throw err;
        }
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
     *                       distinct encryption_key advertised by the
     *                       KeyPackage LeafNode
     *   ratchetTreeBytes  : serialised tree (out-of-band from Welcome)
     *   expectedSignerLeafIndex : member sender_leaf_index parsed from the
     *                       Commit paired with this Welcome (required)
     *   expectedCommitEpoch : epoch carried by that correlated Commit;
     *                       when supplied, GroupInfo must describe exactly
     *                       the following epoch
     *   expectedGroupId   : 32-byte group_id pinned in the invite fragment
     *   expectedCreatorKeyHash : SHA-256(signature_key of leaf 0), also
     *                       pinned in the invite fragment
     */
    Group.joinFromWelcomeWithTree = async function joinFromWelcomeWithTree({
        welcomeMessage, keyPackageBytes, initPrivateKey, identity,
        leafEncKeyPair, ratchetTreeBytes, pskSecret,
        expectedSignerLeafIndex, expectedCommitEpoch,
        expectedGroupId, expectedCreatorKeyHash,
    }) {
        // The joined Group owns and eventually erases this copy.
        const psk = pskSecret
            ? Uint8Array.from(pskSecret)
            : new Uint8Array(HPKE.Nh);
        if (psk.length !== HPKE.Nh) {
            throw new Error(`group.join: pskSecret must be ${HPKE.Nh} bytes (got ${psk.length})`);
        }
        if (!(expectedGroupId instanceof Uint8Array)
            || expectedGroupId.length !== BOOTSTRAP_PIN_BYTES) {
            throw new Error(
                'group.join: missing or invalid 32-byte group_id bootstrap pin',
            );
        }
        if (!(expectedCreatorKeyHash instanceof Uint8Array)
            || expectedCreatorKeyHash.length !== BOOTSTRAP_PIN_BYTES) {
            throw new Error(
                'group.join: missing or invalid 32-byte creator-key bootstrap pin',
            );
        }

        const frame = MLSMessage.parseMLSMessage(welcomeMessage);
        if (frame.wireFormat !== MLSMessage.WireFormat.MLS_WELCOME) {
            throw new Error(
                `group.join: expected mls_welcome, got wire_format ${frame.wireFormat}`,
            );
        }
        const welcome = Welcome.parseWelcome(frame.body);
        if (welcome.cipherSuite !== CIPHERSUITE) {
            throw new Error(
                `group.join: unsupported Welcome cipher_suite ${welcome.cipherSuite}`,
            );
        }

        const kp = KeyPackage.parseKeyPackage(keyPackageBytes);
        await verifyKeyPackageBindings(kp, 'group.join KeyPackage');
        if (kp.cipherSuite !== welcome.cipherSuite) {
            throw new Error(
                'group.join: Welcome cipher_suite does not match KeyPackage',
            );
        }
        if (!identity || !equalBytes(
            identity.signaturePublicKeyBytes, kp.leafNode.signatureKey,
        )) {
            throw new Error(
                'group.join: local identity does not match KeyPackage signature_key',
            );
        }
        if (!leafEncKeyPair || !equalBytes(
            leafEncKeyPair.publicKeyBytes, kp.leafNode.encryptionKey,
        )) {
            throw new Error(
                'group.join: local leaf private key does not match KeyPackage encryption_key',
            );
        }
        const myRef = await KeyPackage.keyPackageRef(keyPackageBytes);
        const matchingEntries = welcome.secrets.filter((s) =>
            s.newMember.length === myRef.length
            && s.newMember.every((b, i) => b === myRef[i])
        );
        if (matchingEntries.length !== 1) {
            throw new Error(
                `group.join: expected exactly one EncryptedGroupSecrets for our KeyPackage (got ${matchingEntries.length})`,
            );
        }
        const entry = matchingEntries[0];

        const gs = await Welcome.decryptGroupSecrets(
            entry.encryptedGroupSecrets, initPrivateKey, kp.initKey, welcome.encryptedGroupInfo,
        );
        if (!Array.isArray(gs.psks) || gs.psks.length !== 0) {
            throw new Error(
                'group.join: MLS PSK identifiers are unsupported by the PinChat profile',
            );
        }
        // Welcome AEAD is keyed off (joiner_secret, psk_secret). A joiner
        // with the wrong PSK will fail the AES-GCM auth tag here, which
        // is exactly the bootstrap-key gating we want.
        const welcomeSecret = await Welcome.deriveWelcomeSecret(
            gs.joinerSecret, psk,
        );
        const { key: wKey, nonce: wNonce } = await Welcome.welcomeKeyNonce(welcomeSecret);
        let giBytes;
        try {
            giBytes = await Welcome.openEncryptedGroupInfo(
                wKey, wNonce, welcome.encryptedGroupInfo,
            );
        } finally {
            welcomeSecret.fill(0);
            wKey.fill(0);
            wNonce.fill(0);
        }
        const groupInfo = GroupInfo.parseGroupInfo(giBytes);
        if (groupInfo.groupContext.version !== PROTOCOL_VERSION) {
            throw new Error(
                `group.join: unsupported GroupContext version ${groupInfo.groupContext.version}`,
            );
        }
        if (groupInfo.groupContext.cipherSuite !== kp.cipherSuite) {
            throw new Error(
                'group.join: GroupContext cipher_suite does not match KeyPackage',
            );
        }
        if (!Array.isArray(groupInfo.groupContext.extensions)
            || groupInfo.groupContext.extensions.length !== 0) {
            throw new Error(
                'group.join: unsupported GroupContext extensions',
            );
        }
        if (!equalBytes(groupInfo.groupContext.groupId, expectedGroupId)) {
            throw new Error('group.join: group_id does not match invite bootstrap pin');
        }
        if (expectedCommitEpoch !== undefined && expectedCommitEpoch !== null) {
            if (typeof expectedCommitEpoch !== 'bigint') {
                throw new Error('group.join: expectedCommitEpoch must be a uint64 BigInt');
            }
            if (groupInfo.groupContext.epoch !== expectedCommitEpoch + 1n) {
                throw new Error(
                    'group.join: Welcome epoch does not immediately follow correlated Commit epoch',
                );
            }
        }

        // Parse the ratchet tree. The committer always serialises with
        // node_width(nLeaves) entries (no trailing-blank truncation), so
        // the wire length tells us nLeaves directly.
        const parsedTree = Nodes.parseRatchetTree(ratchetTreeBytes);
        if (parsedTree.length === 0 || (parsedTree.length & 1) === 0
            || parsedTree.length > TreeMath.nodeWidth(MAX_GROUP_LEAVES)) {
            throw new Error(
                `group.join: ratchet_tree exceeds the ${MAX_GROUP_LEAVES}-leaf profile limit`,
            );
        }
        const nLeaves = TreeMath.numLeaves(parsedTree.length);
        if (nLeaves > MAX_GROUP_LEAVES) {
            throw new Error(
                `group.join: ratchet_tree has ${nLeaves} leaves; maximum is ${MAX_GROUP_LEAVES}`,
            );
        }
        const tree = Nodes.padRatchetTree(parsedTree, TreeMath.nodeWidth(nLeaves));

        // Verify GroupInfo signature with the signer's signature_key.
        const signerLeafIndex = groupInfo.signer;
        if (!Number.isInteger(signerLeafIndex) || signerLeafIndex < 0
            || signerLeafIndex >= nLeaves) {
            throw new Error(
                `group.join: signer leaf_index ${signerLeafIndex} out of range [0,${nLeaves})`,
            );
        }
        // PinChat's single-admin architecture authenticates the permanent
        // creator as leaf 0. Apply the same policy while importing a Welcome
        // as processCommit applies to steady-state epochs; otherwise a member
        // could create a valid side-group that only the new joiner accepts.
        // Multiple or transferable admins would require an authenticated
        // admin key set bound into GroupContext instead of this fixed index.
        if (signerLeafIndex !== CREATOR_LEAF_INDEX) {
            throw new Error(
                `group.join: only creator leaf 0 may sign GroupInfo (got leaf ${signerLeafIndex})`,
            );
        }
        // M-1 (RFC §12.4.3.1): GroupInfo MUST be signed by the
        // member that committed the epoch this Welcome introduces.
        // The orchestrator extracts the Commit's FramedContent
        // sender_leaf_index and passes it as expectedSignerLeafIndex.
        // This is fail-closed: without an observable Commit there is no
        // authenticated claim about which member created the epoch.
        if (!Number.isInteger(expectedSignerLeafIndex)) {
            throw new Error(
                'group.join: missing Commit sender; refusing unbound Welcome',
            );
        }
        if (expectedSignerLeafIndex !== signerLeafIndex) {
            throw new Error(
                `group.join: GroupInfo.signer ${signerLeafIndex} != Commit sender ${expectedSignerLeafIndex}`,
            );
        }
        if (expectedSignerLeafIndex !== CREATOR_LEAF_INDEX) {
            throw new Error(
                `group.join: only creator leaf 0 may commit a Welcome epoch (got leaf ${expectedSignerLeafIndex})`,
            );
        }
        const signerLeaf = RatchetTree.leafFor(tree, signerLeafIndex);
        if (!signerLeaf) throw new Error('group.join: signer leaf not present');
        const creatorKeyHash = await Labeled.sha256(signerLeaf.signatureKey);
        if (!equalBytes(creatorKeyHash, expectedCreatorKeyHash)) {
            throw new Error(
                'group.join: creator signature_key does not match invite bootstrap pin',
            );
        }
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

        // RFC 9420 §§7.3, 7.9, and 12.4.3.1: a Welcome imports the whole
        // public ratchet tree, so validate every live leaf, every live
        // parent-hash chain, unmerged-leaf metadata, and key uniqueness
        // before deriving or retaining any epoch secret.
        await verifyImportedTree(
            tree, nLeaves, groupInfo.groupContext.groupId,
        );

        // RFC §12.4.3.1 identifies our leaf by equality with the LeafNode
        // in the consumed KeyPackage, not merely by one public key. This
        // also prevents a malicious committer from rebinding our Welcome
        // entry to a different, independently valid LeafNode.
        const myLeafBytes = Nodes.leafNodeBytes(kp.leafNode);
        let myLeafIndex = -1;
        for (let li = 0; li < nLeaves; li += 1) {
            const leaf = RatchetTree.leafFor(tree, li);
            if (leaf && equalBytes(Nodes.leafNodeBytes(leaf), myLeafBytes)) {
                myLeafIndex = li;
                break;
            }
        }
        if (myLeafIndex === -1) {
            throw new Error(
                'group.join: KeyPackage LeafNode not present verbatim in ratchet_tree',
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
        try {
            for (let i = lcaIdx; i < myDirectPath.length; i += 1) {
                if (i > lcaIdx) {
                    const next = await KeySchedule.deriveSecret(cur, 'path');
                    cur.fill(0);
                    cur = next;
                }
                const nodeIdx = myDirectPath[i];
                const nodeSecret = await KeySchedule.deriveSecret(cur, 'node');
                let kpDerived;
                try {
                    kpDerived = await HPKE.deriveKeyPair(nodeSecret);
                } finally {
                    nodeSecret.fill(0);
                }
                const slot = tree[nodeIdx];
                if (!slot || slot.nodeType !== Nodes.NodeType.PARENT) {
                    throw new Error(`group.join: parent node ${nodeIdx} unexpectedly blank/non-parent`);
                }
                if (!equalBytes(kpDerived.publicKeyBytes, slot.parent.encryptionKey)) {
                    throw new Error(`group.join: derived public key mismatch at node ${nodeIdx}`);
                }
                parentKeyPairs.set(nodeIdx, kpDerived);
            }
        } finally {
            wipeBytes(cur);
            wipeBytes(gs.pathSecret);
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
        memberSecret.fill(0);

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
            for (const value of Object.values(epochSecrets)) wipeBytes(value);
            throw new Error('group.join: confirmation_tag mismatch');
        }
        const newInterimTranscriptHash = await TranscriptHashes.interimTranscriptHash(
            groupInfo.groupContext.confirmedTranscriptHash, expectedConfTag,
        );
        const preparedEpoch = await prepareEpochSecretsForStorage(
            epochSecrets, tree, nLeaves,
        );

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
            interimTranscriptHash: newInterimTranscriptHash,
            confirmedTranscriptHash: groupInfo.groupContext.confirmedTranscriptHash,
            treeHash: groupInfo.groupContext.treeHash,
            epochSecrets: preparedEpoch.epochSecrets,
            pskSecret: psk,
        };
        const group = new Group(state);
        group._chainStates = preparedEpoch.chainStates;
        return group;
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
                    const notBefore = nowSecs - 60n;
                    return {
                        notBefore, // 1 min clock-skew
                        notAfter: notBefore
                            + MAX_KEY_PACKAGE_LIFETIME_SECONDS,
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
    async function verifyKeyPackageBindings(kp, errorPrefix = 'verifyKeyPackage') {
        if (kp.version !== PROTOCOL_VERSION) {
            throw new Error(
                `${errorPrefix}: protocol version ${kp.version} does not match MLS 1.0`,
            );
        }
        if (kp.cipherSuite !== CIPHERSUITE) {
            throw new Error(
                `${errorPrefix}: cipher_suite ${kp.cipherSuite} does not match group ciphersuite`,
            );
        }
        if (kp.leafNode.leafNodeSource !== Nodes.LeafNodeSource.KEY_PACKAGE) {
            throw new Error(
                `${errorPrefix}: expected source=KEY_PACKAGE, got ${kp.leafNode.leafNodeSource}`,
            );
        }
        // RFC §7.2.3: enforce now ∈ [notBefore, notAfter). Rejects
        // replayed KeyPackages from a former member trying to rejoin
        // off a captured invite.
        const lt = kp.leafNode.lifetime;
        if (!lt || typeof lt.notBefore !== 'bigint' || typeof lt.notAfter !== 'bigint') {
            throw new Error(`${errorPrefix}: missing or malformed Lifetime`);
        }
        if (lt.notBefore >= lt.notAfter) {
            throw new Error(`${errorPrefix}: malformed Lifetime range`);
        }
        if (lt.notAfter - lt.notBefore > MAX_KEY_PACKAGE_LIFETIME_SECONDS) {
            throw new Error(
                `${errorPrefix}: Lifetime exceeds the 24-hour profile maximum`,
            );
        }
        const nowSecs = BigInt(Math.floor(Date.now() / 1000));
        if (nowSecs < lt.notBefore) {
            throw new Error(
                `${errorPrefix}: Lifetime not yet valid (now=${nowSecs} < notBefore=${lt.notBefore})`,
            );
        }
        if (nowSecs >= lt.notAfter) {
            throw new Error(
                `${errorPrefix}: Lifetime expired (now=${nowSecs} >= notAfter=${lt.notAfter})`,
            );
        }
        const sigPub = await validateLeafNodeProfile(
            kp.leafNode, 'KeyPackage leaf', errorPrefix,
        );
        try {
            await HPKE.deserializePublicKey(kp.initKey);
        } catch (err) {
            throw new Error(`${errorPrefix}: init_key invalid: ${err.message}`);
        }
        if (equalBytes(kp.initKey, kp.leafNode.encryptionKey)) {
            throw new Error(
                `${errorPrefix}: init_key must differ from LeafNode encryption_key`,
            );
        }
        validateAdvertisedExtensions(
            kp.extensions,
            kp.leafNode.capabilities,
            errorPrefix,
            'KeyPackage extensions',
        );
        const leafTbs = Nodes.leafNodeTbsBytes(kp.leafNode);
        const leafOk = await Labeled.verifyWithLabel(
            sigPub, 'LeafNodeTBS', leafTbs, kp.leafNode.signature,
        );
        if (!leafOk) {
            throw new Error(`${errorPrefix}: inner LeafNode signature invalid`);
        }
        const kpTbs = KeyPackage.keyPackageTbsBytes(kp);
        const kpOk = await Labeled.verifyWithLabel(
            sigPub, 'KeyPackageTBS', kpTbs, kp.signature,
        );
        if (!kpOk) {
            throw new Error(`${errorPrefix}: outer KeyPackage signature invalid`);
        }
    }

    /**
     * Verify a COMMIT-source LeafNode: the TBS includes group_id and
     * leaf_index appended after the LeafNode body. The signing key in
     * the new leaf must match the OLD leaf's signing key (we don't
     * support identity rotation in this MVP) — that ties the commit's
     * new leaf back to the same member who signed the FramedContent.
     */
    async function verifyCommitLeafBinding(
        leaf,
        expectedSignatureKey,
        previousEncryptionKey,
        groupId,
        leafIndex,
    ) {
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
        if (equalBytes(leaf.encryptionKey, previousEncryptionKey)) {
            throw new Error(
                'verifyCommitLeaf: encryption_key must differ from the current leaf',
            );
        }
        const sigPub = await validateLeafNodeProfile(
            leaf, `leaf ${leafIndex}`, 'verifyCommitLeaf',
        );
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
    async function verifyUpdateLeafBinding(
        leaf,
        expectedSignatureKey,
        previousEncryptionKey,
        groupId,
        leafIndex,
    ) {
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
        if (equalBytes(leaf.encryptionKey, previousEncryptionKey)) {
            throw new Error(
                'verifyUpdateLeaf: encryption_key must differ from the current leaf',
            );
        }
        const sigPub = await validateLeafNodeProfile(
            leaf, `leaf ${leafIndex}`, 'verifyUpdateLeaf',
        );
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

    /**
     * RFC 9420 §7.6 binds each UpdatePathNode's ciphertext vector to the
     * ordered resolution of its corresponding copath node, excluding every
     * leaf introduced by an Add in the same Commit. Validate every level,
     * including levels from which this recipient will not decrypt, so all
     * recipients make the same structural acceptance decision.
     *
     * Returns the filtered resolutions for subsequent ciphertext lookup.
     */
    function verifyUpdatePathCiphertextLayout(
        tree,
        nLeaves,
        committerLeafIndex,
        committerDirectPath,
        updatePathNodes,
        addedLeafNodes,
        operation,
    ) {
        const resolutions = [];
        for (let pathIndex = 0; pathIndex < committerDirectPath.length; pathIndex += 1) {
            const childOnPath = pathIndex === 0
                ? TreeMath.leafToNode(committerLeafIndex)
                : committerDirectPath[pathIndex - 1];
            const copathSibling = TreeMath.sibling(childOnPath, nLeaves);
            const resolution = RatchetTree.resolution(tree, copathSibling);
            const filtered = addedLeafNodes.size > 0
                ? resolution.filter((nodeIndex) => !addedLeafNodes.has(nodeIndex))
                : resolution;
            const updatePathNode = updatePathNodes[pathIndex];
            const ciphertexts = updatePathNode && updatePathNode.encryptedPathSecret;
            if (!Array.isArray(ciphertexts)) {
                throw new Error(
                    `${operation}: UpdatePath node ${pathIndex} has malformed encrypted_path_secret`,
                );
            }
            if (ciphertexts.length !== filtered.length) {
                throw new Error(
                    `${operation}: UpdatePath node ${pathIndex} (tree node `
                    + `${committerDirectPath[pathIndex]}) encrypted_path_secret length `
                    + `${ciphertexts.length} != filtered copath resolution ${filtered.length}`,
                );
            }
            resolutions.push(filtered);
        }
        return resolutions;
    }

    /**
     * Validate all inline or already-resolved proposals against the same
     * pre-Commit tree before constructing a candidate state. RFC 9420 §12.2
     * forbids multiple Update and/or Remove proposals applying to one leaf.
     * In the creator-only PinChat profile, member Updates MUST arrive by
     * reference: an inline Update is authored by the committer and therefore
     * cannot authenticate some other member as its target. Add and Remove
     * remain creator-authored inline proposals.
     *
     * The returned arrays preserve relative order within each proposal type,
     * while placing them into the application phases required by §12.3.
     */
    function validateCommitProposalList(
        proposalOrRefs,
        tree,
        nLeaves,
        committerLeafIndex,
        operation = 'commit',
    ) {
        if (!Array.isArray(proposalOrRefs)) {
            throw new Error(`${operation}: malformed proposal list`);
        }

        const plan = { updates: [], removes: [], adds: [] };
        const leafActions = new Map();

        function claimLeaf(targetLeafIndex, action) {
            const previous = leafActions.get(targetLeafIndex);
            if (previous) {
                throw new Error(
                    `${operation}: multiple Update and/or Remove proposals target leaf `
                    + `${targetLeafIndex} (${previous} + ${action})`,
                );
            }
            leafActions.set(targetLeafIndex, action);
        }

        for (let wireIndex = 0; wireIndex < proposalOrRefs.length; wireIndex += 1) {
            const por = proposalOrRefs[wireIndex];
            if (!por || (por.type !== Proposal.ProposalOrRefType.PROPOSAL
                && por.type !== Proposal.ProposalOrRefType.REFERENCE)) {
                throw new Error(`${operation}: malformed ProposalOrRef at index ${wireIndex}`);
            }
            const proposal = por.proposal;
            if (!proposal || !Number.isInteger(proposal.proposalType)) {
                const source = por.type === Proposal.ProposalOrRefType.REFERENCE
                    ? 'resolved' : 'inline';
                throw new Error(
                    `${operation}: malformed ${source} proposal at index ${wireIndex}`,
                );
            }

            if (proposal.proposalType === Proposal.ProposalType.UPDATE) {
                if (por.type !== Proposal.ProposalOrRefType.REFERENCE) {
                    throw new Error(
                        `${operation}: inline Update proposals are not permitted; `
                        + 'member Updates must be authenticated by ProposalRef',
                    );
                }
                const newLeaf = proposal.leafNode;
                if (!newLeaf || newLeaf.leafNodeSource !== Nodes.LeafNodeSource.UPDATE) {
                    throw new Error(`${operation}: Update proposal leaf not source=update`);
                }
                const targetLeafIndex = por.proposalSenderLeafIndex;
                if (!Number.isInteger(targetLeafIndex)
                    || targetLeafIndex < 0 || targetLeafIndex >= nLeaves
                    || !RatchetTree.leafFor(tree, targetLeafIndex)) {
                    throw new Error(
                        `${operation}: referenced Update has an unknown authenticated sender`,
                    );
                }
                if (targetLeafIndex === committerLeafIndex) {
                    throw new Error(
                        `${operation}: committer must re-key via its own path, not an Update`,
                    );
                }
                claimLeaf(targetLeafIndex, 'Update');
                plan.updates.push({
                    proposal,
                    targetLeafIndex,
                    wireIndex,
                    reference: por.reference,
                });
                continue;
            }

            if (proposal.proposalType === Proposal.ProposalType.REMOVE) {
                if (por.type !== Proposal.ProposalOrRefType.PROPOSAL) {
                    throw new Error(
                        `${operation}: referenced Remove proposals are not supported by this profile`,
                    );
                }
                const targetLeafIndex = proposal.removed;
                if (!Number.isInteger(targetLeafIndex)
                    || targetLeafIndex < 0 || targetLeafIndex >= nLeaves) {
                    throw new Error(
                        `${operation}: invalid removed leaf_index ${targetLeafIndex}`,
                    );
                }
                if (targetLeafIndex === CREATOR_LEAF_INDEX) {
                    throw new Error(`${operation}: creator leaf 0 cannot be removed`);
                }
                if (targetLeafIndex === committerLeafIndex) {
                    throw new Error(`${operation}: committer cannot remove themself`);
                }
                const targetNode = tree[TreeMath.leafToNode(targetLeafIndex)];
                if (!targetNode || targetNode.nodeType !== Nodes.NodeType.LEAF) {
                    throw new Error(
                        `${operation}: leaf ${targetLeafIndex} already blank`,
                    );
                }
                claimLeaf(targetLeafIndex, 'Remove');
                plan.removes.push({ proposal, targetLeafIndex, wireIndex });
                continue;
            }

            if (proposal.proposalType === Proposal.ProposalType.ADD) {
                if (por.type !== Proposal.ProposalOrRefType.PROPOSAL) {
                    throw new Error(
                        `${operation}: referenced Add proposals are not supported by this profile`,
                    );
                }
                if (!proposal.keyPackage || !proposal.keyPackage.leafNode) {
                    throw new Error(`${operation}: malformed Add proposal at index ${wireIndex}`);
                }
                plan.adds.push({ proposal, wireIndex });
                continue;
            }

            throw new Error(
                `${operation}: unsupported proposal_type ${proposal.proposalType}`,
            );
        }

        return plan;
    }

    function bytesMapKey(bytes, fieldName) {
        if (!(bytes instanceof Uint8Array) || bytes.length === 0) {
            throw new Error(`imported-tree: ${fieldName} is empty or malformed`);
        }
        let out = '';
        for (let i = 0; i < bytes.length; i += 1) {
            out += bytes[i].toString(16).padStart(2, '0');
        }
        return out;
    }

    function validateAdvertisedExtensions(
        extensions,
        capabilities,
        errorPrefix,
        fieldName,
    ) {
        if (!Array.isArray(extensions)) {
            throw new Error(`${errorPrefix}: ${fieldName} are malformed`);
        }
        for (const ext of extensions) {
            if (!ext || !Number.isInteger(ext.extensionType)
                || !(ext.extensionData instanceof Uint8Array)) {
                throw new Error(`${errorPrefix}: ${fieldName} contain a malformed extension`);
            }
            if (!capabilities.extensions.includes(ext.extensionType)) {
                throw new Error(
                    `${errorPrefix}: ${fieldName} contain unadvertised extension ${ext.extensionType}`,
                );
            }
        }
    }

    function validateLeafCapabilities(leaf, leafDescription, errorPrefix) {
        const caps = leaf.capabilities;
        if (!caps || !Array.isArray(caps.versions)
            || !Array.isArray(caps.cipherSuites)
            || !Array.isArray(caps.extensions)
            || !Array.isArray(caps.proposals)
            || !Array.isArray(caps.credentials)) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} has malformed capabilities`,
            );
        }
        for (const name of [
            'versions', 'cipherSuites', 'extensions', 'proposals', 'credentials',
        ]) {
            const values = caps[name];
            if (!values.every((value) => Number.isInteger(value)
                && value >= 0 && value <= 0xffff)) {
                throw new Error(
                    `${errorPrefix}: ${leafDescription} has malformed ${name} capabilities`,
                );
            }
        }
        if (!caps.versions.includes(PROTOCOL_VERSION)) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} does not support MLS 1.0`,
            );
        }
        if (!caps.cipherSuites.includes(CIPHERSUITE)) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} does not support ciphersuite 0x${CIPHERSUITE.toString(16)}`,
            );
        }
        if (!leaf.credential
            || leaf.credential.credentialType !== Nodes.CredentialType.BASIC
            || !(leaf.credential.identity instanceof Uint8Array)
            || leaf.credential.identity.length === 0) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} has an invalid basic credential`,
            );
        }
        if (!caps.credentials.includes(leaf.credential.credentialType)) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} does not advertise its credential type`,
            );
        }
        validateAdvertisedExtensions(
            leaf.extensions,
            caps,
            errorPrefix,
            `${leafDescription} extensions`,
        );
    }

    /**
     * Validate the semantic LeafNode profile shared by KeyPackage download,
     * Add/Update/Commit processing, and imported-tree validation. PinChat's
     * BasicCredential deliberately uses the signature public key bytes as
     * its opaque identity, so enforce that application-level binding instead
     * of accepting an arbitrary self-asserted identity blob.
     */
    async function validateLeafNodeProfile(leaf, leafDescription, errorPrefix) {
        validateLeafCapabilities(leaf, leafDescription, errorPrefix);
        if (!equalBytes(leaf.credential.identity, leaf.signatureKey)) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} basic credential identity `
                + 'must equal signature_key in the PinChat profile',
            );
        }
        let signaturePublicKey;
        try {
            signaturePublicKey = await Signature.importPublicKey(leaf.signatureKey);
        } catch (err) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} signature_key invalid: ${err.message}`,
            );
        }
        try {
            await HPKE.deserializePublicKey(leaf.encryptionKey);
        } catch (err) {
            throw new Error(
                `${errorPrefix}: ${leafDescription} encryption_key invalid: ${err.message}`,
            );
        }
        return signaturePublicKey;
    }

    /**
     * Verify a LeafNode as it appears in an imported ratchet tree. The
     * LeafNodeTBS context depends on leaf_node_source: KeyPackage leaves
     * carry Lifetime and no group context, while Update/Commit leaves append
     * group_id and leaf_index to the common TBS prefix (RFC 9420 §7.2).
     */
    async function verifyImportedLeaf(leaf, groupId, leafIndex) {
        const sigPub = await validateLeafNodeProfile(
            leaf, `leaf ${leafIndex}`, 'imported-tree',
        );

        const encoder = new Codec.Encoder();
        Nodes.writeLeafNodeTbs(encoder, leaf);
        if (leaf.leafNodeSource === Nodes.LeafNodeSource.KEY_PACKAGE) {
            const lt = leaf.lifetime;
            if (!lt || typeof lt.notBefore !== 'bigint'
                || typeof lt.notAfter !== 'bigint'
                || lt.notBefore >= lt.notAfter) {
                throw new Error(
                    `imported-tree: leaf ${leafIndex} has malformed Lifetime`,
                );
            }
        } else if (leaf.leafNodeSource === Nodes.LeafNodeSource.UPDATE
            || leaf.leafNodeSource === Nodes.LeafNodeSource.COMMIT) {
            encoder.writeOpaque(groupId);
            encoder.writeU32(leafIndex);
        } else {
            throw new Error(
                `imported-tree: leaf ${leafIndex} has unsupported leaf_node_source ${leaf.leafNodeSource}`,
            );
        }

        const ok = await Labeled.verifyWithLabel(
            sigPub, 'LeafNodeTBS', encoder.bytes(), leaf.signature,
        );
        if (!ok) {
            throw new Error(
                `imported-tree: leaf ${leafIndex} LeafNode signature invalid`,
            );
        }
    }

    function validateUnmergedLeaves(tree, parentNodeIndex, nLeaves) {
        const parent = tree[parentNodeIndex].parent;
        const unmerged = parent.unmergedLeaves || [];
        const descendants = new Set(
            TreeMath.leafDescendants(parentNodeIndex, nLeaves),
        );
        let previous = -1;
        for (const leafIndex of unmerged) {
            if (!Number.isInteger(leafIndex) || leafIndex < 0
                || leafIndex >= nLeaves) {
                throw new Error(
                    `imported-tree: parent ${parentNodeIndex} has out-of-range unmerged leaf ${leafIndex}`,
                );
            }
            if (leafIndex <= previous) {
                throw new Error(
                    `imported-tree: parent ${parentNodeIndex} unmerged_leaves not strictly sorted`,
                );
            }
            previous = leafIndex;
            if (!descendants.has(leafIndex)
                || !RatchetTree.leafFor(tree, leafIndex)) {
                throw new Error(
                    `imported-tree: parent ${parentNodeIndex} references invalid unmerged leaf ${leafIndex}`,
                );
            }

            let node = TreeMath.leafToNode(leafIndex);
            while (node !== parentNodeIndex) {
                node = TreeMath.parent(node, nLeaves);
                if (node === parentNodeIndex) break;
                const intermediate = tree[node];
                if (intermediate
                    && !intermediate.parent.unmergedLeaves.includes(leafIndex)) {
                    throw new Error(
                        `imported-tree: unmerged leaf ${leafIndex} missing from intermediate parent ${node}`,
                    );
                }
            }
        }
    }

    function parentHashAtNode(tree, nodeIndex) {
        const slot = tree[nodeIndex];
        if (!slot) return null;
        if (slot.nodeType === Nodes.NodeType.PARENT) {
            return slot.parent.parentHash;
        }
        if (slot.nodeType === Nodes.NodeType.LEAF
            && slot.leaf.leafNodeSource === Nodes.LeafNodeSource.COMMIT) {
            return slot.leaf.parentHash;
        }
        return null;
    }

    function sameNodeSet(a, b) {
        if (a.length !== b.length) return false;
        const bs = new Set(b);
        if (bs.size !== b.length) return false;
        return a.every((node) => bs.has(node));
    }

    /**
     * RFC 9420 §7.9.2 top-down parent-hash validation. A live parent P is
     * valid only when exactly one already-authenticated descendant D in a
     * child resolution links to P. Commit-source leaves seed the chains;
     * a validated lower parent can extend its chain toward the root.
     */
    async function verifyImportedParentHashes(tree, nLeaves) {
        const authenticated = new Set();
        const parents = [];
        for (let nodeIndex = 0; nodeIndex < tree.length; nodeIndex += 1) {
            const slot = tree[nodeIndex];
            if (!slot) continue;
            if (slot.nodeType === Nodes.NodeType.LEAF
                && slot.leaf.leafNodeSource === Nodes.LeafNodeSource.COMMIT) {
                authenticated.add(nodeIndex);
            } else if (slot.nodeType === Nodes.NodeType.PARENT) {
                parents.push(nodeIndex);
            }
        }
        parents.sort((a, b) => TreeMath.level(a) - TreeMath.level(b));

        for (const parentNodeIndex of parents) {
            const parentSlot = tree[parentNodeIndex];
            const left = TreeMath.left(parentNodeIndex);
            const right = TreeMath.right(parentNodeIndex, nLeaves);
            const validDescendants = [];

            for (const [child, sibling] of [[left, right], [right, left]]) {
                const resolution = RatchetTree.resolution(tree, child);
                const childLeaves = new Set(
                    TreeMath.leafDescendants(child, nLeaves),
                );
                const expectedUnmerged = (parentSlot.parent.unmergedLeaves || [])
                    .filter((leafIndex) => childLeaves.has(leafIndex))
                    .map((leafIndex) => TreeMath.leafToNode(leafIndex));
                const expectedHash = await ParentHash.parentHash(
                    tree, parentSlot.parent, sibling, nLeaves,
                );

                for (const descendant of resolution) {
                    if (!authenticated.has(descendant)) continue;
                    const carriedHash = parentHashAtNode(tree, descendant);
                    if (!carriedHash || !equalBytes(carriedHash, expectedHash)) continue;
                    const remainder = resolution.filter((node) => node !== descendant);
                    if (!sameNodeSet(remainder, expectedUnmerged)) continue;
                    validDescendants.push(descendant);
                }
            }

            if (validDescendants.length !== 1) {
                throw new Error(
                    `imported-tree: parent ${parentNodeIndex} is not parent-hash valid (found ${validDescendants.length} authenticating descendants)`,
                );
            }
            authenticated.add(parentNodeIndex);
        }
    }

    /**
     * Enforce the ratchet-tree key-pair uniqueness invariant shared by
     * imported-tree validation and steady-state Commit processing.
     */
    function verifyTreeKeyUniqueness(tree, errorPrefix) {
        const signatureKeys = new Map();
        const encryptionKeys = new Map();
        const registerEncryptionKey = (keyBytes, nodeIndex) => {
            const key = bytesMapKey(keyBytes, `node ${nodeIndex} encryption_key`);
            if (encryptionKeys.has(key)) {
                throw new Error(
                    `${errorPrefix}: duplicate encryption_key at nodes ${encryptionKeys.get(key)} and ${nodeIndex}`,
                );
            }
            encryptionKeys.set(key, nodeIndex);
        };

        for (let nodeIndex = 0; nodeIndex < tree.length; nodeIndex += 1) {
            const slot = tree[nodeIndex];
            if (!slot) continue;
            if (slot.nodeType === Nodes.NodeType.LEAF) {
                const leafIndex = TreeMath.nodeToLeaf(nodeIndex);
                const signatureKey = bytesMapKey(
                    slot.leaf.signatureKey, `leaf ${leafIndex} signature_key`,
                );
                if (signatureKeys.has(signatureKey)) {
                    throw new Error(
                        `${errorPrefix}: duplicate signature_key at leaves ${signatureKeys.get(signatureKey)} and ${leafIndex}`,
                    );
                }
                signatureKeys.set(signatureKey, leafIndex);
                registerEncryptionKey(slot.leaf.encryptionKey, nodeIndex);
            } else if (slot.nodeType === Nodes.NodeType.PARENT) {
                registerEncryptionKey(slot.parent.encryptionKey, nodeIndex);
            } else {
                throw new Error(`${errorPrefix}: invalid node type at ${nodeIndex}`);
            }
        }

        // P-256 is used for both HPKE and signatures in this ciphersuite;
        // reusing one public key across the two roles violates the ratchet
        // tree key-pair uniqueness invariant (RFC §16.7).
        for (const [key, leafIndex] of signatureKeys) {
            if (encryptionKeys.has(key)) {
                throw new Error(
                    `${errorPrefix}: signature_key at leaf ${leafIndex} collides with encryption_key at node ${encryptionKeys.get(key)}`,
                );
            }
        }
    }

    /**
     * Validate every non-blank entry of a ratchet tree imported with a
     * Welcome before any epoch secret is derived (RFC 9420 §12.4.3.1).
     */
    async function verifyImportedTree(tree, nLeaves, groupId) {
        if (!Number.isInteger(nLeaves) || nLeaves < 1
            || tree.length !== TreeMath.nodeWidth(nLeaves)) {
            throw new Error('imported-tree: invalid ratchet-tree shape');
        }

        // Validate positional node types first so later structural checks
        // can safely traverse parent links even in a malicious encoding.
        for (let nodeIndex = 0; nodeIndex < tree.length; nodeIndex += 1) {
            const slot = tree[nodeIndex];
            if (!slot) continue;
            const isLeafPosition = TreeMath.level(nodeIndex) === 0;
            if (isLeafPosition && slot.nodeType !== Nodes.NodeType.LEAF) {
                throw new Error(
                    `imported-tree: parent node encoded at leaf position ${nodeIndex}`,
                );
            }
            if (!isLeafPosition && slot.nodeType !== Nodes.NodeType.PARENT) {
                throw new Error(
                    `imported-tree: leaf node encoded at parent position ${nodeIndex}`,
                );
            }
        }

        verifyTreeKeyUniqueness(tree, 'imported-tree');

        for (let nodeIndex = 0; nodeIndex < tree.length; nodeIndex += 1) {
            const slot = tree[nodeIndex];
            if (!slot) continue;
            if (slot.nodeType === Nodes.NodeType.PARENT) {
                validateUnmergedLeaves(tree, nodeIndex, nLeaves);
            }
        }

        const rootSlot = tree[TreeMath.root(nLeaves)];
        if (rootSlot && rootSlot.nodeType === Nodes.NodeType.PARENT
            && rootSlot.parent.parentHash.length !== 0) {
            throw new Error('imported-tree: root parent_hash must be empty');
        }

        for (let leafIndex = 0; leafIndex < nLeaves; leafIndex += 1) {
            const leaf = RatchetTree.leafFor(tree, leafIndex);
            if (leaf) await verifyImportedLeaf(leaf, groupId, leafIndex);
        }
        await verifyImportedParentHashes(tree, nLeaves);
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
        MAX_GROUP_LEAVES,
        // Exposed for tests / future add-member path
        buildSelfLeaf,
        signLeafNodeForKeyPackage,
        signLeafNodeInCommit,
        verifyImportedTree,
        proposalReferenceKey,
    });
});
