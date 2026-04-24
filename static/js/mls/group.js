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
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Group = factory(
            root.MLS.Codec, root.MLS.HPKE, root.MLS.Signature,
            root.MLS.Nodes, root.MLS.RatchetTree, root.MLS.TreeMath,
            root.MLS.TreeHash, root.MLS.GroupContext, root.MLS.KeySchedule,
            root.MLS.Framing, root.MLS.PrivateMessage, root.MLS.MLSMessage,
            root.MLS.PublicMessage, root.MLS.Labeled,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (
    Codec, HPKE, Signature, Nodes, RatchetTree, TreeMath,
    TreeHash, GroupContext, KeySchedule, Framing, PrivateMessage,
    MLSMessage, PublicMessage, Labeled,
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

    return Object.freeze({
        Group,
        PROTOCOL_VERSION,
        CIPHERSUITE,
        // Exposed for tests / future add-member path
        buildSelfLeaf,
        signLeafNodeForKeyPackage,
    });
});
