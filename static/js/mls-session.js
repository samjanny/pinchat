/**
 * PinChat MLS session — high-level façade the app.js controller talks
 * to when `room_type === 'group'`. Mirrors the shape of the existing
 * DoubleRatchet wrapper so the UI layer can branch on one field and
 * otherwise keep the same send / receive / on-message API surface.
 *
 * Responsibilities
 * ----------------
 * - Own the Group state for this tab/session.
 * - Build the KeyPackage + signing identity for this member.
 * - Ingest incoming `mls` relay envelopes (type=mls with wire_format)
 *   and dispatch to Group.joinFromWelcomeWithTree / decryptApplicationMessage
 *   based on wire_format.
 * - Emit outgoing `mls` relay envelopes through a caller-supplied
 *   transport function.
 *
 * The orchestration implements the creator-centric PinChat profile for
 * groups of up to 20 logical leaves. Leaf 0 is the permanent creator/admin;
 * other members may publish authenticated Update Proposals, while only leaf
 * 0 authors Commits.
 *
 * Transport contract
 * ------------------
 * The `send(envelope)` callback must broadcast to the room relay and may
 * return `false` to report a synchronous transport rejection; the
 * optional `cancelPendingControl(envelope)` callback removes an exact
 * locally-queued control which ordered relay state has made permanently
 * ineligible for acceptance.
 * envelope is `{ type: 'mls', payload, wire_format, ratchet_tree?,
 * key_package_ref?, commit_ref? }` (the optional references correlate an
 * Add Commit with its Welcome). This is the same shape the Rust server's
 * Message::Mls expects. `onEvent` fires
 * with `{ kind, ... }` for UI updates. `kind` values:
 *   'keypackage-published'   — our KeyPackage has been emitted
 *   'welcome-sent'            — Alice sent a Welcome to the new member
 *   'joined'                  — Bob completed join
 *   'removed'                 — authenticated Remove made this session terminal
 *   'roster'                  — live leaves identified by signature-key hash
 *   'message'                 — payload + authenticated sender key identity
 *   'error'                   — unrecoverable error with { reason }
 */
(function (root) {
    'use strict';

    const MLS = root.MLS;
    if (!MLS) {
        throw new Error('mls-session: window.MLS is not loaded — ensure the mls/*.js modules are included before this file');
    }

    function base64UrlEncode(bytes) {
        return MLS.Codec.bytesToBase64Url(bytes);
    }
    function base64UrlDecode(str) {
        return MLS.Codec.base64UrlToBytes(str);
    }

    // Application-payload tag bytes. Every MLS application_data we send
    // begins with one of these so the receiver can route between text and
    // images (and, later, additional payload kinds) without sniffing.
    // The tag is OUTSIDE the MLS framing — it's the first byte of the
    // ciphertext-protected payload.
    const PAYLOAD_TEXT = 0x01;
    const PAYLOAD_IMAGE = 0x02;
    const CREATOR_LEAF_INDEX = 0;
    const BOOTSTRAP_PIN_BYTES = 32;
    const BOOTSTRAP_PROOF_BYTES = 32;
    const CORRELATION_REF_BYTES = 32;
    const MAX_GROUP_LEAVES = MLS.Group.MAX_GROUP_LEAVES || 20;
    const MAX_PENDING_WELCOME_SENDERS = MAX_GROUP_LEAVES;
    const MAX_PROPOSALS_PER_SENDER = 2;
    const MAX_PROPOSALS_PER_EPOCH =
        MAX_GROUP_LEAVES * MAX_PROPOSALS_PER_SENDER;
    const MAX_DEFERRED_PRIVATE_MESSAGES = 32;
    const MAX_DEFERRED_PRIVATE_BYTES = 4 * 1024 * 1024;
    const MAX_DEFERRED_KEYPACKAGE_BYTES = 512 * 1024;
    const MAX_CONSUMED_KEY_PACKAGE_REFS = 4096;
    // The visible label carries 80 bits of the SHA-256 fingerprint. The full
    // 256-bit value is always emitted alongside it for tooltips/comparison.
    const VISIBLE_FINGERPRINT_HEX = 20;

    function hexEncode(bytes) {
        return Array.from(bytes, (byte) =>
            byte.toString(16).padStart(2, '0')).join('');
    }

    function shortFingerprint(fullFingerprint) {
        return fullFingerprint.slice(0, VISIBLE_FINGERPRINT_HEX)
            .match(/.{1,4}/g).join(' ');
    }

    function equalBytes(a, b) {
        if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)
            || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function wipeBytes(value) {
        if (value instanceof Uint8Array) value.fill(0);
    }

    function fatalMlsStateError(message) {
        const error = new Error(message);
        error.mlsFatalState = true;
        return error;
    }

    function rejectedMlsControlError(error, prefix = '') {
        if (error?.mlsFatalState === true || error?.mlsRetryControl === true) {
            return error;
        }
        if (error?.mlsControlRejected === true) return error;
        const detail = error instanceof Error ? error.message : String(error);
        const rejected = new Error(`${prefix}${detail}`);
        // A deterministic, unauthenticated/invalid ordered control must be
        // consumed after rejection. Replaying the same immutable relay
        // sequence cannot make it valid and would otherwise pin reconnect.
        rejected.mlsControlRejected = true;
        return rejected;
    }

    function validationMlsControlError(message) {
        const error = message instanceof Error
            ? message : new Error(String(message));
        error.mlsValidationFailure = true;
        return error;
    }

    function retryableMlsControlError(error, prefix = '') {
        if (error?.mlsFatalState === true
            || error?.mlsRetryControl === true
            || error?.mlsControlRejected === true) {
            return error;
        }
        const detail = error instanceof Error ? error.message : String(error);
        const retryable = new Error(`${prefix}${detail}`);
        retryable.mlsRetryControl = true;
        if (error?.mlsAuthenticatedControl === true) {
            retryable.mlsAuthenticatedControl = true;
        }
        return retryable;
    }

    function classifyMlsControlError(error, prefix = '') {
        if (error?.mlsFatalState === true
            || error?.mlsRetryControl === true
            || error?.mlsControlRejected === true) {
            return error;
        }
        if (error?.mlsValidationFailure === true) {
            return rejectedMlsControlError(error, prefix);
        }
        return retryableMlsControlError(error, prefix);
    }

    function envelopeEncodedBytes(envelope) {
        if (!envelope || typeof envelope !== 'object') return 0;
        let total = 256;
        for (const name of [
            'payload', 'ratchet_tree', 'key_package_ref', 'commit_ref',
            'bootstrap_proof', 'sender_id',
        ]) {
            if (typeof envelope[name] === 'string') {
                total += envelope[name].length;
            }
        }
        return total;
    }

    function decodeCorrelationRef(value, name) {
        if (typeof value !== 'string' || value.length === 0) {
            throw new Error(`mls-session: ${name} is missing`);
        }
        let decoded;
        try {
            decoded = base64UrlDecode(value);
        } catch (_err) {
            throw validationMlsControlError(
                `mls-session: ${name} is not valid base64url`,
            );
        }
        if (decoded.length !== CORRELATION_REF_BYTES
            || base64UrlEncode(decoded) !== value) {
            throw validationMlsControlError(
                `mls-session: ${name} must be a canonical `
                + `${CORRELATION_REF_BYTES}-byte base64url value`,
            );
        }
        return decoded;
    }

    function copyBootstrapPin(value, name) {
        if (value === null || value === undefined) return null;
        if (!(value instanceof Uint8Array) || value.length !== BOOTSTRAP_PIN_BYTES) {
            throw new Error(
                `mls-session: ${name} must be ${BOOTSTRAP_PIN_BYTES} bytes`,
            );
        }
        return Uint8Array.from(value);
    }

    async function keyPackageBootstrapProof({
        pskSecret,
        expectedGroupId,
        expectedCreatorKeyHash,
        relaySenderId,
        keyPackageBytes,
    }) {
        if (!(pskSecret instanceof Uint8Array)
            || pskSecret.length !== BOOTSTRAP_PROOF_BYTES) {
            throw new Error('mls-session: bootstrap proof requires a 32-byte PSK');
        }
        if (!(expectedGroupId instanceof Uint8Array)
            || expectedGroupId.length !== BOOTSTRAP_PIN_BYTES
            || !(expectedCreatorKeyHash instanceof Uint8Array)
            || expectedCreatorKeyHash.length !== BOOTSTRAP_PIN_BYTES) {
            throw new Error('mls-session: bootstrap proof requires authenticated invite pins');
        }
        if (typeof relaySenderId !== 'string'
            || relaySenderId.length === 0 || relaySenderId.length > 128) {
            throw new Error('mls-session: bootstrap proof requires a stable relay sender_id');
        }
        if (!(keyPackageBytes instanceof Uint8Array)
            || keyPackageBytes.length === 0) {
            throw new Error('mls-session: bootstrap proof requires KeyPackage bytes');
        }
        const encoder = new MLS.Codec.Encoder();
        encoder.writeOpaque(new TextEncoder().encode(
            'pinchat-mls-key-package-bootstrap-proof-v1',
        ));
        encoder.writeOpaque(expectedGroupId);
        encoder.writeOpaque(expectedCreatorKeyHash);
        encoder.writeOpaque(new TextEncoder().encode(relaySenderId));
        encoder.writeOpaque(keyPackageBytes);
        return MLS.HPKE.hmacSha256(pskSecret, encoder.bytes());
    }

    function encodeTextPayload(text) {
        const utf8 = new TextEncoder().encode(String(text));
        const out = new Uint8Array(1 + utf8.length);
        out[0] = PAYLOAD_TEXT;
        out.set(utf8, 1);
        return out;
    }

    function encodeImagePayload(imageBytes, mimeType) {
        const mimeUtf8 = new TextEncoder().encode(String(mimeType || 'application/octet-stream'));
        if (mimeUtf8.length > 255) {
            throw new Error('mls-session: mime type longer than 255 bytes');
        }
        const data = imageBytes instanceof Uint8Array
            ? imageBytes
            : new Uint8Array(imageBytes);
        const out = new Uint8Array(2 + mimeUtf8.length + data.length);
        out[0] = PAYLOAD_IMAGE;
        out[1] = mimeUtf8.length;
        out.set(mimeUtf8, 2);
        out.set(data, 2 + mimeUtf8.length);
        return out;
    }

    function envelopeFromMlsMessage(wireFormat, mlsMessageBytes, ratchetTreeBytes = null) {
        const out = {
            type: 'mls',
            payload: base64UrlEncode(mlsMessageBytes),
            wire_format: wireFormat,
        };
        if (ratchetTreeBytes) {
            out.ratchet_tree = base64UrlEncode(ratchetTreeBytes);
        }
        return out;
    }

    /**
     * Build a fresh identity + HPKE init keypair + HPKE leaf-encryption
     * keypair + signed KeyPackage.
     *
     * RFC 9420 §7.2.1 mandates that LeafNode.encryption_key be DISTINCT
     * from KeyPackage.init_key. The init_key is a one-shot HPKE recipient
     * key used only to decrypt the Welcome's GroupSecrets; the leaf
     * encryption_key is used for TreeKEM path encryption to that leaf
     * across all subsequent epochs the member participates in. Reusing
     * the same keypair would mean a captured Welcome ciphertext could
     * compromise the joiner's first-epoch leaf decryption key.
     */
    async function buildKeyPackage() {
        const sigKp = await MLS.Signature.generateKeyPair();
        const identity = {
            signaturePrivateKey: sigKp.privateKey,
            signaturePublicKeyBytes: sigKp.publicKeyBytes,
        };
        const initKp = await MLS.HPKE.generateKeyPair();
        const leafEncKp = await MLS.HPKE.generateKeyPair();

        const leaf = MLS.Group.buildSelfLeaf({
            encryptionKeyBytes: leafEncKp.publicKeyBytes,
            signatureKeyBytes: identity.signaturePublicKeyBytes,
            credentialIdentity: identity.signaturePublicKeyBytes,
            leafNodeSource: MLS.Nodes.LeafNodeSource.KEY_PACKAGE,
        });
        leaf.signature = await MLS.Group.signLeafNodeForKeyPackage(
            identity.signaturePrivateKey, leaf,
        );
        const kp = {
            version: 0x0001,
            cipherSuite: 0x0002,
            initKey: initKp.publicKeyBytes,
            leafNode: leaf,
            extensions: [],
            signature: new Uint8Array(0),
        };
        const tbs = MLS.KeyPackage.keyPackageTbsBytes(kp);
        kp.signature = await MLS.Labeled.signWithLabel(
            identity.signaturePrivateKey, 'KeyPackageTBS', tbs,
        );
        const keyPackageBytes = MLS.KeyPackage.keyPackageBytes(kp);
        const wrapped = MLS.MLSMessage.serializeMLSMessage(
            MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE, keyPackageBytes,
        );
        return { identity, initKeyPair: initKp, leafEncKeyPair: leafEncKp,
            leaf, keyPackage: kp,
            keyPackageBytes, wrappedKeyPackageBytes: wrapped };
    }

    class MLSSession {
        /**
         * @param {Object} opts
         * @param {'creator' | 'joiner'} opts.role
         * @param {(envelope: object) => void} opts.send
         * @param {(envelope: object) => boolean} [opts.cancelPendingControl]
         * @param {(event: object) => void} opts.onEvent
         * @param {Uint8Array} opts.expectedGroupId
         * @param {Uint8Array} opts.expectedCreatorKeyHash
         * @param {string} opts.relaySenderId
         */
        constructor({
            role, send, cancelPendingControl, onEvent, pskSecret,
            expectedGroupId, expectedCreatorKeyHash, relaySenderId,
        }) {
            if (role !== 'creator' && role !== 'joiner') {
                throw new Error(`mls-session: invalid role "${role}"`);
            }
            this.role = role;
            this.send = send;
            this.cancelPendingControl =
                typeof cancelPendingControl === 'function'
                    ? cancelPendingControl : (() => false);
            this.onEvent = onEvent || (() => {});
            this.group = null;
            this.identity = null;
            this.keyPackageBundle = null;
            this._state = 'idle';
            // 32-byte PSK derived from the URL invite fragment. Bound into
            // every epoch transition (Group.create, joinFromWelcomeWithTree,
            // commitAddMember, processCommit) so a party without the URL
            // key can neither construct nor consume valid Welcomes/Commits
            // even if they reach the relay first.
            // The session owns this copy and can erase it on authenticated
            // removal without mutating the invite/bootstrap buffer held by
            // the application.
            if (!(pskSecret instanceof Uint8Array)
                || pskSecret.length !== BOOTSTRAP_PROOF_BYTES) {
                throw new Error(
                    'mls-session: a 32-byte invite PSK is required',
                );
            }
            this.pskSecret = Uint8Array.from(pskSecret);
            // End-to-end bootstrap pins carried in the URL fragment. The PSK
            // proves possession of the invite secret; these pins additionally
            // identify the exact group and its permanent creator at leaf 0.
            // Creators populate them after Group.create; joiners must receive
            // both before publishing a KeyPackage.
            this.expectedGroupId = copyBootstrapPin(
                expectedGroupId, 'expectedGroupId',
            );
            this.expectedCreatorKeyHash = copyBootstrapPin(
                expectedCreatorKeyHash, 'expectedCreatorKeyHash',
            );
            this.relaySenderId = typeof relaySenderId === 'string'
                ? relaySenderId : null;
            // Join correlation state. KeyPackageRef identifies which
            // broadcast Add/Welcome is addressed to this joiner; commit_ref
            // is PinChat transport metadata equal to SHA-256 over the exact
            // PublicMessage body. A bounded map replaces the old single
            // `_pendingCommitBytes` slot, so unrelated PublicMessages and
            // Welcomes cannot overwrite or consume the candidate we need.
            this._keyPackageRefBytes = null;
            this._keyPackageRef = null;
            this._pendingWelcomeCommits = new Map();
            this._pendingWelcomeCommitBySender = new Map();
            // Per-sender_id → leafIndex map maintained by the creator.
            // We commit at most one KeyPackage per WebSocket sender_id;
            // a second KeyPackage from the same sender (or a sender
            // already represented in the tree) is rejected. Without this
            // a single peer can publish many KeyPackages, growing the
            // tree arbitrarily and exhausting committer resources.
            this._leafBySenderId = new Map();
            // RFC 9420 KeyPackages are one-shot. Keep every accepted Add's
            // KeyPackageRef for the lifetime of this room, including after a
            // Remove, so an old init key cannot be replayed to re-admit the
            // former member. The set is never evicted; reaching the hard cap
            // fails future Adds closed.
            this._consumedKeyPackageRefs = new Set();
            // Reverse leafIndex → sender_id binding used ONLY for transport
            // routing diagnostics. The MLS signature authenticates the leaf
            // and its signature_key; sender_id is relay metadata and MUST
            // never supply a displayed name or security identity. The
            // creator seeds this map at Add time; other members remember the
            // first observed route and warn if the relay later re-stamps it.
            this._senderIdByLeaf = new Map();
            // Public identity cache keyed by the complete raw signature key.
            // Entries contain only SHA-256 fingerprints, never secret state.
            // Keeping prior keys cached lets surviving members' in-flight
            // previous-epoch messages retain their authenticated identity.
            // An authenticated Remove clears the cache completely.
            this._identityBySignatureKey = new Map();
            // Every member retains the complete, authenticated standalone
            // Proposal PublicMessages for the current epoch, keyed by their
            // RFC ProposalRef. Commits carry only those references, so each
            // recipient must resolve from its own store. Entries are
            // consumed atomically only when an epoch transition succeeds.
            this._proposalStore = new Map();
            this._proposalRefsBySender = new Map();
            // Creator-only selection queue: latest newly observed Update per
            // proposer leaf, awaiting the next periodic Commit. Older valid
            // proposals remain resolvable in _proposalStore but a replay of
            // an already-stored reference cannot move this pointer backward.
            this._pendingUpdateProposals = new Map();
            // Member-only: private HPKE keys for every locally-authored
            // current-epoch Update, keyed by ProposalRef. Keeping them by
            // exact reference lets us process a valid Commit even if more
            // than one of our proposals was in flight.
            this._pendingSelfUpdates = new Map();
            // Latest entry retained for compatibility with UI/tests; the
            // keyed map above is authoritative during Commit processing.
            this._pendingSelfUpdate = null;
            // Locally-authored Commits are built against an isolated Group
            // candidate and remain pending until the relay sends back the
            // exact PublicMessage payload. The live Group MUST NOT advance
            // merely because WebSocket.send accepted bytes locally.
            this._pendingCommit = null;
            this._localCommitBusy = false;
            // One promise mutex serializes every browser-facing operation
            // that can read or mutate MLS state. Crypto operations cross
            // multiple await points (signature/HPKE/AEAD), so checking a
            // boolean before the first await is not sufficient: a timer,
            // UI send, or inbound WebSocket frame could otherwise observe a
            // half-advanced ratchet or build a Commit from an unstable
            // epoch. Rejections are removed from the tail so one malformed
            // peer message cannot poison subsequent work.
            this._operationMutex = Promise.resolve();
            // While a local Commit is being built or awaiting its relay
            // echo, defer peer envelopes. This prevents application-ratchet
            // or proposal state from changing underneath the candidate and
            // being rolled back when the candidate is installed.
            this._deferredEnvelopes = [];
            this._deferredEnvelopeBytes = 0;
            // KeyPackages are ordered controls, so accepting one into a
            // bounded, validated per-sender map is the durable application
            // action which permits its control ACK while a prior local Commit
            // is awaiting its own relay echo.
            this._deferredKeyPackages = new Map();
            this._deferredKeyPackageBytes = 0;
            this._deferredRemovals = new Set();
            // Relay lifecycle departures are ordered with MLS controls, but
            // they can still arrive while the corresponding Add is staged or
            // while an earlier local Commit awaits acceptance. Retain a
            // tombstone immediately so a delayed KeyPackage cannot resurrect
            // the departed route. If its Add is later accepted, suppress the
            // Welcome and commit an immediate Remove.
            this._departedSenderIds = new Set();
            this._drainingDeferredEnvelopes = false;
        }

        /**
         * Run one complete MLS operation after all earlier operations have
         * settled. Callers already executing inside this gate must invoke
         * private implementation helpers directly; recursively queueing and
         * awaiting the public wrapper would deadlock.
         */
        _serializeOperation(operation) {
            const task = this._operationMutex.then(() => operation());
            this._operationMutex = task.catch(() => undefined);
            return task;
        }

        /**
         * Start the MLS handshake.
         *   creator: spins up a 1-leaf group and waits for a joiner's
         *            KeyPackage. On arrival, commits Add + sends
         *            Commit + Welcome + ratchet_tree.
         *   joiner:  publishes our own KeyPackage and waits for the
         *            Welcome addressed to us.
         */
        async start() {
            return this._serializeOperation(() => this._start());
        }

        async _start() {
            if (this.role === 'creator') {
                const id = await this._freshIdentity();
                this.identity = id;
                this.group = await MLS.Group.Group.create({
                    identity: id,
                    pskSecret: this.pskSecret,
                });
                this.expectedGroupId = Uint8Array.from(this.group.groupId);
                this.expectedCreatorKeyHash = await MLS.Labeled.sha256(
                    id.signaturePublicKeyBytes,
                );
                this._state = 'awaiting-keypackage';
                await this._emitAuthenticatedRoster();
            } else {
                if (!this.expectedGroupId || !this.expectedCreatorKeyHash) {
                    throw new Error(
                        'mls-session: group invite is missing authenticated '
                        + 'group_id / creator-key pins',
                    );
                }
                if (!this.relaySenderId) {
                    throw new Error(
                        'mls-session: joiner is missing its stable relay sender_id',
                    );
                }
                const bundle = await buildKeyPackage();
                this.identity = bundle.identity;
                this.keyPackageBundle = bundle;
                this._keyPackageRefBytes = await MLS.KeyPackage.keyPackageRef(
                    bundle.keyPackageBytes,
                );
                this._keyPackageRef = base64UrlEncode(this._keyPackageRefBytes);
                const keyPackageEnvelope = envelopeFromMlsMessage(
                    MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE,
                    bundle.keyPackageBytes,
                );
                keyPackageEnvelope.bootstrap_proof = base64UrlEncode(
                    await keyPackageBootstrapProof({
                        pskSecret: this.pskSecret,
                        expectedGroupId: this.expectedGroupId,
                        expectedCreatorKeyHash: this.expectedCreatorKeyHash,
                        relaySenderId: this.relaySenderId,
                        keyPackageBytes: bundle.keyPackageBytes,
                    }),
                );
                await this._sendEnvelopeOrThrow(
                    keyPackageEnvelope,
                    'KeyPackage broadcast failed',
                );
                this.onEvent({ kind: 'keypackage-published' });
                this._state = 'awaiting-welcome';
            }
        }

        async _freshIdentity() {
            const kp = await MLS.Signature.generateKeyPair();
            return {
                signaturePrivateKey: kp.privateKey,
                signaturePublicKeyBytes: kp.publicKeyBytes,
            };
        }

        async _verifyKeyPackageBootstrapProof(
            keyPackageBytes, senderId, encodedProof,
        ) {
            const supplied = decodeCorrelationRef(
                encodedProof, 'bootstrap_proof',
            );
            const expected = await keyPackageBootstrapProof({
                pskSecret: this.pskSecret,
                expectedGroupId: this.expectedGroupId,
                expectedCreatorKeyHash: this.expectedCreatorKeyHash,
                relaySenderId: senderId,
                keyPackageBytes,
            });
            if (!equalBytes(supplied, expected)) {
                throw validationMlsControlError(
                    'mls-session: KeyPackage bootstrap proof is invalid',
                );
            }
        }

        async _availableKeyPackageRef(keyPackageBytes) {
            const reference = base64UrlEncode(
                await MLS.KeyPackage.keyPackageRef(keyPackageBytes),
            );
            if (this._consumedKeyPackageRefs.has(reference)) {
                throw validationMlsControlError(
                    'mls-session: KeyPackageRef was already consumed by an accepted Add',
                );
            }
            if (this._consumedKeyPackageRefs.size
                >= MAX_CONSUMED_KEY_PACKAGE_REFS) {
                throw fatalMlsStateError(
                    'MLS consumed KeyPackageRef capacity exhausted',
                );
            }
            return reference;
        }

        /**
         * Describe one MLS member exclusively from its authenticated
         * LeafNode.signature_key. sender_id is deliberately absent.
         */
        async _authenticatedIdentity(signatureKey, leafIndex, myLeafIndex) {
            if (!(signatureKey instanceof Uint8Array) || signatureKey.length !== 65) {
                throw new Error('mls-session: invalid member signature_key');
            }
            const cacheKey = base64UrlEncode(signatureKey);
            let fingerprint = this._identityBySignatureKey.get(cacheKey);
            if (!fingerprint) {
                const full = hexEncode(await MLS.Labeled.sha256(signatureKey));
                fingerprint = Object.freeze({
                    fingerprint: full,
                    shortFingerprint: shortFingerprint(full),
                });
                this._identityBySignatureKey.set(cacheKey, fingerprint);
            }
            const isCreator = leafIndex === CREATOR_LEAF_INDEX;
            return Object.freeze({
                leafIndex,
                fingerprint: fingerprint.fingerprint,
                shortFingerprint: fingerprint.shortFingerprint,
                displayName: `${isCreator ? 'Creator' : 'Member'} · `
                    + fingerprint.shortFingerprint,
                isCreator,
                isSelf: leafIndex === myLeafIndex,
            });
        }

        async _authenticatedRosterEvent(group = this.group) {
            if (!group) {
                throw new Error('mls-session: cannot build roster without group state');
            }
            const members = [];
            for (let leafIndex = 0; leafIndex < group.nLeaves; leafIndex += 1) {
                const leaf = MLS.RatchetTree.leafFor(
                    group.ratchetTree, leafIndex,
                );
                // Remove commits leave blank leaves. They are not members of
                // the authenticated roster and must disappear only after the
                // Commit installing that blank has been accepted.
                if (!leaf) continue;
                members.push(await this._authenticatedIdentity(
                    leaf.signatureKey, leafIndex, group.myLeafIndex,
                ));
            }
            return Object.freeze({
                kind: 'roster',
                epoch: group.epoch.toString(),
                myLeafIndex: group.myLeafIndex,
                members: Object.freeze(members),
            });
        }

        async _emitAuthenticatedRoster(group = this.group) {
            const event = await this._authenticatedRosterEvent(group);
            this.onEvent(event);
            return event;
        }

        _storeAuthenticatedProposal(verified) {
            if (!this.group || !verified || verified.epoch !== this.group.epoch) {
                throw new Error('mls-session: proposal store entry is not for the current epoch');
            }
            if (!(verified.messageBytes instanceof Uint8Array)) {
                throw new Error('mls-session: proposal store entry has no authenticated message');
            }
            const referenceKey = MLS.Group.proposalReferenceKey(verified.reference);
            const existing = this._proposalStore.get(referenceKey);
            if (existing) {
                if (!equalBytes(existing.messageBytes, verified.messageBytes)) {
                    throw new Error('mls-session: ProposalRef collision in proposal store');
                }
                return { entry: existing, isNew: false };
            }
            const senderLeafIndex = verified.senderLeafIndex;
            if (!Number.isInteger(senderLeafIndex)
                || senderLeafIndex < 0 || senderLeafIndex >= MAX_GROUP_LEAVES) {
                throw new Error(
                    'mls-session: proposal store entry has invalid sender leaf',
                );
            }
            let senderReferences =
                this._proposalRefsBySender.get(senderLeafIndex);
            if (senderReferences
                && senderReferences.length >= MAX_PROPOSALS_PER_SENDER) {
                // A Commit may already have been constructed with any
                // authenticated ProposalRef retained for this epoch. Evicting
                // an older entry to admit a newer one would make that Commit
                // unresolvable on recipients that observed the newer
                // Proposals first. Keep admission monotonic: once the bounded
                // per-sender set is full, reject additional Proposals and
                // retain every previously accepted reference until the epoch
                // changes.
                throw new Error(
                    `mls-session: proposal quota exhausted for sender leaf `
                    + `${senderLeafIndex}; earlier ProposalRefs retained`,
                );
            }
            if (this._proposalStore.size >= MAX_PROPOSALS_PER_EPOCH) {
                throw new Error(
                    'mls-session: authenticated proposal store invariant exceeded',
                );
            }
            if (!senderReferences) {
                senderReferences = [];
                this._proposalRefsBySender.set(
                    senderLeafIndex, senderReferences,
                );
            }
            const entry = Object.freeze({
                proposal: verified.proposal,
                senderLeafIndex,
                epoch: verified.epoch,
                reference: Uint8Array.from(verified.reference),
                messageBytes: Uint8Array.from(verified.messageBytes),
            });
            this._proposalStore.set(referenceKey, entry);
            senderReferences.push(referenceKey);
            return { entry, isNew: true };
        }

        _clearEpochProposalState() {
            this._proposalStore.clear();
            this._proposalRefsBySender.clear();
            this._pendingUpdateProposals.clear();
            this._pendingSelfUpdates.clear();
            this._pendingSelfUpdate = null;
        }

        _transitionToDesynced(reason) {
            if (this._state === 'desynced') return;
            const liveGroup = this.group;
            const candidateGroup = this._pendingCommit?.candidateGroup || null;
            if (this._pendingCommit?.retryTimer) {
                clearTimeout(this._pendingCommit.retryTimer);
            }
            if (candidateGroup && candidateGroup !== liveGroup) {
                candidateGroup.destroySecrets();
            }
            if (liveGroup) liveGroup.destroySecrets();
            this._pendingCommit = null;
            this._clearEpochProposalState();
            this._pendingWelcomeCommits.clear();
            this._pendingWelcomeCommitBySender.clear();
            this._deferredEnvelopes.length = 0;
            this._deferredEnvelopeBytes = 0;
            this._deferredKeyPackages.clear();
            this._deferredKeyPackageBytes = 0;
            this._deferredRemovals.clear();
            this._departedSenderIds.clear();
            this._leafBySenderId.clear();
            this._consumedKeyPackageRefs.clear();
            this._senderIdByLeaf.clear();
            this._identityBySignatureKey.clear();
            wipeBytes(this.pskSecret);
            wipeBytes(this._keyPackageRefBytes);
            wipeBytes(this.expectedGroupId);
            wipeBytes(this.expectedCreatorKeyHash);
            this.pskSecret = null;
            this._keyPackageRefBytes = null;
            this._keyPackageRef = null;
            this.expectedGroupId = null;
            this.expectedCreatorKeyHash = null;
            this.keyPackageBundle = null;
            this.identity = null;
            this._localCommitBusy = false;
            this.group = null;
            this._state = 'desynced';
            this.onEvent({
                kind: 'desynced',
                reason,
            });
        }

        _transitionToRemoved(result) {
            if (!result || result.removedSelf !== true) {
                throw new Error('mls-session: invalid authenticated-removal result');
            }

            const liveGroup = this.group;
            const pendingCommit = this._pendingCommit;
            const candidateGroup = pendingCommit?.candidateGroup || null;
            if (pendingCommit?.retryTimer) {
                clearTimeout(pendingCommit.retryTimer);
            }
            if (candidateGroup && candidateGroup !== liveGroup) {
                candidateGroup.destroySecrets();
            }
            if (liveGroup) liveGroup.destroySecrets();

            this._pendingCommit = null;
            this._clearEpochProposalState();
            this._pendingWelcomeCommits.clear();
            this._pendingWelcomeCommitBySender.clear();
            this._deferredEnvelopes.length = 0;
            this._deferredEnvelopeBytes = 0;
            this._deferredKeyPackages.clear();
            this._deferredKeyPackageBytes = 0;
            this._deferredRemovals.clear();
            this._departedSenderIds.clear();
            this._leafBySenderId.clear();
            this._consumedKeyPackageRefs.clear();
            this._senderIdByLeaf.clear();
            this._identityBySignatureKey.clear();

            wipeBytes(this.pskSecret);
            wipeBytes(this._keyPackageRefBytes);
            wipeBytes(this.expectedGroupId);
            wipeBytes(this.expectedCreatorKeyHash);
            this.pskSecret = null;
            this._keyPackageRefBytes = null;
            this._keyPackageRef = null;
            this.expectedGroupId = null;
            this.expectedCreatorKeyHash = null;
            this.keyPackageBundle = null;
            this.identity = null;
            this.group = null;
            this._localCommitBusy = false;
            this._state = 'removed';

            this.onEvent({
                kind: 'removed',
                removedLeafIndex: result.removedLeafIndex,
                removedLeafIndices: [...result.removedLeafIndices],
                committerLeafIndex: result.committerLeafIndex,
                epoch: result.epoch.toString(),
            });
        }

        async _sendEnvelopeOrThrow(envelope, description) {
            let result;
            try {
                result = await this.send(envelope);
            } catch (err) {
                throw new Error(`${description}: ${err.message}`);
            }
            if (result === false) {
                throw new Error(`${description}: transport rejected envelope`);
            }
        }

        /**
         * Destroy a speculative local Commit without touching the live Group.
         * The exact transport envelope is cancelled first so reconnect replay
         * cannot keep resending a Commit which the ordered relay state has
         * made permanently ineligible for acceptance.
         *
         * Cancellation is advisory cleanup rather than a precondition for
         * erasing the candidate: once the relay has conclusively rejected a
         * Commit (or finalized its Add target's departure), retaining the
         * candidate would deadlock all future MLS work. A transport cleanup
         * failure is surfaced separately while protocol state still aborts.
         */
        async _abortPendingCommit(pending, reason) {
            if (!pending || this._pendingCommit !== pending) return false;

            let cancellationError = null;
            try {
                const cancelled = await this.cancelPendingControl(
                    pending.commitEnvelope,
                );
                if (cancelled === false) {
                    cancellationError = new Error(
                        'transport did not retain the pending control',
                    );
                }
            } catch (err) {
                cancellationError = err;
            }

            // Re-check after the callback in case a custom synchronous
            // transport accepted the candidate while cancellation ran.
            if (this._pendingCommit !== pending) return false;
            if (pending.retryTimer) clearTimeout(pending.retryTimer);
            this._pendingCommit = null;
            pending.candidateGroup.destroySecrets();

            if (pending.kind === 'add') {
                const deferredKeyPackage =
                    this._deferredKeyPackages.get(pending.senderId);
                if (deferredKeyPackage) {
                    this._deferredKeyPackages.delete(pending.senderId);
                    this._deferredKeyPackageBytes = Math.max(
                        0,
                        this._deferredKeyPackageBytes
                            - deferredKeyPackage.encodedBytes,
                    );
                }
                this._deferredRemovals.delete(pending.senderId);
                this._departedSenderIds.delete(pending.senderId);
            }

            this.onEvent({ kind: 'error', reason });
            if (cancellationError) {
                this.onEvent({
                    kind: 'error',
                    reason: `Pending MLS control cancellation failed after `
                        + `candidate abort: ${cancellationError.message}`,
                });
            }
            return true;
        }

        /**
         * The application normally filters relay echoes carrying our own
         * sender_id. The sole exception is the exact Commit currently in
         * PendingCommit: its echo is the relay-acceptance signal that makes
         * the staged epoch eligible for atomic installation.
         */
        shouldHandleOwnEnvelope(envelope) {
            const pending = this._pendingCommit;
            return Boolean(
                pending
                && envelope
                && envelope.type === 'mls'
                && envelope.wire_format
                    === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && envelope.payload === pending.commitEnvelope.payload,
            );
        }

        async _stagePendingCommit({
            candidateGroup, commitMessage, kind,
            commitRef = null, keyPackageRef = null,
            ...metadata
        }) {
            if (this._pendingCommit) {
                throw new Error('mls-session: another Commit is already awaiting relay acceptance');
            }
            const commitBody = stripMlsWrapper(commitMessage);
            const computedCommitRefBytes = await MLS.Labeled.sha256(commitBody);
            const computedCommitRef = base64UrlEncode(computedCommitRefBytes);
            if (commitRef !== null) {
                const suppliedCommitRef = decodeCorrelationRef(
                    commitRef, 'commit_ref',
                );
                if (!equalBytes(suppliedCommitRef, computedCommitRefBytes)) {
                    throw new Error(
                        'mls-session: supplied commit_ref does not match Commit payload',
                    );
                }
            }
            if (keyPackageRef !== null) {
                decodeCorrelationRef(keyPackageRef, 'key_package_ref');
            }
            const commitEnvelope = {
                type: 'mls',
                payload: base64UrlEncode(commitBody),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
                commit_ref: computedCommitRef,
            };
            if (keyPackageRef !== null) {
                commitEnvelope.key_package_ref = keyPackageRef;
            }
            const pending = {
                candidateGroup,
                commitEnvelope,
                kind,
                commitRef: computedCommitRef,
                keyPackageRef,
                ...metadata,
            };
            // Install the pending marker BEFORE calling the transport so a
            // synchronous/in-memory relay cannot race its echo ahead of us.
            this._pendingCommit = pending;
            try {
                await this._sendEnvelopeOrThrow(
                    commitEnvelope, 'Commit broadcast failed before acceptance',
                );
            } catch (err) {
                // A synchronous/in-memory relay may echo and accept the
                // Commit before its send promise settles. In that case the
                // echo is authoritative; never erase the now-live candidate
                // merely because the transport subsequently reports an
                // inconsistent failure.
                if (this._pendingCommit !== pending) return true;
                this._pendingCommit = null;
                candidateGroup.destroySecrets();
                this.onEvent({ kind: 'error', reason: err.message });
                return false;
            }
            return true;
        }

        async _acceptPendingCommit() {
            const pending = this._pendingCommit;
            if (!pending) return false;
            // Claim this exact PendingCommit before the first await. Duplicate
            // relay echoes can arrive back-to-back; without the claim both
            // handlers could derive a roster and install/announce it twice.
            if (pending.accepting) return false;
            pending.accepting = true;

            // Fingerprinting is the only fallible UI preparation. Complete it
            // before installing the candidate so a platform hash failure
            // cannot leave the protocol advanced but the visual roster stale.
            let rosterEvent;
            try {
                rosterEvent = await this._authenticatedRosterEvent(
                    pending.candidateGroup,
                );
            } catch (err) {
                // Keep the candidate pending so a transient local hashing
                // failure can be retried by a later exact echo.
                pending.accepting = false;
                throw retryableMlsControlError(
                    err,
                    'mls-session: pending Commit roster derivation failed: ',
                );
            }

            // Clear first so a duplicate echo cannot install or announce the
            // candidate twice. Everything below is local bookkeeping or a
            // post-acceptance Welcome; the MLS state swap itself is atomic.
            if (pending.retryTimer) clearTimeout(pending.retryTimer);
            this._pendingCommit = null;
            const supersededGroup = this.group;
            this.group = pending.candidateGroup;
            if (supersededGroup && supersededGroup !== this.group) {
                // The accepted candidate owns an independent clone of the
                // outgoing epoch for its bounded grace window. The former
                // live Group must not retain a second complete copy.
                supersededGroup.destroySecrets();
            }
            // ProposalRefs are scoped to the epoch in which their
            // AuthenticatedContent was signed. Only an accepted transition
            // consumes the store; failures and unacknowledged candidates
            // leave it untouched for a later valid Commit.
            this._clearEpochProposalState();
            this.onEvent(rosterEvent);

            if (pending.kind === 'add') {
                if (typeof pending.keyPackageRef !== 'string'
                    || this._consumedKeyPackageRefs.has(
                        pending.keyPackageRef,
                    )) {
                    this._transitionToDesynced(
                        'accepted Add has an invalid or reused KeyPackageRef',
                    );
                    throw fatalMlsStateError(
                        'accepted Add violated one-shot KeyPackageRef state',
                    );
                }
                this._consumedKeyPackageRefs.add(pending.keyPackageRef);
                this._leafBySenderId.set(pending.senderId, pending.addedLeafIndex);
                this._senderIdByLeaf.set(pending.addedLeafIndex, pending.senderId);
                this._state = 'joined';
                if (this._departedSenderIds.has(pending.senderId)) {
                    // The relay ordered a final departure before this Add's
                    // acceptance echo. We must still install the accepted Add
                    // to remain in sync with other members, but the departed
                    // peer must receive neither its Welcome nor lasting roster
                    // membership.
                    this._deferredRemovals.add(pending.senderId);
                } else {
                    try {
                        // A Welcome describes the now-accepted epoch and must
                        // never precede acceptance of the Commit that created it.
                        await this._sendEnvelopeOrThrow(
                            pending.welcomeEnvelope,
                            'Welcome broadcast failed after Commit acceptance',
                        );
                        this.onEvent({ kind: 'welcome-sent' });
                    } catch (err) {
                        // The Commit was already accepted, so rolling back here
                        // would fork existing members. Keep the accepted epoch and
                        // report that the intended joiner needs a fresh retry.
                        this.onEvent({ kind: 'error', reason: err.message });
                    }
                }
            } else if (pending.kind === 'update') {
                this.onEvent({
                    kind: 'update-committed',
                    epoch: this.group.epoch.toString(),
                    foldedUpdates: pending.foldedUpdates,
                });
            } else if (pending.kind === 'remove') {
                if (this._leafBySenderId.get(pending.senderId)
                    === pending.removedLeafIndex) {
                    this._leafBySenderId.delete(pending.senderId);
                }
                if (this._senderIdByLeaf.get(pending.removedLeafIndex)
                    === pending.senderId) {
                    this._senderIdByLeaf.delete(pending.removedLeafIndex);
                }
                this._departedSenderIds.delete(pending.senderId);
                this.onEvent({
                    kind: 'remove-committed',
                    removedLeafIndex: pending.removedLeafIndex,
                });
            } else {
                throw new Error(`mls-session: unknown pending Commit kind "${pending.kind}"`);
            }

            await this._drainDeferredEnvelopes();
            return true;
        }

        async _drainDeferredEnvelopes() {
            if (this._drainingDeferredEnvelopes
                || this._localCommitBusy
                || this._pendingCommit) return;
            this._drainingDeferredEnvelopes = true;
            try {
                while (!this._localCommitBusy
                    && !this._pendingCommit) {
                    if (this._deferredEnvelopes.length > 0) {
                        const deferred = this._deferredEnvelopes.shift();
                        this._deferredEnvelopeBytes = Math.max(
                            0,
                            this._deferredEnvelopeBytes
                                - deferred.encodedBytes,
                        );
                        await this._onRelayEnvelope(deferred.envelope);
                        continue;
                    }
                    const nextKeyPackage =
                        this._deferredKeyPackages.entries().next();
                    if (!nextKeyPackage.done) {
                        const [senderId, deferred] = nextKeyPackage.value;
                        this._deferredKeyPackages.delete(senderId);
                        this._deferredKeyPackageBytes = Math.max(
                            0,
                            this._deferredKeyPackageBytes
                                - deferred.encodedBytes,
                        );
                        if (this._departedSenderIds.has(senderId)
                            || this._leafBySenderId.has(senderId)) {
                            continue;
                        }
                        let keyPackageRef;
                        try {
                            // A preceding accepted Add may have consumed the
                            // final leaf slot or installed a key which collides
                            // with this already-ACKed KeyPackage. Revalidate
                            // against the new live tree and deterministically
                            // reject it instead of retrying forever.
                            await this.group.validateKeyPackageForAdd(
                                deferred.bytes,
                            );
                            keyPackageRef = await this._availableKeyPackageRef(
                                deferred.bytes,
                            );
                        } catch (err) {
                            const classified = classifyMlsControlError(
                                err, 'deferred KeyPackage validation failed: ',
                            );
                            if (classified.mlsRetryControl === true
                                || classified.mlsFatalState === true) {
                                this._deferredKeyPackages.set(
                                    senderId, deferred,
                                );
                                this._deferredKeyPackageBytes +=
                                    deferred.encodedBytes;
                                throw classified;
                            }
                            this.onEvent({
                                kind: 'error',
                                reason: classified.message,
                            });
                            continue;
                        }
                        let staged;
                        try {
                            staged = await this._handleIncomingKeyPackage(
                                deferred.bytes, senderId, keyPackageRef,
                            );
                        } catch (err) {
                            if (err?.mlsRetryControl === true
                                || err?.mlsFatalState === true) {
                                this._deferredKeyPackages.set(
                                    senderId, deferred,
                                );
                                this._deferredKeyPackageBytes +=
                                    deferred.encodedBytes;
                            }
                            if (err?.mlsFatalState === true) throw err;
                            if (err?.mlsRetryControl === true) break;
                            continue;
                        }
                        if (!staged && !this._departedSenderIds.has(senderId)
                            && !this._leafBySenderId.has(senderId)) {
                            // A transient local crypto/platform failure must
                            // not lose an already-ACKed KeyPackage. Retain it
                            // for the next replay-sync/timer drain without
                            // spinning in this invocation.
                            this._deferredKeyPackages.set(senderId, deferred);
                            this._deferredKeyPackageBytes +=
                                deferred.encodedBytes;
                            break;
                        }
                        continue;
                    }
                    // userleft handling is deliberately fire-and-forget in
                    // app.js, so a Remove request can race an in-flight local
                    // Commit without passing through onRelayEnvelope. Retain
                    // it here instead of silently losing the membership
                    // revocation.
                    const nextRemoval = this._deferredRemovals.values().next();
                    if (nextRemoval.done) break;
                    this._deferredRemovals.delete(nextRemoval.value);
                    await this._removeMemberBySenderId(nextRemoval.value);
                }
            } finally {
                this._drainingDeferredEnvelopes = false;
            }
        }

        /**
         * Dispatch an incoming `mls` envelope from the relay. Own echoes
         * are filtered upstream except for shouldHandleOwnEnvelope().
         */
        async onRelayEnvelope(envelope) {
            // Preserve support for a transport that synchronously feeds the
            // exact Commit echo back from inside send(). The candidate is
            // complete once _pendingCommit exists, and waiting behind the
            // operation mutex here would deadlock that transport. All other
            // relay traffic enters the same queue as local UI/timer work.
            if (this._localCommitBusy && this.shouldHandleOwnEnvelope(envelope)) {
                return this._acceptPendingCommit();
            }
            // Queue an immutable-by-convention snapshot. Otherwise a caller
            // retaining the transport object could change routing metadata or
            // payload strings while an earlier crypto operation is awaiting.
            const queuedEnvelope = { ...envelope };
            return this._serializeOperation(
                () => this._onRelayEnvelope(queuedEnvelope),
            );
        }

        /**
         * Consume a direct relay rejection for a locally staged Commit. The
         * live Group has not advanced yet. A quota rejection retains that
         * isolated candidate and retries the exact bytes after the server's
         * advertised window; rebuilding would lose Add context and could
         * create a different Commit.
         */
        async onTransportRejection(rejection) {
            const snapshot = { ...rejection };
            return this._serializeOperation(
                () => this._onTransportRejection(snapshot),
            );
        }

        async _onTransportRejection(rejection) {
            const retryableReasons = new Set([
                'commit_rate_limited',
                'room_rate_limited',
            ]);
            const permanentReasons = new Set([
                'unknown_key_package_ref',
                'not_group_creator',
                'commit_correlation_conflict',
                'welcome_not_correlated',
            ]);
            if (!rejection || rejection.type !== 'mlsrejected'
                || (!retryableReasons.has(rejection.reason)
                    && !permanentReasons.has(rejection.reason))
                || typeof rejection.commit_ref !== 'string'
                || (permanentReasons.has(rejection.reason)
                    && rejection.retry_after_secs !== 0)) {
                throw new Error('mls-session: malformed transport rejection');
            }
            if (rejection.reason === 'welcome_not_correlated') {
                this.onEvent({
                    kind: 'error',
                    reason: 'relay permanently rejected Welcome because its accepted Add correlation is unavailable; the joiner must publish a fresh KeyPackage',
                });
                return true;
            }
            const pending = this._pendingCommit;
            if (rejection.reason === 'not_group_creator') {
                const explanation =
                    'relay permanently rejected MLS control because this connection is not the group creator';
                if (pending && pending.commitRef === rejection.commit_ref) {
                    await this._abortPendingCommit(pending, explanation);
                }
                this._transitionToDesynced(explanation);
                const fatal = new Error(explanation);
                fatal.mlsFatalState = true;
                throw fatal;
            }
            if (!pending || pending.commitRef !== rejection.commit_ref) {
                return false;
            }
            if (permanentReasons.has(rejection.reason)) {
                const explanation = rejection.reason
                    === 'unknown_key_package_ref'
                    ? 'relay permanently rejected Add Commit because its KeyPackageRef is no longer available'
                    : 'relay permanently rejected Add Commit because its Commit/KeyPackage correlation conflicts with retained state';
                const aborted = await this._abortPendingCommit(
                    pending, explanation,
                );
                if (aborted) await this._drainDeferredEnvelopes();
                return aborted;
            }
            const retryAfter = Number.isSafeInteger(rejection.retry_after_secs)
                && rejection.retry_after_secs > 0
                ? Math.min(rejection.retry_after_secs, 3600) : 60;
            this.onEvent({
                kind: 'error',
                reason: `MLS Commit was ${rejection.reason === 'room_rate_limited'
                    ? 'deferred by the room traffic limit'
                    : 'rate-limited by the relay'}; retrying after `
                    + `${retryAfter} seconds`,
            });
            if (!pending.retryTimer) {
                pending.retryTimer = setTimeout(() => {
                    pending.retryTimer = null;
                    void this._serializeOperation(async () => {
                        if (this._pendingCommit !== pending
                            || this._state === 'removed') return;
                        try {
                            await this._sendEnvelopeOrThrow(
                                pending.commitEnvelope,
                                'Commit retry failed before acceptance',
                            );
                        } catch (err) {
                            this.onEvent({ kind: 'error', reason: err.message });
                        }
                    });
                }, retryAfter * 1000);
                // Node regression tests should not stay alive solely for a
                // browser-style retry timer.
                if (typeof pending.retryTimer?.unref === 'function') {
                    pending.retryTimer.unref();
                }
            }
            return true;
        }

        async _onRelayEnvelope(envelope) {
            if (this.shouldHandleOwnEnvelope(envelope)) {
                await this._acceptPendingCommit();
                return;
            }
            let payload;
            try {
                payload = base64UrlDecode(envelope.payload);
            } catch (err) {
                throw rejectedMlsControlError(
                    err, 'mls-session: malformed MLS envelope payload: ',
                );
            }
            const wireFormat = envelope.wire_format;
            if (this._localCommitBusy || this._pendingCommit) {
                if (wireFormat
                    === MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE) {
                    const encodedBytes = envelopeEncodedBytes(envelope);
                    if (this._deferredEnvelopes.length
                            >= MAX_DEFERRED_PRIVATE_MESSAGES
                        || this._deferredEnvelopeBytes + encodedBytes
                            > MAX_DEFERRED_PRIVATE_BYTES) {
                        // PrivateMessages are ephemeral rather than ordered
                        // controls. Drop excess traffic instead of allowing a
                        // peer to grow the candidate's old-epoch receive queue
                        // without bound.
                        this.onEvent({
                            kind: 'error',
                            reason: 'MLS private-message queue full while Commit awaits acceptance',
                        });
                        return;
                    }
                    this._deferredEnvelopes.push({
                        envelope: { ...envelope },
                        encodedBytes,
                    });
                    this._deferredEnvelopeBytes += encodedBytes;
                    return;
                }
                if (wireFormat === MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE
                    && this.role === 'creator'
                    && (this._state === 'awaiting-keypackage'
                        || this._state === 'joined')) {
                    const senderId = envelope.sender_id;
                    if (!senderId) {
                        this.onEvent({ kind: 'error',
                            reason: 'KeyPackage envelope missing sender_id' });
                        return;
                    }
                    if (this._departedSenderIds.has(senderId)
                        || this._leafBySenderId.has(senderId)
                        || this._deferredKeyPackages.has(senderId)) {
                        return;
                    }
                    let keyPackageRef;
                    try {
                        await this._verifyKeyPackageBootstrapProof(
                            payload, senderId, envelope.bootstrap_proof,
                        );
                        // Validate all deterministic admission properties
                        // before treating this ordered control as durably
                        // accepted.
                        await this.group.validateKeyPackageForAdd(payload);
                        keyPackageRef = await this._availableKeyPackageRef(
                            payload,
                        );
                    } catch (err) {
                        const classified = classifyMlsControlError(
                            err, 'invalid deferred KeyPackage: ',
                        );
                        this.onEvent({
                            kind: 'error',
                            reason: classified.message,
                        });
                        throw classified;
                    }
                    const encodedBytes = envelopeEncodedBytes(envelope);
                    if (this._deferredKeyPackageBytes + encodedBytes
                        > MAX_DEFERRED_KEYPACKAGE_BYTES) {
                        throw fatalMlsStateError(
                            'MLS deferred KeyPackage byte budget exhausted',
                        );
                    }
                    this._deferredKeyPackages.set(senderId, {
                        bytes: Uint8Array.from(payload),
                        encodedBytes,
                        keyPackageRef,
                    });
                    this._deferredKeyPackageBytes += encodedBytes;
                    return;
                }
                // PublicMessage Proposal/Commit controls are safe to parse
                // against the unchanged live epoch while our candidate waits.
                // In particular, never ACK a raw, unvalidated PublicMessage
                // merely because it was appended to a deferred queue.
                if (wireFormat !==
                    MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE) {
                    this.onEvent({
                        kind: 'error',
                        reason: 'unsupported MLS envelope while Commit awaits acceptance',
                    });
                    return;
                }
            }

            // Creator: accept KeyPackages from new joiners while we have
            // a valid group to commit into. The state machine moves
            // 'awaiting-keypackage' → 'joined' on the first commit and
            // stays 'joined' afterwards; both states accept new KPs.
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE
                && this.role === 'creator'
                && (this._state === 'awaiting-keypackage' || this._state === 'joined')) {
                // Bind the KeyPackage to the relay's sender_id. A peer
                // who already has a leaf cannot publish a second one;
                // an envelope without sender_id (legacy/relay bug) is
                // rejected so attackers can't bypass the per-sender
                // quota by spoofing the field's absence.
                const senderId = envelope.sender_id;
                if (!senderId) {
                    this.onEvent({ kind: 'error',
                        reason: 'KeyPackage envelope missing sender_id' });
                    return;
                }
                if (this._departedSenderIds.has(senderId)) {
                    // A replay-delayed KeyPackage from a route whose final
                    // departure was already ordered must not create a phantom
                    // MLS member.
                    return;
                }
                if (this._leafBySenderId.has(senderId)) {
                    this.onEvent({ kind: 'error',
                        reason: `sender ${senderId} already has a leaf — duplicate KeyPackage rejected` });
                    return;
                }
                let keyPackageRef;
                try {
                    await this._verifyKeyPackageBootstrapProof(
                        payload, senderId, envelope.bootstrap_proof,
                    );
                    await this.group.validateKeyPackageForAdd(payload);
                    keyPackageRef = await this._availableKeyPackageRef(
                        payload,
                    );
                } catch (err) {
                    const classified = classifyMlsControlError(
                        err, 'invalid KeyPackage: ',
                    );
                    this.onEvent({
                        kind: 'error',
                        reason: classified.message,
                    });
                    throw classified;
                }
                const staged = await this._handleIncomingKeyPackage(
                    payload, senderId, keyPackageRef,
                );
                if (!staged && !this._departedSenderIds.has(senderId)
                    && !this._leafBySenderId.has(senderId)) {
                    // Validation succeeded, but the local candidate could
                    // not be built or staged. This is an ordered control:
                    // force a reconnect without ACK so the relay replays the
                    // same KeyPackage instead of silently losing the join.
                    const error = new Error(
                        'mls-session: validated KeyPackage could not be staged',
                    );
                    error.mlsRetryControl = true;
                    throw error;
                }
                return;
            }

            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_WELCOME
                && this.role === 'joiner' && this._state === 'awaiting-welcome') {
                try {
                    const candidate = await this._matchingWelcomeCommit(
                        payload, envelope,
                    );
                    // Welcomes are room broadcasts. A Welcome for another
                    // KeyPackage is expected during simultaneous joins and
                    // must not consume any of our buffered Commit candidates.
                    if (!candidate) return;
                    if (!envelope.ratchet_tree) {
                        this.onEvent({ kind: 'error',
                            reason: 'Welcome envelope missing ratchet_tree side-channel' });
                        return;
                    }
                    await this._handleWelcome(
                        payload,
                        base64UrlDecode(envelope.ratchet_tree),
                        candidate,
                    );
                    this._pendingWelcomeCommits.clear();
                    this._pendingWelcomeCommitBySender.clear();
                    return;
                } catch (err) {
                    throw classifyMlsControlError(
                        err, 'mls-session: rejected targeted Welcome: ',
                    );
                }
            }

            // Existing members (creator or already-joined joiners) process
            // incoming PublicMessage broadcasts. A PublicMessage is either
            // a Commit (advance epoch) or a standalone Proposal (an Update
            // proposal a member wants folded into the next Commit). We peek
            // the content_type to route; every member stores authenticated
            // Updates for ProposalRef resolution, while only the creator
            // selects proposals and authors Commits.
            // Own echoes are filtered upstream via sender_id.
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this._state === 'joined') {
                await this._handlePublicMessage(payload);
                return;
            }
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this.role === 'joiner' && this._state === 'awaiting-welcome') {
                try {
                    await this._bufferWelcomeCommit(payload, envelope);
                    return;
                } catch (err) {
                    throw classifyMlsControlError(
                        err, 'mls-session: rejected pre-Welcome control: ',
                    );
                }
            }

            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE
                && this._state === 'joined') {
                await this._handleApplication(payload, envelope.sender_id);
                return;
            }

            // Anything else (commit while still awaiting-welcome, etc.)
            // is silently dropped — Welcome is the catch-up path.
        }

        /**
         * Validate and retain an Add Commit addressed to our exact
         * KeyPackage. The outer Commit is not yet cryptographically
         * verifiable because a pre-Welcome joiner has no membership_key or
         * ratchet tree; GroupInfo/tree validation supplies that trust at
         * join. Here we enforce structural correlation, creator leaf 0,
         * pinned group_id, exact KeyPackage bytes, and a payload-derived
         * commit_ref so unrelated room traffic cannot replace the candidate.
         */
        async _bufferWelcomeCommit(mlsMessageBytes, envelope) {
            let pm;
            try {
                const wrapped = MLS.MLSMessage.serializeMLSMessage(
                    MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
                    mlsMessageBytes,
                );
                const frame = MLS.MLSMessage.parseMLSMessage(wrapped);
                pm = MLS.PublicMessage.parsePublicMessage(
                    frame.body,
                    (decoder, contentType) => {
                        if (contentType === MLS.Framing.ContentType.PROPOSAL) {
                            return MLS.Proposal.readProposal(decoder);
                        }
                        if (contentType === MLS.Framing.ContentType.COMMIT) {
                            return MLS.Commit.readCommit(decoder);
                        }
                        throw new Error(
                            `unsupported PublicMessage content_type ${contentType}`,
                        );
                    },
                );
            } catch (err) {
                throw validationMlsControlError(
                    `mls-session: malformed pre-Welcome PublicMessage: ${err.message}`,
                );
            }

            // Standalone proposals and ordinary membership/path commits do
            // not carry a KeyPackageRef for this joiner; ignore them while
            // waiting for the Add that actually addresses us.
            if (pm.content.contentType !== MLS.Framing.ContentType.COMMIT
                || !envelope.key_package_ref) return false;

            if (!this._keyPackageRefBytes || !this._keyPackageRef) {
                throw validationMlsControlError(
                    'mls-session: local KeyPackageRef is unavailable',
                );
            }
            const envelopeKeyPackageRef = decodeCorrelationRef(
                envelope.key_package_ref, 'key_package_ref',
            );
            if (!equalBytes(envelopeKeyPackageRef, this._keyPackageRefBytes)) {
                return false;
            }
            if (!equalBytes(pm.content.groupId, this.expectedGroupId)) {
                throw validationMlsControlError(
                    'mls-session: correlated Add Commit has unexpected group_id',
                );
            }
            if (!pm.content.sender
                || pm.content.sender.senderType !== MLS.Framing.SenderType.MEMBER
                || pm.content.sender.leafIndex !== CREATOR_LEAF_INDEX) {
                throw validationMlsControlError(
                    'mls-session: correlated Add Commit was not sent by creator leaf 0',
                );
            }

            let containsOurKeyPackage = false;
            for (const item of pm.content.parsed.proposals) {
                if (item.type !== MLS.Proposal.ProposalOrRefType.PROPOSAL
                    || !item.proposal
                    || item.proposal.proposalType !== MLS.Proposal.ProposalType.ADD) {
                    continue;
                }
                const addedKeyPackageBytes = MLS.KeyPackage.keyPackageBytes(
                    item.proposal.keyPackage,
                );
                if (equalBytes(
                    addedKeyPackageBytes,
                    this.keyPackageBundle.keyPackageBytes,
                )) {
                    containsOurKeyPackage = true;
                    break;
                }
            }
            if (!containsOurKeyPackage) {
                throw validationMlsControlError(
                    'mls-session: correlated Add Commit does not contain our KeyPackage',
                );
            }

            const commitRefBytes = decodeCorrelationRef(
                envelope.commit_ref, 'commit_ref',
            );
            const computedCommitRef = await MLS.Labeled.sha256(mlsMessageBytes);
            if (!equalBytes(commitRefBytes, computedCommitRef)) {
                throw validationMlsControlError(
                    'mls-session: commit_ref does not match PublicMessage payload',
                );
            }
            if (!envelope.sender_id) {
                throw validationMlsControlError(
                    'mls-session: correlated Add Commit envelope missing sender_id',
                );
            }
            const commitRef = base64UrlEncode(commitRefBytes);
            const existing = this._pendingWelcomeCommits.get(commitRef);
            if (existing) {
                if (existing.senderId !== envelope.sender_id) {
                    throw validationMlsControlError(
                        'mls-session: duplicate commit_ref arrived from a different relay sender',
                    );
                }
                return true;
            }
            const previousCommitRef =
                this._pendingWelcomeCommitBySender.get(envelope.sender_id);
            if (previousCommitRef && previousCommitRef !== commitRef) {
                // Pre-Welcome Commit signatures cannot yet be verified. Keep
                // exactly one candidate per stable relay sender so one room
                // participant cannot consume every candidate slot and starve
                // the authentic creator's later Commit.
                this._pendingWelcomeCommits.delete(previousCommitRef);
            }
            if (!previousCommitRef
                && this._pendingWelcomeCommits.size
                    >= MAX_PENDING_WELCOME_SENDERS) {
                throw validationMlsControlError(
                    'mls-session: too many distinct Welcome Commit senders',
                );
            }
            this._pendingWelcomeCommits.set(commitRef, {
                bytes: Uint8Array.from(mlsMessageBytes),
                commitRef,
                keyPackageRef: this._keyPackageRef,
                senderId: envelope.sender_id,
                senderLeafIndex: CREATOR_LEAF_INDEX,
                epoch: pm.content.epoch,
            });
            this._pendingWelcomeCommitBySender.set(
                envelope.sender_id, commitRef,
            );
            return true;
        }

        /**
         * Return the exact buffered Commit named by an incoming Welcome, or
         * null when the Welcome is addressed to another KeyPackage. Invalid
         * targeted Welcomes fail closed without deleting any candidate, so a
         * later authentic retransmission can still complete the join.
         */
        async _matchingWelcomeCommit(mlsMessageBytes, envelope) {
            if (!this._keyPackageRefBytes || !this._keyPackageRef) {
                throw validationMlsControlError(
                    'mls-session: local KeyPackageRef is unavailable',
                );
            }
            const envelopeKeyPackageRef = decodeCorrelationRef(
                envelope.key_package_ref, 'key_package_ref',
            );
            if (!equalBytes(envelopeKeyPackageRef, this._keyPackageRefBytes)) {
                return null;
            }

            let welcome;
            try {
                welcome = MLS.Welcome.parseWelcome(mlsMessageBytes);
            } catch (err) {
                throw validationMlsControlError(
                    `mls-session: malformed targeted Welcome: ${err.message}`,
                );
            }
            const containsOurKeyPackageRef = welcome.secrets.some((entry) =>
                equalBytes(entry.newMember, this._keyPackageRefBytes));
            if (!containsOurKeyPackageRef) {
                throw validationMlsControlError(
                    'mls-session: targeted Welcome does not contain our KeyPackageRef',
                );
            }

            const commitRefBytes = decodeCorrelationRef(
                envelope.commit_ref, 'commit_ref',
            );
            const commitRef = base64UrlEncode(commitRefBytes);
            const candidate = this._pendingWelcomeCommits.get(commitRef);
            if (!candidate) {
                throw validationMlsControlError(
                    'mls-session: Welcome received without its matching buffered Commit',
                );
            }
            if (candidate.keyPackageRef !== this._keyPackageRef) {
                throw validationMlsControlError(
                    'mls-session: Welcome/Commit KeyPackageRef correlation mismatch',
                );
            }
            if (candidate.senderId !== envelope.sender_id) {
                throw validationMlsControlError(
                    'mls-session: Welcome and Commit relay sender_id mismatch',
                );
            }
            return candidate;
        }

        async _handleIncomingKeyPackage(
            kpBytes, senderId, admittedKeyPackageRef = null,
        ) {
            // The envelope payload is the raw KeyPackage body — wire_format
            // rides as a separate envelope field, so the bytes are NOT wrapped
            // in MLSMessage framing. Pass them straight to commitAddMember
            // which calls KeyPackage.parseKeyPackage internally.
            if (this._departedSenderIds.has(senderId)) return;
            if (this._localCommitBusy || this._pendingCommit) {
                throw new Error('mls-session: cannot build Add while another Commit is pending');
            }
            this._localCommitBusy = true;
            let staged = false;
            let candidateGroup = null;
            try {
                const keyPackageRef = admittedKeyPackageRef
                    || await this._availableKeyPackageRef(kpBytes);
                decodeCorrelationRef(
                    keyPackageRef, 'admitted key_package_ref',
                );
                candidateGroup = this.group.forkForPendingCommit();
                const { commitMessage, welcomeMessage, addedLeafIndex } =
                    await candidateGroup.commitAddMember({
                        keyPackageBytes: kpBytes,
                    });
                // commitAddMember returns the exact slot because Add reuses
                // the leftmost blank leaf before growing the tree.
                const ratchetTreeBytes = MLS.Nodes.ratchetTreeBytes(
                    candidateGroup.ratchetTree,
                );
                const commitRef = base64UrlEncode(
                    await MLS.Labeled.sha256(stripMlsWrapper(commitMessage)),
                );
                const welcomeEnvelope = {
                    type: 'mls',
                    payload: base64UrlEncode(stripMlsWrapper(welcomeMessage)),
                    wire_format: MLS.MLSMessage.WireFormat.MLS_WELCOME,
                    ratchet_tree: base64UrlEncode(ratchetTreeBytes),
                    key_package_ref: keyPackageRef,
                    commit_ref: commitRef,
                };
                staged = await this._stagePendingCommit({
                    candidateGroup,
                    commitMessage,
                    kind: 'add',
                    keyPackageRef,
                    commitRef,
                    senderId,
                    addedLeafIndex,
                    welcomeEnvelope,
                });
            } catch (err) {
                if (candidateGroup && !staged) candidateGroup.destroySecrets();
                const classified = classifyMlsControlError(
                    err, 'commitAddMember failed: ',
                );
                console.error('[MLS] commitAddMember failed:', classified);
                this.onEvent({ kind: 'error', reason: classified.message });
                throw classified;
            } finally {
                this._localCommitBusy = false;
            }
            // Usually a staged Commit is still pending and this is a no-op.
            // It matters for a synchronous relay echo, which may already
            // have accepted the candidate while _localCommitBusy was true.
            await this._drainDeferredEnvelopes();
            return staged;
        }

        async _handleWelcome(mlsMessageBytes, ratchetTreeBytes, candidate) {
            // The envelope payload is the INNER MLSMessage body; wrap it
            // back so joinFromWelcomeWithTree can parse the full frame.
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_WELCOME, mlsMessageBytes,
            );

            // M-1 (RFC §12.4.3.1): the correlated Commit was parsed and
            // restricted to creator leaf 0 before buffering. Recheck its
            // payload-derived reference here before passing both signer and
            // old epoch into the cryptographic join routine.
            if (!candidate
                || this._pendingWelcomeCommits.get(candidate.commitRef) !== candidate) {
                throw validationMlsControlError(
                    'mls-session: Welcome has no live correlated Commit candidate',
                );
            }
            const computedCommitRef = base64UrlEncode(
                await MLS.Labeled.sha256(candidate.bytes),
            );
            if (computedCommitRef !== candidate.commitRef) {
                throw validationMlsControlError(
                    'mls-session: buffered Commit bytes no longer match commit_ref',
                );
            }

            const joinedGroup = await MLS.Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: wrapped,
                keyPackageBytes: this.keyPackageBundle.keyPackageBytes,
                initPrivateKey: this.keyPackageBundle.initKeyPair.privateKey,
                identity: this.identity,
                leafEncKeyPair: this.keyPackageBundle.leafEncKeyPair,
                ratchetTreeBytes,
                pskSecret: this.pskSecret,
                expectedSignerLeafIndex: candidate.senderLeafIndex,
                expectedCommitEpoch: candidate.epoch,
                expectedGroupId: this.expectedGroupId,
                expectedCreatorKeyHash: this.expectedCreatorKeyHash,
            });
            let rosterEvent;
            try {
                rosterEvent = await this._authenticatedRosterEvent(joinedGroup);
            } catch (err) {
                joinedGroup.destroySecrets();
                throw retryableMlsControlError(
                    err,
                    'mls-session: authenticated roster derivation failed: ',
                );
            }
            this.group = joinedGroup;
            this._state = 'joined';
            // The KeyPackage init key is a one-shot Welcome decryption key.
            // The joined Group now owns the long-lived identity and leaf
            // key handles, so release the bootstrap bundle and its lookup
            // reference immediately after the authenticated join succeeds.
            this.keyPackageBundle = null;
            wipeBytes(this._keyPackageRefBytes);
            this._keyPackageRefBytes = null;
            this._keyPackageRef = null;
            // Correlating the route is useful for diagnostics, but the relay
            // controls this value. It is never included in roster identities.
            this._senderIdByLeaf.set(CREATOR_LEAF_INDEX, candidate.senderId);
            this.onEvent(rosterEvent);
            this.onEvent({ kind: 'joined' });
        }

        async _handleApplication(mlsMessageBytes, senderId) {
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE, mlsMessageBytes,
            );
            let res;
            try {
                res = await this.group.decryptApplicationMessage(wrapped);
            } catch (err) {
                this.onEvent({ kind: 'error',
                    reason: `decrypt failed: ${err.message}` });
                return;
            }
            const pt = res.plaintext;
            const senderLeafIndex = res.senderLeafIndex;
            const senderIdentity = await this._authenticatedIdentity(
                res.senderSignatureKey,
                senderLeafIndex,
                this.group.myLeafIndex,
            );

            // sender_id remains useful for detecting relay routing changes,
            // but never participates in senderIdentity or anything displayed
            // as an MLS identity. In particular, a malicious relay may choose
            // the FIRST association without affecting the key fingerprint.
            let attributionWarning = false;
            const pinned = this._senderIdByLeaf.get(senderLeafIndex);
            if (pinned === undefined) {
                if (senderId) this._senderIdByLeaf.set(senderLeafIndex, senderId);
            } else if (senderId && senderId !== pinned) {
                attributionWarning = true;
            }

            if (pt.length === 0) {
                this.onEvent({ kind: 'error', reason: 'empty application payload' });
                return;
            }
            const tag = pt[0];
            if (tag === PAYLOAD_TEXT) {
                this.onEvent({
                    kind: 'message',
                    text: new TextDecoder().decode(pt.subarray(1)),
                    senderLeafIndex,
                    senderIdentity,
                    attributionWarning,
                });
                return;
            }
            if (tag === PAYLOAD_IMAGE) {
                if (pt.length < 2) {
                    this.onEvent({ kind: 'error', reason: 'truncated image payload' });
                    return;
                }
                const mimeLen = pt[1];
                if (pt.length < 2 + mimeLen) {
                    this.onEvent({ kind: 'error', reason: 'truncated image mime header' });
                    return;
                }
                const mimeType = new TextDecoder().decode(pt.subarray(2, 2 + mimeLen));
                const data = pt.subarray(2 + mimeLen);
                this.onEvent({
                    kind: 'image',
                    mimeType,
                    data,
                    senderLeafIndex,
                    senderIdentity,
                    attributionWarning,
                });
                return;
            }
            this.onEvent({
                kind: 'error',
                reason: `unknown application payload tag 0x${tag.toString(16)}`,
            });
        }

        /**
         * Route an incoming PublicMessage: Commit vs standalone Proposal.
         * PublicMessage has no length prefix around the Proposal/Commit body,
         * so the parse callback MUST consume that body before auth_data and
         * membership_tag can be decoded.  Parse it fully here, then dispatch;
         * processCommit deliberately re-parses the original bytes while doing
         * its cryptographic validation.
         */
        async _handlePublicMessage(mlsMessageBytes) {
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE, mlsMessageBytes,
            );
            let pm;
            try {
                const frame = MLS.MLSMessage.parseMLSMessage(wrapped);
                pm = MLS.PublicMessage.parsePublicMessage(frame.body, (decoder, contentType) => {
                    if (contentType === MLS.Framing.ContentType.PROPOSAL) {
                        return MLS.Proposal.readProposal(decoder);
                    }
                    if (contentType === MLS.Framing.ContentType.COMMIT) {
                        return MLS.Commit.readCommit(decoder);
                    }
                    throw new Error(`unsupported PublicMessage content_type ${contentType}`);
                });
            } catch (err) {
                this.onEvent({ kind: 'error',
                    reason: `malformed PublicMessage: ${err.message}` });
                throw rejectedMlsControlError(
                    validationMlsControlError(err),
                    'malformed PublicMessage: ',
                );
            }
            if (pm.content.contentType === MLS.Framing.ContentType.PROPOSAL) {
                await this._handleIncomingProposal(wrapped);
                return;
            }
            if (pm.content.contentType === MLS.Framing.ContentType.COMMIT) {
                await this._handleIncomingCommit(wrapped);
                return;
            }
            this.onEvent({ kind: 'error',
                reason: `unsupported PublicMessage content_type ${pm.content.contentType}` });
            throw rejectedMlsControlError(validationMlsControlError(
                `unsupported PublicMessage content_type ${pm.content.contentType}`,
            ));
        }

        /**
         * Authenticate and store a standalone member Update on EVERY member.
         * A later Commit contains only ProposalRef, so non-committers need
         * the same authenticated current-epoch PublicMessage in order to
         * resolve and independently verify it. The creator additionally
         * selects the latest newly-observed Update per sender for its next
         * Commit; replaying an already-stored reference cannot roll that
         * selection back.
         */
        async _handleIncomingProposal(wrappedBytes) {
            let verified;
            try {
                verified = await this.group.verifyUpdateProposal(wrappedBytes);
            } catch (err) {
                const classified = classifyMlsControlError(
                    err, 'invalid Update proposal: ',
                );
                this.onEvent({ kind: 'error',
                    reason: classified.message });
                throw classified;
            }
            let stored;
            try {
                stored = this._storeAuthenticatedProposal(verified);
            } catch (err) {
                const classified = rejectedMlsControlError(
                    validationMlsControlError(err),
                    'invalid Update proposal store entry: ',
                );
                this.onEvent({ kind: 'error',
                    reason: classified.message });
                throw classified;
            }
            if (!stored.isNew) return;
            if (this.role === 'creator') {
                this._pendingUpdateProposals.set(
                    stored.entry.senderLeafIndex, stored.entry,
                );
            }
            this.onEvent({
                kind: 'update-proposal-received',
                senderLeafIndex: stored.entry.senderLeafIndex,
            });
        }

        /**
         * Apply an incoming Commit broadcast to the local group state.
         * `wrapped` is already MLSMessage-framed. Errors are surfaced via
         * onEvent. If the Commit folds an Update proposal we authored,
         * the pending keypair is swapped in inside processCommit.
         */
        async _handleIncomingCommit(wrapped) {
            let result;
            try {
                result = await this.group.processCommit(wrapped, {
                    pendingSelfUpdate: this._pendingSelfUpdate
                        ? this._pendingSelfUpdate.keyPair
                        : null,
                    pendingSelfUpdates: this._pendingSelfUpdates,
                    proposalStore: this._proposalStore,
                });
            } catch (err) {
                console.error('[MLS] processCommit failed:', err);
                const reason = `processCommit failed: ${err.message}`;
                if (err?.mlsRetryControl === true
                    || err?.mlsFatalState === true) {
                    this.onEvent({ kind: 'error', reason });
                    throw err;
                }
                if (err?.authenticatedMlsControl === true) {
                    // The relay sequence names a current-epoch Commit whose
                    // creator signature and membership_tag are valid. If its
                    // tree/path/proposal/confirmation processing fails, ACKing
                    // and continuing would strand this member in the old
                    // epoch. Make the state terminal and propagate a typed
                    // failure so WebSocketManager neither advances the cursor
                    // nor reconnects into an infinite replay loop.
                    this._transitionToDesynced(reason);
                    throw fatalMlsStateError(reason);
                }
                const classified = classifyMlsControlError(err, '');
                this.onEvent({ kind: 'error',
                    reason: classified.message || reason });
                throw classified;
            }
            if (result.removedSelf === true) {
                this._transitionToRemoved(result);
                return;
            }
            // Every stored Proposal is now stale regardless of whether this
            // Commit selected our own Update. Consume only after the Group
            // transition has fully authenticated and committed.
            this._clearEpochProposalState();
            try {
                await this._emitAuthenticatedRoster();
            } catch (err) {
                // The Commit is already accepted; never misreport it as a
                // processCommit rollback. Suppress plaintext identities until
                // a roster can be derived instead of falling back to relay IDs.
                this.onEvent({ kind: 'error',
                    reason: `authenticated roster update failed: ${err.message}`,
                    fatalIdentity: true });
                return;
            }
            this.onEvent({ kind: 'commit-applied', ...result });
        }

        /**
         * Encrypt and broadcast an application text message. Throws if
         * we haven't joined the group yet.
         */
        async sendMessage(text) {
            const payload = encodeTextPayload(text);
            return this._serializeOperation(
                () => this._sendApplicationPayload(payload),
            );
        }

        /**
         * Encrypt and broadcast an image. `imageBytes` is the raw image
         * data (Uint8Array or ArrayBuffer); `mimeType` is the MIME string
         * (e.g. "image/png"). Both fields end up inside the AEAD-protected
         * MLS application_data, so the relay never sees them.
         */
        async sendImage(imageBytes, mimeType) {
            const payload = encodeImagePayload(imageBytes, mimeType);
            return this._serializeOperation(
                () => this._sendApplicationPayload(payload),
            );
        }

        /**
         * Creator-only: broadcast a path-only Update commit that re-keys
         * our leaf and direct path (periodic PCS rotation). No-ops
         * unless we are the joined creator of a group with at least one
         * other leaf. Errors are surfaced via onEvent but never thrown:
         * the caller is typically a timer.
         */
        async commitUpdate() {
            return this._serializeOperation(() => this._commitUpdate());
        }

        async _commitUpdate() {
            if (this.role !== 'creator') return;
            if (this._state !== 'joined') return;
            if (!this.group || this.group.nLeaves < 2) return;
            if (this._localCommitBusy || this._pendingCommit) return;
            // Fold any pending member Update proposals into this Commit,
            // dropping stale ones. Standalone proposals are authenticated
            // for one specific epoch; an Add/Remove or another local Commit
            // can advance the creator while a proposal is queued, so never
            // carry an old-epoch leaf update forward merely because its
            // inner LeafNode signature is still valid.
            const updateProposals = [];
            const queuedProposalEntries = [...this._pendingUpdateProposals.entries()];
            for (const [li, entry] of queuedProposalEntries) {
                if (entry.epoch === this.group.epoch && li < this.group.nLeaves) {
                    updateProposals.push(entry);
                }
            }
            this._localCommitBusy = true;
            let staged = false;
            let candidateGroup = null;
            try {
                candidateGroup = this.group.forkForPendingCommit();
                const { commitMessage } = await candidateGroup.commitUpdate({
                    updateProposals,
                });
                staged = await this._stagePendingCommit({
                    candidateGroup,
                    commitMessage,
                    kind: 'update',
                    queuedProposalEntries,
                    foldedUpdates: updateProposals.length,
                });
            } catch (err) {
                if (candidateGroup && !staged) candidateGroup.destroySecrets();
                console.error('[MLS] commitUpdate failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `commitUpdate failed: ${err.message}` });
            } finally {
                this._localCommitBusy = false;
            }
            await this._drainDeferredEnvelopes();
        }

        /**
         * Member-only: broadcast an Update proposal that re-keys our own
         * leaf (per-member PCS). The creator folds it into its next
         * Commit; we hold the fresh keypair until that Commit lands and
         * processCommit swaps it in. No-ops for the creator (it re-keys
         * via its own periodic path Commit) or before we have joined.
         */
        async proposeUpdate() {
            return this._serializeOperation(() => this._proposeUpdate());
        }

        async _proposeUpdate() {
            if (this.role !== 'joiner') return;
            if (this._state !== 'joined') return;
            if (!this.group) return;
            if (this._pendingCommit) {
                this.onEvent({ kind: 'error',
                    reason: 'proposeUpdate blocked while a Commit awaits relay acceptance' });
                return;
            }
            let proposed;
            // Snapshot every bounded bookkeeping map first: a transport
            // rejection must remove the unaccepted ProposalRef/private key
            // without disturbing any earlier resolvable proposal.
            const proposalStoreBefore = new Map(this._proposalStore);
            const proposalRefsBefore = new Map(
                [...this._proposalRefsBySender].map(
                    ([leafIndex, references]) => [
                        leafIndex, [...references],
                    ],
                ),
            );
            const pendingUpdatesBefore =
                new Map(this._pendingUpdateProposals);
            const pendingSelfUpdatesBefore =
                new Map(this._pendingSelfUpdates);
            const pendingSelfUpdateBefore = this._pendingSelfUpdate;
            try {
                proposed = await this.group.proposeUpdate();
                this._storeAuthenticatedProposal(proposed);
                const referenceKey = MLS.Group.proposalReferenceKey(
                    proposed.reference,
                );
                this._pendingSelfUpdates.set(
                    referenceKey, proposed.pendingLeafKeyPair,
                );
                this._pendingSelfUpdate = {
                    keyPair: proposed.pendingLeafKeyPair,
                    referenceKey,
                };
                // Publish only after the author has installed all local
                // ProposalRef/private-key state required to consume a
                // synchronously returned Commit. Keep the operation mutex
                // held through the transport handoff.
                await this._sendEnvelopeOrThrow({
                    type: 'mls',
                    payload: base64UrlEncode(stripMlsWrapper(
                        proposed.proposalMessage,
                    )),
                    wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
                }, 'Update proposal broadcast failed');
            } catch (err) {
                // A locally-created proposal that never reached the relay
                // must not occupy the store, disturb an older resolvable
                // ProposalRef, or leave an unselectable private key.
                this._proposalStore.clear();
                for (const [key, value] of proposalStoreBefore) {
                    this._proposalStore.set(key, value);
                }
                this._proposalRefsBySender.clear();
                for (const [leafIndex, references] of proposalRefsBefore) {
                    this._proposalRefsBySender.set(
                        leafIndex, [...references],
                    );
                }
                this._pendingUpdateProposals.clear();
                for (const [leafIndex, entry] of pendingUpdatesBefore) {
                    this._pendingUpdateProposals.set(leafIndex, entry);
                }
                this._pendingSelfUpdates.clear();
                for (const [key, keyPair] of pendingSelfUpdatesBefore) {
                    this._pendingSelfUpdates.set(key, keyPair);
                }
                this._pendingSelfUpdate = pendingSelfUpdateBefore;
                console.error('[MLS] proposeUpdate failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `proposeUpdate failed: ${err.message}` });
                return;
            }
            this.onEvent({ kind: 'update-proposed' });
        }

        /**
         * Creator-only: emit a Remove commit for a peer that left the
         * room. Bound to a sender_id from the relay so we can map the
         * disconnected peer to their leaf index. If no leaf exists yet,
         * retain a tombstone so a queued KeyPackage/Add cannot create a
         * phantom member after the final relay departure.
         */
        async removeMemberBySenderId(senderId) {
            return this._serializeOperation(
                () => this._removeMemberBySenderId(senderId),
            );
        }

        /**
         * Retry lifecycle work durably retained while an earlier Commit was
         * pending or after a transient local Remove-construction failure.
         * Called at replay completion before application sending is enabled.
         */
        async flushDeferredMembershipChanges() {
            return this._serializeOperation(
                () => this._drainDeferredEnvelopes(),
            );
        }

        async _removeMemberBySenderId(senderId) {
            if (this.role !== 'creator') return;
            if (typeof senderId !== 'string' || senderId.length === 0) return;
            if (this._state === 'removed') return;
            const hasLiveLeaf = this._leafBySenderId.has(senderId);
            const hasDeferredKeyPackage =
                this._deferredKeyPackages.has(senderId);
            const pendingAdd = this._pendingCommit?.kind === 'add'
                && this._pendingCommit.senderId === senderId;
            const pendingRemove = this._pendingCommit?.kind === 'remove'
                && this._pendingCommit.senderId === senderId;
            // Ordered UserLeft for a route which never published a
            // KeyPackage and never owned a leaf needs no tombstone: every
            // earlier control has already been processed by this mutex, so
            // retaining arbitrary relay IDs would only create an unbounded
            // attacker-controlled set.
            if (!hasLiveLeaf && !hasDeferredKeyPackage
                && !pendingAdd && !pendingRemove) {
                return;
            }
            // Record the final relay departure only when there is actual MLS
            // admission state which a delayed operation could resurrect.
            if (pendingRemove) {
                this._departedSenderIds.add(senderId);
                return;
            }
            if (pendingAdd) {
                // The relay sequences Add acceptance and UserLeft in one
                // total order. If this final departure is visible while the
                // Add is still unaccepted, the relay has already discarded
                // that route's one-shot KeyPackageRef; the Commit can never
                // be accepted later. Abort the isolated candidate instead of
                // installing a phantom leaf merely to Remove it next.
                await this._abortPendingCommit(
                    this._pendingCommit,
                    'pending Add cancelled because its relay participant departed before Commit acceptance',
                );
                await this._drainDeferredEnvelopes();
                return;
            }
            this._departedSenderIds.add(senderId);
            if (hasDeferredKeyPackage && !hasLiveLeaf) return;
            if (this._state !== 'joined') return;
            if (!hasLiveLeaf) return;
            if (this._localCommitBusy || this._pendingCommit) {
                this._deferredRemovals.add(senderId);
                return;
            }
            const leafIndex = this._leafBySenderId.get(senderId);
            this._localCommitBusy = true;
            let staged = false;
            let candidateGroup = null;
            try {
                candidateGroup = this.group.forkForPendingCommit();
                const { commitMessage } = await candidateGroup.commitRemoveMember({
                    removedLeafIndex: leafIndex,
                });
                staged = await this._stagePendingCommit({
                    candidateGroup,
                    commitMessage,
                    kind: 'remove',
                    senderId,
                    removedLeafIndex: leafIndex,
                });
            } catch (err) {
                if (candidateGroup && !staged) candidateGroup.destroySecrets();
                // Preserve the revocation request and propagate failure so the
                // ordered lifecycle event (or replay sync marker) is not
                // treated as successfully applied.
                this._deferredRemovals.add(senderId);
                console.error('[MLS] commitRemoveMember failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `commitRemoveMember failed: ${err.message}` });
                throw err;
            } finally {
                this._localCommitBusy = false;
            }
            await this._drainDeferredEnvelopes();
        }

        async _sendApplicationPayload(payloadBytes) {
            if (this._state !== 'joined') {
                throw new Error(`mls-session: cannot send in state "${this._state}"`);
            }
            if (this._localCommitBusy || this._pendingCommit) {
                throw new Error(
                    'mls-session: cannot send while a Commit awaits relay acceptance',
                );
            }
            // The operation mutex remains held through ratchet advancement
            // and transport handoff. A failed handoff deliberately consumes
            // the generation rather than risking AES-GCM nonce reuse.
            const wrapped = await this.group.encryptApplicationMessage(payloadBytes);
            const body = stripMlsWrapper(wrapped);
            await this._sendEnvelopeOrThrow({
                type: 'mls',
                payload: base64UrlEncode(body),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE,
            }, 'application message broadcast failed');
        }

        get state() { return this._state; }

        get bootstrapPins() {
            if (!this.expectedGroupId || !this.expectedCreatorKeyHash) return null;
            return {
                groupId: Uint8Array.from(this.expectedGroupId),
                creatorKeyHash: Uint8Array.from(this.expectedCreatorKeyHash),
            };
        }
    }

    // MLSMessage bytes wrap = version(u16) || wire_format(u16) || body.
    // The Rust relay expects only the body on the wire; the wire_format
    // rides alongside as an envelope field. Strip the 4-byte prefix.
    function stripMlsWrapper(mlsMessageBytes) {
        if (mlsMessageBytes.length < 4) {
            throw new Error('mls-session: MLSMessage shorter than framing header');
        }
        return mlsMessageBytes.slice(4);
    }

    root.MLSSession = MLSSession;
    root.buildMlsKeyPackage = buildKeyPackage;
})(typeof self !== 'undefined' ? self : this);
