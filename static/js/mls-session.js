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
 * The orchestration this commit lands is the MVP path: 2-leaf groups
 * only, creator (leaf 0) + one joiner (leaf 1). 3+-member support is
 * a follow-up that will need Group.processCommit and filtered direct
 * path encryption.
 *
 * Transport contract
 * ------------------
 * The `send(envelope)` callback must broadcast to the room relay and may
 * return `false` to report a synchronous transport rejection; the
 * envelope is `{ type: 'mls', payload, wire_format, ratchet_tree?,
 * key_package_ref?, commit_ref? }` (the optional references correlate an
 * Add Commit with its Welcome). This is the same shape the Rust server's
 * Message::Mls expects. `onEvent` fires
 * with `{ kind, ... }` for UI updates. `kind` values:
 *   'keypackage-published'   — our KeyPackage has been emitted
 *   'welcome-sent'            — Alice sent a Welcome to the new member
 *   'joined'                  — Bob completed join
 *   'message'                 — application payload decrypted
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
    const CORRELATION_REF_BYTES = 32;
    const MAX_PENDING_WELCOME_COMMITS = 8;

    function equalBytes(a, b) {
        if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)
            || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    function decodeCorrelationRef(value, name) {
        if (typeof value !== 'string' || value.length === 0) {
            throw new Error(`mls-session: ${name} is missing`);
        }
        let decoded;
        try {
            decoded = base64UrlDecode(value);
        } catch (_err) {
            throw new Error(`mls-session: ${name} is not valid base64url`);
        }
        if (decoded.length !== CORRELATION_REF_BYTES
            || base64UrlEncode(decoded) !== value) {
            throw new Error(
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
         * @param {(event: object) => void} opts.onEvent
         * @param {Uint8Array} opts.expectedGroupId
         * @param {Uint8Array} opts.expectedCreatorKeyHash
         */
        constructor({
            role, send, onEvent, pskSecret,
            expectedGroupId, expectedCreatorKeyHash,
        }) {
            if (role !== 'creator' && role !== 'joiner') {
                throw new Error(`mls-session: invalid role "${role}"`);
            }
            this.role = role;
            this.send = send;
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
            this.pskSecret = pskSecret || null;
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
            // Join correlation state. KeyPackageRef identifies which
            // broadcast Add/Welcome is addressed to this joiner; commit_ref
            // is PinChat transport metadata equal to SHA-256 over the exact
            // PublicMessage body. A bounded map replaces the old single
            // `_pendingCommitBytes` slot, so unrelated PublicMessages and
            // Welcomes cannot overwrite or consume the candidate we need.
            this._keyPackageRefBytes = null;
            this._keyPackageRef = null;
            this._pendingWelcomeCommits = new Map();
            // Per-sender_id → leafIndex map maintained by the creator.
            // We commit at most one KeyPackage per WebSocket sender_id;
            // a second KeyPackage from the same sender (or a sender
            // already represented in the tree) is rejected. Without this
            // a single peer can publish many KeyPackages, growing the
            // tree arbitrarily and exhausting committer resources.
            this._leafBySenderId = new Map();
            // Reverse binding leafIndex → sender_id used for E2E message
            // attribution. The MLS signature authenticates the sender's
            // LEAF; the relay's sender_id is unauthenticated transport
            // metadata. The creator seeds this map at commit time; every
            // member pins the first observed association (TOFU). On a
            // later mismatch we keep the pinned identity and flag the
            // message: a mismatch means the relay re-stamped the
            // envelope's sender_id.
            this._senderIdByLeaf = new Map();
            // Creator-only: Update proposals received from members, keyed
            // by proposer leaf index, awaiting the next periodic Commit.
            this._pendingUpdateProposals = new Map();
            // Member-only: our own in-flight Update ({ keyPair, leafNode })
            // waiting for the creator's Commit that folds it in. Kept until
            // processCommit reports selfUpdated (or a later proposal
            // supersedes it).
            this._pendingSelfUpdate = null;
            // Locally-authored Commits are built against an isolated Group
            // candidate and remain pending until the relay sends back the
            // exact PublicMessage payload. The live Group MUST NOT advance
            // merely because WebSocket.send accepted bytes locally.
            this._pendingCommit = null;
            this._localCommitBusy = false;
            // While a local Commit is being built or awaiting its relay
            // echo, defer peer envelopes. This prevents application-ratchet
            // or proposal state from changing underneath the candidate and
            // being rolled back when the candidate is installed.
            this._deferredEnvelopes = [];
            this._deferredRemovals = new Set();
            this._drainingDeferredEnvelopes = false;
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
            } else {
                if (!this.expectedGroupId || !this.expectedCreatorKeyHash) {
                    throw new Error(
                        'mls-session: group invite is missing authenticated '
                        + 'group_id / creator-key pins',
                    );
                }
                const bundle = await buildKeyPackage();
                this.identity = bundle.identity;
                this.keyPackageBundle = bundle;
                this._keyPackageRefBytes = await MLS.KeyPackage.keyPackageRef(
                    bundle.keyPackageBytes,
                );
                this._keyPackageRef = base64UrlEncode(this._keyPackageRefBytes);
                this.send(envelopeFromMlsMessage(
                    MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE,
                    bundle.keyPackageBytes,
                ));
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
                if (this._pendingCommit === pending) this._pendingCommit = null;
                candidateGroup.destroySecrets();
                this.onEvent({ kind: 'error', reason: err.message });
                return false;
            }
            return true;
        }

        async _acceptPendingCommit() {
            const pending = this._pendingCommit;
            if (!pending) return false;

            // Clear first so a duplicate echo cannot install or announce the
            // candidate twice. Everything below is local bookkeeping or a
            // post-acceptance Welcome; the MLS state swap itself is atomic.
            this._pendingCommit = null;
            const supersededGroup = this.group;
            this.group = pending.candidateGroup;
            if (supersededGroup && supersededGroup !== this.group) {
                // The accepted candidate owns an independent clone of the
                // outgoing epoch for its bounded grace window. The former
                // live Group must not retain a second complete copy.
                supersededGroup.destroySecrets();
            }

            if (pending.kind === 'add') {
                this._leafBySenderId.set(pending.senderId, pending.addedLeafIndex);
                this._senderIdByLeaf.set(pending.addedLeafIndex, pending.senderId);
                this._state = 'joined';
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
            } else if (pending.kind === 'update') {
                // Remove only queue entries that were present when this
                // candidate was built. A newer proposal arriving meanwhile
                // must survive for the next epoch.
                for (const [leafIndex, entry] of pending.queuedProposalEntries) {
                    if (this._pendingUpdateProposals.get(leafIndex) === entry) {
                        this._pendingUpdateProposals.delete(leafIndex);
                    }
                }
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
                        const envelope = this._deferredEnvelopes.shift();
                        await this.onRelayEnvelope(envelope);
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
                    await this.removeMemberBySenderId(nextRemoval.value);
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
            if (this.shouldHandleOwnEnvelope(envelope)) {
                await this._acceptPendingCommit();
                return;
            }
            if (this._localCommitBusy || this._pendingCommit) {
                // Room membership is capped well below this. The bound keeps
                // a withheld ACK from turning this into an unbounded queue.
                if (this._deferredEnvelopes.length >= 64) {
                    this.onEvent({
                        kind: 'error',
                        reason: 'MLS envelope queue full while Commit awaits acceptance',
                    });
                    return;
                }
                this._deferredEnvelopes.push({ ...envelope });
                return;
            }
            const payload = base64UrlDecode(envelope.payload);
            const wireFormat = envelope.wire_format;

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
                if (this._leafBySenderId.has(senderId)) {
                    this.onEvent({ kind: 'error',
                        reason: `sender ${senderId} already has a leaf — duplicate KeyPackage rejected` });
                    return;
                }
                await this._handleIncomingKeyPackage(payload, senderId);
                return;
            }

            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_WELCOME
                && this.role === 'joiner' && this._state === 'awaiting-welcome') {
                const candidate = await this._matchingWelcomeCommit(
                    payload, envelope,
                );
                // Welcomes are room broadcasts. A Welcome for another
                // KeyPackage is expected during simultaneous joins and must
                // not consume any of our buffered Commit candidates.
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
                return;
            }

            // Existing members (creator or already-joined joiners) process
            // incoming PublicMessage broadcasts. A PublicMessage is either
            // a Commit (advance epoch) or a standalone Proposal (an Update
            // proposal a member wants folded into the next Commit). We peek
            // the content_type to route; the creator stores Update
            // proposals, everyone processes Commits.
            // Own echoes are filtered upstream via sender_id.
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this._state === 'joined') {
                await this._handlePublicMessage(payload);
                return;
            }
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this.role === 'joiner' && this._state === 'awaiting-welcome') {
                await this._bufferWelcomeCommit(payload, envelope);
                return;
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
                throw new Error(
                    `mls-session: malformed pre-Welcome PublicMessage: ${err.message}`,
                );
            }

            // Standalone proposals and ordinary membership/path commits do
            // not carry a KeyPackageRef for this joiner; ignore them while
            // waiting for the Add that actually addresses us.
            if (pm.content.contentType !== MLS.Framing.ContentType.COMMIT
                || !envelope.key_package_ref) return false;

            if (!this._keyPackageRefBytes || !this._keyPackageRef) {
                throw new Error('mls-session: local KeyPackageRef is unavailable');
            }
            const envelopeKeyPackageRef = decodeCorrelationRef(
                envelope.key_package_ref, 'key_package_ref',
            );
            if (!equalBytes(envelopeKeyPackageRef, this._keyPackageRefBytes)) {
                return false;
            }
            if (!equalBytes(pm.content.groupId, this.expectedGroupId)) {
                throw new Error(
                    'mls-session: correlated Add Commit has unexpected group_id',
                );
            }
            if (!pm.content.sender
                || pm.content.sender.senderType !== MLS.Framing.SenderType.MEMBER
                || pm.content.sender.leafIndex !== CREATOR_LEAF_INDEX) {
                throw new Error(
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
                throw new Error(
                    'mls-session: correlated Add Commit does not contain our KeyPackage',
                );
            }

            const commitRefBytes = decodeCorrelationRef(
                envelope.commit_ref, 'commit_ref',
            );
            const computedCommitRef = await MLS.Labeled.sha256(mlsMessageBytes);
            if (!equalBytes(commitRefBytes, computedCommitRef)) {
                throw new Error(
                    'mls-session: commit_ref does not match PublicMessage payload',
                );
            }
            const commitRef = base64UrlEncode(commitRefBytes);
            const existing = this._pendingWelcomeCommits.get(commitRef);
            if (existing) {
                if (existing.senderId !== envelope.sender_id) {
                    throw new Error(
                        'mls-session: duplicate commit_ref arrived from a different relay sender',
                    );
                }
                return true;
            }
            if (this._pendingWelcomeCommits.size >= MAX_PENDING_WELCOME_COMMITS) {
                throw new Error(
                    'mls-session: too many correlated Add Commits while awaiting Welcome',
                );
            }
            if (!envelope.sender_id) {
                throw new Error(
                    'mls-session: correlated Add Commit envelope missing sender_id',
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
                throw new Error('mls-session: local KeyPackageRef is unavailable');
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
                throw new Error(`mls-session: malformed targeted Welcome: ${err.message}`);
            }
            const containsOurKeyPackageRef = welcome.secrets.some((entry) =>
                equalBytes(entry.newMember, this._keyPackageRefBytes));
            if (!containsOurKeyPackageRef) {
                throw new Error(
                    'mls-session: targeted Welcome does not contain our KeyPackageRef',
                );
            }

            const commitRefBytes = decodeCorrelationRef(
                envelope.commit_ref, 'commit_ref',
            );
            const commitRef = base64UrlEncode(commitRefBytes);
            const candidate = this._pendingWelcomeCommits.get(commitRef);
            if (!candidate) {
                throw new Error(
                    'mls-session: Welcome received without its matching buffered Commit',
                );
            }
            if (candidate.keyPackageRef !== this._keyPackageRef) {
                throw new Error(
                    'mls-session: Welcome/Commit KeyPackageRef correlation mismatch',
                );
            }
            if (candidate.senderId !== envelope.sender_id) {
                throw new Error(
                    'mls-session: Welcome and Commit relay sender_id mismatch',
                );
            }
            return candidate;
        }

        async _handleIncomingKeyPackage(kpBytes, senderId) {
            // The envelope payload is the raw KeyPackage body — wire_format
            // rides as a separate envelope field, so the bytes are NOT wrapped
            // in MLSMessage framing. Pass them straight to commitAddMember
            // which calls KeyPackage.parseKeyPackage internally.
            if (this._localCommitBusy || this._pendingCommit) {
                throw new Error('mls-session: cannot build Add while another Commit is pending');
            }
            this._localCommitBusy = true;
            let staged = false;
            let candidateGroup = null;
            try {
                candidateGroup = this.group.forkForPendingCommit();
                const { commitMessage, welcomeMessage } =
                    await candidateGroup.commitAddMember({
                        keyPackageBytes: kpBytes,
                    });
                // commitAddMember always inserts at `nLeaves` (pre-bump).
                // Only the candidate has advanced at this point.
                const addedLeafIndex = candidateGroup.nLeaves - 1;
                const ratchetTreeBytes = MLS.Nodes.ratchetTreeBytes(
                    candidateGroup.ratchetTree,
                );
                const keyPackageRef = base64UrlEncode(
                    await MLS.KeyPackage.keyPackageRef(kpBytes),
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
                console.error('[MLS] commitAddMember failed:', err);
                this.onEvent({ kind: 'error', reason: `commitAddMember failed: ${err.message}` });
            } finally {
                this._localCommitBusy = false;
            }
            if (!staged) await this._drainDeferredEnvelopes();
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
                throw new Error(
                    'mls-session: Welcome has no live correlated Commit candidate',
                );
            }
            const computedCommitRef = base64UrlEncode(
                await MLS.Labeled.sha256(candidate.bytes),
            );
            if (computedCommitRef !== candidate.commitRef) {
                throw new Error(
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
            this.group = joinedGroup;
            this._state = 'joined';
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

            // E2E attribution (audit fix): senderLeafIndex is the
            // signature-verified sender; the envelope's sender_id is
            // relay-stamped and unauthenticated. Pin the first observed
            // association and keep the pinned value on mismatch.
            let attributedSenderId = senderId;
            let attributionWarning = false;
            const pinned = this._senderIdByLeaf.get(senderLeafIndex);
            if (pinned === undefined) {
                if (senderId) this._senderIdByLeaf.set(senderLeafIndex, senderId);
            } else if (senderId && senderId !== pinned) {
                attributedSenderId = pinned;
                attributionWarning = true;
            } else {
                attributedSenderId = pinned;
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
                    senderId: attributedSenderId,
                    senderLeafIndex,
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
                    senderId: attributedSenderId,
                    senderLeafIndex,
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
                return;
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
        }

        /**
         * Creator-only: buffer a member's Update proposal so the next
         * periodic Commit folds it in. Non-creators ignore proposals
         * (the creator is the sole committer). Authenticate the complete
         * PublicMessage before buffering: the outer signature and
         * membership_tag bind the Update to the current epoch, while the
         * inner LeafNode signature binds its fresh key to the same member.
         * The authenticated leaf index keys the buffer so a newer proposal
         * from that member supersedes an older one.
         */
        async _handleIncomingProposal(wrappedBytes) {
            if (this.role !== 'creator') return;
            let proposal;
            let senderLeafIndex;
            let proposalEpoch;
            try {
                ({ proposal, senderLeafIndex, epoch: proposalEpoch } =
                    await this.group.verifyUpdateProposal(wrappedBytes));
            } catch (err) {
                this.onEvent({ kind: 'error',
                    reason: `invalid Update proposal: ${err.message}` });
                return;
            }
            this._pendingUpdateProposals.set(senderLeafIndex, {
                proposal,
                senderLeafIndex,
                epoch: proposalEpoch,
            });
            this.onEvent({ kind: 'update-proposal-received', senderLeafIndex });
        }

        /**
         * Apply an incoming Commit broadcast to the local group state.
         * `wrapped` is already MLSMessage-framed. Errors are surfaced via
         * onEvent. If the Commit folds an Update proposal we authored,
         * the pending keypair is swapped in inside processCommit.
         */
        async _handleIncomingCommit(wrapped) {
            try {
                const result = await this.group.processCommit(wrapped, {
                    pendingSelfUpdate: this._pendingSelfUpdate
                        ? this._pendingSelfUpdate.keyPair
                        : null,
                });
                if (result.selfUpdated && this._pendingSelfUpdate) {
                    this._pendingSelfUpdate = null;
                }
                this.onEvent({ kind: 'commit-applied', ...result });
            } catch (err) {
                console.error('[MLS] processCommit failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `processCommit failed: ${err.message}` });
            }
        }

        /**
         * Encrypt and broadcast an application text message. Throws if
         * we haven't joined the group yet.
         */
        async sendMessage(text) {
            await this._sendApplicationPayload(encodeTextPayload(text));
        }

        /**
         * Encrypt and broadcast an image. `imageBytes` is the raw image
         * data (Uint8Array or ArrayBuffer); `mimeType` is the MIME string
         * (e.g. "image/png"). Both fields end up inside the AEAD-protected
         * MLS application_data, so the relay never sees them.
         */
        async sendImage(imageBytes, mimeType) {
            await this._sendApplicationPayload(encodeImagePayload(imageBytes, mimeType));
        }

        /**
         * Creator-only: broadcast a path-only Update commit that re-keys
         * our leaf and direct path (periodic PCS rotation). No-ops
         * unless we are the joined creator of a group with at least one
         * other leaf. Errors are surfaced via onEvent but never thrown:
         * the caller is typically a timer.
         */
        async commitUpdate() {
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
            if (!staged) await this._drainDeferredEnvelopes();
        }

        /**
         * Member-only: broadcast an Update proposal that re-keys our own
         * leaf (per-member PCS). The creator folds it into its next
         * Commit; we hold the fresh keypair until that Commit lands and
         * processCommit swaps it in. No-ops for the creator (it re-keys
         * via its own periodic path Commit) or before we have joined.
         */
        async proposeUpdate() {
            if (this.role !== 'joiner') return;
            if (this._state !== 'joined') return;
            if (!this.group) return;
            let proposalMessage;
            let pendingLeafKeyPair;
            try {
                ({ proposalMessage, pendingLeafKeyPair } = await this.group.proposeUpdate());
            } catch (err) {
                console.error('[MLS] proposeUpdate failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `proposeUpdate failed: ${err.message}` });
                return;
            }
            // Supersede any earlier in-flight self-update: only the most
            // recent proposal can be folded, older keypairs are useless.
            this._pendingSelfUpdate = { keyPair: pendingLeafKeyPair };
            this.send({
                type: 'mls',
                payload: base64UrlEncode(stripMlsWrapper(proposalMessage)),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
            });
            this.onEvent({ kind: 'update-proposed' });
        }

        /**
         * Creator-only: emit a Remove commit for a peer that left the
         * room. Bound to a sender_id from the relay so we can map the
         * disconnected peer to their leaf index. Silently no-ops if we
         * never saw a KeyPackage from this sender (the peer was the
         * creator's own previous tab, or never published a KP).
         */
        async removeMemberBySenderId(senderId) {
            if (this.role !== 'creator') return;
            if (this._state !== 'joined') return;
            if (!this._leafBySenderId.has(senderId)) return;
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
                console.error('[MLS] commitRemoveMember failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `commitRemoveMember failed: ${err.message}` });
            } finally {
                this._localCommitBusy = false;
            }
            if (!staged) await this._drainDeferredEnvelopes();
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
            const wrapped = await this.group.encryptApplicationMessage(payloadBytes);
            const body = stripMlsWrapper(wrapped);
            this.send({
                type: 'mls',
                payload: base64UrlEncode(body),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE,
            });
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
