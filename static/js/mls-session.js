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
 * The `send(envelope)` callback must broadcast to the room relay; the
 * envelope is `{ type: 'mls', payload, wire_format, ratchet_tree? }`
 * (same shape the Rust server's Message::Mls expects). `onEvent` fires
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
            // Buffered Commit envelope while we're in 'awaiting-welcome'.
            // The committer broadcasts Commit + Welcome atomically; we
            // ignore the Commit while we don't yet have a group state,
            // but capturing it lets us bind groupInfo.signer to the
            // Commit's FramedContent sender_leaf_index when the Welcome
            // arrives (RFC §12.4.3.1). Without this binding, a creator
            // who commits and signs a forged GroupInfo claiming a
            // different leaf "minted" the epoch would go undetected.
            this._pendingCommitBytes = null;
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

        /**
         * Dispatch an incoming `mls` envelope from the relay. Envelopes
         * from our own sender_id should be filtered upstream — this
         * method assumes every envelope is from a peer.
         */
        async onRelayEnvelope(envelope) {
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
                if (!envelope.ratchet_tree) {
                    this.onEvent({ kind: 'error',
                        reason: 'Welcome envelope missing ratchet_tree side-channel' });
                    return;
                }
                await this._handleWelcome(payload, base64UrlDecode(envelope.ratchet_tree));
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
                await this._handlePublicMessage(payload, envelope.sender_id);
                return;
            }
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this.role === 'joiner' && this._state === 'awaiting-welcome') {
                this._pendingCommitBytes = payload;
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

        async _handleIncomingKeyPackage(kpBytes, senderId) {
            // The envelope payload is the raw KeyPackage body — wire_format
            // rides as a separate envelope field, so the bytes are NOT wrapped
            // in MLSMessage framing. Pass them straight to commitAddMember
            // which calls KeyPackage.parseKeyPackage internally.
            let commitMessage, welcomeMessage, addedLeafIndex;
            try {
                ({ commitMessage, welcomeMessage } = await this.group.commitAddMember({
                    keyPackageBytes: kpBytes,
                }));
                // commitAddMember always inserts at `nLeaves` (pre-bump).
                // After the call, this.group.nLeaves has been bumped, so
                // the new leaf occupies index nLeaves - 1.
                addedLeafIndex = this.group.nLeaves - 1;
            } catch (err) {
                console.error('[MLS] commitAddMember failed:', err);
                this.onEvent({ kind: 'error', reason: `commitAddMember failed: ${err.message}` });
                return;
            }
            if (senderId !== undefined) {
                this._leafBySenderId.set(senderId, addedLeafIndex);
                this._senderIdByLeaf.set(addedLeafIndex, senderId);
            }
            const ratchetTreeBytes = MLS.Nodes.ratchetTreeBytes(this.group.ratchetTree);

            // Broadcast commit + welcome. We ship the ratchet_tree as a
            // side-channel on the welcome envelope only.
            this.send({
                type: 'mls',
                payload: base64UrlEncode(stripMlsWrapper(commitMessage)),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
            });
            this.send({
                type: 'mls',
                payload: base64UrlEncode(stripMlsWrapper(welcomeMessage)),
                wire_format: MLS.MLSMessage.WireFormat.MLS_WELCOME,
                ratchet_tree: base64UrlEncode(ratchetTreeBytes),
            });
            this._state = 'joined';
            this.onEvent({ kind: 'welcome-sent' });
        }

        async _handleWelcome(mlsMessageBytes, ratchetTreeBytes) {
            // The envelope payload is the INNER MLSMessage body; wrap it
            // back so joinFromWelcomeWithTree can parse the full frame.
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_WELCOME, mlsMessageBytes,
            );

            // M-1 (RFC §12.4.3.1): bind GroupInfo.signer to the
            // FramedContent sender of the Commit that produced this
            // epoch. Extract the Commit's sender_leaf_index from the
            // buffered PublicMessage and pass it to the join routine.
            // Fail closed if the Commit was absent, malformed, not actually
            // a Commit, or not sent as a group member. A Welcome without
            // this binding cannot establish who created the imported epoch.
            if (!this._pendingCommitBytes) {
                throw new Error(
                    'mls-session: Welcome received without a buffered Commit',
                );
            }
            let expectedSignerLeafIndex;
            try {
                const commitWrapped = MLS.MLSMessage.serializeMLSMessage(
                    MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
                    this._pendingCommitBytes,
                );
                const frame = MLS.MLSMessage.parseMLSMessage(commitWrapped);
                const pm = MLS.PublicMessage.parsePublicMessage(
                    frame.body, (decoder) => MLS.Commit.readCommit(decoder),
                );
                if (!pm.content
                    || pm.content.contentType !== MLS.Framing.ContentType.COMMIT) {
                    throw new Error('buffered PublicMessage is not a Commit');
                }
                if (!pm.content.sender
                    || pm.content.sender.senderType !== MLS.Framing.SenderType.MEMBER
                    || !Number.isInteger(pm.content.sender.leafIndex)) {
                    throw new Error('buffered Commit has no member sender_leaf_index');
                }
                if (pm.content.sender.leafIndex !== CREATOR_LEAF_INDEX) {
                    throw new Error(
                        'only creator leaf 0 may commit a Welcome epoch '
                        + `(got leaf ${pm.content.sender.leafIndex})`,
                    );
                }
                expectedSignerLeafIndex = pm.content.sender.leafIndex;
            } catch (err) {
                throw new Error(
                    `mls-session: cannot bind Welcome to Commit: ${err.message}`,
                );
            } finally {
                this._pendingCommitBytes = null;
            }

            this.group = await MLS.Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: wrapped,
                keyPackageBytes: this.keyPackageBundle.keyPackageBytes,
                initPrivateKey: this.keyPackageBundle.initKeyPair.privateKey,
                identity: this.identity,
                leafEncKeyPair: this.keyPackageBundle.leafEncKeyPair,
                ratchetTreeBytes,
                pskSecret: this.pskSecret,
                expectedSignerLeafIndex,
                expectedGroupId: this.expectedGroupId,
                expectedCreatorKeyHash: this.expectedCreatorKeyHash,
            });
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
        async _handlePublicMessage(mlsMessageBytes, senderId) {
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
                await this._handleIncomingProposal(wrapped, senderId, pm);
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
         * (the creator is the sole committer). The proposal is fully
         * verified when applied (commitUpdate / processCommit run the
         * signature checks); here we only parse and stash it, keyed by
         * the proposer's leaf index so a re-proposal supersedes.
         */
        async _handleIncomingProposal(wrappedBytes, senderId, parsedPublicMessage = null) {
            if (this.role !== 'creator') return;
            let proposal;
            let senderLeafIndex;
            try {
                let pm = parsedPublicMessage;
                if (!pm) {
                    const frame = MLS.MLSMessage.parseMLSMessage(wrappedBytes);
                    pm = MLS.PublicMessage.parsePublicMessage(frame.body, (decoder, ct) => {
                        if (ct !== MLS.Framing.ContentType.PROPOSAL) {
                            throw new Error(`expected Proposal, got content_type ${ct}`);
                        }
                        return MLS.Proposal.readProposal(decoder);
                    });
                }
                if (pm.content.sender.senderType !== MLS.Framing.SenderType.MEMBER) return;
                senderLeafIndex = pm.content.sender.leafIndex;
                proposal = pm.content.parsed;
            } catch (err) {
                this.onEvent({ kind: 'error',
                    reason: `malformed Update proposal: ${err.message}` });
                return;
            }
            if (!proposal || proposal.proposalType !== MLS.Proposal.ProposalType.UPDATE) {
                // We only fold Update proposals; Add/Remove are creator-driven.
                return;
            }
            this._pendingUpdateProposals.set(senderLeafIndex, { proposal, senderLeafIndex });
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
            // Fold any pending member Update proposals into this Commit,
            // dropping stale ones (proposer no longer in the tree).
            const updateProposals = [];
            for (const [li, entry] of this._pendingUpdateProposals) {
                if (li < this.group.nLeaves) updateProposals.push(entry);
            }
            this._pendingUpdateProposals = new Map();
            let commitMessage;
            try {
                ({ commitMessage } = await this.group.commitUpdate({ updateProposals }));
            } catch (err) {
                console.error('[MLS] commitUpdate failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `commitUpdate failed: ${err.message}` });
                return;
            }
            this.send({
                type: 'mls',
                payload: base64UrlEncode(stripMlsWrapper(commitMessage)),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
            });
            this.onEvent({
                kind: 'update-committed',
                epoch: this.group.epoch.toString(),
                foldedUpdates: updateProposals.length,
            });
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
            const leafIndex = this._leafBySenderId.get(senderId);
            this._leafBySenderId.delete(senderId);
            this._senderIdByLeaf.delete(leafIndex);

            let commitMessage;
            try {
                ({ commitMessage } = await this.group.commitRemoveMember({
                    removedLeafIndex: leafIndex,
                }));
            } catch (err) {
                console.error('[MLS] commitRemoveMember failed:', err);
                this.onEvent({ kind: 'error',
                    reason: `commitRemoveMember failed: ${err.message}` });
                return;
            }
            this.send({
                type: 'mls',
                payload: base64UrlEncode(stripMlsWrapper(commitMessage)),
                wire_format: MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE,
            });
            this.onEvent({ kind: 'remove-committed', removedLeafIndex: leafIndex });
        }

        async _sendApplicationPayload(payloadBytes) {
            if (this._state !== 'joined') {
                throw new Error(`mls-session: cannot send in state "${this._state}"`);
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
