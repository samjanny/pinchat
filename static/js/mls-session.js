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
     * Build a fresh identity + HPKE init keypair + signed KeyPackage.
     * Returns { identity, initKeyPair, leaf, keyPackage, keyPackageBytes }.
     */
    async function buildKeyPackage() {
        const sigKp = await MLS.Signature.generateKeyPair();
        const identity = {
            signaturePrivateKey: sigKp.privateKey,
            signaturePublicKeyBytes: sigKp.publicKeyBytes,
        };
        const initKp = await MLS.HPKE.generateKeyPair();

        const leaf = MLS.Group.buildSelfLeaf({
            encryptionKeyBytes: initKp.publicKeyBytes,
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
        return { identity, initKeyPair: initKp, leaf, keyPackage: kp,
            keyPackageBytes, wrappedKeyPackageBytes: wrapped };
    }

    class MLSSession {
        /**
         * @param {Object} opts
         * @param {'creator' | 'joiner'} opts.role
         * @param {(envelope: object) => void} opts.send
         * @param {(event: object) => void} opts.onEvent
         */
        constructor({ role, send, onEvent }) {
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
                this.group = await MLS.Group.Group.create({ identity: id });
                this._state = 'awaiting-keypackage';
            } else {
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

            console.log('[MLS] envelope wire_format=', wireFormat,
                'role=', this.role, 'state=', this._state);

            // Creator: accept KeyPackages from new joiners while we have
            // a valid group to commit into. The state machine moves
            // 'awaiting-keypackage' → 'joined' on the first commit and
            // stays 'joined' afterwards; both states accept new KPs.
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_KEY_PACKAGE
                && this.role === 'creator'
                && (this._state === 'awaiting-keypackage' || this._state === 'joined')) {
                await this._handleIncomingKeyPackage(payload);
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
            // incoming Commit broadcasts to advance their epoch state.
            // The creator filters their own echoes upstream via sender_id;
            // joiners-still-awaiting-welcome ignore commits because their
            // group state isn't built yet (Welcome is the catch-up path).
            if (wireFormat === MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE
                && this._state === 'joined') {
                await this._handleIncomingCommit(payload);
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

        async _handleIncomingKeyPackage(kpBytes) {
            // The envelope payload is the raw KeyPackage body — wire_format
            // rides as a separate envelope field, so the bytes are NOT wrapped
            // in MLSMessage framing. Pass them straight to commitAddMember
            // which calls KeyPackage.parseKeyPackage internally.
            console.log('[MLS] creator: received KeyPackage (', kpBytes.length, 'bytes), committing Add…');
            let commitMessage, welcomeMessage;
            try {
                ({ commitMessage, welcomeMessage } = await this.group.commitAddMember({
                    keyPackageBytes: kpBytes,
                }));
            } catch (err) {
                console.error('[MLS] commitAddMember failed:', err);
                this.onEvent({ kind: 'error', reason: `commitAddMember failed: ${err.message}` });
                return;
            }
            console.log('[MLS] creator: Add committed, broadcasting Commit + Welcome');
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
            this.group = await MLS.Group.Group.joinFromWelcomeWithTree({
                welcomeMessage: wrapped,
                keyPackageBytes: this.keyPackageBundle.keyPackageBytes,
                initPrivateKey: this.keyPackageBundle.initKeyPair.privateKey,
                identity: this.identity,
                leafEncKeyPair: this.keyPackageBundle.initKeyPair,
                ratchetTreeBytes,
            });
            this._state = 'joined';
            this.onEvent({ kind: 'joined' });
        }

        async _handleApplication(mlsMessageBytes, senderId) {
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_PRIVATE_MESSAGE, mlsMessageBytes,
            );
            let pt;
            try {
                pt = await this.group.decryptApplicationMessage(wrapped);
            } catch (err) {
                this.onEvent({ kind: 'error',
                    reason: `decrypt failed: ${err.message}` });
                return;
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
                    senderId,
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
                    senderId,
                });
                return;
            }
            this.onEvent({
                kind: 'error',
                reason: `unknown application payload tag 0x${tag.toString(16)}`,
            });
        }

        /**
         * Apply an incoming Commit broadcast to the local group state.
         * Re-wraps the body with MLSMessage framing so processCommit can
         * dispatch off wire_format. Errors during processing are surfaced
         * via onEvent — they should be rare in our scenario (creator-only
         * adds), so we treat them as actionable rather than silent drops.
         */
        async _handleIncomingCommit(mlsMessageBytes) {
            const wrapped = MLS.MLSMessage.serializeMLSMessage(
                MLS.MLSMessage.WireFormat.MLS_PUBLIC_MESSAGE, mlsMessageBytes,
            );
            try {
                const result = await this.group.processCommit(wrapped);
                console.log('[MLS] processed commit, added leaf', result.addedLeafIndex,
                    'committer leaf', result.committerLeafIndex);
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
