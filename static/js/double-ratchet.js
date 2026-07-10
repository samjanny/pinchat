/**
 * Double Ratchet Implementation (Signal Protocol)
 *
 * Implements the full Double Ratchet algorithm with:
 * 1. DH Ratchet (Diffie-Hellman) - Provides Post-Compromise Security (PCS)
 * 2. Symmetric Ratchet (HMAC Chain Ratchet) - Provides Perfect Forward Secrecy (PFS)
 *
 * Architecture:
 *   Root Key (DH ratchet)
 *     ├── Sending Chain Key (symmetric ratchet)
 *     │     └── Message Keys (ephemeral)
 *     └── Receiving Chain Key (symmetric ratchet)
 *           └── Message Keys (ephemeral)
 *
 * Security Guarantees:
 * - Perfect Forward Secrecy (PFS): Past messages secure even if current key compromised
 * - Post-Compromise Security (PCS): Future messages secure after key rotation (self-healing)
 * - MITM Protection: All ephemeral keys authenticated via identity key signatures
 *
 * Key Innovation (Signal Protocol):
 * - DH ratchet happens on RECEIVE, not SEND
 * - Every message includes sender's current DH public key
 * - When you receive a NEW public key, you derive BOTH chains
 * - This ensures both parties derive the same shared secrets
 *
 * Based on Signal Protocol specification:
 * https://signal.org/docs/specifications/doubleratchet/
 */

class DoubleRatchet {
    constructor(identityManager) {
        this.identityManager = identityManager;  // Identity key manager for signatures

        // Root key (ratcheted with DH)
        this.rootKey = null;  // Current root key material (32 bytes)

        // DH Ratchet state (Signal Protocol)
        this.DHs = null;     // Our current DH keypair (CryptoKeyPair)
        this.DHr = null;     // Their current DH public key (CryptoKey)
        this.DHrRaw = null;  // Their current DH public key (raw bytes for comparison)

        // Chain Ratchets
        this.sendingChain = null;   // ChainRatchet instance for outgoing messages
        this.receivingChain = null; // ChainRatchet instance for incoming messages

        // Message counters
        this.Ns = 0;  // Sending message number (in current chain)
        this.Nr = 0;  // Receiving message number (in current chain)
        this.PN = 0;  // Previous sending chain length (for out-of-order handling)

        // Skipped message keys (for out-of-order messages)
        // Map of "ratchetPublicKey:messageNumber" -> {key: CryptoKey, ratchetCount: number}
        // The ratchetCount is needed to prune entries from chains more than one
        // round old (PFS: drop keys from past DH ratchets we no longer need).
        this.skippedKeys = new Map();
        this.MAX_SKIP = 100;                  // Maximum messages to skip per chain (DoS protection)
        this.MAX_SKIPPED_KEYS_TOTAL = 1000;   // Global cap across all ratchet rounds (anti-DoS)

        // Cached signature for the current DH key and ratchet counters.
        this.DHsSignature = null;

        // Ratchet state
        this.isInitiator = false;  // Whether we initiated the handshake
        this.ratchetCount = 0;     // Number of DH ratchets performed
        this.hasRatchetedSinceReceive = true;  // Track if we've ratcheted since last receive
        // Initiator starts as true (no need to ratchet before first send)
        // Responder will set to false when they receive first message

        // Highest (ratchetCount, messageNumber) tuple successfully decrypted.
        // Used to flag late/reordered arrivals to the UI without weakening the
        // cryptographic acceptance rules — out-of-order messages are still
        // valid, but the application can mark them visually.
        this.maxRatchetSeen = -1;
        this.maxCounterSeen = -1;

        // Configuration
        this.CURVE = 'P-256';

        // C-01: serialize all ratchet state mutations through an internal
        // promise mutex. encryptMessage and decryptMessage mutate
        // this.{Ns, Nr, chains, DHs, DHr, rootKey, ratchetCount} across
        // multiple `await` points. An intermediate await would otherwise let
        // another invocation observe an in-progress state (e.g. messageNumber
        // already incremented but chainKeyMaterial not yet ratcheted),
        // producing message keys the peer cannot derive. The mutex serializes
        // BOTH directions: the receive-side DH ratchet touches sendingChain
        // too, so per-direction locks are not sufficient.
        this._mutex = Promise.resolve();

        // C-01b (audit C-1): synchronous fatal-auth gate. Set to true the
        // moment SIGNATURE_INVALID is detected in _decryptMessageImpl. Once
        // set, every subsequent encryptMessage / decryptMessage call —
        // including those already queued on the mutex chain when detection
        // fired — short-circuits at the entry gate and refuses to touch
        // ratchet state. This eliminates the race window between
        // SIGNATURE_INVALID detection and the asynchronous WS close: even
        // if the WS layer drains buffered frames before the close handshake
        // completes, no further decryption can advance state under attacker
        // control. The flag is intentionally not resettable from inside
        // this class — the only valid recovery is a full session refresh.
        this.fatalAuthFailure = false;
    }

    /**
     * Run fn() after every previously-queued task has settled. Returns the
     * result of fn() to the caller; rejections are NOT propagated into the
     * mutex chain (the `.catch(() => undefined)` resets it so a single
     * decrypt failure does not poison subsequent operations).
     *
     * @private
     */
    _serialize(fn) {
        const task = this._mutex.then(() => fn());
        this._mutex = task.catch(() => undefined);
        return task;
    }

    /**
     * Build the canonical byte sequence that is signed to authenticate the
     * current DH public key at a given ratchet round. Deterministic and
     * length-prefixed to avoid concatenation ambiguity.
     *
     *   tag || len(dh_raw):u16_be || dh_raw || pn:u32_be || n:u32_be || rc:u32_be
     *
     * @private
     * @param {ArrayBuffer|Uint8Array} dhRaw - raw exported DH public key
     * @param {number} pn - previous sending-chain length
     * @param {number} n - message number in the current chain
     * @param {number} rc - ratchet count at signing time
     * @returns {Uint8Array}
     */
    _buildCanonicalBytes(dhRaw, pn, n, rc) {
        const tag = new TextEncoder().encode('pinchat-drheader-v2');
        const dhBytes = dhRaw instanceof Uint8Array ? dhRaw : new Uint8Array(dhRaw);
        const out = new Uint8Array(tag.length + 2 + dhBytes.byteLength + 12);
        out.set(tag, 0);
        new DataView(out.buffer).setUint16(tag.length, dhBytes.byteLength, false);
        out.set(dhBytes, tag.length + 2);
        const view = new DataView(out.buffer);
        view.setUint32(tag.length + 2 + dhBytes.byteLength, pn, false);
        view.setUint32(tag.length + 6 + dhBytes.byteLength, n, false);
        view.setUint32(tag.length + 10 + dhBytes.byteLength, rc, false);
        return out;
    }

    /**
     * Sign the current DHs public key with the identity ECDSA key and cache
     * the base64url signature. Must be invoked after every fresh DHs keypair
     * generation (initialize, performDHRatchetOnReceive, performSendSideDHRatchet).
     */
    async signCurrentDHs(pn = this.PN, n = this.Ns) {
        if (!this.identityManager) {
            throw new Error('identityManager required for signed DH ratchet (protocol v1)');
        }
        const raw = await crypto.subtle.exportKey('raw', this.DHs.publicKey);
        const canon = this._buildCanonicalBytes(raw, pn, n, this.ratchetCount);
        const sigBuf = await this.identityManager.sign(canon);
        this.DHsSignature = this.arrayBufferToBase64url(sigBuf);
    }

    /**
     * Initialize Double Ratchet with shared secret from initial ECDH handshake
     *
     * Signal Protocol initialization:
     * - Both parties have completed ECDH handshake
     * - They share a root key derived from the handshake
     * - Initiator: Has DHs keypair, knows DHr (responder's public key)
     * - Responder: Has DHs keypair, DHr = null (will trigger ratchet on first message)
     *
     * IMPORTANT: Responder's DHr starts as null so the first received message
     * triggers a DH ratchet. This is how Signal Protocol works.
     *
     * @param {Uint8Array} sharedSecret - 32-byte shared secret from initial ECDH
     * @param {boolean} isInitiator - Whether we initiated the handshake
     * @param {CryptoKeyPair} myKeypair - Our ECDH keypair from handshake
     * @param {CryptoKey} theirPublicKey - Peer's ECDH public key from handshake
     */
    async initialize(sharedSecret, isInitiator, myKeypair = null, theirPublicKey = null) {
        if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== 32) {
            throw new Error('Shared secret must be 32 bytes');
        }

        this.isInitiator = isInitiator;
        debugLog(`[DoubleRatchet] Initializing (role: ${isInitiator ? 'initiator' : 'responder'})...`);

        // Derive independent initial root and chain keys. Chain keys MUST NOT
        // be derivable from the retained root key: doing so lets a state
        // compromise reconstruct every prior message in the current chain.
        const initialMaterial = await this.hkdf(
            sharedSecret, new Uint8Array(32), 'DoubleRatchet-Init-v1', 96,
        );
        this.rootKey = initialMaterial.slice(0, 32);

        // Store initial DH state from handshake
        if (myKeypair) {
            this.DHs = myKeypair;
            debugLog('[DoubleRatchet] Using provided ECDH keypair');
        } else {
            // Generate new keypair if not provided (backward compatibility).
            // C-05: extractable=false on the private side; the public side of
            // an asymmetric CryptoKey is always extractable per W3C WebCrypto,
            // so exportKey('raw', publicKey) still works for header construction.
            this.DHs = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: this.CURVE },
                false,
                ['deriveKey', 'deriveBits']
            );
            debugLog('[DoubleRatchet] Generated new ECDH keypair');
        }

        // Signal Protocol: Only INITIATOR stores peer's public key
        // RESPONDER leaves DHr = null so first received message triggers DH ratchet
        if (isInitiator && theirPublicKey) {
            this.DHr = theirPublicKey;
            this.DHrRaw = await crypto.subtle.exportKey('raw', theirPublicKey);
            debugLog('[DoubleRatchet] Initiator: Stored peer public key as DHr');
        } else {
            this.DHr = null;
            this.DHrRaw = null;
            debugLog('[DoubleRatchet] Responder: DHr is null (first message will trigger ratchet)');
        }

        // Role-based chain derivation for proper symmetry:
        // - Initiator sends with "InitiatorToResponder" and receives with "ResponderToInitiator"
        // - Responder sends with "ResponderToInitiator" and receives with "InitiatorToResponder"
        // This ensures: Alice's sendingChain === Bob's receivingChain (and vice versa)
        const sendingLabel = isInitiator ? 'InitiatorToResponder' : 'ResponderToInitiator';
        const receivingLabel = isInitiator ? 'ResponderToInitiator' : 'InitiatorToResponder';

        const sendingChainKey = isInitiator
            ? initialMaterial.slice(32, 64)
            : initialMaterial.slice(64, 96);
        const receivingChainKey = isInitiator
            ? initialMaterial.slice(64, 96)
            : initialMaterial.slice(32, 64);

        // Initialize Chain Ratchets
        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(sendingChainKey);

        this.receivingChain = new ChainRatchet();
        await this.receivingChain.initialize(receivingChainKey);

        // Reset counters
        this.Ns = 0;
        this.Nr = 0;
        this.PN = 0;
        this.ratchetCount = 0;

        // Sign the initial DHs (protocol v1 authenticated ratchet).
        await this.signCurrentDHs();

        debugLog('[DoubleRatchet] ✅ Initialized with root key + bidirectional chains');
        debugLog('[DoubleRatchet] ✅ DH ratchet will trigger automatically on direction change');
    }

    /**
     * Encrypt message (sending path)
     *
     * Signal Protocol encryption:
     * 1. Check if we need to do a send-side DH ratchet (direction change)
     * 2. Derive message key from sending chain
     * 3. Encrypt message with AES-GCM
     * 4. Include our DH public key in header (for receiver's DH ratchet)
     * 5. Ratchet sending chain forward
     *
     * @param {string} plaintext - Message to encrypt
     * @param {string} roomId - Room ID for AAD binding
     * @param {string} senderId - Sender ID for AAD binding
     * @returns {Promise<Object>} Encrypted message envelope with header
     */
    async encryptMessage(plaintext, roomId, senderId, msgType = 'message') {
        // C-01: serialize through the ratchet mutex so concurrent calls
        // cannot read a stale chain state between deriveMessageKey() and
        // ratchet(). See _serialize() and the constructor.
        return this._serialize(() => this._encryptMessageImpl(plaintext, roomId, senderId, msgType));
    }

    async _encryptMessageImpl(plaintext, roomId, senderId, msgType = 'message') {
        if (this.fatalAuthFailure) {
            // Session is irreversibly compromised — refuse to emit ciphertext
            // that could be observed by an attacker who already swapped DH
            // keys. UI will surface SIGNATURE_INVALID via the receive path.
            throw new Error('SIGNATURE_INVALID');
        }
        if (!this.sendingChain) {
            throw new Error('Double Ratchet not initialized');
        }

        // F-10: snapshot ratchet state before any mutation, mirroring the
        // decrypt path. WebCrypto encrypt failure on valid AES-GCM inputs is
        // practically zero, but performSendSideDHRatchet rotates DHs / rootKey
        // / sendingChain / ratchetCount and the chain ratchet itself zeroes
        // chainKeyMaterial after deriveMessageKey + ratchet. A throw between
        // those mutations and a successful return would leave the session in
        // an inconsistent state where the peer cannot derive matching keys.
        // Object.assign restores the snapshot on any thrown error.
        const _drSnapshot = {
            Nr: this.Nr,
            Ns: this.Ns,
            PN: this.PN,
            DHr: this.DHr,
            DHrRaw: this.DHrRaw ? new Uint8Array(this.DHrRaw) : null,
            sendingChain: this.sendingChain ? this.sendingChain.clone() : null,
            receivingChain: this.receivingChain ? this.receivingChain.clone() : null,
            skippedKeys: new Map(this.skippedKeys),
            ratchetCount: this.ratchetCount,
            hasRatchetedSinceReceive: this.hasRatchetedSinceReceive,
            DHs: this.DHs,
            DHsSignature: this.DHsSignature,
            rootKey: this.rootKey ? new Uint8Array(this.rootKey) : null,
            maxRatchetSeen: this.maxRatchetSeen,
            maxCounterSeen: this.maxCounterSeen,
        };

        try {
            // Signal Protocol: Do DH ratchet before sending if we have DHr but haven't ratcheted yet
            // This triggers the first ratchet when responder sends their first message
            if (this.DHr && !this.hasRatchetedSinceReceive) {
                debugLog('[DoubleRatchet] 🔄 Performing send-side DH ratchet (direction change)...');
                await this.performSendSideDHRatchet();
            }

            // Derive message key from sending chain
            const { key: messageKey, counter: messageNumber } = await this.sendingChain.deriveMessageKey();

            // The signature authenticates every semantic header field. The
            // message number is reserved before the await above, so sign the
            // exact values that will be emitted on the wire.
            await this.signCurrentDHs(this.PN, messageNumber);

            // Export our current DH public key for the header
            const dhPublicKeyRaw = await crypto.subtle.exportKey('raw', this.DHs.publicKey);
            const dhPublicKeyBase64 = this.arrayBufferToBase64url(dhPublicKeyRaw);

            // Create message envelope (inner plaintext)
            const envelope = {
                ts: Date.now(),
                text: plaintext
            };

            // Serialize envelope
            const encoder = new TextEncoder();
            const envelopeJson = JSON.stringify(envelope);
            const plaintextBytes = encoder.encode(envelopeJson);

            // Generate IV
            const iv = crypto.getRandomValues(new Uint8Array(12));

            // Create AAD with message context (prevents cross-context attacks)
            // Include ratchetCount for binding ciphertext to specific ratchet state
            const aad = encodeAADWithLengthPrefix([
                {type: AAD_FIELD_TYPES.ROOM_ID, value: roomId},
                {type: AAD_FIELD_TYPES.SENDER_ID, value: senderId},
                {type: AAD_FIELD_TYPES.MESSAGE_NUMBER, value: messageNumber},
                {type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: msgType},
                {type: AAD_FIELD_TYPES.RATCHET_COUNT, value: this.ratchetCount},
                {type: AAD_FIELD_TYPES.PREVIOUS_CHAIN_LENGTH, value: this.PN}
            ]);

            // Encrypt with AES-GCM
            const ciphertext = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: aad
                },
                messageKey,
                plaintextBytes
            );

            // Ratchet sending chain
            await this.sendingChain.ratchet();

            // Combine IV + ciphertext
            const combined = new Uint8Array(iv.length + ciphertext.byteLength);
            combined.set(iv, 0);
            combined.set(new Uint8Array(ciphertext), iv.length);

            // Encode payload
            const payload = this.arrayBufferToBase64url(combined);

            // Increment sending counter
            this.Ns++;

            debugLog(`[DoubleRatchet] Message encrypted #${messageNumber} (ratchet: ${this.ratchetCount})`);

            // Return message with header containing DH public key + signature (v1).
            // The header allows the receiver to (a) verify authenticity of the DH
            // public key via the cached identity signature, and (b) perform the DH
            // ratchet when needed.
            if (!this.DHsSignature) {
                throw new Error('DHsSignature missing — signCurrentDHs must run after every DHs generation');
            }
            return {
                payload: payload,
                header: {
                    v: 1,                      // Protocol version
                    dh: dhPublicKeyBase64,     // Our current DH public key
                    pn: this.PN,               // Previous chain length (for skipped messages)
                    n: messageNumber,          // Message number in current chain
                    rc: this.ratchetCount,     // Ratchet count for debugging
                    sig: this.DHsSignature     // ECDSA signature over all header counters
                }
            };
        } catch (err) {
            Object.assign(this, _drSnapshot);
            throw err;
        }
    }

    /**
     * Decrypt message (receiving path)
     *
     * Signal Protocol decryption:
     * 1. Check if header contains a NEW DH public key
     * 2. If new, perform DH ratchet to derive new chains
     * 3. Derive message key from receiving chain
     * 4. Decrypt with AES-GCM
     *
     * @param {string} payloadBase64 - Base64url-encoded encrypted message
     * @param {Object} header - Message header with DH public key
     * @param {string} roomId - Room ID for AAD binding
     * @param {string} senderId - Sender ID for AAD binding
     * @returns {Promise<Object>} Decrypted message envelope
     */
    async decryptMessage(payloadBase64, header, roomId, senderId, msgType = 'message') {
        // C-01: serialize through the ratchet mutex (same rationale as
        // encryptMessage). The receive-side DH ratchet also resets the
        // sending chain, so this MUST share the mutex with encrypt.
        return this._serialize(() => this._decryptMessageImpl(payloadBase64, header, roomId, senderId, msgType));
    }

    async _decryptMessageImpl(payloadBase64, header, roomId, senderId, msgType = 'message') {
        // Audit C-1: synchronous fatal-auth gate. Any decryptMessage call
        // queued on the mutex *before* SIGNATURE_INVALID detection fired but
        // not yet executed will land here and short-circuit. Crucial because
        // WS frame draining and the close handshake are not synchronous with
        // the throw inside the detection branch below.
        if (this.fatalAuthFailure) {
            throw new Error('SIGNATURE_INVALID');
        }

        if (!this.receivingChain) {
            throw new Error('Double Ratchet not initialized');
        }

        // Protocol v1 header shape validation. These checks read header
        // fields only; they don't touch ratchet state, so they live outside
        // the snapshot/rollback block.
        if (!header || typeof header !== 'object') {
            throw new Error('PROTOCOL_MISMATCH');
        }
        // Resolve protocol version from globalThis for Node/test harness compatibility.
        const expectedV = (typeof globalThis !== 'undefined' && globalThis.PINCHAT_PROTOCOL_VERSION) || 1;
        if (header.v !== expectedV) {
            throw new Error('PROTOCOL_MISMATCH');
        }
        if (!header.sig || typeof header.sig !== 'string') {
            throw new Error('MISSING_SIGNATURE');
        }

        // Extract header fields
        const { dh: dhPublicKeyBase64, pn: prevChainLength, n: messageNumber, rc: ratchetCount } = header;

        debugLog(`[DoubleRatchet] Attempting to decrypt message #${messageNumber} (ratchet: ${ratchetCount})...`);

        // Check if this is a NEW DH public key (triggers DH ratchet)
        const dhPublicKeyRaw = this.base64urlToArrayBuffer(dhPublicKeyBase64);

        // Verify identity signature over the canonical (tag || len || dh || pn || n || rc) tuple
        // BEFORE any path that mutates state (skipped-key delete, chain ratchet,
        // DH ratchet). This is the MITM defense for the DH ratchet: without it,
        // a MITM could swap the DH public key in the header and hijack the chain
        // direction.
        //
        // Audit H-2: this is intentionally outside the snapshot/rollback block —
        // the verify path is pure (no this.* mutation), so a rollback would be a
        // no-op. The throw path sets `this.fatalAuthFailure = true` SYNCHRONOUSLY
        // before re-throwing (audit C-1), so any decryptMessage() / encryptMessage()
        // calls already queued on the mutex chain at detection time will
        // short-circuit at their entry gate when their turn comes — closing the
        // race between detection and the async WS close handshake.
        try {
            const sigBytes = this.base64urlToArrayBuffer(header.sig);
            const canon = this._buildCanonicalBytes(
                dhPublicKeyRaw, prevChainLength, messageNumber, ratchetCount,
            );
            await this.identityManager.verify(canon, sigBytes);
        } catch (e) {
            debugError('[DoubleRatchet] DH header signature INVALID - MITM suspected:', e);
            this.fatalAuthFailure = true;
            throw new Error('SIGNATURE_INVALID');
        }

        // C-02: Skipped-key short-circuit.
        // If we have already derived this (dh, n) message key — either via a
        // forward-jump pre-derive (skipMessageKeys with messageNumber > Nr) or
        // via a pre-ratchet skip on receive (prevChainLength > Nr) — use it
        // directly WITHOUT touching chain state.
        //
        // Without this, a late message from a previous DH chain would hit the
        // `isNewKey` branch below (because header.dh != this.DHrRaw after the
        // chain has rotated), trigger a SPURIOUS performDHRatchetOnReceive on
        // an OLD key, and the subsequent AEAD would fail. State would roll
        // back, but the legitimate message — whose key is sitting in
        // this.skippedKeys — would be lost.
        const skippedKeyId = `${dhPublicKeyBase64}:${messageNumber}`;
        if (this.skippedKeys.has(skippedKeyId)) {
            debugLog(`[DoubleRatchet] Skipped-key hit for #${messageNumber} (dh=${dhPublicKeyBase64.substring(0, 12)}...)`);
            const entry = this.skippedKeys.get(skippedKeyId);

            try {
                const combined = this.base64urlToArrayBuffer(payloadBase64);
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);
                const aad = encodeAADWithLengthPrefix([
                    {type: AAD_FIELD_TYPES.ROOM_ID, value: roomId},
                    {type: AAD_FIELD_TYPES.SENDER_ID, value: senderId},
                    {type: AAD_FIELD_TYPES.MESSAGE_NUMBER, value: messageNumber},
                    {type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: msgType},
                    {type: AAD_FIELD_TYPES.RATCHET_COUNT, value: ratchetCount},
                    {type: AAD_FIELD_TYPES.PREVIOUS_CHAIN_LENGTH, value: prevChainLength}
                ]);
                const plaintextBytes = await crypto.subtle.decrypt(
                    { name: 'AES-GCM', iv: iv, additionalData: aad },
                    entry.key,
                    ciphertext
                );

                // Single-use: remove from the map AFTER successful AEAD.
                // If the AEAD fails the entry remains and will be GC'd by
                // MAX_SKIPPED_KEYS_TOTAL eviction or by a future DH ratchet.
                this.skippedKeys.delete(skippedKeyId);

                const envelope = JSON.parse(new TextDecoder().decode(plaintextBytes));
                // Late deliveries are by definition out-of-order. We do NOT
                // update maxRatchetSeen / maxCounterSeen — those track the
                // forward edge of the conversation, not late arrivals.
                envelope._outOfOrder = true;
                debugLog(`[DoubleRatchet] Skipped-key decrypt success #${messageNumber}`);
                return envelope;
            } catch (err) {
                debugError('[DoubleRatchet] Skipped-key AEAD failed:', err);
                throw new Error('Message decryption failed - authentication error');
            }
        }

        const isFirstMessage = !this.DHrRaw;  // Responder's first received message
        const isNewKey = !isFirstMessage && !this.arraysEqual(dhPublicKeyRaw, new Uint8Array(this.DHrRaw));

        // Snapshot ratchet state before any mutation (Signal Protocol "tentative decrypt").
        // The DH header signature was already verified above, but the AEAD tag
        // authenticates the payload only later. A replay of a valid header with a
        // corrupt/injected payload would permanently desynchronise the ratchet without
        // this rollback guard. State is committed only on successful AES-GCM decryption.
        const _drSnapshot = {
            Nr: this.Nr,
            Ns: this.Ns,
            PN: this.PN,
            DHr: this.DHr,
            DHrRaw: this.DHrRaw ? new Uint8Array(this.DHrRaw) : null,
            sendingChain: this.sendingChain ? this.sendingChain.clone() : null,
            receivingChain: this.receivingChain ? this.receivingChain.clone() : null,
            skippedKeys: new Map(this.skippedKeys),
            ratchetCount: this.ratchetCount,
            hasRatchetedSinceReceive: this.hasRatchetedSinceReceive,
            DHs: this.DHs,
            DHsSignature: this.DHsSignature,
            rootKey: this.rootKey ? new Uint8Array(this.rootKey) : null,
            maxRatchetSeen: this.maxRatchetSeen,
            maxCounterSeen: this.maxCounterSeen,
        };

        let envelope;
        try {
            if (isFirstMessage) {
                // Responder receiving first message from initiator
                // Don't do DH ratchet - just store their public key and use initial chains
                // The initial receivingChain (from handshake) matches initiator's sendingChain
                debugLog('[DoubleRatchet] First message received - storing DHr (no ratchet yet)');

                // C-05: extractable=false. We never exportKey on DHr; we
                // keep raw bytes in this.DHrRaw for keyId construction and
                // identity-change detection (cf. skipMessageKeys).
                const newDHr = await crypto.subtle.importKey(
                    'raw',
                    dhPublicKeyRaw,
                    { name: 'ECDH', namedCurve: this.CURVE },
                    false,
                    []
                );
                this.DHr = newDHr;
                this.DHrRaw = new Uint8Array(dhPublicKeyRaw);

                // Mark that we need to do a send-side DH ratchet before our next send
                this.hasRatchetedSinceReceive = false;
            } else if (isNewKey) {
                debugLog('[DoubleRatchet] 🔄 New DH public key detected - performing RECEIVE-SIDE DH ratchet...');
                debugLog(`[DoubleRatchet] Old DHr: ${this.arrayBufferToBase64url(this.DHrRaw).substring(0, 20)}...`);
                debugLog(`[DoubleRatchet] New DHr: ${dhPublicKeyBase64.substring(0, 20)}...`);

                // Skip message keys for out-of-order messages from previous chain
                if (this.receivingChain && prevChainLength > this.Nr) {
                    await this.skipMessageKeys(prevChainLength);
                }

                // Perform DH ratchet
                await this.performDHRatchetOnReceive(dhPublicKeyRaw);

                // After receive-side ratchet, we DON'T need another send-side ratchet
                // because performDHRatchetOnReceive already generates new DHs and sendingChain
                this.hasRatchetedSinceReceive = true;
                debugLog('[DoubleRatchet] ✅ Receive-side ratchet complete - new sendingChain ready for reply');
            } else {
                debugLog('[DoubleRatchet] Same DH public key - no ratchet needed');
            }

            // Decide which path derives the message key, and whether the chain
            // state should be advanced afterwards.
            //   - skipped-key path: already past this counter, do NOT touch chain state
            //   - forward-jump path: messageNumber > Nr, store intermediate keys first
            //   - replay/too-old path: messageNumber < Nr with no stored key → reject
            //   - in-order path: messageNumber === Nr (after skip), derive and advance once
            const skippedKeyId = `${dhPublicKeyBase64}:${messageNumber}`;
            const isSkippedKey = this.skippedKeys.has(skippedKeyId);

            if (!isSkippedKey && messageNumber < this.Nr) {
                // Already advanced past this counter and no skipped key stored.
                // Treat as replay / out-of-window to preserve PFS.
                debugError(`[DoubleRatchet] Message #${messageNumber} is behind Nr=${this.Nr} and not in skipped keys`);
                throw new Error('Message decryption failed - authentication error');
            }

            if (!isSkippedKey && messageNumber > this.Nr) {
                // Forward jump within the current chain: store keys for Nr..messageNumber-1
                // so delayed messages can still be decrypted. After this call, Nr has
                // advanced to messageNumber and the chain is positioned at messageNumber.
                await this.skipMessageKeys(messageNumber);
            }

            // Try to decrypt with current receiving chain
            let plaintextBytes;
            try {
                let messageKey;

                if (isSkippedKey) {
                    const entry = this.skippedKeys.get(skippedKeyId);
                    messageKey = entry.key;
                    this.skippedKeys.delete(skippedKeyId);
                    debugLog(`[DoubleRatchet] Using skipped key for message #${messageNumber}`);
                } else {
                    messageKey = await this.receivingChain.deriveMessageKeyForCounter(messageNumber);
                }

                // Decode payload
                const combined = this.base64urlToArrayBuffer(payloadBase64);
                const iv = combined.slice(0, 12);
                const ciphertext = combined.slice(12);

                // Create AAD (must match encryption)
                const aad = encodeAADWithLengthPrefix([
                    {type: AAD_FIELD_TYPES.ROOM_ID, value: roomId},
                    {type: AAD_FIELD_TYPES.SENDER_ID, value: senderId},
                    {type: AAD_FIELD_TYPES.MESSAGE_NUMBER, value: messageNumber},
                    {type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: msgType},
                    {type: AAD_FIELD_TYPES.RATCHET_COUNT, value: ratchetCount},
                    {type: AAD_FIELD_TYPES.PREVIOUS_CHAIN_LENGTH, value: prevChainLength}
                ]);

                // Decrypt with AES-GCM — this is the AEAD authentication point.
                // Only on success does the outer try block reach the commit phase.
                plaintextBytes = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: iv,
                        additionalData: aad
                    },
                    messageKey,
                    ciphertext
                );

            } catch (error) {
                debugError('[DoubleRatchet] Decryption failed:', error);
                throw new Error('Message decryption failed - authentication error');
            }

            if (!isSkippedKey) {
                // In-order (or just caught up via skip): ratchet exactly once past
                // messageNumber so the chain is ready for messageNumber+1.
                await this.receivingChain.ratchet();
                this.Nr = messageNumber + 1;
                this.receivingChain.messageNumber = this.Nr;
            }
            // Skipped-key path: chain state is already well ahead of messageNumber,
            // leave Nr and chain untouched.

            // Parse envelope
            const decoder = new TextDecoder();
            const envelopeJson = decoder.decode(plaintextBytes);
            envelope = JSON.parse(envelopeJson);

            // Tag the envelope as out-of-order if this (ratchetCount, messageNumber)
            // tuple is strictly less than the highest tuple we have ever decrypted.
            // The AEAD already authenticated the counter; this is purely a UI hint.
            const isLate =
                ratchetCount < this.maxRatchetSeen ||
                (ratchetCount === this.maxRatchetSeen && messageNumber < this.maxCounterSeen);
            if (isLate) {
                envelope._outOfOrder = true;
            }

            if (
                ratchetCount > this.maxRatchetSeen ||
                (ratchetCount === this.maxRatchetSeen && messageNumber > this.maxCounterSeen)
            ) {
                this.maxRatchetSeen = ratchetCount;
                this.maxCounterSeen = messageNumber;
            }

        } catch (err) {
            // AEAD failed or any other error: roll back all ratchet state mutations
            // so the session remains synchronised and future valid messages can still
            // be decrypted.
            Object.assign(this, _drSnapshot);
            throw err;
        }

        debugLog(`[DoubleRatchet] ✅ Message decrypted #${messageNumber} (ratchet: ${this.ratchetCount})`);

        return envelope;
    }

    /**
     * Perform DH ratchet step when receiving a NEW public key
     *
     * Signal Protocol DH Ratchet:
     * 1. Derive receiving chain from DH(our_current_private, their_new_public)
     * 2. Generate new keypair for ourselves
     * 3. Derive sending chain from DH(our_new_private, their_new_public)
     *
     * This is the core of Post-Compromise Security (PCS):
     * - Old keys are destroyed
     * - New keys are derived from fresh DH exchange
     * - Attacker who compromised old keys cannot decrypt future messages
     *
     * @param {Uint8Array} newDHrRaw - New DH public key from peer (raw bytes)
     */
    async performDHRatchetOnReceive(newDHrRaw) {
        // Import peer's new public key.
        // C-05: extractable=false. We use this.DHrRaw cache for any byte-level
        // access (cf. skipMessageKeys).
        const newDHr = await crypto.subtle.importKey(
            'raw',
            newDHrRaw,
            { name: 'ECDH', namedCurve: this.CURVE },
            false,
            []
        );

        // Save previous chain state
        this.PN = this.Ns;
        this.Ns = 0;
        this.Nr = 0;

        // Update stored peer public key
        this.DHr = newDHr;
        this.DHrRaw = new Uint8Array(newDHrRaw);

        // Step 1: Derive new receiving chain
        // DH_out = DH(our_current_private, their_new_public)
        const dhOutput1 = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: newDHr },
            this.DHs.privateKey,
            256
        );

        // Derive new root key and receiving chain key
        const dhBytes1 = new Uint8Array(dhOutput1);
        const material1 = await this.hkdf(this.rootKey, dhBytes1, 'DoubleRatchet-RootKey', 64);
        const newRootKey1 = material1.slice(0, 32);
        const newReceivingChainKey = material1.slice(32, 64);

        // Initialize new receiving chain
        this.receivingChain = new ChainRatchet();
        await this.receivingChain.initialize(newReceivingChainKey);

        // Step 2: Generate new keypair for ourselves.
        // C-05: private side non-extractable.
        const oldDHs = this.DHs;
        this.DHs = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            false,
            ['deriveKey', 'deriveBits']
        );

        // Step 3: Derive new sending chain
        // DH_out = DH(our_new_private, their_new_public)
        const dhOutput2 = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: newDHr },
            this.DHs.privateKey,
            256
        );

        // Derive new root key and sending chain key
        const dhBytes2 = new Uint8Array(dhOutput2);
        const material2 = await this.hkdf(newRootKey1, dhBytes2, 'DoubleRatchet-RootKey', 64);
        const newRootKey2 = material2.slice(0, 32);
        const newSendingChainKey = material2.slice(32, 64);

        // Initialize new sending chain
        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(newSendingChainKey);

        // Update root key (zero out old one for PFS)
        if (this.rootKey) {
            this.rootKey.fill(0);
        }
        this.rootKey = newRootKey2;

        // Increment ratchet count
        this.ratchetCount++;

        // Prune skipped keys from chains more than one ratchet round old.
        // We keep the previous chain (ratchetCount - 1) in case a delayed
        // message arrives after the ratchet, but drop anything older.
        for (const [id, entry] of this.skippedKeys) {
            if (entry.ratchetCount < this.ratchetCount - 1) {
                this.skippedKeys.delete(id);
            }
        }

        // Sign the freshly generated DHs for the new ratchet round.
        await this.signCurrentDHs();

        debugLog(`[DoubleRatchet] ✅ RECEIVE-SIDE DH ratchet #${this.ratchetCount} completed`);
        debugLog('[DoubleRatchet] 🔐 Post-Compromise Security (PCS) checkpoint reached');
        debugLog('[DoubleRatchet] 📤 New sendingChain derived - ready for reply');
    }

    /**
     * Perform send-side DH ratchet (before sending after receiving)
     *
     * This is called when we're about to send but haven't ratcheted since
     * our last receive. This triggers the first DH ratchet for the responder
     * and maintains the ping-pong ratcheting pattern.
     *
     * Only the SENDING chain is updated:
     * 1. Generate new keypair
     * 2. Derive new sending chain from DH(new_private, DHr)
     *
     * The receiving chain stays the same until we receive a new public key.
     */
    async performSendSideDHRatchet() {
        if (!this.DHr) {
            throw new Error('Cannot perform send-side DH ratchet without DHr');
        }

        // Save previous sending chain length
        this.PN = this.Ns;
        this.Ns = 0;

        // Generate new keypair.
        // C-05: private side non-extractable (see initialize() rationale).
        const oldDHs = this.DHs;
        this.DHs = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            false,
            ['deriveKey', 'deriveBits']
        );

        // Derive new sending chain from DH(new_DHs_private, DHr)
        const dhOutput = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: this.DHr },
            this.DHs.privateKey,
            256
        );

        const dhBytes = new Uint8Array(dhOutput);
        const material = await this.hkdf(this.rootKey, dhBytes, 'DoubleRatchet-RootKey', 64);
        const newRootKey = material.slice(0, 32);
        const newSendingChainKey = material.slice(32, 64);

        // Initialize new sending chain
        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(newSendingChainKey);

        // Update root key
        if (this.rootKey) {
            this.rootKey.fill(0);
        }
        this.rootKey = newRootKey;

        // Increment ratchet count
        this.ratchetCount++;

        // Mark that we've ratcheted
        this.hasRatchetedSinceReceive = true;

        // Sign the freshly generated DHs (v1 authenticated ratchet).
        await this.signCurrentDHs();

        debugLog(`[DoubleRatchet] ✅ Send-side DH ratchet #${this.ratchetCount} completed`);
        debugLog('[DoubleRatchet] 🔐 New keypair generated, sending chain updated');
    }

    /**
     * Skip message keys for out-of-order handling
     *
     * When we receive a message with a higher counter than expected,
     * we need to derive and store the skipped keys so we can decrypt
     * out-of-order messages later.
     *
     * @param {number} until - Skip keys up to this counter (exclusive)
     */
    async skipMessageKeys(until) {
        if (until - this.Nr > this.MAX_SKIP) {
            throw new Error(`Too many skipped messages: ${until - this.Nr} (max: ${this.MAX_SKIP})`);
        }

        // C-05: this.DHr is now imported non-extractable; read raw bytes from
        // the cache populated alongside every DHr assignment (initialize,
        // first-message branch, performDHRatchetOnReceive). Defence-in-depth
        // guard against developer error: if DHrRaw was somehow not populated,
        // fail loudly instead of producing keyIds based on undefined.
        if (!this.DHrRaw) {
            throw new Error('skipMessageKeys called before DHrRaw is set');
        }
        const dhPublicKeyBase64 = this.arrayBufferToBase64url(this.DHrRaw);

        while (this.Nr < until) {
            const messageKey = await this.receivingChain.deriveMessageKeyForCounter(this.Nr);
            const keyId = `${dhPublicKeyBase64}:${this.Nr}`;
            this.skippedKeys.set(keyId, { key: messageKey, ratchetCount: this.ratchetCount });

            // Global cap: FIFO eviction (Map preserves insertion order).
            // Prevents memory exhaustion across many ratchet rounds.
            if (this.skippedKeys.size > this.MAX_SKIPPED_KEYS_TOTAL) {
                const oldest = this.skippedKeys.keys().next().value;
                this.skippedKeys.delete(oldest);
                debugLog(`[DoubleRatchet] Evicted oldest skipped key (global cap ${this.MAX_SKIPPED_KEYS_TOTAL})`);
            }

            await this.receivingChain.ratchet();
            // Keep chain.messageNumber aligned with chainKeyMaterial's position,
            // so the next deriveMessageKeyForCounter() computes stepsAhead from
            // the true chain position rather than a stale baseline.
            this.receivingChain.messageNumber++;
            this.Nr++;
        }

        debugLog(`[DoubleRatchet] Skipped ${until} message keys for out-of-order handling`);
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) - RFC 5869
     *
     * @param {Uint8Array} ikm - Input key material
     * @param {Uint8Array} salt - Salt (use zeros if not needed)
     * @param {string} info - Context string
     * @param {number} length - Output length in bytes
     * @returns {Promise<Uint8Array>}
     */
    async hkdf(ikm, salt, info, length) {
        // Import IKM as raw key for HKDF
        const ikmKey = await crypto.subtle.importKey(
            'raw',
            ikm,
            'HKDF',
            false,
            ['deriveBits']
        );

        // Encode info string
        const encoder = new TextEncoder();
        const infoBytes = encoder.encode(info);

        // Derive bits using HKDF
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: infoBytes
            },
            ikmKey,
            length * 8  // bits
        );

        return new Uint8Array(derivedBits);
    }

    /**
     * Compare two Uint8Arrays for equality.
     *
     * NOTE: The XOR-accumulator pattern below is structurally constant-time
     * at the algorithmic level (every byte is compared, no early return).
     * It is NOT a true wall-clock constant-time primitive — JS engines
     * (V8/SpiderMonkey) make no guarantees about branch prediction or
     * cache effects on `|=`. That is acceptable here because this helper
     * only compares PUBLIC DH key bytes (this.DHrRaw vs incoming header.dh)
     * for ratchet-direction detection. Public material; no secret is leaked
     * by a timing side channel on a public comparison.
     *
     * @private
     */
    arraysEqual(a, b) {
        if (a.length !== b.length) return false;

        let result = 0;
        for (let i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result === 0;
    }

    /**
     * Destroy Double Ratchet state (session cleanup)
     */
    destroy() {
        debugLog('[DoubleRatchet] Destroying state...');

        // Zero out sensitive key material
        if (this.rootKey) this.rootKey.fill(0);

        // Reset chains first: this zeroes chainKeyMaterial before we let the
        // chain references go.
        if (this.sendingChain) this.sendingChain.reset();
        if (this.receivingChain) this.receivingChain.reset();

        this.rootKey = null;
        this.sendingChain = null;
        this.receivingChain = null;
        this.DHs = null;
        this.DHr = null;
        this.DHrRaw = null;
        this.skippedKeys.clear();

        debugLog('[DoubleRatchet] ✅ State destroyed');
    }

    /**
     * Convert ArrayBuffer to Base64url
     * @private
     */
    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Convert Base64url to ArrayBuffer
     * @private
     */
    base64urlToArrayBuffer(base64url) {
        const base64 = base64url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

// Expose globally (browser) or via CommonJS (Node test harness). The check
// keeps the browser path identical and only activates exports under Node.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { DoubleRatchet };
} else {
    window.DoubleRatchet = DoubleRatchet;
}
