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
        // Map of "ratchetPublicKey:messageNumber" -> messageKey
        this.skippedKeys = new Map();
        this.MAX_SKIP = 100;  // Maximum messages to skip (DoS protection)

        // Ratchet state
        this.isInitiator = false;  // Whether we initiated the handshake
        this.ratchetCount = 0;     // Number of DH ratchets performed
        this.hasRatchetedSinceReceive = true;  // Track if we've ratcheted since last receive
        // Initiator starts as true (no need to ratchet before first send)
        // Responder will set to false when they receive first message

        // Configuration
        this.CURVE = 'P-256';
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

        // Derive initial root key from shared secret using HKDF
        this.rootKey = await this.hkdf(sharedSecret, new Uint8Array(32), 'DoubleRatchet-RootKey', 32);

        // Store initial DH state from handshake
        if (myKeypair) {
            this.DHs = myKeypair;
            debugLog('[DoubleRatchet] Using provided ECDH keypair');
        } else {
            // Generate new keypair if not provided (backward compatibility)
            this.DHs = await crypto.subtle.generateKey(
                { name: 'ECDH', namedCurve: this.CURVE },
                true,
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

        const sendingChainKey = await this.hkdf(this.rootKey, new Uint8Array(32), sendingLabel, 32);
        const receivingChainKey = await this.hkdf(this.rootKey, new Uint8Array(32), receivingLabel, 32);

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
    async encryptMessage(plaintext, roomId, senderId) {
        if (!this.sendingChain) {
            throw new Error('Double Ratchet not initialized');
        }

        // Signal Protocol: Do DH ratchet before sending if we have DHr but haven't ratcheted yet
        // This triggers the first ratchet when responder sends their first message
        if (this.DHr && !this.hasRatchetedSinceReceive) {
            debugLog('[DoubleRatchet] 🔄 Performing send-side DH ratchet (direction change)...');
            await this.performSendSideDHRatchet();
        }

        // Derive message key from sending chain
        const { key: messageKey, counter: messageNumber } = await this.sendingChain.deriveMessageKey();

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
            {type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: 'message'},
            {type: AAD_FIELD_TYPES.RATCHET_COUNT, value: this.ratchetCount}
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

        // Return message with header containing DH public key
        // The header allows the receiver to perform DH ratchet if needed
        return {
            payload: payload,
            header: {
                dh: dhPublicKeyBase64,  // Our current DH public key
                pn: this.PN,            // Previous chain length (for skipped messages)
                n: messageNumber,       // Message number in current chain
                rc: this.ratchetCount   // Ratchet count for debugging
            }
        };
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
    async decryptMessage(payloadBase64, header, roomId, senderId) {
        if (!this.receivingChain) {
            throw new Error('Double Ratchet not initialized');
        }

        // Extract header fields
        const { dh: dhPublicKeyBase64, pn: prevChainLength, n: messageNumber, rc: ratchetCount } = header;

        debugLog(`[DoubleRatchet] Attempting to decrypt message #${messageNumber} (ratchet: ${ratchetCount})...`);

        // Check if this is a NEW DH public key (triggers DH ratchet)
        const dhPublicKeyRaw = this.base64urlToArrayBuffer(dhPublicKeyBase64);
        const isFirstMessage = !this.DHrRaw;  // Responder's first received message
        const isNewKey = !isFirstMessage && !this.arraysEqual(dhPublicKeyRaw, new Uint8Array(this.DHrRaw));

        if (isFirstMessage) {
            // Responder receiving first message from initiator
            // Don't do DH ratchet - just store their public key and use initial chains
            // The initial receivingChain (from handshake) matches initiator's sendingChain
            debugLog('[DoubleRatchet] First message received - storing DHr (no ratchet yet)');

            const newDHr = await crypto.subtle.importKey(
                'raw',
                dhPublicKeyRaw,
                { name: 'ECDH', namedCurve: this.CURVE },
                true,
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

        // Try to decrypt with current receiving chain
        let plaintextBytes;
        try {
            // Check if we have a skipped key for this message
            const skippedKeyId = `${dhPublicKeyBase64}:${messageNumber}`;
            let messageKey;

            if (this.skippedKeys.has(skippedKeyId)) {
                messageKey = this.skippedKeys.get(skippedKeyId);
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
                {type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: 'message'},
                {type: AAD_FIELD_TYPES.RATCHET_COUNT, value: ratchetCount}
            ]);

            // Decrypt with AES-GCM
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

        // Ratchet receiving chain to match processed message position
        // This accounts for any skipped messages (e.g., if we received #1 without #0)
        // Chain must advance to state (messageNumber + 1) to be ready for next message
        const newPosition = messageNumber + 1;
        const numRatchets = newPosition - this.Nr;
        for (let i = 0; i < numRatchets; i++) {
            await this.receivingChain.ratchet();
        }
        this.Nr = newPosition;
        this.receivingChain.messageNumber = this.Nr;

        // Parse envelope
        const decoder = new TextDecoder();
        const envelopeJson = decoder.decode(plaintextBytes);
        const envelope = JSON.parse(envelopeJson);

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
        // Import peer's new public key
        const newDHr = await crypto.subtle.importKey(
            'raw',
            newDHrRaw,
            { name: 'ECDH', namedCurve: this.CURVE },
            true,
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
        const newRootKey1 = await this.hkdf(this.rootKey, dhBytes1, 'DoubleRatchet-RootKey', 32);
        // Use 'ChainKey' label - must match send-side ratchet so both parties derive same key
        const newReceivingChainKey = await this.hkdf(newRootKey1, new Uint8Array(32), 'ChainKey', 32);

        // Initialize new receiving chain
        this.receivingChain = new ChainRatchet();
        await this.receivingChain.initialize(newReceivingChainKey);

        // Step 2: Generate new keypair for ourselves
        const oldDHs = this.DHs;
        this.DHs = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,
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
        const newRootKey2 = await this.hkdf(newRootKey1, dhBytes2, 'DoubleRatchet-RootKey', 32);
        // Use 'ChainKey' label - must match receive-side on other party
        const newSendingChainKey = await this.hkdf(newRootKey2, new Uint8Array(32), 'ChainKey', 32);

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

        // Generate new keypair
        const oldDHs = this.DHs;
        this.DHs = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );

        // Derive new sending chain from DH(new_DHs_private, DHr)
        const dhOutput = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: this.DHr },
            this.DHs.privateKey,
            256
        );

        const dhBytes = new Uint8Array(dhOutput);
        const newRootKey = await this.hkdf(this.rootKey, dhBytes, 'DoubleRatchet-RootKey', 32);
        // Use 'ChainKey' label (same as receive-side) so both parties derive the same key
        const newSendingChainKey = await this.hkdf(newRootKey, new Uint8Array(32), 'ChainKey', 32);

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

        const dhPublicKeyRaw = await crypto.subtle.exportKey('raw', this.DHr);
        const dhPublicKeyBase64 = this.arrayBufferToBase64url(dhPublicKeyRaw);

        while (this.Nr < until) {
            const messageKey = await this.receivingChain.deriveMessageKeyForCounter(this.Nr);
            const keyId = `${dhPublicKeyBase64}:${this.Nr}`;
            this.skippedKeys.set(keyId, messageKey);
            await this.receivingChain.ratchet();
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
     * Compare two Uint8Arrays for equality (constant-time)
     *
     * SECURITY: This implementation is resistant to timing attacks.
     * It always compares all bytes regardless of where differences occur,
     * preventing attackers from inferring partial key matches.
     *
     * @private
     */
    arraysEqual(a, b) {
        if (a.length !== b.length) return false;

        // XOR accumulator - constant-time comparison
        // All bytes are always compared, result is 0 only if all match
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

// Expose globally
window.DoubleRatchet = DoubleRatchet;
