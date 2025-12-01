/**
 * Module for end-to-end encryption/decryption using the WebCrypto API
 */

/**
 * Converts standard Base64 to URL-safe Base64url (RFC 4648)
 * @param {string} base64 - Standard Base64 string
 * @returns {string} Base64url string
 */
function base64ToBase64url(base64) {
    return base64
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Converts URL-safe Base64url to standard Base64
 * @param {string} base64url - Base64url string
 * @returns {string} Standard Base64 string
 */
function base64urlToBase64(base64url) {
    let base64 = base64url
        .replace(/-/g, '+')
        .replace(/_/g, '/');

    // Re-add padding if needed
    const pad = base64.length % 4;
    if (pad) {
        base64 += '='.repeat(4 - pad);
    }

    return base64;
}

/**
 * AAD Field Types for TLV (Type-Length-Value) encoding
 * Prevents parsing ambiguity when concatenating variable-length fields
 */
const AAD_FIELD_TYPES = {
    ROOM_ID: 0x01,        // UTF-8 string
    SENDER_ID: 0x02,      // UTF-8 string (connection ID)
    TIMESTAMP: 0x03,      // 8 bytes (BigUint64)
    NONCE: 0x04,          // Binary data (typically 16 bytes)
    MESSAGE_NUMBER: 0x05, // 8 bytes (BigUint64) - Enhanced Chain Ratchet: prevents message reordering
    MESSAGE_TYPE: 0x06,   // UTF-8 string - binds message type to ciphertext
    RATCHET_COUNT: 0x07   // 8 bytes (BigUint64) - binds ratchet count to ciphertext
};

/**
 * Encodes AAD fields using TLV (Type-Length-Value) format
 *
 * TLV Format: [type:1][length:2][value:n]
 * - type: 1 byte (field type identifier)
 * - length: 2 bytes (big-endian, value length in bytes)
 * - value: n bytes (actual field data)
 *
 * SECURITY: This prevents parsing ambiguity when concatenating fields.
 * Without length prefixes, "abc" + "def" and "ab" + "cdef" produce
 * the same binary output, allowing cross-context replay attacks.
 *
 * @param {Array<{type: number, value: string|Uint8Array|number}>} fields - Fields to encode
 * @returns {Uint8Array} TLV-encoded AAD
 *
 * @example
 * const aad = encodeAADWithLengthPrefix([
 *   {type: AAD_FIELD_TYPES.ROOM_ID, value: "room-123"},
 *   {type: AAD_FIELD_TYPES.SENDER_ID, value: "user-456"}
 * ]);
 */
function encodeAADWithLengthPrefix(fields) {
    const encoder = new TextEncoder();
    const parts = [];

    // Debug helper: log AAD fields being encoded for visibility during development
    console.log('[DEBUG-AAD] Encoding fields:', fields.map(f => ({
        type: Object.keys(AAD_FIELD_TYPES).find(k => AAD_FIELD_TYPES[k] === f.type),
        value: f.value
    })));

    for (const field of fields) {
        let valueBytes;

        // Convert value to Uint8Array based on type
        if (field.type === AAD_FIELD_TYPES.TIMESTAMP ||
            field.type === AAD_FIELD_TYPES.MESSAGE_NUMBER ||
            field.type === AAD_FIELD_TYPES.RATCHET_COUNT) {
            // Numeric fields (timestamp, message counter, ratchet count): convert to 8-byte BigUint64
            valueBytes = new Uint8Array(
                new BigUint64Array([BigInt(field.value)]).buffer
            );
        } else if (typeof field.value === 'string') {
            // String fields: encode as UTF-8
            valueBytes = encoder.encode(field.value);
        } else if (field.value instanceof Uint8Array) {
            // Binary fields: use as-is
            valueBytes = field.value;
        } else {
            throw new Error(`Invalid AAD field value type for field type ${field.type}`);
        }

        // Validate length fits in 2 bytes (max 65535)
        if (valueBytes.length > 0xFFFF) {
            throw new Error(`AAD field too large: ${valueBytes.length} bytes (max 65535)`);
        }

        // Encode TLV: [type:1][length:2][value:n]
        parts.push(field.type);                           // Type (1 byte)
        parts.push((valueBytes.length >> 8) & 0xFF);      // Length high byte
        parts.push(valueBytes.length & 0xFF);             // Length low byte
        parts.push(...valueBytes);                        // Value (n bytes)
    }

    return new Uint8Array(parts);
}

/**
 * Chain Ratchet for Perfect Forward Secrecy
 *
 * Implements a KDF (Key Derivation Function) chain that:
 * 1. Derives a unique message key for each message
 * 2. Deletes the message key immediately after use (PFS)
 * 3. Ratchets the chain key forward (one-way, irreversible)
 *
 * Security guarantee: If an attacker compromises the chain key at time T,
 * they CANNOT decrypt messages sent before time T (keys already deleted).
 *
 * Based on Signal Protocol's symmetric-key ratchet.
 */
class ChainRatchet {
    constructor() {
        this.chainKeyMaterial = null;  // Uint8Array(32) - raw chain key
        this.messageNumber = 0;         // Counter for message numbering
    }

    /**
     * Initialize chain with session key material from ECDH
     * @param {Uint8Array} keyMaterial - 32-byte raw key from ECDH shared secret
     */
    async initialize(keyMaterial) {
        if (!(keyMaterial instanceof Uint8Array) || keyMaterial.length !== 32) {
            throw new Error('Chain key material must be 32 bytes');
        }

        this.chainKeyMaterial = new Uint8Array(keyMaterial);  // Copy to prevent mutations
        this.messageNumber = 0;
        this.messageKeyWindow = new Map();  // Sliding window for out-of-order message tolerance
        this.WINDOW_SIZE = 16;              // Pre-derive next 16 keys for resilience

        console.log('[ChainRatchet] Initialized with 32-byte key material');
    }

    /**
     * Derive ephemeral message key for encryption/decryption
     *
     * Uses HMAC-SHA256 as KDF:
     *   MK_n = HMAC-SHA256(CK_n, "MessageKey-" || n)
     *
     * The counter is reserved before awaiting to prevent concurrent calls from
     * reusing the same message number.
     *
     * @returns {Promise<{key: CryptoKey, counter: number}>} Message key and its counter
     */
    async deriveMessageKey() {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        // Reserve the counter before any awaited operations to avoid race conditions
        const myCounter = this.messageNumber;
        this.messageNumber++;

        // Derive current message key using helper (0 steps ahead = no ratchet simulation)
        const messageKey = await this._deriveKeyForCounter(myCounter, myCounter);

        // Pre-derive the next WINDOW_SIZE keys by simulating the chain state at each position
        for (let i = 1; i <= this.WINDOW_SIZE; i++) {
            const futureCounter = myCounter + i;
            const futureKey = await this._deriveKeyForCounter(futureCounter, myCounter);
            this.messageKeyWindow.set(futureCounter, futureKey);
        }

        // Remove keys that have fallen outside the sliding window to preserve PFS
        for (const [counter] of this.messageKeyWindow) {
            if (counter < myCounter) {
                this.messageKeyWindow.delete(counter);
            }
        }

        console.log(`[ChainRatchet] Derived message key #${myCounter} (window: ${myCounter+1}..${myCounter+this.WINDOW_SIZE})`);

        // Return both key and counter (counter needed for AAD binding)
        return { key: messageKey, counter: myCounter };
    }

    /**
     * Derive message key for a specific counter (used by Double Ratchet for decryption)
     *
     * First checks the sliding window for pre-derived keys (common case for in-order messages).
     * Falls back to direct derivation for out-of-order messages within tolerance.
     *
     * @param {number} counter - Message counter to derive key for
     * @returns {Promise<CryptoKey>} AES-GCM key for this counter
     */
    async deriveMessageKeyForCounter(counter) {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        // Check sliding window first (common case)
        if (this.messageKeyWindow.has(counter)) {
            console.log(`[ChainRatchet] Using pre-derived key from window for #${counter}`);
            return this.messageKeyWindow.get(counter);
        }

        // Derive key directly (out-of-order message)
        console.log(`[ChainRatchet] Deriving key for counter #${counter} (not in window)`);
        const currentCounter = this.messageNumber;
        const messageKey = await this._deriveKeyForCounter(counter, currentCounter);

        return messageKey;
    }

    /**
     * Helper: Derive message key for a specific counter with simulated ratcheting
     *
     * Simulates chain ratcheting N steps forward to derive the correct key for counter.
     * This ensures sliding window keys match what the sender will use.
     *
     * @private
     * @param {number} counter - Message counter to derive key for
     * @param {number} currentCounter - Current messageNumber (counter offset)
     * @returns {Promise<CryptoKey>} AES-GCM key for this counter
     */
    async _deriveKeyForCounter(counter, currentCounter) {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        // Calculate how many ratchet steps ahead this counter is
        const stepsAhead = counter - currentCounter;

        // Simulate ratcheting forward (without modifying actual chain state)
        let simulatedChainKey = new Uint8Array(this.chainKeyMaterial);

        for (let i = 0; i < stepsAhead; i++) {
            // Ratchet: CK_{n+1} = HMAC-SHA256(CK_n, "ChainRatchet")
            const ratchetInfo = new TextEncoder().encode('ChainRatchet');
            const hmacKey = await crypto.subtle.importKey(
                'raw',
                simulatedChainKey,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const nextChainKeyRaw = await crypto.subtle.sign('HMAC', hmacKey, ratchetInfo);
            simulatedChainKey = new Uint8Array(nextChainKeyRaw);
        }

        // Now derive message key from the simulated chain key at position 'counter'
        const info = new TextEncoder().encode(`MessageKey-${counter}`);
        const hmacKey = await crypto.subtle.importKey(
            'raw',
            simulatedChainKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Derive raw message key: HMAC-SHA256(simulatedChainKey, info)
        const messageKeyRaw = await crypto.subtle.sign('HMAC', hmacKey, info);

        // Zero out simulated key (security hygiene)
        simulatedChainKey.fill(0);

        // Import as AES-GCM key (for message encryption)
        return await crypto.subtle.importKey(
            'raw',
            messageKeyRaw,
            { name: 'AES-GCM', length: 256 },
            false,  // Non-extractable (ephemeral, RAM-only)
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Ratchet chain key forward (one-way transformation)
     *
     * Uses HMAC-SHA256 as one-way function:
     *   CK_{n+1} = HMAC-SHA256(CK_n, "ChainRatchet")
     *
     * After this call, the previous message key CANNOT be re-derived.
     * This is the core of Perfect Forward Secrecy.
     */
    async ratchet() {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        // KDF constant for chain ratcheting
        const info = new TextEncoder().encode('ChainRatchet');

        const hmacKey = await crypto.subtle.importKey(
            'raw',
            this.chainKeyMaterial,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Compute next chain key: HMAC-SHA256(currentChainKey, "ChainRatchet")
        const nextChainKeyRaw = await crypto.subtle.sign('HMAC', hmacKey, info);

        // Overwrite old chain key material to keep the ratchet one-way
        this.chainKeyMaterial = new Uint8Array(nextChainKeyRaw);

        // NOTE: messageNumber is incremented in deriveMessageKey() to prevent race conditions
        console.log(`[ChainRatchet] Ratcheted forward (counter now at #${this.messageNumber})`);
    }

    /**
     * Reset chain state (when PFS session ends)
     * Called when participant leaves or connection drops
     */
    reset() {
        if (this.chainKeyMaterial) {
            // Zero out memory before dropping the key material
            this.chainKeyMaterial.fill(0);
            this.chainKeyMaterial = null;
        }
        this.messageNumber = 0;
        console.log('[ChainRatchet] Reset (chain key destroyed)');
    }
}

class CryptoManager {
    constructor() {
        this.key = null;                  // Bootstrap key (from URL)
        this.sessionKey = null;           // ECDH-derived session key (DEPRECATED - use chain ratchet)
        this.algorithm = {
            name: 'AES-GCM',
            length: 256
        };

        // Chain Ratchet for Perfect Forward Secrecy
        this.sendingChain = new ChainRatchet();     // For messages we send
        this.receivingChain = new ChainRatchet();   // For messages we receive
        this.ratchetActive = false;                 // Flag: is chain ratchet initialized?

        // Signal-inspired Double Ratchet for Post-Compromise Security
        this.doubleRatchet = null;                  // DoubleRatchet instance (DH + symmetric)
        this.doubleRatchetActive = false;           // Flag: is double ratchet initialized?

        // Enhanced Chain Ratchet: Bidirectional ratcheting (break-in recovery)
        this.lastSenderId = null;                   // Track last message sender for direction-change detection

        // Desync protection: Maximum allowed message gap
        this.MAX_SKIP = 1000;                       // Anti-DoS: prevent memory exhaustion from excessive skips

        // Anti-replay: Track seen message hashes
        this.seenMessageHashes = new Set();
        this.hashTimestamps = new Map(); // hash -> timestamp

        // Security constants
        this.MAX_MESSAGE_AGE = 5 * 60 * 1000;      // 5 minutes
        this.FUTURE_TOLERANCE = 30 * 1000;          // 30 seconds (clock skew)
        this.HASH_CLEANUP_INTERVAL = 60 * 1000;     // 1 minute

        // Start periodic cleanup
        this.startHashCleanup();
    }

    /**
     * Extracts the key from the URL fragment
     * @returns {Promise<CryptoKey|null>}
     */
    async extractKeyFromURL() {
        const fragment = window.location.hash.substring(1);
        const params = new URLSearchParams(fragment);
        let keyBase64 = params.get('key');

        if (!keyBase64) {
            console.error('No encryption key found in URL');
            return null;
        }

        try {
            // Convert Base64url to standard Base64 if needed
            // Detect Base64url format (contains '-' or '_' instead of '+' or '/')
            if (keyBase64.includes('-') || keyBase64.includes('_')) {
                console.log('Detected Base64url format, converting to standard Base64');
                keyBase64 = base64urlToBase64(keyBase64);
            }
            // Otherwise assume standard Base64 (backward compatibility)

            // Decode the key from Base64
            const keyString = atob(keyBase64);
            const keyBuffer = new Uint8Array(keyString.length);
            for (let i = 0; i < keyString.length; i++) {
                keyBuffer[i] = keyString.charCodeAt(i);
            }

            // Import the key (non-extractable for security)
            // SECURITY: extractable=false prevents key exfiltration via XSS or malicious browser extensions
            // The key remains in memory for re-handshaking but cannot be exported
            this.key = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                this.algorithm,
                false,  // Non-extractable: prevents key theft even if XSS occurs
                ['encrypt', 'decrypt']
            );

            console.log('✅ Encryption key loaded successfully');
            return this.key;

        } catch (error) {
            console.error('Failed to load encryption key:', error);
            return null;
        }
    }

    /**
     * Generates a new encryption key
     * @returns {Promise<CryptoKey>}
     */
    async generateKey() {
        this.key = await crypto.subtle.generateKey(
            this.algorithm,
            true,
            ['encrypt', 'decrypt']
        );
        return this.key;
    }

    /**
     * REMOVED: exportKeyAsBase64() - Dead code, never called
     * Bootstrap key is now non-extractable (extractable=false) for security.
     * This function would fail anyway since the key cannot be exported.
     */

    /**
     * Resync receiving chain to target counter (recovery from dropped messages)
     *
     * When a message is dropped (network loss, malicious server), the sender's
     * counter advances but receiver's doesn't. This method fast-forwards the
     * receiving chain to match the sender's counter.
     *
     * Security:
     * - Anti-DoS: Limits maximum skip to prevent memory exhaustion
     * - Logs warning for audit trail
     * - Maintains PFS: skipped keys are not stored (irrecoverable)
     *
     * @param {number} targetCounter - Target message counter to reach
     * @throws {Error} If gap exceeds MAX_SKIP (DoS protection)
     */
    async resyncReceivingChain(targetCounter) {
        // Adjust for the already-incremented messageNumber to locate the last processed counter
        const lastProcessedCounter = this.receivingChain.messageNumber - 1;
        const gap = targetCounter - lastProcessedCounter;

        if (gap <= 0) {
            // No resync needed (already at or past target)
            return;
        }

        if (gap > this.MAX_SKIP) {
            throw new Error(
                `[ChainRatchet] Desync gap too large: ${gap} messages (max ${this.MAX_SKIP}). ` +
                `Possible DoS attack or severe network issues. Counter reset required.`
            );
        }

        console.warn(`[ChainRatchet] Desync detected: ${gap} message(s) dropped`);
        console.warn(`[ChainRatchet] Fast-forwarding from #${lastProcessedCounter} to #${targetCounter}`);

        // Fast-forward: advance chain without deriving message keys
        // (Skipped messages are permanently lost - cannot be decrypted)
        for (let i = lastProcessedCounter; i < targetCounter; i++) {
            await this.receivingChain.ratchet();
            // Manually increment messageNumber to keep it in sync
            this.receivingChain.messageNumber++;

            // Remove consumed keys from window (maintain PFS)
            this.receivingChain.messageKeyWindow.delete(i);
        }

        // Pre-derive next WINDOW_SIZE keys so the sliding window is ready for upcoming messages
        for (let offset = 1; offset <= this.receivingChain.WINDOW_SIZE; offset++) {
            const futureCounter = targetCounter + offset;
            const futureKey = await this.receivingChain._deriveKeyForCounter(futureCounter, targetCounter);
            this.receivingChain.messageKeyWindow.set(futureCounter, futureKey);
        }

        console.log(`[ChainRatchet] Resync complete - now at counter #${this.receivingChain.messageNumber}`);
        console.log(`[ChainRatchet] Sliding window repopulated: [${targetCounter + 1}..${targetCounter + this.receivingChain.WINDOW_SIZE}]`);
    }

    /**
     * Encrypts a message with room and sender context binding (anti-replay protection)
     *
     * With Double Ratchet enabled:
     * 1. Derives unique message key from sending chain
     * 2. Encrypts message with ephemeral key
     * 3. Includes DH public key in header (for receiver's DH ratchet)
     * 4. Ratchets chain forward (message key becomes irrecoverable - PFS!)
     *
     * @param {string} plaintext - Message to encrypt
     * @param {string} roomId - Room UUID
     * @param {string} mySenderId - Sender's connection UUID
     * @returns {Promise<Object>} Object with {payload, header} for WebSocket
     */
    async encryptMessage(plaintext, roomId, mySenderId) {
        // Use the Double Ratchet for encryption (PFS + PCS)
        if (!this.doubleRatchetActive) {
            throw new Error('Double Ratchet not initialized - cannot encrypt');
        }

        console.log('[CRYPTO] Using Double Ratchet for encryption (PFS + PCS)');
        const result = await this.doubleRatchet.encryptMessage(plaintext, roomId, mySenderId);
        // DoubleRatchet returns {payload, header}
        // Return both for WebSocket message
        return {
            payload: result.payload,
            header: result.header
        };
    }

    /**
     * Decrypts a message with room and sender context verification (anti-replay protection)
     *
     * Uses Signal Protocol Double Ratchet:
     * 1. Checks if header contains a NEW DH public key
     * 2. If new, performs DH ratchet to derive new chains
     * 3. Derives unique message key from receiving chain
     * 4. Decrypts message with ephemeral key
     * 5. Ratchets chain forward (message key becomes irrecoverable - PFS!)
     *
     * @param {string} ciphertextBase64 - Base64 encoded ciphertext
     * @param {Object} header - Message header with DH public key
     * @param {string} roomId - Expected room UUID
     * @param {string} expectedSenderId - Expected sender's connection UUID (from server)
     * @returns {Promise<string>} Decrypted plaintext
     * @throws {Error} If authentication fails or replay attack detected
     */
    async decryptMessage(ciphertextBase64, header, roomId, expectedSenderId) {
        // Use the Double Ratchet for decryption (PFS + PCS)
        if (!this.doubleRatchetActive) {
            throw new Error('Double Ratchet not initialized - cannot decrypt');
        }

        console.log('[CRYPTO] Using Double Ratchet for decryption (PFS + PCS)');
        const envelope = await this.doubleRatchet.decryptMessage(ciphertextBase64, header, roomId, expectedSenderId);
        // DoubleRatchet returns {ts, text}
        // We need to return just the text for compatibility
        return envelope.text;
    }

    /**
     * Calculates SHA-256 hash of encrypted payload (for deduplication)
     * @param {string} ciphertextBase64 - Base64 encoded ciphertext
     * @returns {Promise<string>} Base64 encoded hash
     */
    async hashPayload(ciphertextBase64) {
        const encoder = new TextEncoder();
        const data = encoder.encode(ciphertextBase64);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        return btoa(String.fromCharCode(...hashArray));
    }

    /**
     * Starts periodic cleanup of old message hashes
     */
    startHashCleanup() {
        setInterval(() => {
            this.cleanupOldHashes();
        }, this.HASH_CLEANUP_INTERVAL);
    }

    /**
     * Removes message hashes older than MAX_MESSAGE_AGE
     */
    cleanupOldHashes() {
        const now = Date.now();
        let cleanedCount = 0;

        for (const [hash, ts] of this.hashTimestamps.entries()) {
            if (now - ts > this.MAX_MESSAGE_AGE) {
                this.seenMessageHashes.delete(hash);
                this.hashTimestamps.delete(hash);
                cleanedCount++;
            }
        }

        if (cleanedCount > 0) {
            console.log(`[SECURITY] Cleaned up ${cleanedCount} old message hashes`);
        }
    }

    /**
     * Checks whether the key has been loaded
     * @returns {boolean}
     */
    hasKey() {
        return this.key !== null || this.sessionKey !== null || this.ratchetActive;
    }

    /**
     * Initialize Chain Ratchet with ECDH-derived key material
     *
     * Derives separate sending/receiving chains from session key to prevent
     * KDF collisions between Alice→Bob and Bob→Alice messages.
     *
     * Uses RFC 5869 HKDF with context-bound salt for defense-in-depth against
     * theoretical preimage attacks.
     *
     * @param {Uint8Array} sessionKeyMaterial - 32-byte raw key from ECDH shared secret
     * @param {boolean} isInitiator - Whether this party initiated the handshake
     * @param {string|null} roomId - Room identifier for salt binding (optional but recommended)
     * @param {string|null} userId - User identifier for salt binding (optional but recommended)
     * @param {string|null} otherUserId - Other party's user identifier (optional but recommended)
     */
    async initializeChainRatchet(sessionKeyMaterial, isInitiator, roomId = null, userId = null, otherUserId = null) {
        console.log('[CRYPTO] Initializing Chain Ratchet for Perfect Forward Secrecy...');
        console.log(`[CRYPTO] Role: ${isInitiator ? 'Initiator' : 'Responder'}`);

        if (!(sessionKeyMaterial instanceof Uint8Array) || sessionKeyMaterial.length !== 32) {
            throw new Error('Session key material must be 32 bytes');
        }

        // Generate context-bound salt for HKDF (defense-in-depth)
        // Binds chain keys to specific room and participant pair
        let salt = null;
        if (roomId && userId && otherUserId) {
            // Sort user IDs to ensure both parties compute identical salt
            const sortedUserIds = [userId, otherUserId].sort();
            const saltContext = `PinChat-ChainRatchet-v1-${roomId}-${sortedUserIds[0]}-${sortedUserIds[1]}`;
            const saltInput = new TextEncoder().encode(saltContext);
            const saltBuffer = await crypto.subtle.digest('SHA-256', saltInput);
            salt = new Uint8Array(saltBuffer);
            console.log('[CRYPTO] Using context-bound salt for HKDF (roomId + participant IDs)');
        } else {
            console.log('[CRYPTO] Using default all-zero salt for HKDF (RFC 5869 compliant)');
        }

        // Role-based chain derivation for perfect symmetry:
        // - Initiator sends with "InitiatorToResponder" and receives with "ResponderToInitiator"
        // - Responder sends with "ResponderToInitiator" and receives with "InitiatorToResponder"
        // This ensures: Alice's sendingChain === Bob's receivingChain (and vice versa)

        const sendingLabel = isInitiator ? 'InitiatorToResponder' : 'ResponderToInitiator';
        const receivingLabel = isInitiator ? 'ResponderToInitiator' : 'InitiatorToResponder';

        const sendingKeyMaterial = await this.hkdf(
            sessionKeyMaterial,
            sendingLabel,
            32,
            salt  // Context-bound salt
        );

        const receivingKeyMaterial = await this.hkdf(
            sessionKeyMaterial,
            receivingLabel,
            32,
            salt  // Same salt for both chains
        );

        await this.sendingChain.initialize(sendingKeyMaterial);
        await this.receivingChain.initialize(receivingKeyMaterial);

        this.ratchetActive = true;

        console.log('[CRYPTO] ✅ Chain Ratchet active (Perfect Forward Secrecy enabled)');
    }

    /**
     * Initialize Double Ratchet with ECDH-derived key material (Signal Protocol)
     *
     * Provides both Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS)
     * through combination of DH ratchet and symmetric ratchet.
     *
     * Signal Protocol: Pass the ECDH keypairs so the DH ratchet can use them
     * for initial state. This is required for automatic ratchet on receive.
     *
     * @param {Object} identityManager - IdentityKeyManager instance for signing
     * @param {Uint8Array} sessionKeyMaterial - 32-byte raw key from ECDH shared secret
     * @param {boolean} isInitiator - Whether this party initiated the handshake
     * @param {CryptoKeyPair} myKeypair - Our ECDH keypair from handshake
     * @param {CryptoKey} theirPublicKey - Peer's ECDH public key from handshake
     */
    async initializeDoubleRatchet(identityManager, sessionKeyMaterial, isInitiator, myKeypair = null, theirPublicKey = null) {
        console.log('[CRYPTO] Initializing Double Ratchet for Post-Compromise Security...');
        console.log(`[CRYPTO] Role: ${isInitiator ? 'Initiator' : 'Responder'}`);

        if (!(sessionKeyMaterial instanceof Uint8Array) || sessionKeyMaterial.length !== 32) {
            throw new Error('Session key material must be 32 bytes');
        }

        if (!identityManager) {
            throw new Error('Identity manager required for Double Ratchet');
        }

        // Create DoubleRatchet instance
        this.doubleRatchet = new DoubleRatchet(identityManager);

        // Initialize with shared secret + keypairs for Signal Protocol DH ratchet
        await this.doubleRatchet.initialize(sessionKeyMaterial, isInitiator, myKeypair, theirPublicKey);

        this.doubleRatchetActive = true;

        console.log('[CRYPTO] ✅ Double Ratchet active (PFS + PCS enabled)');
    }

    /**
     * HKDF (HMAC-based Key Derivation Function) - RFC 5869 compliant
     *
     * Uses native Web Crypto API for standards compliance and security best practices.
     * Implements both HKDF-Extract and HKDF-Expand phases with optional salt.
     *
     * @param {Uint8Array} inputKeyMaterial - Input key material (IKM), typically ECDH shared secret
     * @param {string} info - Context string for domain separation (e.g., "InitiatorToResponder")
     * @param {number} length - Output length in bytes (typically 32 for AES-256)
     * @param {Uint8Array|null} salt - Optional salt for HKDF-Extract phase.
     *                                  If null, defaults to all-zeros per RFC 5869 Section 3.3.
     *                                  For defense-in-depth, use context-bound salt (e.g., hash of roomId||connectionId)
     * @returns {Promise<Uint8Array>} Derived key material
     */
    async hkdf(inputKeyMaterial, info, length, salt = null) {
        // Default to all-zero salt (RFC 5869 Section 3.3: "salt is optional")
        if (!salt) {
            salt = new Uint8Array(32);  // 32 bytes for SHA-256 hash length
        }

        // Import IKM as HKDF key for derivation
        const ikmKey = await crypto.subtle.importKey(
            'raw',
            inputKeyMaterial,
            { name: 'HKDF' },
            false,  // Non-extractable
            ['deriveBits']
        );

        // Derive key material using RFC 5869 HKDF
        const infoBytes = new TextEncoder().encode(info);
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: infoBytes
            },
            ikmKey,
            length * 8  // Convert bytes to bits
        );

        return new Uint8Array(derivedBits);
    }

    /**
     * Sets session key (ECDH-derived key for PFS)
     * @param {CryptoKey} sessionKey - AES-256 key derived from ECDH
     * @deprecated Use initializeChainRatchet() instead for true PFS
     */
    setSessionKey(sessionKey) {
        console.log('[CRYPTO] Switching to session key (ECDH-derived)');
        this.sessionKey = sessionKey;
    }

    /**
     * Marks bootstrap key as no longer in use (after ECDH handshake)
     *
     * NOTE: We keep the bootstrap key in memory to allow multiple handshakes
     * (e.g., when a user leaves and rejoins, or during reconnection).
     * The bootstrap key is only used to encrypt/decrypt ECDH public keys,
     * not actual messages (which use the Chain Ratchet).
     *
     * This is a deliberate trade-off:
     * - Messages still have Perfect Forward Secrecy via Chain Ratchet
     * - Handshake can be repeated without re-extracting key from URL
     * - Bootstrap key only protects ECDH public keys (already ephemeral)
     */
    deleteBootstrapKey() {
        console.log('[CRYPTO] Bootstrap key marked as inactive (Chain Ratchet now active)');
        // NOTE: We intentionally do NOT delete this.key to allow re-handshaking
        // this.key = null;  // ← Commented out to support multiple handshakes
    }

    /**
     * Resets to bootstrap key (fallback when PFS ends)
     *
     * Called when participant count drops below 2 in a 1:1 room.
     * Clears the ECDH session key and chain ratchet, falls back to bootstrap key
     * so new handshakes can start from a clean state.
     *
     * IMPORTANT: This prevents DoS where:
     * - User A keeps old sessionKey after User B leaves
     * - User C enters and uses bootstrapKey
     * - Messages become incompatible → permanent DoS
     */
    resetToBootstrapKey() {
        console.log('[CRYPTO] Resetting to bootstrap key (PFS ended, waiting for new handshake)');

        // Reset chain ratchet
        this.sendingChain.reset();
        this.receivingChain.reset();
        this.ratchetActive = false;

        // Clear legacy session key
        this.sessionKey = null;

        // Keep this.key (bootstrap) - it's still needed for next handshake
    }

    /**
     * Gets the active encryption key (session key if available, otherwise bootstrap key)
     * @returns {CryptoKey}
     */
    getActiveKey() {
        return this.sessionKey || this.key;
    }

    /**
     * Encrypts an image for sending
     *
     * Uses Double Ratchet for encryption, similar to text messages.
     * Image data is packed with metadata (MIME type) before encryption.
     *
     * @param {ArrayBuffer} imageData - Raw image binary data
     * @param {string} mimeType - Image MIME type (e.g., 'image/jpeg')
     * @param {string} roomId - Room UUID for AAD binding
     * @param {string} senderId - Sender's connection UUID
     * @returns {Promise<Object>} Object with {payload, header}
     */
    async encryptImage(imageData, mimeType, roomId, senderId) {
        if (!this.doubleRatchetActive) {
            throw new Error('Double Ratchet not initialized - cannot encrypt');
        }

        console.log('[CRYPTO] Encrypting image with Double Ratchet...');

        // Create image envelope with metadata
        const envelope = {
            type: 'image',
            mimeType: mimeType,
            // Convert ArrayBuffer to base64 for JSON compatibility
            data: this.arrayBufferToBase64(imageData),
            ts: Date.now()
        };

        // Use the existing Double Ratchet encryption
        const envelopeJson = JSON.stringify(envelope);
        const result = await this.doubleRatchet.encryptMessage(envelopeJson, roomId, senderId);

        console.log('[CRYPTO] Image encrypted successfully');

        return {
            payload: result.payload,
            header: result.header
        };
    }

    /**
     * Decrypts an incoming image message
     *
     * @param {string} payloadBase64 - Base64 encoded encrypted payload
     * @param {Object} header - Signal Protocol header
     * @param {string} roomId - Room UUID for AAD verification
     * @param {string} senderId - Sender's connection UUID
     * @returns {Promise<Object>} Object with {data: Uint8Array, mimeType: string}
     */
    async decryptImage(payloadBase64, header, roomId, senderId) {
        if (!this.doubleRatchetActive) {
            throw new Error('Double Ratchet not initialized - cannot decrypt');
        }

        console.log('[CRYPTO] Decrypting image with Double Ratchet...');

        // Use the existing Double Ratchet decryption
        const envelope = await this.doubleRatchet.decryptMessage(payloadBase64, header, roomId, senderId);

        // Parse the envelope (it's the inner JSON with image data)
        // The Double Ratchet returns {ts, text} but for images we encoded the full envelope as 'text'
        const imageEnvelope = JSON.parse(envelope.text);

        if (imageEnvelope.type !== 'image') {
            throw new Error('Expected image message but got: ' + imageEnvelope.type);
        }

        // Convert base64 back to ArrayBuffer
        const imageData = this.base64ToArrayBuffer(imageEnvelope.data);

        console.log('[CRYPTO] Image decrypted successfully');

        return {
            data: imageData,
            mimeType: imageEnvelope.mimeType
        };
    }

    /**
     * Converts ArrayBuffer to base64 string
     * @param {ArrayBuffer} buffer
     * @returns {string}
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * Converts base64 string to Uint8Array
     * @param {string} base64
     * @returns {Uint8Array}
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }
}

// Export a singleton instance
window.cryptoManager = new CryptoManager();
