/**
 * Module for end-to-end encryption/decryption using the WebCrypto API
 */

/**
 * PinChat wire-protocol version. First explicit numbered version.
 * Clients before this release are "v0 implicit" and will be rejected.
 */
const PINCHAT_PROTOCOL_VERSION = 1;
// Browser path: expose to window. Node test harness has no window — the
// Node export block at the bottom of this file mirrors the value onto
// globalThis there. The `typeof` guard keeps both runtimes happy.
if (typeof window !== 'undefined') {
    window.PINCHAT_PROTOCOL_VERSION = PINCHAT_PROTOCOL_VERSION;
}

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
    RATCHET_COUNT: 0x07,  // 8 bytes (BigUint64) - binds ratchet count to ciphertext
    PREVIOUS_CHAIN_LENGTH: 0x08 // 8 bytes (BigUint64) - binds pn to ciphertext
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
    debugLog('[DEBUG-AAD] Encoding fields:', fields.map(f => ({
        type: Object.keys(AAD_FIELD_TYPES).find(k => AAD_FIELD_TYPES[k] === f.type),
        value: f.value
    })));

    for (const field of fields) {
        let valueBytes;

        // Convert value to Uint8Array based on type
        if (field.type === AAD_FIELD_TYPES.TIMESTAMP ||
            field.type === AAD_FIELD_TYPES.MESSAGE_NUMBER ||
            field.type === AAD_FIELD_TYPES.RATCHET_COUNT ||
            field.type === AAD_FIELD_TYPES.PREVIOUS_CHAIN_LENGTH) {
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

        debugLog('[ChainRatchet] Initialized with 32-byte key material');
    }

    /**
     * Return a deep copy of this chain's mutable state.
     * Used by DoubleRatchet to snapshot state before tentative decrypt.
     */
    clone() {
        const c = new ChainRatchet();
        c.chainKeyMaterial = this.chainKeyMaterial ? new Uint8Array(this.chainKeyMaterial) : null;
        c.messageNumber = this.messageNumber;
        return c;
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

        debugLog(`[ChainRatchet] Derived message key #${myCounter}`);

        // Return both key and counter (counter needed for AAD binding)
        return { key: messageKey, counter: myCounter };
    }

    /**
     * Derive message key for a specific counter (used by Double Ratchet for decryption)
     *
     * Derives directly from the current chain position (messageNumber is kept
     * aligned with chainKeyMaterial by the Double Ratchet receive path).
     * Out-of-order tolerance lives one layer up: DoubleRatchet.skipMessageKeys
     * pre-derives and stores the keys of skipped counters in its skippedKeys map.
     *
     * @param {number} counter - Message counter to derive key for
     * @returns {Promise<CryptoKey>} AES-GCM key for this counter
     */
    async deriveMessageKeyForCounter(counter) {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        debugLog(`[ChainRatchet] Deriving key for counter #${counter}`);
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
        debugLog(`[ChainRatchet] Ratcheted forward (counter now at #${this.messageNumber})`);
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
        debugLog('[ChainRatchet] Reset (chain key destroyed)');
    }
}

/**
 * Derive a 32-byte MLS PSK from the raw URL-fragment bytes via HKDF-SHA256.
 *   salt = empty (RFC 5869 default — IKM is already 256 bits of entropy)
 *   info = "PinChat MLS PSK v1" (domain-separation label per RFC 5869 §3.2)
 *
 * Per RFC 5869 the `info` field is the canonical domain-separator across
 * different uses of the same IKM; salts are intended to amplify low-entropy
 * IKM. Our IKM is a freshly-generated 256-bit key, so an empty salt is
 * appropriate.
 *
 * The output is independent of the AES-GCM key the 1:1 ratchet uses, so
 * exposing it as `cryptoManager.mlsPskSecret` doesn't degrade the AES-GCM
 * key's strength. It's the MLS-side binding to the URL invite secret.
 */
async function deriveMlsPsk(rawKeyBytes) {
    const info = new TextEncoder().encode('PinChat MLS PSK v1');
    const ikm = await crypto.subtle.importKey(
        'raw', rawKeyBytes, { name: 'HKDF' }, false, ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
        ikm, 256,
    );
    return new Uint8Array(bits);
}

class CryptoManager {
    constructor() {
        this.key = null;                  // Bootstrap key (from URL)
        this.mlsPskSecret = null;         // 32-byte PSK derived from URL key for MLS
        this.algorithm = {
            name: 'AES-GCM',
            length: 256
        };

        // Signal-inspired Double Ratchet for Post-Compromise Security.
        // The legacy "Chain Ratchet" fields (sendingChain / receivingChain /
        // ratchetActive / sessionKey / seenMessageHashes etc.) that lived
        // on this class predate the Double Ratchet rewrite and are no
        // longer reachable from any caller. They were removed in the
        // hygiene pass; see C-13 in the audit report. The DoubleRatchet
        // is the single source of truth for chain state.
        this.doubleRatchet = null;
        this.doubleRatchetActive = false;

        // Wall-clock guardrails for defence-in-depth against captured
        // ciphertexts that somehow land inside an active skipped-key
        // window. The Double Ratchet's monotone counter is the primary
        // anti-replay; these are belt-and-braces.
        this.MAX_MESSAGE_AGE = 5 * 60 * 1000;      // 5 minutes
        this.FUTURE_TOLERANCE = 30 * 1000;          // 30 seconds (clock skew)
    }

    /**
     * Extracts the key from the URL fragment, then promotes the fragment
     * to sessionStorage and scrubs the URL bar (C-06).
     *
     * Sources, in priority order:
     *   1. window.location.hash — initial page load via the invite link.
     *   2. sessionStorage[`pinchat_hash:${pathname}`] — post-login restore
     *      (login-stash.js / websocket.js / homepage.js) AND in-tab re-reads
     *      after C-06 has already scrubbed the URL on a previous call.
     *
     * After a successful import the raw fragment bytes are written back to
     * sessionStorage and the URL is rewritten via history.replaceState() to
     * remove `#key=...`. Rationale: keeping the bootstrap secret in
     * window.location.hash for the entire chat session means any same-origin
     * script (extension, popup, devtools observer) can read it directly, and
     * the URL bar becomes a leak vector during screen-sharing. sessionStorage
     * is tab-scoped, auto-cleared on tab close, and not visible in the URL.
     *
     * @returns {Promise<CryptoKey|null>}
     */
    async extractKeyFromURL() {
        const stashKey = `pinchat_hash:${window.location.pathname}`;

        // Priority 1: the URL fragment.
        let fragment = window.location.hash.substring(1);

        // Priority 2: sessionStorage stash (login-stash.js, in-tab re-read,
        // or websocket.js's 401-bounce path). We intentionally do NOT
        // remove the stash here — the post-import block below rewrites it
        // anyway, and leaving it in place during the import phase means a
        // crash before the rewrite still keeps the secret recoverable.
        if (!fragment) {
            const saved = sessionStorage.getItem(stashKey);
            if (saved) {
                fragment = saved.startsWith('#') ? saved.substring(1) : saved;
            }
        }

        const params = new URLSearchParams(fragment);
        let keyBase64 = params.get('key');

        if (!keyBase64) {
            debugError('No encryption key found in URL or sessionStorage');
            return null;
        }

        try {
            // Convert Base64url to standard Base64 if needed
            // Detect Base64url format (contains '-' or '_' instead of '+' or '/')
            if (keyBase64.includes('-') || keyBase64.includes('_')) {
                debugLog('Detected Base64url format, converting to standard Base64');
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

            // Derive a 32-byte PSK from the URL fragment for the MLS key
            // schedule. We HKDF-Extract with a domain-separation salt so
            // this output is independent of the AES-GCM key used by the
            // 1:1 ratchet path. Without this, a relay (or any party who
            // can talk to the room before legitimate joiners) could
            // bootstrap their own MLS group inside the same room, since
            // MLS itself doesn't otherwise know the URL fragment exists.
            this.mlsPskSecret = await deriveMlsPsk(keyBuffer);

            // C-06: Move the bootstrap secret out of window.location.hash
            // and into sessionStorage. The key remains recoverable across
            // reloads (sessionStorage persists for the tab) and across
            // resetToBootstrapKey() calls, but it is no longer visible in
            // the URL bar, browser history, or to any code reading
            // window.location.hash.
            try {
                sessionStorage.setItem(stashKey, '#' + fragment);
            } catch (_) {
                // Storage full / disabled: keep the fragment in URL as a
                // fallback. Functional, just less private.
            }
            if (window.location.hash) {
                try {
                    history.replaceState(
                        null,
                        '',
                        window.location.pathname + window.location.search
                    );
                } catch (_) {
                    /* replaceState unavailable: best-effort */
                }
            }

            debugLog('✅ Encryption key loaded successfully');
            return this.key;

        } catch (error) {
            debugError('Failed to load encryption key:', error);
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
            false,  // non-extractable: XSS cannot export raw bytes after fragment is cleared
            ['encrypt', 'decrypt']
        );
        return this.key;
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

        debugLog('[CRYPTO] Using Double Ratchet for encryption (PFS + PCS)');
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

        debugLog('[CRYPTO] Using Double Ratchet for decryption (PFS + PCS)');
        const envelope = await this.doubleRatchet.decryptMessage(ciphertextBase64, header, roomId, expectedSenderId);

        // Defence-in-depth timestamp window. The Double Ratchet's counter
        // already rejects in-session replays, but a captured ciphertext that
        // somehow lands inside a current skipped-key window still must respect
        // the wall-clock guardrail: a message older than MAX_MESSAGE_AGE or
        // farther in the future than FUTURE_TOLERANCE indicates either a
        // stale replay across reconnects or clock manipulation.
        if (typeof envelope.ts === 'number') {
            const now = Date.now();
            const age = now - envelope.ts;
            if (age > this.MAX_MESSAGE_AGE) {
                throw new Error('REPLAY_TOO_OLD');
            }
            if (age < -this.FUTURE_TOLERANCE) {
                throw new Error('REPLAY_FUTURE');
            }
        }

        // DoubleRatchet returns {ts, text} plus the receiver-only `_outOfOrder`
        // flag set when (ratchetCount, messageNumber) was below the highest
        // tuple already decrypted. We surface that flag to the app layer so
        // late arrivals can be visually marked.
        return { text: envelope.text, outOfOrder: envelope._outOfOrder === true };
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
        debugLog('[CRYPTO] Initializing Double Ratchet for Post-Compromise Security...');
        debugLog(`[CRYPTO] Role: ${isInitiator ? 'Initiator' : 'Responder'}`);

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

        debugLog('[CRYPTO] ✅ Double Ratchet active (PFS + PCS enabled)');
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
     * Drop the bootstrap key reference after handshake completion (protocol v1).
     *
     * PFS hardening: previously this method was a no-op to support re-handshaking
     * without re-reading the URL fragment. That kept the AES-GCM key alive in
     * memory for the entire session, which meant a later client compromise
     * could re-derive handshake material. Now we null the reference; re-handshake
     * goes through `resetToBootstrapKey()` which re-extracts from the URL fragment.
     */
    deleteBootstrapKey() {
        debugLog('[CRYPTO] Dropping bootstrap key reference (v1 hardening)');
        this.key = null;
        if (this.mlsPskSecret) {
            this.mlsPskSecret.fill(0);
            this.mlsPskSecret = null;
        }
    }

    /**
     * Full reset of ratchet state and re-extraction of the bootstrap key.
     *
     * Tears down the live Double Ratchet instance (the only ratchet at
     * runtime — the legacy single-chain path was removed in the C-13
     * hygiene pass) and re-reads the bootstrap key from the URL fragment
     * or sessionStorage. Throws BOOTSTRAP_KEY_LOST when neither source
     * has it any more so the caller can surface "re-open the room link"
     * instead of starting a handshake without a bootstrap key.
     *
     * @throws {Error} 'BOOTSTRAP_KEY_LOST' if the URL fragment / sessionStorage stash is missing.
     */
    async resetToBootstrapKey() {
        debugLog('[CRYPTO] Full reset → re-extract bootstrap key');

        if (this.doubleRatchet) {
            this.doubleRatchet.destroy();
            this.doubleRatchet = null;
        }
        this.doubleRatchetActive = false;

        // Re-extract bootstrap key. extractKeyFromURL handles both the URL
        // fragment and the sessionStorage stash (post-login restore + C-06
        // in-tab persistence after the URL bar has been scrubbed).
        const reExtracted = await this.extractKeyFromURL();
        if (!reExtracted) {
            throw new Error('BOOTSTRAP_KEY_LOST');
        }
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

        debugLog('[CRYPTO] Encrypting image with Double Ratchet...');

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
        const result = await this.doubleRatchet.encryptMessage(envelopeJson, roomId, senderId, 'image');

        debugLog('[CRYPTO] Image encrypted successfully');

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

        debugLog('[CRYPTO] Decrypting image with Double Ratchet...');

        // Use the existing Double Ratchet decryption
        const envelope = await this.doubleRatchet.decryptMessage(payloadBase64, header, roomId, senderId, 'image');

        // Apply the same timestamp window as text messages: late replays
        // captured across reconnects must still be rejected even if the
        // Double Ratchet counter slot happens to be available.
        if (typeof envelope.ts === 'number') {
            const now = Date.now();
            const age = now - envelope.ts;
            if (age > this.MAX_MESSAGE_AGE) {
                throw new Error('REPLAY_TOO_OLD');
            }
            if (age < -this.FUTURE_TOLERANCE) {
                throw new Error('REPLAY_FUTURE');
            }
        }

        // Parse the envelope (it's the inner JSON with image data)
        // The Double Ratchet returns {ts, text} but for images we encoded the full envelope as 'text'
        const imageEnvelope = JSON.parse(envelope.text);

        if (imageEnvelope.type !== 'image') {
            throw new Error('Expected image message but got: ' + imageEnvelope.type);
        }

        // Convert base64 back to ArrayBuffer
        const imageData = this.base64ToArrayBuffer(imageEnvelope.data);

        debugLog('[CRYPTO] Image decrypted successfully');

        return {
            data: imageData,
            mimeType: imageEnvelope.mimeType,
            outOfOrder: envelope._outOfOrder === true
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

// Expose globally (browser) or via CommonJS (Node test harness).
// Under Node we ALSO promote AAD_FIELD_TYPES, encodeAADWithLengthPrefix and
// ChainRatchet to globalThis because the browser path relies on top-level
// `const` declarations being visible across <script> files. Without this,
// requiring double-ratchet.js after crypto.js would fail at runtime with
// `AAD_FIELD_TYPES is not defined`.
if (typeof module !== 'undefined' && module.exports) {
    globalThis.AAD_FIELD_TYPES = AAD_FIELD_TYPES;
    globalThis.encodeAADWithLengthPrefix = encodeAADWithLengthPrefix;
    globalThis.ChainRatchet = ChainRatchet;
    module.exports = {
        CryptoManager,
        ChainRatchet,
        AAD_FIELD_TYPES,
        encodeAADWithLengthPrefix,
        base64ToBase64url,
        base64urlToBase64,
    };
} else {
    window.cryptoManager = new CryptoManager();
}
