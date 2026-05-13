/**
 * ECDH Key Exchange Manager for Perfect Forward Secrecy
 *
 * Implements hybrid encryption:
 * 1. Bootstrap key (from URL) encrypts ECDH public key exchange
 * 2. Session key derived from ECDH shared secret
 * 3. Bootstrap key deleted after handshake
 *
 * Security guarantee: Even if bootstrap key compromised later,
 * historical messages remain secure (ECDH private keys ephemeral).
 */

class ECDHKeyExchange {
    constructor(bootstrapKey, identityManager) {
        this.bootstrapKey = bootstrapKey;       // From URL fragment (AES-256 key)
        this.identityManager = identityManager; // Identity key manager (ECDSA)
        this.keyPair = null;                    // ECDH keypair (P-256)
        this.otherPublicKey = null;             // Other participant's public key
        this.sessionKey = null;                 // Derived AES-256 key for messages
        this.handshakeComplete = false;
        this.handshakeTimeout = null;
        this.keysDestroyed = false;             // Flag to prevent key re-use after destruction

        // Context data for SAS generation (stored during handshake)
        this.myNonce = null;                    // Our nonce (sent during handshake)
        this.myTimestamp = null;                // Our timestamp (sent during handshake)
        this.otherNonce = null;                 // Other participant's nonce
        this.otherTimestamp = null;             // Other participant's timestamp

        // Configuration
        this.HANDSHAKE_TIMEOUT_MS = 30000;      // 30 seconds

        // Curve Selection: P-256 (NIST P-256, secp256r1)
        //
        // SECURITY NOTE: X25519 (Curve25519) would be preferred for:
        // - Simpler implementation (Montgomery curve, no point compression concerns)
        // - Constant-time guarantees (more resistant to timing side-channel attacks)
        // - Better performance on some platforms
        // - Used by Signal Protocol, WireGuard, TLS 1.3
        //
        // However, Web Crypto API does NOT natively support X25519 for ECDH.
        // Using X25519 would require external libraries (libsodium.js, tweetnacl.js),
        // adding ~100KB+ dependency and attack surface.
        //
        // P-256 is secure, widely supported, and avoids external dependencies.
        // Future consideration: migrate to X25519 if/when Web Crypto API adds support.
        this.CURVE = 'P-256';

        // SAS Emoji Alphabet (64 emoji = 6 bits per emoji)
        // Carefully curated for visual distinctiveness and platform compatibility
        this.EMOJI_ALPHABET = [
            // Animali (16)
            '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼',
            '🐨', '🐯', '🦁', '🐮', '🐷', '🐸', '🐵', '🐔',
            // Natura (16)
            '🌸', '🌺', '🌻', '🌷', '🌹', '🌲', '🌴', '🌵',
            '🍀', '🌿', '🍄', '🌾', '⭐', '🌟', '✨', '💫',
            // Oggetti (16)
            '⚽', '🏀', '🎯', '🎨', '🎭', '🎪', '🎸', '🎹',
            '🎺', '🎻', '🎮', '🎲', '🎰', '🏆', '🎁', '🎈',
            // Simboli (16) - using single-codepoint emoji only (no variation selectors)
            '🔥', '💧', '⚡', '🌞', '🌙', '🌈', '⛅', '🧊',
            '💎', '🔑', '🔒', '🔓', '🚀', '🛸', '⚓', '🎡'
        ];
    }

    /**
     * Generate ECDH keypair (P-256)
     * @returns {Promise<CryptoKeyPair>}
     */
    async generateKeypair() {
        debugLog('[ECDH] Generating P-256 keypair...');

        this.keyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: this.CURVE
            },
            false,  // Not extractable (ephemeral, RAM-only)
            ['deriveKey', 'deriveBits']  // Add 'deriveBits' for Chain Ratchet raw key export
        );

        debugLog('[ECDH] ✅ Keypair generated (ephemeral)');
        return this.keyPair;
    }

    /**
     * Export public key and encrypt it with bootstrap key + AAD context binding
     *
     * SIGNAL PROTOCOL ENHANCEMENT:
     * - Includes identity public key for long-term authentication
     * - Signs ephemeral public key with identity private key (MITM protection)
     *
     * SECURITY: AAD prevents cross-context replay attacks by binding the
     * encrypted public key to a specific room, sender, and session.
     *
     * @param {string} roomId - Room identifier (prevents cross-room replay)
     * @param {string} myConnectionId - Sender's connection/user ID (prevents impersonation)
     * @returns {Promise<Object>} Object with {encryptedKey, identityPublicKey, signature, timestamp, nonce}
     */
    async encryptPublicKey(roomId, myConnectionId) {
        if (!this.keyPair) {
            throw new Error('ECDH keypair not generated');
        }

        if (!this.identityManager || !this.identityManager.identityKeyPair) {
            throw new Error('Identity manager not initialized');
        }

        if (!roomId || !myConnectionId) {
            throw new Error('roomId and myConnectionId required for AAD binding');
        }

        debugLog('[ECDH] Exporting and encrypting public key with AAD context binding...');
        debugLog(`[ECDH] Context: roomId=${roomId}, myConnectionId=${myConnectionId}`);

        // Export ephemeral public key to raw format
        const publicKeyRaw = await crypto.subtle.exportKey(
            'raw',
            this.keyPair.publicKey
        );

        // Sign the ephemeral public key with the identity private key
        debugLog('[ECDH] Signing ephemeral public key with identity key...');
        const signature = await this.identityManager.sign(publicKeyRaw);
        debugLog('[ECDH] ✅ Ephemeral key signed (MITM protection active)');

        // Export the identity public key alongside the ephemeral material
        const identityPublicKeyRaw = await this.identityManager.exportIdentityPublicKey();

        // Generate IV for AES-GCM encryption
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // Generate nonce (16 bytes) for session uniqueness
        const nonce = crypto.getRandomValues(new Uint8Array(16));

        // Generate timestamp (milliseconds since epoch)
        const timestamp = Date.now();

        // Create AAD: roomId + myConnectionId + timestamp + nonce
        // This binds the encrypted key to a specific context
        //
        // SECURITY: TLV encoding prevents parsing ambiguity
        // Without length prefixes, different field splits could produce
        // the same binary output, enabling cross-context replay attacks
        const aad = encodeAADWithLengthPrefix([
            {type: AAD_FIELD_TYPES.ROOM_ID, value: roomId},
            {type: AAD_FIELD_TYPES.SENDER_ID, value: myConnectionId},
            {type: AAD_FIELD_TYPES.TIMESTAMP, value: timestamp},
            {type: AAD_FIELD_TYPES.NONCE, value: nonce}
        ]);

        debugLog(`[ECDH] AAD length: ${aad.length} bytes (TLV-encoded: roomId + connectionId + timestamp + nonce)`);

        // Encrypt public key with bootstrap key + AAD
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: aad  // Context binding for the encrypted key
            },
            this.bootstrapKey,
            publicKeyRaw
        );

        // Combine IV + ciphertext
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        // Encode to Base64url
        const encryptedKey = this.arrayBufferToBase64url(combined);
        const identityPublicKey = this.arrayBufferToBase64url(identityPublicKeyRaw);
        const signatureBase64 = this.arrayBufferToBase64url(signature);

        // Store our context data for SAS generation
        this.myTimestamp = timestamp;
        this.myNonce = this.arrayBufferToBase64url(nonce);

        // Return object with all context information needed for decryption
        const result = {
            encryptedKey: encryptedKey,
            identityPublicKey: identityPublicKey,
            signature: signatureBase64,
            timestamp: timestamp,
            nonce: this.myNonce
        };

        debugLog('[ECDH] ✅ Public key encrypted with AAD binding + identity key + signature');
        debugLog(`[ECDH] Timestamp: ${timestamp}, Nonce: ${result.nonce.substring(0, 16)}...`);
        debugLog(`[ECDH] Identity public key: ${identityPublicKey.substring(0, 20)}...`);

        return result;
    }

    /**
     * Decrypt other participant's public key using bootstrap key + AAD validation
     *
     * SIGNAL PROTOCOL ENHANCEMENT:
     * - Verifies signature on ephemeral key using peer's identity key
     * - Imports peer's identity key for future ratchet verification
     *
     * SECURITY: Validates AAD to prevent cross-context replay attacks.
     * Ensures the encrypted key was intended for this specific room, sender, and session.
     *
     * @param {string} encryptedPublicKey - Base64url-encoded encrypted public key
     * @param {string} expectedRoomId - Expected room identifier
     * @param {string} senderConnectionId - Sender's connection/user ID
     * @param {number} timestamp - Timestamp from sender (ms since epoch)
     * @param {string} nonceBase64url - Base64url-encoded nonce from sender
     * @param {string} identityPublicKeyBase64 - Peer's identity public key (Base64url)
     * @param {string} signatureBase64 - Signature on the ephemeral key (Base64url)
     * @returns {Promise<CryptoKey>}
     */
    async decryptPublicKey(encryptedPublicKey, expectedRoomId, senderConnectionId, timestamp, nonceBase64url, identityPublicKeyBase64, signatureBase64) {
        if (!expectedRoomId || !senderConnectionId || !timestamp || !nonceBase64url) {
            throw new Error('AAD validation requires: expectedRoomId, senderConnectionId, timestamp, nonce');
        }

        // Validate identity key and signature parameters before decryption
        if (!identityPublicKeyBase64 || !signatureBase64) {
            throw new Error('Signal Protocol requires: identityPublicKey, signature');
        }

        debugLog('[ECDH] Decrypting other public key with AAD validation...');
        debugLog(`[ECDH] Expected context: roomId=${expectedRoomId}, sender=${senderConnectionId}`);
        debugLog(`[ECDH] Timestamp: ${timestamp}, Nonce: ${nonceBase64url.substring(0, 16)}...`);

        // Import peer's identity public key for signature verification
        debugLog('[ECDH] Importing peer identity public key...');
        const identityPublicKeyRaw = this.base64urlToArrayBuffer(identityPublicKeyBase64);
        await this.identityManager.importPeerIdentityPublicKey(identityPublicKeyRaw);
        debugLog('[ECDH] ✅ Peer identity public key imported');

        // SECURITY: Validate timestamp freshness (max 60 seconds age)
        const now = Date.now();
        const age = now - timestamp;
        const MAX_AGE_MS = 60000;  // 60 seconds
        const FUTURE_TOLERANCE_MS = 30000;  // 30 seconds tolerance for clock skew

        if (age < -FUTURE_TOLERANCE_MS) {
            throw new Error(`ECDH timestamp is too far in the future (clock skew: ${-age}ms, max: ${FUTURE_TOLERANCE_MS}ms) - possible replay attack`);
        }

        if (age > MAX_AGE_MS) {
            throw new Error(`ECDH timestamp too old (age: ${age}ms, max: ${MAX_AGE_MS}ms) - possible replay attack`);
        }

        debugLog(`[ECDH] ✅ Timestamp freshness validated (age: ${age}ms)`);

        // Decode nonce from Base64url
        const nonce = this.base64urlToArrayBuffer(nonceBase64url);

        // Store other participant's context data for SAS generation
        this.otherTimestamp = timestamp;
        this.otherNonce = nonceBase64url;

        // Reconstruct AAD using the SAME process as encryption
        // AAD = roomId + senderConnectionId + timestamp + nonce
        //
        // SECURITY: TLV encoding prevents parsing ambiguity
        // Must exactly match the encoding used during encryption
        const aad = encodeAADWithLengthPrefix([
            {type: AAD_FIELD_TYPES.ROOM_ID, value: expectedRoomId},
            {type: AAD_FIELD_TYPES.SENDER_ID, value: senderConnectionId},
            {type: AAD_FIELD_TYPES.TIMESTAMP, value: timestamp},
            {type: AAD_FIELD_TYPES.NONCE, value: nonce}
        ]);

        debugLog(`[ECDH] AAD reconstructed (${aad.length} bytes, TLV-encoded)`);

        // Decode from Base64url
        const combined = this.base64urlToArrayBuffer(encryptedPublicKey);

        // Extract IV and ciphertext
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        // Decrypt with bootstrap key + AAD validation
        // If AAD doesn't match, AES-GCM will throw authentication error
        let publicKeyRaw;
        try {
            publicKeyRaw = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    additionalData: aad  // ← SECURITY: AAD must match encryption context
                },
                this.bootstrapKey,
                ciphertext
            );
            debugLog('[ECDH] ✅ AAD validation passed (context matches)');
        } catch (error) {
            debugError('[ECDH] ❌ AAD validation failed:', error);
            throw new Error('ECDH AAD validation failed - possible cross-context replay attack or wrong room/sender');
        }

        // Verify the signature on the ephemeral public key
        // This is the CRITICAL MITM detection step - if signature verification fails,
        // an attacker has attempted to substitute the ephemeral key
        debugLog('[ECDH] Verifying signature on ephemeral public key...');
        const signature = this.base64urlToArrayBuffer(signatureBase64);

        try {
            await this.identityManager.verify(publicKeyRaw, signature);
            debugLog('[ECDH] ✅ Signature verified - ephemeral key authenticated (MITM protection)');
        } catch (error) {
            debugError('[ECDH] ❌ SIGNATURE VERIFICATION FAILED:', error);
            throw new Error('🚨 MITM ATTACK DETECTED - Ephemeral key signature is invalid');
        }

        // Import the peer's ephemeral ECDH public key.
        // extractable=true: the Double Ratchet needs the raw bytes for DHrRaw
        // (key-ID construction + ratchet-change detection). Public keys are not
        // secret material, so making them extractable does not weaken PFS.
        this.otherPublicKey = await crypto.subtle.importKey(
            'raw',
            publicKeyRaw,
            {
                name: 'ECDH',
                namedCurve: this.CURVE
            },
            true,
            []
        );

        debugLog('[ECDH] ✅ Other public key decrypted and imported');
        return this.otherPublicKey;
    }

    /**
     * Derive session key material from ECDH shared secret
     *
     * Returns raw key material (Uint8Array) instead of CryptoKey to enable
     * Chain Ratchet initialization with separate sending/receiving chains.
     *
     * SECURITY: This method can only be called ONCE. After destroyEphemeralKeys()
     * is called, attempting to re-derive the session key will fail, preventing
     * session key re-derivation attacks.
     *
     * @returns {Promise<Uint8Array>} 32-byte session key material
     * @throws {Error} If keys have been destroyed (PFS requirement)
     */
    async deriveSessionKey() {
        if (this.keysDestroyed) {
            throw new Error('[ECDH] Cannot derive session key - ephemeral keys have been destroyed (PFS requirement)');
        }

        if (!this.keyPair || !this.otherPublicKey) {
            throw new Error('ECDH keypair or other public key missing');
        }

        debugLog('[ECDH] Deriving session key material from shared secret...');

        // Derive shared secret using ECDH (as raw bits, not CryptoKey)
        const sharedSecretBits = await crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: this.otherPublicKey
            },
            this.keyPair.privateKey,
            256  // 256 bits = 32 bytes
        );

        // Convert to Uint8Array for Chain Ratchet initialization
        const sessionKeyMaterial = new Uint8Array(sharedSecretBits);

        this.handshakeComplete = true;

        debugLog('[ECDH] ✅ Session key material derived (32 bytes)');
        debugLog('[ECDH] 🔐 Ready for Chain Ratchet initialization');

        return sessionKeyMaterial;
    }

    /**
     * Drop the bootstrap key reference after handshake completion (protocol v1).
     *
     * Previously this was a no-op to support re-handshaking without re-reading
     * the URL fragment. v1 hardening: we null the reference. Re-handshake is
     * driven from CryptoManager.resetToBootstrapKey() which rebuilds an
     * ECDHKeyExchange with a freshly-extracted bootstrap key.
     */
    deleteBootstrapKey() {
        debugLog('[ECDH] Dropping bootstrap key reference (v1 hardening)');
        this.bootstrapKey = null;
    }

    /**
     * Destroy ephemeral ECDH keys after Chain Ratchet initialization
     *
     * CRITICAL SECURITY: This method MUST be called immediately after Chain Ratchet
     * initialization to prevent session key re-derivation attacks. Without this,
     * any code with page access (XSS, malicious extensions) can:
     * 1. Call deriveSessionKey() to regenerate session material
     * 2. Initialize identical Chain Ratchet state
     * 3. Decrypt all past and future messages
     *
     * By destroying these keys, we ensure true Perfect Forward Secrecy:
     * - Session key cannot be re-derived
     * - Chain Ratchet state cannot be replicated
     * - Historical messages remain secure even if page is compromised
     *
     * @throws {Error} If called before handshake completion
     */
    destroyEphemeralKeys() {
        if (!this.handshakeComplete) {
            throw new Error('[ECDH] Cannot destroy keys before handshake completion');
        }

        debugLog('[ECDH] 🔥 Destroying ephemeral keys (PFS requirement)');

        // Nullify ECDH keypair (prevents session key re-derivation)
        this.keyPair = null;
        this.otherPublicKey = null;

        // Clear handshake context data (no longer needed)
        this.myNonce = null;
        this.myTimestamp = null;
        this.otherNonce = null;
        this.otherTimestamp = null;

        // Mark as destroyed to prevent accidental re-use
        this.keysDestroyed = true;

        debugLog('[ECDH] ✅ Ephemeral keys destroyed - PFS guaranteed');
    }

    /**
     * Encode bytes to emoji using 64-emoji alphabet (6 bits per emoji)
     * Uses BigInt to avoid JavaScript's 32-bit overflow in bitwise operations.
     *
     * Emoji count = floor(bytes.length * 8 / 6). For 9 input bytes (72 bits)
     * this is 12 emoji — the v2 SAS layout. The pre-v2 path used 6 input
     * bytes / 8 emoji; the encoding is the same algorithm, just shorter.
     *
     * @param {Uint8Array} bytes - Input bytes (length × 8 must be a multiple of 6)
     * @returns {string} Emoji string of bytes.length × 8 / 6 emoji
     */
    encodeToEmoji(bytes) {
        // Convert bytes to BigInt to avoid 32-bit overflow
        let value = 0n;
        for (const byte of bytes) {
            value = (value << 8n) | BigInt(byte);
        }

        const emojiCount = Math.floor((bytes.length * 8) / 6);
        let result = '';
        for (let i = emojiCount - 1; i >= 0; i--) {
            const index = Number((value >> (BigInt(i) * 6n)) & 0x3Fn);
            result += this.EMOJI_ALPHABET[index];
        }

        return result;
    }

    /**
     * Encode bytes to hexadecimal string with dashes
     * @param {Uint8Array} bytes - Input bytes
     * @returns {string} Hex string (e.g., "AB-CD-EF-12-34-56-78")
     */
    encodeToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).toUpperCase().padStart(2, '0'))
            .join('-');
    }

    /**
     * Generate Short Authentication String (SAS) for MITM detection — v2.
     *
     * SAS is a function of (sorted identity public keys, room id) only:
     *   IKM   = sorted(IK_A_raw || IK_B_raw)        — high-entropy public material
     *   salt  = roomId || "pinchat-sas-v2"          — fixed for the room
     *   info  = "SAS-display-v2"                    — domain separation
     *   bits  = 72                                  — 12 emoji × 6 bits
     *
     * Construction is HKDF-SHA256 via WebCrypto. This replaces the pre-v0.3.0
     * PBKDF2-SHA256-100K-with-per-handshake-salt path. Audit-3 M-02 was
     * correct: PBKDF2 is a password-stretcher for low-entropy human inputs.
     * SAS inputs are not passwords. HKDF is the natural keyed-PRF construction
     * for deriving display bytes from high-entropy public material plus
     * domain context. The 100K iterations were not buying any security
     * property — they were paying ~30-100ms per derivation for nothing.
     *
     * Why the new salt drops nonces/timestamps:
     *   The pre-v0.3.0 salt incorporated `myNonce`, `otherNonce`,
     *   `myTimestamp`, `otherTimestamp` from the current handshake. These
     *   are fresh per handshake, so the SAS was fresh per handshake.
     *   Users saw a different emoji code every reconnect, learned to skip
     *   verification, and the C-04 fix (identity persistence) did not
     *   deliver the "stable SAS" property it was supposed to. v2 makes the
     *   SAS a function of (IK_A, IK_B, room_id) only — stable for the
     *   identity TTL, so "verify once" is honest.
     *
     * Why 72 bits:
     *   At 48 bits a real-time MITM grinder on a single RTX-4090-class GPU
     *   needs ~10 minutes to find a SAS collision (computing PBKDF2-100K
     *   was ~250 K/s — the iteration count was the only friction left).
     *   With HKDF the per-derivation cost drops to ~µs, so the only
     *   defence against grinding is output width. 72 bits / 12 emoji
     *   lifts collision-search to days-weeks on commodity hardware.
     *
     * Interop: pre-v0.3.0 clients use PBKDF2-100K + 48-bit + per-handshake
     * salt. Mixed-version chats will display different codes on each side —
     * users should update both endpoints. This is a one-time UX blip
     * during the v0.2.x → v0.3.0 transition, and the new design eliminates
     * the recurring instability that motivated the change.
     *
     * @param {string} roomId - Room identifier for context binding
     * @returns {Promise<Object>} Object with emoji, hex, bits, version
     * @throws {Error} If identity keys are not available
     */
    async generateSAS(roomId) {
        if (!this.identityManager || !this.identityManager.identityKeyPair) {
            throw new Error('[ECDH] Cannot generate SAS - identity keypair not available');
        }

        if (!this.identityManager.peerIdentityPublicKey) {
            throw new Error('[ECDH] Cannot generate SAS - peer identity public key not available');
        }

        if (!roomId) {
            throw new Error('roomId required for SAS context binding');
        }

        debugLog('[ECDH] Generating SAS v2 (HKDF-SHA256, 72 bits, stable salt)...');

        // Export own identity public key (CryptoKey is intentionally extractable
        // for transmission to the peer). Peer's key was imported as
        // non-extractable, but the raw bytes were cached at import time, so we
        // read them directly from the identity manager — never via exportKey.
        const myPublicKeyRaw = await crypto.subtle.exportKey('raw', this.identityManager.identityKeyPair.publicKey);
        const myKeyBytes = new Uint8Array(myPublicKeyRaw);
        const otherKeyBytes = new Uint8Array(this.identityManager.peerIdentityPublicKeyRaw);

        // Sort public keys lexicographically so both parties feed the same
        // bytes into HKDF regardless of which side they're on. The sort key
        // is the full byte string; equal-length P-256 raw exports (65 bytes
        // each) make this a clean lexicographic order.
        const keys = [myKeyBytes, otherKeyBytes].sort((a, b) => {
            for (let i = 0; i < Math.min(a.length, b.length); i++) {
                if (a[i] !== b[i]) return a[i] - b[i];
            }
            return a.length - b.length;
        });

        const ikm = new Uint8Array(keys[0].length + keys[1].length);
        ikm.set(keys[0], 0);
        ikm.set(keys[1], keys[0].length);

        // Salt = roomId || "pinchat-sas-v2"
        // The literal tag domain-separates the SAS derivation from any other
        // HKDF use of these same identity keys (e.g. future safety-number
        // computations or alternative display formats). Both pieces are
        // public, both are fixed for the room, both peers compute the same
        // salt — that is the entire point of v2.
        const encoder = new TextEncoder();
        const roomIdBytes = encoder.encode(roomId);
        const tagBytes = encoder.encode('pinchat-sas-v2');
        const salt = new Uint8Array(roomIdBytes.length + tagBytes.length);
        salt.set(roomIdBytes, 0);
        salt.set(tagBytes, roomIdBytes.length);

        const info = encoder.encode('SAS-display-v2');

        const baseKey = await crypto.subtle.importKey(
            'raw',
            ikm,
            'HKDF',
            false,
            ['deriveBits']
        );

        // 72 bits = 9 bytes = 12 emoji × 6 bits
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: info
            },
            baseKey,
            72
        );

        const sasBytes = new Uint8Array(derivedBits);

        const sasObject = {
            emoji: this.encodeToEmoji(sasBytes),
            hex: this.encodeToHex(sasBytes),
            bits: 72,
            version: 2
        };

        debugLog('[ECDH] ✅ SAS v2 generated (HKDF-SHA256, 72 bits):', sasObject);
        return sasObject;
    }

    /**
     * Start handshake timeout - fallback to bootstrap key if timeout.
     *
     * The callback may be async (e.g. app.js passes an async arrow that
     * awaits handleECDHAborted). We wrap in Promise.resolve().then() so both
     * async rejections and synchronous throws are caught — no unhandled
     * promise rejections on the timeout path.
     *
     * @param {Function} onTimeout - Callback if handshake times out
     */
    startTimeout(onTimeout) {
        debugLog(`[ECDH] Starting handshake timeout (${this.HANDSHAKE_TIMEOUT_MS}ms)...`);

        this.handshakeTimeout = setTimeout(() => {
            if (!this.handshakeComplete) {
                debugWarn('[ECDH] ⏱️ Handshake timeout - falling back to bootstrap key');
                Promise.resolve()
                    .then(() => onTimeout())
                    .catch((err) => {
                        console.error('[ECDH] Error in handshake timeout callback:', err);
                    });
            }
        }, this.HANDSHAKE_TIMEOUT_MS);
    }

    /**
     * Clear handshake timeout
     */
    clearTimeout() {
        if (this.handshakeTimeout) {
            clearTimeout(this.handshakeTimeout);
            this.handshakeTimeout = null;
        }
    }

    /**
     * Convert ArrayBuffer to Base64url
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
window.ECDHKeyExchange = ECDHKeyExchange;
