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

        // Handshake v2 (PFS key separation). Two distinct ECDH P-256 keypairs:
        //   handshakeKeyPair - derives the initial shared secret S, then is
        //                      DESTROYED. Its private side never reaches the
        //                      Double Ratchet, so S is not recomputable after
        //                      cleanup (closes the "initial secret recoverable
        //                      after destroyEphemeralKeys" PFS gap).
        //   ratchetKeyPair   - becomes the Double Ratchet's initial DHs. Its
        //                      private side does NOT reconstruct S.
        this.handshakeKeyPair = null;           // Derives S (destroyed after handshake)
        this.ratchetKeyPair = null;             // Becomes Double Ratchet DHs
        this.otherHandshakePublicKey = null;    // Peer handshake public key (for S)
        this.otherRatchetPublicKey = null;      // Peer ratchet public key (for DHr)

        this.sessionKey = null;                 // Derived AES-256 key for messages
        this.handshakeComplete = false;
        this.handshakeTimeout = null;
        this.keysDestroyed = false;             // Flag to prevent key re-use after destruction

        // Wire/protocol version of the handshake envelope this instance speaks.
        this.HANDSHAKE_VERSION = 2;

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
     * Generate the two ephemeral ECDH keypairs for handshake v2 (P-256).
     *
     * handshakeKeyPair derives the initial shared secret S and is destroyed
     * after the handshake; ratchetKeyPair is handed to the Double Ratchet as
     * its initial DHs. Keeping these separate is what guarantees PFS: after
     * cleanup no reachable private key can recompute S.
     *
     * @returns {Promise<void>}
     */
    async generateKeypair() {
        debugLog('[ECDH] Generating P-256 keypairs (handshake + ratchet)...');

        const genOpts = [
            { name: 'ECDH', namedCurve: this.CURVE },
            false,  // Not extractable (ephemeral, RAM-only)
            ['deriveKey', 'deriveBits'],
        ];
        this.handshakeKeyPair = await crypto.subtle.generateKey(...genOpts);
        this.ratchetKeyPair = await crypto.subtle.generateKey(...genOpts);

        debugLog('[ECDH] ✅ Keypairs generated (handshake + ratchet, ephemeral)');
    }

    /**
     * Length-prefix a byte array as u16-be(len) || bytes. Used to build
     * unambiguous concatenations for the signed transcript and the encrypted
     * envelope (mirrors the TLV discipline of encodeAADWithLengthPrefix).
     * @private
     */
    _lenPrefix(bytes) {
        const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
        if (b.length > 0xffff) throw new Error('field too long for u16 length prefix');
        const out = new Uint8Array(2 + b.length);
        new DataView(out.buffer).setUint16(0, b.length, false);
        out.set(b, 2);
        return out;
    }

    /** Concatenate a list of Uint8Arrays. @private */
    _concat(parts) {
        const total = parts.reduce((n, p) => n + p.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) { out.set(p, off); off += p.length; }
        return out;
    }

    /**
     * Read a u16-be length-prefixed field at `offset`. Returns [bytes, next].
     * Throws on truncation so a malformed envelope fails closed.
     * @private
     */
    _readLenPrefixed(u8, offset) {
        if (offset + 2 > u8.length) throw new Error('envelope truncated (length prefix)');
        const len = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint16(offset, false);
        const start = offset + 2;
        const end = start + len;
        if (end > u8.length) throw new Error('envelope truncated (field body)');
        return [u8.slice(start, end), end];
    }

    /**
     * Canonical bytes signed by the identity key to authenticate BOTH ephemeral
     * public keys and the handshake context. Binding the ratchet key here means
     * any substitution or corruption of it yields an invalid signature (fail
     * closed) and is reflected in the SAS transcript.
     *
     *   "pinchat-handshake-v2"
     *     || lp(roomId) || lp(senderId) || lp(timestampAscii) || lp(nonce)
     *     || lp(handshakePubRaw) || lp(ratchetPubRaw)
     * @private
     */
    _buildHandshakeTranscript(roomId, senderId, timestamp, nonceBytes, handshakePubRaw, ratchetPubRaw) {
        const enc = new TextEncoder();
        return this._concat([
            enc.encode('pinchat-handshake-v2'),
            this._lenPrefix(enc.encode(roomId)),
            this._lenPrefix(enc.encode(senderId)),
            this._lenPrefix(enc.encode(String(timestamp))),
            this._lenPrefix(nonceBytes),
            this._lenPrefix(new Uint8Array(handshakePubRaw)),
            this._lenPrefix(new Uint8Array(ratchetPubRaw)),
        ]);
    }

    /**
     * Build the handshake v2 envelope: AES-GCM(bootstrapKey) over both ephemeral
     * public keys (handshake + ratchet) plus the identity key and a signature
     * over the canonical transcript.
     *
     * HANDSHAKE v2:
     * - Carries two ephemeral keys: handshake (derives S, destroyed) + ratchet (DHs)
     * - Identity key + signature are ENCRYPTED (anti-correlation: no cleartext
     *   long-term identity for a passive relay to link across rooms)
     * - Signature covers both ephemeral keys + room/sender/timestamp/nonce
     *
     * SECURITY: AAD prevents cross-context replay attacks by binding the
     * envelope to a specific room, sender, and session.
     *
     * @param {string} roomId - Room identifier (prevents cross-room replay)
     * @param {string} myConnectionId - Sender's connection/user ID (prevents impersonation)
     * @returns {Promise<Object>} Object with {version, encryptedEnvelope, timestamp, nonce}
     */
    async encryptPublicKey(roomId, myConnectionId) {
        if (!this.handshakeKeyPair || !this.ratchetKeyPair) {
            throw new Error('ECDH keypairs not generated');
        }

        if (!this.identityManager || !this.identityManager.identityKeyPair) {
            throw new Error('Identity manager not initialized');
        }

        if (!roomId || !myConnectionId) {
            throw new Error('roomId and myConnectionId required for AAD binding');
        }

        debugLog('[ECDH] Building v2 handshake envelope (encrypted identity + dual keys)...');
        debugLog(`[ECDH] Context: roomId=${roomId}, myConnectionId=${myConnectionId}`);

        // Export both ephemeral public keys to raw format.
        const handshakePubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', this.handshakeKeyPair.publicKey));
        const ratchetPubRaw = new Uint8Array(await crypto.subtle.exportKey('raw', this.ratchetKeyPair.publicKey));

        // Generate nonce (16 bytes) and timestamp; both are also fed into the
        // signed transcript so a replay with a different context fails.
        const nonce = crypto.getRandomValues(new Uint8Array(16));
        const timestamp = Date.now();

        // Sign the canonical transcript covering BOTH public keys + context.
        // This authenticates the ratchet key too (v1 only signed one ephemeral).
        const transcript = this._buildHandshakeTranscript(
            roomId, myConnectionId, timestamp, nonce, handshakePubRaw, ratchetPubRaw,
        );
        const signature = new Uint8Array(await this.identityManager.sign(transcript));
        debugLog('[ECDH] ✅ Handshake transcript signed (both ephemeral keys bound)');

        const identityPublicKeyRaw = new Uint8Array(await this.identityManager.exportIdentityPublicKey());

        // Plaintext envelope. Identity key + signature move INSIDE the AES-GCM
        // ciphertext (anti-correlation: a passive relay no longer sees the
        // long-term identity key that would link a user across rooms).
        //   u8(version) || lp(handshakePub) || lp(ratchetPub) || lp(identityPub) || lp(signature)
        const envelope = this._concat([
            new Uint8Array([this.HANDSHAKE_VERSION]),
            this._lenPrefix(handshakePubRaw),
            this._lenPrefix(ratchetPubRaw),
            this._lenPrefix(identityPublicKeyRaw),
            this._lenPrefix(signature),
        ]);

        // AAD still binds room/sender/timestamp/nonce (defense in depth).
        const aad = encodeAADWithLengthPrefix([
            {type: AAD_FIELD_TYPES.ROOM_ID, value: roomId},
            {type: AAD_FIELD_TYPES.SENDER_ID, value: myConnectionId},
            {type: AAD_FIELD_TYPES.TIMESTAMP, value: timestamp},
            {type: AAD_FIELD_TYPES.NONCE, value: nonce}
        ]);

        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: aad },
            this.bootstrapKey,
            envelope,
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        // Store our context data for SAS generation
        this.myTimestamp = timestamp;
        this.myNonce = this.arrayBufferToBase64url(nonce);

        const result = {
            version: this.HANDSHAKE_VERSION,
            encryptedEnvelope: this.arrayBufferToBase64url(combined),
            timestamp: timestamp,
            nonce: this.myNonce,
        };

        debugLog('[ECDH] ✅ v2 envelope built (identity + signature encrypted, dual keys)');
        debugLog(`[ECDH] Timestamp: ${timestamp}, Nonce: ${result.nonce.substring(0, 16)}...`);

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
     * @param {string} encryptedEnvelope - Base64url-encoded encrypted v2 envelope
     * @param {string} expectedRoomId - Expected room identifier
     * @param {string} senderConnectionId - Sender's connection/user ID
     * @param {number} timestamp - Timestamp from sender (ms since epoch)
     * @param {string} nonceBase64url - Base64url-encoded nonce from sender
     * @param {number} version - Handshake envelope version (must be 2)
     * @returns {Promise<CryptoKey>}
     */
    async decryptPublicKey(encryptedEnvelope, expectedRoomId, senderConnectionId, timestamp, nonceBase64url, version) {
        if (typeof expectedRoomId !== 'string' || expectedRoomId.length === 0
            || typeof senderConnectionId !== 'string' || senderConnectionId.length === 0
            || typeof encryptedEnvelope !== 'string' || encryptedEnvelope.length === 0
            || typeof nonceBase64url !== 'string' || nonceBase64url.length === 0) {
            throw new Error('AAD validation requires: expectedRoomId, senderConnectionId, timestamp, nonce');
        }

        // Fail closed on any non-v2 handshake. There is no downgrade path: a v1
        // peer (single-keypair, cleartext identity) cannot establish the PFS
        // guarantees v2 provides, so we refuse rather than interoperate.
        if (version !== this.HANDSHAKE_VERSION) {
            throw new Error(`Unsupported handshake version ${version} (expected ${this.HANDSHAKE_VERSION}) - refusing legacy/v1 peer`);
        }

        if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
            throw new Error('invalid ECDH timestamp');
        }

        debugLog('[ECDH] Decrypting v2 handshake envelope with AAD validation...');
        debugLog(`[ECDH] Expected context: roomId=${expectedRoomId}, sender=${senderConnectionId}`);

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

        const nonce = this.base64urlToArrayBuffer(nonceBase64url);
        if (nonce.byteLength !== 16) {
            throw new Error('invalid ECDH nonce length');
        }

        // Reconstruct AAD (must match encryption context exactly).
        const aad = encodeAADWithLengthPrefix([
            {type: AAD_FIELD_TYPES.ROOM_ID, value: expectedRoomId},
            {type: AAD_FIELD_TYPES.SENDER_ID, value: senderConnectionId},
            {type: AAD_FIELD_TYPES.TIMESTAMP, value: timestamp},
            {type: AAD_FIELD_TYPES.NONCE, value: nonce}
        ]);

        const combined = this.base64urlToArrayBuffer(encryptedEnvelope);
        // 12-byte IV + at least the 16-byte AES-GCM authentication tag.
        if (combined.byteLength < 28) {
            throw new Error('encrypted handshake envelope is truncated');
        }
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        let envelope;
        try {
            envelope = new Uint8Array(await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv, additionalData: aad },
                this.bootstrapKey,
                ciphertext,
            ));
            debugLog('[ECDH] ✅ AAD validation passed (context matches)');
        } catch (error) {
            debugError('[ECDH] ❌ AAD validation failed:', error);
            throw new Error('ECDH AAD validation failed - possible cross-context replay attack or wrong room/sender');
        }

        // Parse envelope: u8(version) || lp(handshakePub) || lp(ratchetPub)
        //                 || lp(identityPub) || lp(signature)
        if (envelope.length < 1 || envelope[0] !== this.HANDSHAKE_VERSION) {
            throw new Error('handshake envelope version mismatch');
        }
        let off = 1;
        let handshakePubRaw, ratchetPubRaw, identityPubRaw, signature;
        [handshakePubRaw, off] = this._readLenPrefixed(envelope, off);
        [ratchetPubRaw, off] = this._readLenPrefixed(envelope, off);
        [identityPubRaw, off] = this._readLenPrefixed(envelope, off);
        [signature, off] = this._readLenPrefixed(envelope, off);
        if (off !== envelope.length) {
            throw new Error('trailing bytes in handshake envelope');
        }
        // P-256 raw public keys are exactly 65 bytes (0x04 || X32 || Y32),
        // and WebCrypto ECDSA/P-256 signatures use fixed-width P1363 r||s.
        // Strict schema checks keep malformed-but-authenticated envelopes from
        // reaching any state mutation.
        if (handshakePubRaw.length !== 65 || handshakePubRaw[0] !== 0x04
            || ratchetPubRaw.length !== 65 || ratchetPubRaw[0] !== 0x04) {
            throw new Error('invalid ephemeral public key encoding');
        }
        if (identityPubRaw.length !== 65 || identityPubRaw[0] !== 0x04) {
            throw new Error('invalid identity public key encoding');
        }
        if (signature.length !== 64) {
            throw new Error('invalid handshake signature length');
        }

        // Verify the transcript signature with a TEMPORARY key BEFORE committing
        // any peer state. A bad signature must not mutate the identity manager.
        const transcript = this._buildHandshakeTranscript(
            expectedRoomId, senderConnectionId, timestamp, nonce, handshakePubRaw, ratchetPubRaw,
        );
        const tempIdentity = await crypto.subtle.importKey(
            'raw', identityPubRaw, { name: 'ECDSA', namedCurve: this.CURVE }, false, ['verify'],
        );
        const sigOk = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' }, tempIdentity, signature, transcript,
        );
        if (!sigOk) {
            debugError('[ECDH] ❌ SIGNATURE VERIFICATION FAILED');
            throw new Error('🚨 MITM ATTACK DETECTED - handshake transcript signature is invalid');
        }
        debugLog('[ECDH] ✅ Transcript signature verified (both ephemeral keys bound)');

        // Validate/import BOTH ECDH points into local variables before touching
        // any peer state. A participant can validly sign arbitrary bytes; an
        // off-curve point must therefore fail without leaving a partially
        // committed identity, context, or handshake key behind.
        // extractable=true is safe for public material and is required by the
        // SAS transcript / Double Ratchet key-ID construction.
        const importedHandshakePublicKey = await crypto.subtle.importKey(
            'raw', handshakePubRaw, { name: 'ECDH', namedCurve: this.CURVE }, true, [],
        );
        const importedRatchetPublicKey = await crypto.subtle.importKey(
            'raw', ratchetPubRaw, { name: 'ECDH', namedCurve: this.CURVE }, true, [],
        );

        // Atomic commit: every fallible async operation has completed. These
        // synchronous assignments run without an event-loop turn in between,
        // so observers can see either the old state or the complete new state,
        // never a partially imported peer.
        this.identityManager.commitPeerIdentityPublicKey(identityPubRaw, tempIdentity);
        this.otherHandshakePublicKey = importedHandshakePublicKey;
        this.otherRatchetPublicKey = importedRatchetPublicKey;
        this.otherTimestamp = timestamp;
        this.otherNonce = nonceBase64url;

        debugLog('[ECDH] ✅ v2 envelope decrypted - handshake + ratchet keys imported');
        return this.otherRatchetPublicKey;
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

        if (!this.handshakeKeyPair || !this.otherHandshakePublicKey) {
            throw new Error('ECDH handshake keypair or peer handshake public key missing');
        }

        debugLog('[ECDH] Deriving session key material from handshake shared secret...');

        // Derive S from the HANDSHAKE keypair (never the ratchet keypair). The
        // handshake private key is destroyed after cleanup, so S is not
        // recomputable from any state the Double Ratchet retains.
        const sharedSecretBits = await crypto.subtle.deriveBits(
            {
                name: 'ECDH',
                public: this.otherHandshakePublicKey
            },
            this.handshakeKeyPair.privateKey,
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
     * Drop the bootstrap key reference after handshake completion.
     *
     * Previously this was a no-op to support re-handshaking without re-reading
     * the URL fragment. PFS hardening: we null the reference. Re-handshake is
     * driven from CryptoManager.resetToBootstrapKey() which rebuilds an
     * ECDHKeyExchange with a freshly-extracted bootstrap key.
     */
    deleteBootstrapKey() {
        debugLog('[ECDH] Dropping bootstrap key reference (PFS hardening)');
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

        // Drop the HANDSHAKE keypair: this is the private key that derived S.
        // It was never handed to the Double Ratchet, so once this reference is
        // gone S cannot be recomputed by anything reachable in the page.
        this.handshakeKeyPair = null;
        this.otherHandshakePublicKey = null;

        // The ratchet keypair is now owned by the Double Ratchet (DHs); release
        // our references so the ECDH manager no longer holds a second handle.
        this.ratchetKeyPair = null;
        this.otherRatchetPublicKey = null;

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
     * Emoji count = floor(bytes.length * 8 / 6). For 12 input bytes (96 bits)
     * this is 16 emoji - the v4 SAS layout. Earlier layouts used 9 bytes / 12
     * emoji (v2) and 6 bytes / 8 emoji; the encoding is the same algorithm,
     * just a different length.
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
     * Lexicographically order two byte arrays so both peers feed an identical,
     * side-independent ordering into the SAS derivation. Returns [low, high].
     *
     * @private
     */
    _sortKeyPair(a, b) {
        return [a, b].sort((x, y) => {
            for (let i = 0; i < Math.min(x.length, y.length); i++) {
                if (x[i] !== y[i]) return x[i] - y[i];
            }
            return x.length - y.length;
        });
    }

    /**
     * Generate Short Authentication String (SAS) for MITM detection - v4.
     *
     * v4 derivation (HKDF-SHA256 via WebCrypto):
     *   IKM   = sorted(IK_A_raw || IK_B_raw)        - the two identity public keys
     *   salt  = roomId || "pinchat-sas-v4"          - fixed for the room
     *   info  = "SAS-display-v4" || transcript      - domain separation + session binding
     *   where transcript = SHA-256( sorted(BLOCK_A, BLOCK_B) )
     *         BLOCK_x     = handshakePub_x || ratchetPub_x  (both live ECDH keys)
     *   bits  = 96                                  - 16 emoji × 6 bits
     *
     * v4 changes from v3 (handshake key separation): the transcript now folds
     * in BOTH ephemeral public keys per side (the S-deriving handshake key AND
     * the ratchet key that becomes DHs), so the out-of-band code authenticates
     * the entire v2 handshake. v3 bound only the single ephemeral key.
     *
     * Why v3 changes from v2 (audit H1):
     *   v2 derived the SAS from (sorted identity keys, roomId) ONLY. That made
     *   the displayed code precomputable: roomId is a server-generated UUID known
     *   to the relay BEFORE the handshake, and HKDF is ~microseconds per eval, so
     *   a malicious relay running a double-MITM could mount an OFFLINE two-sided
     *   birthday search. It presents IK_M1 to A and IK_M2 to B (both attacker-
     *   chosen real keypairs that validly sign the substituted ephemerals), and
     *   looks for IK_M1, IK_M2 such that SAS_A == SAS_B. That is a collision over
     *   two attacker-controlled inputs, i.e. ~2^(n/2) work, NOT an n-bit preimage.
     *   At 72 bits the effective security was only ~2^36 and fully precomputable
     *   over the 24h identity TTL - both users would then see identical codes and
     *   "verify" a man-in-the-middle.
     *
     *   v3 closes this two ways:
     *   1. Transcript binding. The info string folds in a hash of BOTH live ECDH
     *      ephemeral public keys. The honest party's ephemeral key is fresh per
     *      handshake and NOT under attacker control before the handshake starts,
     *      so the SAS can no longer be precomputed: the attacker must grind ONLINE,
     *      inside the live handshake window, against ephemerals it cannot fix in
     *      advance. The transcript also makes the SAS authenticate the actual
     *      session (the keys that derive the root key), not merely the identity
     *      pair - closing the separate "SAS does not bind the session" gap.
     *   2. Wider output. 96 bits lifts the residual (now online-only) birthday
     *      bound to ~2^48, which is infeasible to grind within a single handshake.
     *
     *   Net effect: the only remaining attack is an online ~2^48 two-sided grind
     *   that must complete before the handshake times out (30s) - not a thing.
     *
     * Stability note: because the transcript includes the per-handshake ephemeral
     * keys, the SAS is fresh on every new handshake (including reconnects). The
     * "verify once" UX is preserved by the identity-key persistence + peer-
     * identity-change detection in app.js (a stable IDENTITY pair across reconnects
     * keeps sasVerified set; only an identity-key change forces re-verification).
     * The displayed emoji changing on reconnect is expected and is the price of
     * binding the live session; identity continuity, not SAS stability, is what
     * carries the user's trust decision forward.
     *
     * Interop: v4 is wire-incompatible with v3 and earlier SAS layouts. Both
     * endpoints must run this version or the displayed codes will differ. There
     * is no security downgrade path - a mismatch surfaces as a non-matching SAS,
     * which is the correct, fail-closed behaviour.
     *
     * @param {string} roomId - Room identifier for context binding
     * @returns {Promise<Object>} Object with emoji, hex, bits, version
     * @throws {Error} If identity keys or live ephemeral keys are not available
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

        // Transcript binding (audit H1) requires the LIVE ECDH ephemeral keys.
        // generateSAS() is invoked before destroyEphemeralKeys() (see app.js), so
        // both keys are present here. Fail closed rather than silently fall back
        // to an identity-only (precomputable) SAS if they are missing.
        if (!this.handshakeKeyPair || !this.handshakeKeyPair.publicKey || !this.otherHandshakePublicKey
            || !this.ratchetKeyPair || !this.ratchetKeyPair.publicKey || !this.otherRatchetPublicKey) {
            throw new Error('[ECDH] Cannot generate SAS - live ephemeral ECDH keys not available (transcript binding required)');
        }

        debugLog('[ECDH] Generating SAS v4 (HKDF-SHA256, 96 bits, dual-key transcript-bound)...');

        // --- IKM: sorted identity public keys -------------------------------
        // The own identity CryptoKey public side is always exportable per
        // WebCrypto; the peer key's raw bytes were cached at import time and are
        // read directly (never via exportKey on the non-extractable handle).
        const myPublicKeyRaw = await crypto.subtle.exportKey('raw', this.identityManager.identityKeyPair.publicKey);
        const myKeyBytes = new Uint8Array(myPublicKeyRaw);
        const otherKeyBytes = new Uint8Array(this.identityManager.peerIdentityPublicKeyRaw);

        const idKeys = this._sortKeyPair(myKeyBytes, otherKeyBytes);
        const ikm = new Uint8Array(idKeys[0].length + idKeys[1].length);
        ikm.set(idKeys[0], 0);
        ikm.set(idKeys[1], idKeys[0].length);

        // --- Transcript: SHA-256 over both peers' (handshake||ratchet) keys ---
        // v4 binds BOTH ephemeral public keys of each side. Each side forms a
        // per-side block = handshakePubRaw || ratchetPubRaw; the two blocks are
        // sorted so the transcript is side-independent. Substituting or
        // corrupting either key on either side changes the SAS, so the user's
        // out-of-band comparison authenticates the full v2 handshake, not just
        // the S-deriving key.
        const myBlock = this._concat([
            new Uint8Array(await crypto.subtle.exportKey('raw', this.handshakeKeyPair.publicKey)),
            new Uint8Array(await crypto.subtle.exportKey('raw', this.ratchetKeyPair.publicKey)),
        ]);
        const otherBlock = this._concat([
            new Uint8Array(await crypto.subtle.exportKey('raw', this.otherHandshakePublicKey)),
            new Uint8Array(await crypto.subtle.exportKey('raw', this.otherRatchetPublicKey)),
        ]);
        const blocks = this._sortKeyPair(myBlock, otherBlock);
        const transcriptInput = this._concat([blocks[0], blocks[1]]);
        const transcriptHash = new Uint8Array(await crypto.subtle.digest('SHA-256', transcriptInput));

        // --- Salt = roomId || "pinchat-sas-v4" ------------------------------
        const encoder = new TextEncoder();
        const roomIdBytes = encoder.encode(roomId);
        const saltTagBytes = encoder.encode('pinchat-sas-v4');
        const salt = new Uint8Array(roomIdBytes.length + saltTagBytes.length);
        salt.set(roomIdBytes, 0);
        salt.set(saltTagBytes, roomIdBytes.length);

        // --- info = "SAS-display-v4" || transcriptHash ----------------------
        const infoTagBytes = encoder.encode('SAS-display-v4');
        const info = new Uint8Array(infoTagBytes.length + transcriptHash.length);
        info.set(infoTagBytes, 0);
        info.set(transcriptHash, infoTagBytes.length);

        const baseKey = await crypto.subtle.importKey(
            'raw',
            ikm,
            'HKDF',
            false,
            ['deriveBits']
        );

        // 96 bits = 12 bytes = 16 emoji × 6 bits
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: salt,
                info: info
            },
            baseKey,
            96
        );

        const sasBytes = new Uint8Array(derivedBits);

        const sasObject = {
            emoji: this.encodeToEmoji(sasBytes),
            hex: this.encodeToHex(sasBytes),
            bits: 96,
            version: 4
        };

        debugLog('[ECDH] ✅ SAS v4 generated (HKDF-SHA256, 96 bits, dual-key transcript-bound):', sasObject);
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
