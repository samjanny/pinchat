/**
 * Identity Key Manager for Signal Protocol Implementation
 *
 * Implements long-term identity keys (ECDSA) that authenticate ephemeral ECDH keys.
 * This prevents MITM attacks during Double Ratchet key rotation.
 *
 * Architecture:
 * 1. Identity Keys (ECDSA P-256, long-lived) - Generated once per session
 * 2. Ephemeral Keys (ECDH P-256, short-lived) - Rotated during ratcheting
 * 3. Identity key authenticates all ephemeral keys via digital signatures
 *
 * Security Guarantee:
 * - SAS verification authenticates identity keys (one-time, out-of-band)
 * - All subsequent ephemeral keys must be signed by verified identity key
 * - MITM cannot substitute ephemeral keys without detection (invalid signature)
 */

class IdentityKeyManager {
    constructor() {
        this.identityKeyPair = null;           // ECDSA keypair (long-term)
        this.peerIdentityPublicKey = null;     // Peer's identity public key (SAS-verified)
        this.sasVerified = false;              // Whether SAS has been verified by user
        this.previousPeerIdentity = null;      // Last known peer identity (for reconnect diff)

        // Configuration
        this.CURVE = 'P-256';  // Same curve for both ECDSA (signing) and ECDH (key agreement)
    }

    /**
     * Generate long-term identity keypair (ECDSA)
     *
     * This key is used to sign ephemeral ECDH public keys during ratcheting.
     * It should persist for the duration of the chat session.
     *
     * SECURITY: The private key is made non-extractable after generation to prevent
     * exfiltration via XSS, malicious extensions, or console access. Only the public
     * key remains extractable for transmission to the peer.
     *
     * @returns {Promise<CryptoKeyPair>}
     */
    async generateIdentityKeypair() {
        debugLog('[Identity] Generating ECDSA identity keypair (P-256)...');

        // Step 1: Generate keypair with extractable=true (needed to re-import private key)
        const tempKeyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: this.CURVE
            },
            true,  // Temporarily extractable
            ['sign', 'verify']
        );

        // Step 2: Export private key to re-import as non-extractable
        const privateKeyPkcs8 = await crypto.subtle.exportKey('pkcs8', tempKeyPair.privateKey);

        // Step 3: Re-import private key with extractable=false (SECURITY HARDENING)
        // This prevents XSS/extension attacks from exfiltrating the private key
        const nonExtractablePrivateKey = await crypto.subtle.importKey(
            'pkcs8',
            privateKeyPkcs8,
            {
                name: 'ECDSA',
                namedCurve: this.CURVE
            },
            false,  // NON-EXTRACTABLE - cannot be exported after this point
            ['sign']
        );

        // Step 4: Public key remains extractable (needed for peer exchange and SAS)
        // No need to re-import, the original is already suitable
        this.identityKeyPair = {
            privateKey: nonExtractablePrivateKey,
            publicKey: tempKeyPair.publicKey  // Remains extractable for export
        };

        // Clear sensitive data from memory (best effort)
        // Note: JavaScript doesn't guarantee memory clearing, but this helps
        const clearBuffer = new Uint8Array(privateKeyPkcs8);
        clearBuffer.fill(0);

        debugLog('[Identity] ✅ Identity keypair generated (private key non-extractable)');
        return this.identityKeyPair;
    }

    /**
     * Export identity public key for transmission to peer
     *
     * @returns {Promise<ArrayBuffer>} Raw public key bytes
     */
    async exportIdentityPublicKey() {
        if (!this.identityKeyPair) {
            throw new Error('Identity keypair not generated');
        }

        const publicKeyRaw = await crypto.subtle.exportKey(
            'raw',
            this.identityKeyPair.publicKey
        );

        debugLog('[Identity] Exported identity public key (65 bytes, uncompressed P-256)');
        return publicKeyRaw;
    }

    /**
     * Import peer's identity public key
     *
     * This key will be used to verify signatures on peer's ephemeral keys.
     * Should only be trusted after SAS verification.
     *
     * @param {ArrayBuffer} publicKeyRaw - Peer's raw public key
     * @returns {Promise<CryptoKey>}
     */
    async importPeerIdentityPublicKey(publicKeyRaw) {
        debugLog('[Identity] Importing peer identity public key...');

        this.peerIdentityPublicKey = await crypto.subtle.importKey(
            'raw',
            publicKeyRaw,
            {
                name: 'ECDSA',
                namedCurve: this.CURVE
            },
            true,  // Extractable (needed for SAS generation)
            ['verify']
        );

        debugLog('[Identity] ✅ Peer identity public key imported');
        return this.peerIdentityPublicKey;
    }

    /**
     * Sign data with identity private key
     *
     * Used to authenticate ephemeral ECDH public keys during ratcheting.
     *
     * @param {ArrayBuffer} data - Data to sign (typically ephemeral public key)
     * @returns {Promise<ArrayBuffer>} Digital signature
     */
    async sign(data) {
        if (!this.identityKeyPair) {
            throw new Error('Identity keypair not generated');
        }

        debugLog('[Identity] Signing data with identity private key...');

        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            this.identityKeyPair.privateKey,
            data
        );

        debugLog('[Identity] ✅ Data signed (signature length:', signature.byteLength, 'bytes)');
        return signature;
    }

    /**
     * Verify signature with peer's identity public key
     *
     * SECURITY: This is the MITM detection mechanism. If signature verification fails,
     * an attacker has attempted to substitute the ephemeral key.
     *
     * @param {ArrayBuffer} data - Original data (ephemeral public key)
     * @param {ArrayBuffer} signature - Signature to verify
     * @returns {Promise<boolean>} True if signature is valid
     * @throws {Error} If signature verification fails (MITM detected)
     */
    async verify(data, signature) {
        if (!this.peerIdentityPublicKey) {
            throw new Error('Peer identity public key not imported');
        }

        debugLog('[Identity] Verifying signature with peer identity public key...');

        const isValid = await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            this.peerIdentityPublicKey,
            signature,
            data
        );

        if (!isValid) {
            debugError('[Identity] ❌ Signature verification FAILED - MITM attack detected!');
            throw new Error('🚨 MITM ATTACK DETECTED - Signature verification failed');
        }

        debugLog('[Identity] ✅ Signature verified - ephemeral key authenticated');
        return true;
    }

    /**
     * Check if peer identity key changed (used after reconnect)
     * @param {CryptoKey|null} currentKey - Current peer identity key
     * @returns {Promise<boolean>} True if different from previousPeerIdentity
     */
    async hasPeerIdentityChanged(currentKey) {
        if (!this.previousPeerIdentity || !currentKey) {
            return false;
        }

        const exportKey = async (key) => {
            const raw = await crypto.subtle.exportKey('raw', key);
            return new Uint8Array(raw);
        };

        const prev = await exportKey(this.previousPeerIdentity);
        const curr = await exportKey(currentKey);

        if (prev.length !== curr.length) {
            return true;
        }

        for (let i = 0; i < prev.length; i++) {
            if (prev[i] !== curr[i]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Mark SAS as verified by user (out-of-band verification)
     *
     * This indicates the user has confirmed the SAS code matches via
     * a secondary channel (phone call, Signal, etc.)
     */
    markSASVerified() {
        this.sasVerified = true;
        debugLog('[Identity] ✅ SAS marked as verified - identity keys authenticated');
    }

    /**
     * Check if SAS has been verified
     *
     * @returns {boolean}
     */
    isSASVerified() {
        return this.sasVerified;
    }

    /**
     * Destroy identity keys (for session cleanup)
     *
     * NOTE: Unlike ephemeral keys, identity keys should persist for the
     * entire session to authenticate ratcheting. Only destroy on session end.
     */
    destroy() {
        debugLog('[Identity] Destroying identity keys (session cleanup)...');

        this.identityKeyPair = null;
        this.peerIdentityPublicKey = null;
        this.sasVerified = false;
        this.previousPeerIdentity = null;

        debugLog('[Identity] ✅ Identity keys destroyed');
    }

    /**
     * Convert ArrayBuffer to Base64url for transmission
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
window.IdentityKeyManager = IdentityKeyManager;
