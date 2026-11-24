/**
 * Identity Key Manager for Signal Protocol Implementation
 *
 * Implements long-term identity keys (ECDSA) that authenticate ephemeral ECDH keys.
 * This prevents MITM attacks during Double Ratchet key rotation.
 *
 * Architecture:
 * 1. Identity Keys (ECDSA P-256, one per room) - Persisted in IndexedDB under
 *    an entry derived from the room ID, for at most 24h (the longest room
 *    TTL). Re-loaded when the same room is reopened so the peer sees the
 *    same identity across reconnects and tab refreshes (C-04). A different
 *    room gets a different keypair, so the key a relay can recover from
 *    message signatures (audit C-F2) does not link rooms. The private side
 *    is non-extractable both on initial creation and after structured-clone
 *    restore from IndexedDB.
 * 2. Ephemeral Keys (ECDH P-256, short-lived) - Rotated during ratcheting
 * 3. Identity key authenticates all ephemeral keys via digital signatures
 *
 * Security Guarantee:
 * - SAS verification authenticates identity keys (out-of-band). The verdict
 *   is bound to the exact peer identity key bytes it was given for (audit
 *   C-F1): it holds only while the peer presents those same bytes.
 * - All subsequent ephemeral keys must be signed by verified identity key
 * - MITM cannot substitute ephemeral keys without detection (invalid signature)
 */

// ── IndexedDB-backed identity persistence (C-04) ────────────────────────
//
// We store the ECDSA keypair as an opaque CryptoKey pair in IndexedDB. Per
// W3C IndexedDB §6 + WebCrypto §13, structured-clone of a CryptoKey
// preserves the [[extractable]] internal slot. Restoring a non-extractable
// private key yields another non-extractable CryptoKey - the bytes never
// become reachable to JS, even across page loads.
//
// The store is scoped to the origin, never synced, and auto-bounded by the
// expiresAt timestamp written alongside the keys. A `version` field allows
// future schema migrations without invalidating in-flight chats.
//
// One entry per room (audit C-F2). The entry key is a SHA-256 digest of the
// room ID rather than the ID itself, so the database does not list the rooms
// this browser opened in plain text. Expired entries are swept whenever an
// identity is requested, and the single cross-room entry written by earlier
// releases (IDENTITY_LEGACY_ENTRY_KEY) is deleted and never read.

const IDENTITY_DB_NAME = 'pinchat_identity_v1';
const IDENTITY_STORE_NAME = 'keys';
const IDENTITY_LEGACY_ENTRY_KEY = 'identity';
const IDENTITY_ROOM_ENTRY_PREFIX = 'room:';
const IDENTITY_TTL_MS = 24 * 60 * 60 * 1000;  // 24h, the longest room TTL
const IDENTITY_SCHEMA_VERSION = 1;

/**
 * IndexedDB entry key for a room's identity: "room:" + hex(SHA-256(roomId)).
 * Returns null when there is no usable room ID, which makes the identity
 * ephemeral (never persisted) instead of shared between rooms.
 *
 * @private
 * @param {string} roomId
 * @returns {Promise<string|null>}
 */
async function _identityEntryKey(roomId) {
    if (typeof roomId !== 'string' || roomId.length === 0) return null;
    const digest = new Uint8Array(await crypto.subtle.digest(
        'SHA-256', new TextEncoder().encode(roomId),
    ));
    let hex = '';
    for (const b of digest) hex += b.toString(16).padStart(2, '0');
    return IDENTITY_ROOM_ENTRY_PREFIX + hex;
}

/**
 * Open (or create) the identity database. Returns null on any error or
 * when IndexedDB is unavailable (Node, locked-down browsers, private mode
 * with storage blocked, ...) - the caller falls back to ephemeral identity.
 *
 * @private
 * @returns {Promise<IDBDatabase|null>}
 */
function _openIdentityDb() {
    return new Promise((resolve) => {
        if (typeof indexedDB === 'undefined') {
            return resolve(null);
        }
        let req;
        try {
            req = indexedDB.open(IDENTITY_DB_NAME, 1);
        } catch (_) {
            return resolve(null);
        }
        req.onupgradeneeded = () => {
            const db = req.result;
            if (!db.objectStoreNames.contains(IDENTITY_STORE_NAME)) {
                db.createObjectStore(IDENTITY_STORE_NAME);
            }
        };
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => resolve(null);
        req.onblocked = () => resolve(null);
    });
}

/**
 * Delete every expired or malformed entry, and the legacy cross-room entry.
 * Best-effort: any failure leaves the store as it was.
 *
 * @private
 * @returns {Promise<void>}
 */
async function _sweepStoredIdentities() {
    const db = await _openIdentityDb();
    if (!db) return;
    const now = Date.now();
    return new Promise((resolve) => {
        try {
            const tx = db.transaction(IDENTITY_STORE_NAME, 'readwrite');
            const store = tx.objectStore(IDENTITY_STORE_NAME);
            store.delete(IDENTITY_LEGACY_ENTRY_KEY);
            const req = store.openCursor();
            req.onsuccess = () => {
                const cursor = req.result;
                if (!cursor) return;
                const v = cursor.value;
                if (!v || typeof v.expiresAt !== 'number' || v.expiresAt < now) {
                    cursor.delete();
                }
                cursor.continue();
            };
            tx.oncomplete = () => resolve();
            tx.onerror = () => resolve();
            tx.onabort = () => resolve();
        } catch (_) {
            resolve();
        }
    });
}

/**
 * Load the stored identity keypair if present, valid, and not expired.
 * Returns null on any failure - the caller must regenerate.
 *
 * @private
 * @param {string} entryKey - per-room entry key from _identityEntryKey()
 * @returns {Promise<{privateKey: CryptoKey, publicKey: CryptoKey}|null>}
 */
async function _loadStoredIdentity(entryKey) {
    const db = await _openIdentityDb();
    if (!db) return null;
    return new Promise((resolve) => {
        try {
            const tx = db.transaction(IDENTITY_STORE_NAME, 'readonly');
            const req = tx.objectStore(IDENTITY_STORE_NAME).get(entryKey);
            req.onsuccess = () => {
                const v = req.result;
                if (!v
                    || v.version !== IDENTITY_SCHEMA_VERSION
                    || !v.privateKey
                    || !v.publicKey
                    || typeof v.expiresAt !== 'number'
                ) {
                    return resolve(null);
                }
                if (v.expiresAt < Date.now()) {
                    // Expired entry: caller will overwrite with a fresh one.
                    return resolve(null);
                }
                resolve({ privateKey: v.privateKey, publicKey: v.publicKey });
            };
            req.onerror = () => resolve(null);
        } catch (_) {
            resolve(null);
        }
    });
}

/**
 * Persist the identity keypair. Best-effort: failure is logged via debugWarn
 * and the in-memory keypair remains usable for the current session.
 *
 * @private
 * @param {string} entryKey - per-room entry key from _identityEntryKey()
 * @returns {Promise<boolean>}
 */
async function _saveStoredIdentity(entryKey, privateKey, publicKey) {
    const db = await _openIdentityDb();
    if (!db) return false;
    return new Promise((resolve) => {
        try {
            const tx = db.transaction(IDENTITY_STORE_NAME, 'readwrite');
            const now = Date.now();
            tx.objectStore(IDENTITY_STORE_NAME).put({
                version: IDENTITY_SCHEMA_VERSION,
                privateKey: privateKey,
                publicKey: publicKey,
                createdAt: now,
                expiresAt: now + IDENTITY_TTL_MS,
            }, entryKey);
            tx.oncomplete = () => resolve(true);
            tx.onerror = () => resolve(false);
            tx.onabort = () => resolve(false);
        } catch (_) {
            resolve(false);
        }
    });
}

/**
 * Remove a stored identity. Used by IdentityKeyManager.clearStoredIdentity
 * (manual user-initiated reset).
 *
 * @private
 * @param {string} entryKey - per-room entry key from _identityEntryKey()
 * @returns {Promise<void>}
 */
async function _deleteStoredIdentity(entryKey) {
    const db = await _openIdentityDb();
    if (!db) return;
    return new Promise((resolve) => {
        try {
            const tx = db.transaction(IDENTITY_STORE_NAME, 'readwrite');
            tx.objectStore(IDENTITY_STORE_NAME).delete(entryKey);
            tx.oncomplete = () => resolve();
            tx.onerror = () => resolve();
            tx.onabort = () => resolve();
        } catch (_) {
            resolve();
        }
    });
}

class IdentityKeyManager {
    constructor() {
        this.identityKeyPair = null;             // ECDSA keypair (long-term)
        this.peerIdentityPublicKey = null;       // Peer's identity public key (CryptoKey, non-extractable)
        this.peerIdentityPublicKeyRaw = null;    // Peer's identity public key (Uint8Array, cached at import)
        // Peer identity key bytes the user confirmed with the SAS (audit
        // C-F1). The verdict is not a flag: it holds only for these bytes.
        this.verifiedPeerIdentityRaw = null;
        this.previousPeerIdentityRaw = null;     // Last known peer identity raw bytes (for reconnect diff)
        this.storedEntryKey = null;              // IndexedDB entry of this room's identity (null: ephemeral)

        // Configuration
        this.CURVE = 'P-256';  // Same curve for both ECDSA (signing) and ECDH (key agreement)
    }

    /**
     * Obtain this room's identity keypair (ECDSA P-256).
     *
     * C-04: persistence-aware. Tries to load the keypair stored for this
     * room from IndexedDB first; only when none is present (first visit,
     * expired TTL, IndexedDB unavailable) does it generate a fresh one and
     * persist it. This keeps the peer's view of our identity stable across
     * reconnects, tab refreshes and short browser restarts within the TTL
     * window, so a reload does not look like an identity change.
     *
     * C-F2: the keypair is per room. Every 1:1 message header carries an
     * ECDSA signature over cleartext fields, so a relay can recover the
     * signing public key from two headers. A keypair shared by all rooms
     * would let it link the rooms one browser opens; a per-room keypair
     * links nothing beyond the room it already sees. Without a roomId the
     * keypair is ephemeral (generated, never stored).
     *
     * SECURITY: The private key is non-extractable after generation. When
     * later restored from IndexedDB via structured-clone, the
     * [[extractable]] internal slot is preserved (W3C IndexedDB §6 +
     * WebCrypto §13) - so the bytes never become reachable to JS, neither
     * on creation nor across page loads.
     *
     * @param {string} [roomId] - room the identity belongs to
     * @returns {Promise<CryptoKeyPair>}
     */
    async generateIdentityKeypair(roomId) {
        const entryKey = await _identityEntryKey(roomId);
        this.storedEntryKey = entryKey;
        if (entryKey) {
            await _sweepStoredIdentities();
            // Try to restore this room's identity first. The stored CryptoKey
            // private side comes back non-extractable; we use it as-is.
            const stored = await _loadStoredIdentity(entryKey);
            if (stored) {
                this.identityKeyPair = stored;
                debugLog('[Identity] Restored this room\'s identity from IndexedDB');
                return this.identityKeyPair;
            }
        }

        debugLog('[Identity] No stored identity found - generating fresh ECDSA P-256 keypair...');

        // F-02: generate the keypair directly with extractable=false. WebCrypto
        // (W3C §13) sets [[extractable]] per side and for asymmetric ECDSA
        // keypairs the public side is ALWAYS extractable regardless of the
        // parameter - so exportKey('raw', publicKey) for peer exchange and SAS
        // continues to work. The prior pattern (extractable=true -> export PKCS#8
        // -> re-import non-extractable -> fill(0) the buffer) created a window in
        // which the raw private key bytes lived in the JS heap as a PKCS#8
        // ArrayBuffer; an XSS or hostile extension running during this window
        // could exfiltrate the long-term identity key. The fill(0) was
        // best-effort and not GC-safe. The single-call form removes that
        // window entirely: the private bytes never become reachable to JS.
        this.identityKeyPair = await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: this.CURVE
            },
            false,  // Private side non-extractable from creation; public side stays exportable per spec.
            ['sign', 'verify']
        );

        // Persist for identity continuity across reconnects / refreshes in
        // this room (C-04). Best-effort: a write failure leaves us with an
        // ephemeral identity for this session, which is the pre-C-04
        // behaviour and remains cryptographically valid.
        const saved = entryKey !== null && await _saveStoredIdentity(
            entryKey,
            this.identityKeyPair.privateKey,
            this.identityKeyPair.publicKey,
        );
        if (saved) {
            debugLog('[Identity] Identity keypair generated and persisted to IndexedDB for this room');
        } else {
            debugWarn('[Identity] Identity keypair generated; not persisted (ephemeral session)');
        }
        return this.identityKeyPair;
    }

    /**
     * Forget this room's persisted identity. The next call to
     * generateIdentityKeypair() for the room mints a fresh keypair and (if
     * IndexedDB is available) persists it.
     *
     * Intended for an explicit "forget me on this device" user gesture or
     * for a clean-slate reset after a confirmed compromise. NOT called by
     * destroy(): SAS mismatch / handshake abort should NOT throw away the
     * user's identity by default - those events typically point at peer
     * substitution, not at compromise of the user's own private key.
     *
     * @returns {Promise<void>}
     */
    async clearStoredIdentity() {
        if (this.storedEntryKey) {
            await _deleteStoredIdentity(this.storedEntryKey);
        }
        debugLog('[Identity] Stored identity cleared (next session will mint a fresh keypair)');
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

        // Complete the fallible import before mutating peer state. This keeps
        // standalone callers transactional too (the handshake-v2 path imports
        // into a temporary key and calls commitPeerIdentityPublicKey directly).
        const rawBytes = (publicKeyRaw instanceof Uint8Array)
            ? new Uint8Array(publicKeyRaw)
            : new Uint8Array(publicKeyRaw);
        const importedPublicKey = await crypto.subtle.importKey(
            'raw',
            rawBytes,
            {
                name: 'ECDSA',
                namedCurve: this.CURVE
            },
            false,  // Non-extractable: SAS uses peerIdentityPublicKeyRaw, not exportKey
            ['verify']
        );

        this.commitPeerIdentityPublicKey(rawBytes, importedPublicKey);

        debugLog('[Identity] ✅ Peer identity public key imported (non-extractable)');
        return this.peerIdentityPublicKey;
    }

    /**
     * Atomically publish a peer identity key that has already been imported
     * and validated. No await occurs here, so raw bytes and CryptoKey become
     * visible together in one event-loop turn.
     *
     * @param {ArrayBuffer|Uint8Array} publicKeyRaw - 65-byte raw P-256 point
     * @param {CryptoKey} importedPublicKey - Non-extractable ECDSA verify key
     * @returns {CryptoKey}
     */
    commitPeerIdentityPublicKey(publicKeyRaw, importedPublicKey) {
        const rawBytes = new Uint8Array(publicKeyRaw);
        const algorithm = importedPublicKey && importedPublicKey.algorithm;
        if (rawBytes.length !== 65 || rawBytes[0] !== 0x04
            || !importedPublicKey || importedPublicKey.type !== 'public'
            || !algorithm || algorithm.name !== 'ECDSA' || algorithm.namedCurve !== this.CURVE
            || !importedPublicKey.usages.includes('verify')) {
            throw new Error('invalid pre-imported peer identity key');
        }

        this.peerIdentityPublicKeyRaw = rawBytes;
        this.peerIdentityPublicKey = importedPublicKey;
        return importedPublicKey;
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
     * Check if peer identity key changed (used after reconnect).
     *
     * Compares cached raw bytes - both the previous identity (captured
     * before reconnect) and the current identity must have been imported
     * via importPeerIdentityPublicKey, which populates the *Raw caches.
     *
     * @returns {boolean} True if different from previousPeerIdentityRaw
     */
    hasPeerIdentityChanged() {
        const prev = this.previousPeerIdentityRaw;
        const curr = this.peerIdentityPublicKeyRaw;
        if (!prev || !curr) {
            return false;
        }

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
     * Record that the user confirmed, out of band, the SAS computed for the
     * peer identity key `peerIdentityRaw`.
     *
     * Audit C-F1: the verdict used to be a bare boolean, so after any
     * teardown the next handshake inherited "verified" whatever identity key
     * it carried. It is now bound to the key bytes the code was computed
     * for, and isSASVerified() holds only while the peer presents them.
     *
     * @param {Uint8Array} peerIdentityRaw - 65-byte raw P-256 identity key
     */
    markSASVerified(peerIdentityRaw) {
        if (!(peerIdentityRaw instanceof Uint8Array)
            || peerIdentityRaw.length !== 65 || peerIdentityRaw[0] !== 0x04) {
            throw new Error('markSASVerified needs the peer identity key the code was computed for');
        }
        this.verifiedPeerIdentityRaw = new Uint8Array(peerIdentityRaw);
        debugLog('[Identity] SAS marked as verified for the current peer identity key');
    }

    /**
     * True when the user verified the SAS for the peer identity key the
     * peer presents now.
     *
     * @returns {boolean}
     */
    isSASVerified() {
        return this.isVerifiedPeerIdentity(this.peerIdentityPublicKeyRaw);
    }

    /**
     * True when `peerIdentityRaw` is the identity key the user verified.
     *
     * @param {Uint8Array|null} peerIdentityRaw
     * @returns {boolean}
     */
    isVerifiedPeerIdentity(peerIdentityRaw) {
        const verified = this.verifiedPeerIdentityRaw;
        if (!verified || !peerIdentityRaw || verified.length !== peerIdentityRaw.length) {
            return false;
        }
        let diff = 0;
        for (let i = 0; i < verified.length; i++) diff |= verified[i] ^ peerIdentityRaw[i];
        return diff === 0;
    }

    /**
     * True when the user has verified some peer identity in this room,
     * whether or not it is the one the peer presents now.
     *
     * @returns {boolean}
     */
    hasVerifiedPeerIdentity() {
        return this.verifiedPeerIdentityRaw !== null;
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
        this.peerIdentityPublicKeyRaw = null;
        this.verifiedPeerIdentityRaw = null;
        this.previousPeerIdentityRaw = null;

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

// Expose globally (browser) or via CommonJS (Node test harness).
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { IdentityKeyManager };
} else {
    window.IdentityKeyManager = IdentityKeyManager;
}
