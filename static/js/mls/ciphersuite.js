/**
 * PinChat MLS — ciphersuite profile.
 *
 * We commit to a single MLS ciphersuite end-to-end so the protocol stays
 * auditable and implementable with WebCrypto alone, with no vendored
 * cryptographic libraries.
 *
 *   Ciphersuite 0x0002 — MLS_128_DHKEMP256_AES128GCM_SHA256_P256
 *     KEM        : DHKEM(P-256, HKDF-SHA256)     kem_id  = 0x0010
 *     KDF        : HKDF-SHA256                   kdf_id  = 0x0001
 *     AEAD       : AES-128-GCM                   aead_id = 0x0001
 *     Signature  : ECDSA over P-256 with SHA-256
 *
 * Rationale:
 *   - P-256, HKDF-SHA256 and AES-GCM are already present in the PinChat
 *     1:1 crypto (see crypto.js, double-ratchet.js, ecdh.js). No new
 *     primitive is added to the TCB for group chats.
 *   - Every primitive is available natively through the WebCrypto
 *     `SubtleCrypto` interface, so the implementation stays bundler-free
 *     and has no external JavaScript dependency.
 *   - Ciphersuite 0x0002 is a first-class citizen of RFC 9420.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Ciphersuite = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const CIPHERSUITE_ID = 0x0002;
    const KEM_ID = 0x0010;
    const KDF_ID = 0x0001;
    const AEAD_ID = 0x0001;

    // Lengths, in bytes, for the chosen primitives.
    const LENGTHS = Object.freeze({
        Nh: 32,    // HKDF-SHA256 output
        Nk: 16,    // AES-128 key
        Nn: 12,    // AES-GCM nonce
        Nt: 16,    // AES-GCM auth tag
        Npk: 65,   // P-256 uncompressed public key (0x04 || X || Y)
        Nsk: 32,   // P-256 private scalar
        Nsecret: 32, // DHKEM shared secret (HKDF output width)
        Nsig: 64,  // ECDSA P-256 raw r||s signature
    });

    /**
     * HPKE suite_id for RFC 9180 labeled operations:
     *   suite_id = "HPKE" || I2OSP(kem_id,2) || I2OSP(kdf_id,2) || I2OSP(aead_id,2)
     */
    function hpkeSuiteId() {
        const prefix = new TextEncoder().encode('HPKE');
        const out = new Uint8Array(prefix.length + 6);
        out.set(prefix, 0);
        out[prefix.length + 0] = (KEM_ID >> 8) & 0xff;
        out[prefix.length + 1] = KEM_ID & 0xff;
        out[prefix.length + 2] = (KDF_ID >> 8) & 0xff;
        out[prefix.length + 3] = KDF_ID & 0xff;
        out[prefix.length + 4] = (AEAD_ID >> 8) & 0xff;
        out[prefix.length + 5] = AEAD_ID & 0xff;
        return out;
    }

    /**
     * DHKEM suite_id for RFC 9180 labeled operations at the KEM layer:
     *   kem_suite_id = "KEM" || I2OSP(kem_id, 2)
     */
    function kemSuiteId() {
        const prefix = new TextEncoder().encode('KEM');
        const out = new Uint8Array(prefix.length + 2);
        out.set(prefix, 0);
        out[prefix.length + 0] = (KEM_ID >> 8) & 0xff;
        out[prefix.length + 1] = KEM_ID & 0xff;
        return out;
    }

    /**
     * MLS application-level label prefix (RFC 9420 §8):
     *   MLS-v1 labels are used outside HPKE itself.
     */
    const MLS_LABEL_PREFIX = 'MLS 1.0 ';

    return Object.freeze({
        CIPHERSUITE_ID,
        KEM_ID,
        KDF_ID,
        AEAD_ID,
        LENGTHS,
        MLS_LABEL_PREFIX,
        hpkeSuiteId,
        kemSuiteId,
    });
});
