/**
 * PinChat MLS — "labeled operations" (RFC 9420 §5).
 *
 * This module provides the top-level labeled wrappers the MLS spec
 * layers over the raw cryptographic primitives:
 *
 *   §5.2 RefHash(label, value) = Hash(serialize(RefHashInput))
 *
 *   §5.1.1 SignWithLabel / VerifyWithLabel — wraps ECDSA P-256 over
 *          serialize(SignContent{label="MLS 1.0 "+Label, content}).
 *
 *   §5.1.2 EncryptWithLabel / DecryptWithLabel — wraps HPKE-SealBase /
 *          OpenBase with info = serialize(EncryptContext{label, context})
 *          and empty AAD.
 *
 * Current scope
 * -------------
 * Only RefHash is implemented here for now; SignWithLabel and
 * EncryptWithLabel will land in follow-up commits alongside the modules
 * that need them (KeyPackage, Welcome). Placing the RFC §5 wrappers in
 * one file keeps the API surface flat and avoids circular imports.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Labeled = factory(root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    const enc = new TextEncoder();
    const MLS_LABEL_PREFIX = 'MLS 1.0 ';

    function getSubtle() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        // eslint-disable-next-line global-require
        const { webcrypto } = require('crypto');
        return webcrypto.subtle;
    }

    async function sha256(data) {
        const d = await getSubtle().digest('SHA-256', data);
        return new Uint8Array(d);
    }

    /**
     * RefHash(label, value) from RFC 9420 §5.2.
     *
     *   struct {
     *       opaque label<V>;
     *       opaque value<V>;
     *   } RefHashInput;
     *
     *   RefHash(label, value) = Hash(serialize(RefHashInput{label, value}))
     *
     * Unlike the KDF / Sign / Encrypt labels, RefHash does *not* prefix
     * the label with "MLS 1.0 " — verified empirically against the IETF
     * crypto-basics.json vectors.
     *
     * `label` is a JS string (written verbatim as the opaque label bytes).
     * `value` is a Uint8Array.
     */
    async function refHash(label, value) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(enc.encode(label));
        encoder.writeOpaque(value);
        return sha256(encoder.bytes());
    }

    return Object.freeze({
        refHash,
        sha256,
        MLS_LABEL_PREFIX,
    });
});
