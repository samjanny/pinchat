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
        module.exports = factory(
            require('./codec.js'),
            require('./signature.js'),
            require('./hpke.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Labeled = factory(root.MLS.Codec, root.MLS.Signature, root.MLS.HPKE);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Signature, HPKE) {
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

    /**
     * Serialize a SignContent for §5.1.1 SignWithLabel / VerifyWithLabel:
     *
     *   struct {
     *       opaque label<V>;    // "MLS 1.0 " || Label
     *       opaque content<V>;
     *   } SignContent;
     */
    function signContentBytes(label, content) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(enc.encode(MLS_LABEL_PREFIX + label));
        encoder.writeOpaque(content);
        return encoder.bytes();
    }

    /**
     * SignWithLabel(SignatureKey, Label, Content):
     *   Sign(SignatureKey, serialize(SignContent{"MLS 1.0 "||Label, Content}))
     *
     * Returns the DER-encoded ECDSA signature bytes.
     */
    async function signWithLabel(privateKey, label, content) {
        return Signature.sign(privateKey, signContentBytes(label, content));
    }

    /**
     * VerifyWithLabel(VerificationKey, Label, Content, SignatureValue):
     *   Verify(VerificationKey,
     *          serialize(SignContent{"MLS 1.0 "||Label, Content}),
     *          SignatureValue)
     *
     * `signatureValue` is DER-encoded (as emitted by signWithLabel and as
     * carried on the wire). Returns a boolean.
     */
    async function verifyWithLabel(publicKey, label, content, signatureValue) {
        return Signature.verify(publicKey, signContentBytes(label, content), signatureValue);
    }

    /**
     * Serialize an EncryptContext for §5.1.2:
     *
     *   struct {
     *       opaque label<V>;       // "MLS 1.0 " || Label
     *       opaque context<V>;
     *   } EncryptContext;
     */
    function encryptContextBytes(label, context) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(enc.encode(MLS_LABEL_PREFIX + label));
        encoder.writeOpaque(context);
        return encoder.bytes();
    }

    /**
     * EncryptWithLabel(PublicKey, Label, Context, Plaintext):
     *   encrypt_context = EncryptContext{"MLS 1.0 "||Label, Context}
     *   HPKE-SealBase(PublicKey, encrypt_context, aad="", Plaintext)
     *
     * `publicKey` may be either raw uncompressed 65-byte P-256 bytes or a
     * CryptoKey. Returns { kemOutput, ciphertext }.
     */
    async function encryptWithLabel(publicKey, label, context, plaintext) {
        const info = encryptContextBytes(label, context);
        const { enc: kemOutput, ct } = await HPKE.seal(publicKey, info, new Uint8Array(0), plaintext);
        return { kemOutput, ciphertext: ct };
    }

    /**
     * DecryptWithLabel(PrivateKey, Label, Context, KEMOutput, Ciphertext):
     *   encrypt_context = EncryptContext{"MLS 1.0 "||Label, Context}
     *   HPKE-OpenBase(PrivateKey, KEMOutput, encrypt_context, "", Ciphertext)
     *
     * `privateKey` is the recipient's ECDH P-256 CryptoKey (deriveBits
     * capable). `publicKeyBytes` is the recipient's public key as bytes
     * — required by HPKE's key-schedule context.
     */
    async function decryptWithLabel(privateKey, publicKeyBytes, label, context, kemOutput, ciphertext) {
        const info = encryptContextBytes(label, context);
        return HPKE.open(kemOutput, privateKey, publicKeyBytes, info, new Uint8Array(0), ciphertext);
    }

    return Object.freeze({
        refHash,
        sha256,
        signWithLabel,
        verifyWithLabel,
        signContentBytes,
        encryptWithLabel,
        decryptWithLabel,
        encryptContextBytes,
        MLS_LABEL_PREFIX,
    });
});
