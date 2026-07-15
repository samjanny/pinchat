/**
 * PinChat MLS — key schedule (RFC 9420 §8).
 *
 * Inputs per epoch:
 *   - init_secret_[n-1] : the previous epoch's init_secret. For a freshly
 *                         created group use the test-vector's
 *                         `initial_init_secret` (or all-zero bytes of
 *                         length Nh when bootstrapping without vectors).
 *   - commit_secret     : output of TreeKEM path-secret chain (or zeros
 *                         if no path was included in the Commit).
 *   - psk_secret        : aggregated PSK secret (all-zero bytes of length
 *                         Nh when no PSKs are used).
 *   - group_context     : serialized GroupContext_[n] (we accept it as a
 *                         byte string — serialization is handled by the
 *                         caller since GroupContext lives outside the key
 *                         schedule).
 *
 * Outputs:
 *   - joiner_secret, welcome_secret, epoch_secret
 *   - sender_data_secret, encryption_secret, exporter_secret,
 *     external_secret, confirmation_key, membership_key, resumption_psk,
 *     epoch_authenticator, init_secret_[n]
 *
 * Formula shape:
 *   joiner_secret = ExpandWithLabel(
 *                       KDF.Extract(init_secret_[n-1], commit_secret),
 *                       "joiner", group_context, Nh)
 *   welcome_secret = DeriveSecret(
 *                       KDF.Extract(joiner_secret, psk_secret),
 *                       "welcome")
 *                  = ExpandWithLabel(
 *                       KDF.Extract(joiner_secret, psk_secret),
 *                       "welcome", "", Nh)
 *   epoch_secret  = ExpandWithLabel(
 *                       KDF.Extract(joiner_secret, psk_secret),
 *                       "epoch", group_context, Nh)
 *   <label>_secret / _key / _psk / _authenticator =
 *       DeriveSecret(epoch_secret, <label>)
 *
 * The concrete `<label>` strings used by DeriveSecret (as chosen by the
 * reference test vectors — see tests/vectors/mls/key-schedule.json) are:
 *   "sender data" (NB: space), "encryption", "exporter", "external",
 *   "confirm", "membership", "resumption", "authentication", "init".
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./hpke.js'), require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.KeySchedule = factory(root.MLS.HPKE, root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (HPKE, Codec) {
    'use strict';

    const enc = new TextEncoder();
    const MLS_LABEL_PREFIX = 'MLS 1.0 ';
    const Nh = HPKE.Nh;

    /**
     * Serialize a KDFLabel struct:
     *   struct {
     *       uint16 length;          // output length in bytes
     *       opaque label<V>;        // "MLS 1.0 " || label
     *       opaque context<V>;
     *   }
     */
    function kdfLabelBytes(length, label, context) {
        const fullLabel = enc.encode(MLS_LABEL_PREFIX + label);
        const encoder = new Codec.Encoder();
        encoder.writeU16(length);
        encoder.writeOpaque(fullLabel);
        encoder.writeOpaque(context);
        return encoder.bytes();
    }

    /**
     * ExpandWithLabel(Secret, Label, Context, Length) =
     *     KDF.Expand(Secret, KDFLabel{Length, "MLS 1.0 "||Label, Context}, Length)
     */
    async function expandWithLabel(secret, label, context, length) {
        const info = kdfLabelBytes(length, label, context);
        return HPKE.hkdfExpand(secret, info, length);
    }

    /**
     * DeriveSecret(Secret, Label) = ExpandWithLabel(Secret, Label, "", Nh)
     */
    async function deriveSecret(secret, label) {
        return expandWithLabel(secret, label, new Uint8Array(0), Nh);
    }

    /**
     * Compute the full key schedule for one epoch transition.
     * All inputs are Uint8Arrays. All outputs are Uint8Arrays of length Nh.
     */
    async function deriveEpoch({ initSecretPrev, commitSecret, pskSecret, groupContext }) {
        if (initSecretPrev.length !== Nh) throw new Error('key-schedule: initSecretPrev wrong length');
        if (commitSecret.length !== Nh) throw new Error('key-schedule: commitSecret wrong length');
        if (pskSecret.length !== Nh) throw new Error('key-schedule: pskSecret wrong length');
        if (!(groupContext instanceof Uint8Array)) throw new Error('key-schedule: groupContext must be Uint8Array');

        let joinerExtract = null;
        let memberSecret = null;
        const derivedOutputs = [];
        let complete = false;
        try {
            // Step 1: join key material
            joinerExtract = await HPKE.hkdfExtract(initSecretPrev, commitSecret);
            const joinerSecret = await expandWithLabel(
                joinerExtract, 'joiner', groupContext, Nh,
            );
            derivedOutputs.push(joinerSecret);

            // Step 2: combine PSK
            memberSecret = await HPKE.hkdfExtract(joinerSecret, pskSecret);

            // Step 3: welcome (context is empty) + epoch (context is group_context)
            const welcomeSecret = await expandWithLabel(
                memberSecret, 'welcome', new Uint8Array(0), Nh,
            );
            derivedOutputs.push(welcomeSecret);
            const epochSecret = await expandWithLabel(
                memberSecret, 'epoch', groupContext, Nh,
            );
            derivedOutputs.push(epochSecret);

            // Step 4: epoch-derived secrets
            const senderDataSecret    = await deriveSecret(epochSecret, 'sender data');
            derivedOutputs.push(senderDataSecret);
            const encryptionSecret    = await deriveSecret(epochSecret, 'encryption');
            derivedOutputs.push(encryptionSecret);
            const exporterSecret      = await deriveSecret(epochSecret, 'exporter');
            derivedOutputs.push(exporterSecret);
            const externalSecret      = await deriveSecret(epochSecret, 'external');
            derivedOutputs.push(externalSecret);
            const confirmationKey     = await deriveSecret(epochSecret, 'confirm');
            derivedOutputs.push(confirmationKey);
            const membershipKey       = await deriveSecret(epochSecret, 'membership');
            derivedOutputs.push(membershipKey);
            const resumptionPsk       = await deriveSecret(epochSecret, 'resumption');
            derivedOutputs.push(resumptionPsk);
            const epochAuthenticator  = await deriveSecret(epochSecret, 'authentication');
            derivedOutputs.push(epochAuthenticator);
            const initSecret          = await deriveSecret(epochSecret, 'init');
            derivedOutputs.push(initSecret);

            complete = true;
            return {
                joinerSecret,
                welcomeSecret,
                epochSecret,
                senderDataSecret,
                encryptionSecret,
                exporterSecret,
                externalSecret,
                confirmationKey,
                membershipKey,
                resumptionPsk,
                epochAuthenticator,
                initSecret,
            };
        } finally {
            // These HKDF intermediates are never part of persistent epoch
            // state. Outputs above are independent Uint8Arrays.
            if (joinerExtract) joinerExtract.fill(0);
            if (memberSecret) memberSecret.fill(0);
            if (!complete) {
                for (const value of derivedOutputs) value.fill(0);
            }
        }
    }

    /**
     * MLS exporter (§8.5):
     *   MLS-Exporter(label, context, length) =
     *     ExpandWithLabel(
     *       DeriveSecret(exporter_secret, label),
     *       "exported",
     *       Hash(context),
     *       length)
     *
     * We leave the `Hash(context)` to the caller since we don't export
     * SHA-256 as a separate helper — HPKE.hkdfExtract with a zero-key
     * achieves the same effect, or the caller can use SubtleCrypto.digest.
     */
    async function mlsExporter(exporterSecret, label, contextHash, length) {
        const derived = await deriveSecret(exporterSecret, label);
        try {
            return await expandWithLabel(derived, 'exported', contextHash, length);
        } finally {
            derived.fill(0);
        }
    }

    return Object.freeze({
        kdfLabelBytes,
        expandWithLabel,
        deriveSecret,
        deriveEpoch,
        mlsExporter,
        Nh,
    });
});
