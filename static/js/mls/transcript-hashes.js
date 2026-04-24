/**
 * PinChat MLS — transcript hashes (RFC 9420 §5.3 + §8.2).
 *
 * Every committed state transition is bound into a two-hash transcript
 * chain so that joiners can verify a consistent group history:
 *
 *   confirmed_transcript_hash_[n] = Hash(
 *       interim_transcript_hash_[n-1] ||
 *       serialize(ConfirmedTranscriptHashInput_[n])
 *   )
 *
 *   confirmation_tag_[n] = MAC(confirmation_key_[n],
 *                               confirmed_transcript_hash_[n])
 *
 *   interim_transcript_hash_[n] = Hash(
 *       confirmed_transcript_hash_[n] ||
 *       serialize_opaque(confirmation_tag_[n])
 *   )
 *
 * Where:
 *   - ConfirmedTranscriptHashInput is serialize(wire_format ||
 *     FramedContent || signature) — i.e. the AuthenticatedContent minus
 *     the trailing `opaque<V>` confirmation_tag.
 *   - The MAC is HMAC-SHA256 with the current epoch's confirmation_key.
 *   - In the interim hash, confirmation_tag is wrapped as `opaque<V>` —
 *     a single-byte varint length prefix (0x20) followed by the 32
 *     HMAC-SHA256 output bytes.
 *
 * This module hands both hash derivations and the confirmation_tag
 * computation. It expects the caller to have already serialized
 * ConfirmedTranscriptHashInput; that serialization lives in the framing
 * module (to be added) because it requires the full FramedContent
 * structure.
 *
 * Verified byte-for-byte against the IETF transcript-hashes.json vectors
 * — see tests/test-mls-transcript-hashes.js.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'), require('./hpke.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.TranscriptHashes = factory(root.MLS.Codec, root.MLS.HPKE);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, HPKE) {
    'use strict';

    function getSubtle() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        // eslint-disable-next-line global-require
        const { webcrypto } = require('crypto');
        return webcrypto.subtle;
    }

    async function sha256(data) {
        return new Uint8Array(await getSubtle().digest('SHA-256', data));
    }

    /**
     * Compute confirmation_tag = HMAC-SHA256(confirmation_key,
     *                                        confirmed_transcript_hash).
     */
    async function confirmationTag(confirmationKey, confirmedTranscriptHash) {
        return HPKE.hmacSha256(confirmationKey, confirmedTranscriptHash);
    }

    /**
     * confirmed_transcript_hash_[n] = Hash(
     *     interim_transcript_hash_[n-1] ||
     *     confirmed_transcript_hash_input_bytes
     * )
     *
     * `confirmedTranscriptHashInputBytes` must be the already-serialized
     * ConfirmedTranscriptHashInput (wire_format || FramedContent ||
     * opaque<V>(signature)). The caller — typically the framing module —
     * produces these bytes.
     */
    async function confirmedTranscriptHash(interimTranscriptHashPrev, confirmedTranscriptHashInputBytes) {
        return sha256(Codec.concatBytes([interimTranscriptHashPrev, confirmedTranscriptHashInputBytes]));
    }

    /**
     * interim_transcript_hash_[n] = Hash(
     *     confirmed_transcript_hash_[n] ||
     *     serialize_opaque(confirmation_tag_[n])
     * )
     */
    async function interimTranscriptHash(confirmedTranscriptHashValue, confirmationTagValue) {
        const encoder = new Codec.Encoder();
        encoder.writeBytes(confirmedTranscriptHashValue);
        encoder.writeOpaque(confirmationTagValue);
        return sha256(encoder.bytes());
    }

    /**
     * Convenience: apply a full Commit transition to the transcript
     * chain. Inputs:
     *   - interimTranscriptHashPrev : 32 bytes
     *   - confirmationKey           : 32 bytes (this epoch's)
     *   - confirmedInputBytes       : bytes of ConfirmedTranscriptHashInput
     *
     * Returns {confirmedTranscriptHashAfter, confirmationTag,
     *          interimTranscriptHashAfter}.
     */
    async function applyCommit(interimTranscriptHashPrev, confirmationKey, confirmedInputBytes) {
        const cth = await confirmedTranscriptHash(interimTranscriptHashPrev, confirmedInputBytes);
        const tag = await confirmationTag(confirmationKey, cth);
        const interim = await interimTranscriptHash(cth, tag);
        return {
            confirmedTranscriptHashAfter: cth,
            confirmationTag: tag,
            interimTranscriptHashAfter: interim,
        };
    }

    return Object.freeze({
        sha256,
        confirmationTag,
        confirmedTranscriptHash,
        interimTranscriptHash,
        applyCommit,
    });
});
