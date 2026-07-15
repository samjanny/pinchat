/**
 * PinChat MLS — PrivateMessage (RFC 9420 §6.3).
 *
 *   struct {
 *       opaque group_id<V>;
 *       uint64 epoch;
 *       ContentType content_type;
 *       opaque authenticated_data<V>;
 *       opaque encrypted_sender_data<V>;
 *       opaque ciphertext<V>;
 *   } PrivateMessage;
 *
 * The `ciphertext` is AEAD over the per-leaf/generation ratchet key &
 * nonce from the secret tree. The plaintext is PrivateMessageContent:
 *
 *   struct {
 *       select (PrivateMessage.content_type) {
 *           case application: opaque application_data<V>;
 *           case proposal:    Proposal proposal;
 *           case commit:      Commit commit;
 *       };
 *       FramedContentAuthData auth;
 *       opaque padding[arbitrary];   // zero-filled, length implicit
 *   } PrivateMessageContent;
 *
 * AAD for `ciphertext`:
 *
 *   struct {
 *       opaque group_id<V>;
 *       uint64 epoch;
 *       ContentType content_type;
 *       opaque authenticated_data<V>;
 *   } PrivateContentAAD;
 *
 * The `encrypted_sender_data` AEAD uses sender_data_key / sender_data_nonce
 * (derived from sender_data_secret and a sample of `ciphertext` — see
 * secret-tree.js), with AAD = SenderDataAAD:
 *
 *   struct {
 *       opaque group_id<V>;
 *       uint64 epoch;
 *       ContentType content_type;
 *   } SenderDataAAD;
 *
 * SenderData payload:
 *
 *   struct {
 *       uint32 leaf_index;
 *       uint32 generation;
 *       opaque reuse_guard[4];
 *   } SenderData;
 *
 * Ratchet-nonce masking: the per-generation nonce is XORed with the
 * 4-byte reuse_guard in its *first* 4 bytes (remaining bytes unchanged)
 * before being used as the AEAD nonce for the ciphertext.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./framing.js'),
            require('./secret-tree.js'),
            require('./hpke.js'),
            require('./proposal.js'),
            require('./commit.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.PrivateMessage = factory(
            root.MLS.Codec, root.MLS.Framing, root.MLS.SecretTree,
            root.MLS.HPKE, root.MLS.Proposal, root.MLS.Commit,
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Framing, SecretTree, HPKE, Proposal, Commit) {
    'use strict';

    function getSubtle() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        // eslint-disable-next-line global-require
        const { webcrypto } = require('crypto');
        return webcrypto.subtle;
    }

    // --- Wire serde -------------------------------------------------------

    function writePrivateMessage(encoder, pm) {
        encoder.writeOpaque(pm.groupId);
        encoder.writeU64(pm.epoch);
        encoder.writeU8(pm.contentType);
        encoder.writeOpaque(pm.authenticatedData);
        encoder.writeOpaque(pm.encryptedSenderData);
        encoder.writeOpaque(pm.ciphertext);
    }

    function readPrivateMessage(decoder) {
        return {
            groupId: decoder.readOpaque(),
            epoch: decoder.readU64(),
            contentType: decoder.readU8(),
            authenticatedData: decoder.readOpaque(),
            encryptedSenderData: decoder.readOpaque(),
            ciphertext: decoder.readOpaque(),
        };
    }

    function privateMessageBytes(pm) {
        const encoder = new Codec.Encoder();
        writePrivateMessage(encoder, pm);
        return encoder.bytes();
    }

    function parsePrivateMessage(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const pm = readPrivateMessage(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`private_message: ${decoder.remaining()} trailing bytes`);
        }
        return pm;
    }

    // --- SenderData / SenderDataAAD --------------------------------------

    function senderDataBytes(sd) {
        const encoder = new Codec.Encoder();
        encoder.writeU32(sd.leafIndex);
        encoder.writeU32(sd.generation);
        encoder.writeBytes(sd.reuseGuard);
        return encoder.bytes();
    }

    function parseSenderData(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const leafIndex = decoder.readU32();
        const generation = decoder.readU32();
        const reuseGuard = decoder.readBytes(4);
        if (decoder.remaining() !== 0) {
            throw new Error(`sender_data: ${decoder.remaining()} trailing bytes`);
        }
        return { leafIndex, generation, reuseGuard };
    }

    function senderDataAadBytes(groupId, epoch, contentType) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(groupId);
        encoder.writeU64(epoch);
        encoder.writeU8(contentType);
        return encoder.bytes();
    }

    function privateContentAadBytes(groupId, epoch, contentType, authenticatedData) {
        const encoder = new Codec.Encoder();
        encoder.writeOpaque(groupId);
        encoder.writeU64(epoch);
        encoder.writeU8(contentType);
        encoder.writeOpaque(authenticatedData);
        return encoder.bytes();
    }

    // --- AEAD helpers ----------------------------------------------------

    async function aesGcmDecrypt(keyBytes, nonce, aad, ct) {
        const k = await getSubtle().importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
        );
        const pt = await getSubtle().decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
            k, ct,
        );
        return new Uint8Array(pt);
    }

    async function aesGcmEncrypt(keyBytes, nonce, aad, pt) {
        const k = await getSubtle().importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']
        );
        const ct = await getSubtle().encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
            k, pt,
        );
        return new Uint8Array(ct);
    }

    /**
     * Apply reuse_guard: XOR the first 4 bytes of `nonce` with the 4-byte
     * `reuseGuard`, leaving the remaining bytes unchanged.
     */
    function applyReuseGuard(nonce, reuseGuard) {
        if (reuseGuard.length !== 4) {
            throw new Error('private-message: reuse_guard must be 4 bytes');
        }
        const out = new Uint8Array(nonce);
        for (let i = 0; i < 4; i += 1) out[i] ^= reuseGuard[i];
        return out;
    }

    // --- Content plaintext layout ---------------------------------------

    /**
     * Build the plaintext of `ciphertext` before encryption:
     *   <inline payload bytes> || FramedContentAuthData || padding (zeros)
     *
     * For content_type == application, "inline payload" is opaque<V>
     * around application_data. For proposal/commit it's the raw struct
     * bytes (Proposal.writeProposal / Commit.writeCommit output).
     */
    function privateMessageContentBytes(contentType, payloadBytes, auth, paddingLen) {
        const encoder = new Codec.Encoder();
        if (contentType === Framing.ContentType.APPLICATION) {
            encoder.writeOpaque(payloadBytes);
        } else if (contentType === Framing.ContentType.PROPOSAL
                || contentType === Framing.ContentType.COMMIT) {
            encoder.writeBytes(payloadBytes);
        } else {
            throw new Error(`private-message: unsupported content_type ${contentType}`);
        }
        Framing.writeFramedContentAuthData(encoder, auth, contentType);
        if (paddingLen > 0) {
            encoder.writeBytes(new Uint8Array(paddingLen));
        }
        return encoder.bytes();
    }

    /**
     * Reverse of privateMessageContentBytes. Returns
     *   { payloadBytes, payloadParsed, auth, paddingLen }
     * For non-application content, `payloadParsed` is the result of
     * readProposal / readCommit. Trailing bytes after auth are treated
     * as zero-padding and discarded (the padding length is reported).
     */
    function parsePrivateMessageContent(bytes, contentType) {
        const decoder = new Codec.Decoder(bytes);
        let payloadBytes;
        let payloadParsed = null;

        if (contentType === Framing.ContentType.APPLICATION) {
            payloadBytes = decoder.readOpaque();
        } else if (contentType === Framing.ContentType.PROPOSAL) {
            const start = decoder.pos;
            payloadParsed = Proposal.readProposal(decoder);
            payloadBytes = bytes.slice(start, decoder.pos);
        } else if (contentType === Framing.ContentType.COMMIT) {
            const start = decoder.pos;
            payloadParsed = Commit.readCommit(decoder);
            payloadBytes = bytes.slice(start, decoder.pos);
        } else {
            throw new Error(`private-message: unsupported content_type ${contentType}`);
        }

        const auth = Framing.readFramedContentAuthData(decoder, contentType);
        const paddingLen = decoder.remaining();
        // Check padding is all zeros.
        const padding = decoder.readBytes(paddingLen);
        for (let i = 0; i < padding.length; i += 1) {
            if (padding[i] !== 0) {
                throw new Error(`private-message: non-zero padding byte at offset ${i}`);
            }
        }
        return { payloadBytes, payloadParsed, auth, paddingLen };
    }

    // --- Decrypt -----------------------------------------------------------

    /**
     * Full decrypt of a PrivateMessage. Inputs:
     *   pm                 : parsed PrivateMessage struct
     *   senderDataSecret   : 32 bytes
     *   encryptionSecret   : 32 bytes (key-schedule output)
     *   nLeaves            : tree size (used to walk the secret tree)
     *
     * Returns { senderData, content } where `content` is the parsed
     * PrivateMessageContent (payloadBytes/Parsed + auth + paddingLen).
     */
    async function decryptPrivateMessage({
        pm, senderDataSecret, encryptionSecret, nLeaves, keyNonceProvider,
    }) {
        // 1. Decrypt sender_data.
        let sdKey = null;
        let sdNonce = null;
        let sdPlain = null;
        let senderData;
        try {
            ({ key: sdKey, nonce: sdNonce } = await SecretTree.senderDataKeyNonce(
                senderDataSecret, pm.ciphertext,
            ));
            const sdAad = senderDataAadBytes(pm.groupId, pm.epoch, pm.contentType);
            sdPlain = await aesGcmDecrypt(
                sdKey, sdNonce, sdAad, pm.encryptedSenderData,
            );
            senderData = parseSenderData(sdPlain);
        } finally {
            if (sdKey) sdKey.fill(0);
            if (sdNonce) sdNonce.fill(0);
            if (sdPlain) sdPlain.fill(0);
        }

        // 2. Derive the per-leaf ratchet key/nonce. When the caller
        // supplies a keyNonceProvider (Group's stateful forward-secret
        // chains), that is authoritative: it deletes consumed keys and
        // rejects replays. The stateless fallback derives from the chain
        // root and is retained for the IETF vector tests.
        const which = (pm.contentType === Framing.ContentType.APPLICATION)
            ? 'application' : 'handshake';
        let key = null;
        let baseNonce = null;
        let nonce = null;
        let leafSec = null;
        let chainRoot = null;
        let plaintext = null;
        try {
            if (keyNonceProvider) {
                ({ key, nonce: baseNonce } = await keyNonceProvider(
                    senderData.leafIndex, which, senderData.generation,
                ));
            } else {
                leafSec = await SecretTree.leafSecret(
                    encryptionSecret, senderData.leafIndex, nLeaves,
                );
                chainRoot = await SecretTree.leafChainRoot(leafSec, which);
                const derived = await SecretTree.keyNonceAtGeneration(
                    chainRoot, senderData.generation,
                );
                key = derived.key;
                baseNonce = derived.nonce;
                derived.nextSecret.fill(0);
            }
            nonce = applyReuseGuard(baseNonce, senderData.reuseGuard);

            // 3. Decrypt the ciphertext.
            const aad = privateContentAadBytes(
                pm.groupId, pm.epoch, pm.contentType, pm.authenticatedData,
            );
            plaintext = await aesGcmDecrypt(key, nonce, aad, pm.ciphertext);
            const content = parsePrivateMessageContent(plaintext, pm.contentType);
            return { senderData, content };
        } finally {
            if (key) key.fill(0);
            if (baseNonce) baseNonce.fill(0);
            if (nonce) nonce.fill(0);
            if (plaintext) plaintext.fill(0);
            if (chainRoot) chainRoot.fill(0);
            if (leafSec && leafSec !== encryptionSecret) leafSec.fill(0);
        }
    }

    /**
     * Encrypt a PrivateMessage. Inputs mirror decryptPrivateMessage
     * plus the senderData and padding length.
     *
     * `payloadBytes` is the *inner* payload (raw application_data or
     * serialised Proposal/Commit — not wrapped for application case;
     * this function wraps as opaque<V> when content_type is application).
     */
    async function encryptPrivateMessage({
        groupId, epoch, contentType, authenticatedData,
        payloadBytes, auth,
        senderData, paddingLen = 0,
        senderDataSecret, encryptionSecret, nLeaves, keyNonceProvider,
    }) {
        // Derive ratchet key/nonce for this sender/generation. Stateful
        // provider preferred (forward secrecy); stateless fallback for
        // the IETF vector tests.
        const which = (contentType === Framing.ContentType.APPLICATION)
            ? 'application' : 'handshake';
        let key = null;
        let baseNonce = null;
        let nonce = null;
        let leafSec = null;
        let chainRoot = null;
        let plaintext = null;
        let senderDataPlain = null;
        let sdKey = null;
        let sdNonce = null;
        try {
            if (keyNonceProvider) {
                ({ key, nonce: baseNonce } = await keyNonceProvider(
                    senderData.leafIndex, which, senderData.generation,
                ));
            } else {
                leafSec = await SecretTree.leafSecret(
                    encryptionSecret, senderData.leafIndex, nLeaves,
                );
                chainRoot = await SecretTree.leafChainRoot(leafSec, which);
                const derived = await SecretTree.keyNonceAtGeneration(
                    chainRoot, senderData.generation,
                );
                key = derived.key;
                baseNonce = derived.nonce;
                derived.nextSecret.fill(0);
            }
            nonce = applyReuseGuard(baseNonce, senderData.reuseGuard);

            plaintext = privateMessageContentBytes(
                contentType, payloadBytes, auth, paddingLen,
            );
            const aad = privateContentAadBytes(
                groupId, epoch, contentType, authenticatedData,
            );
            const ciphertext = await aesGcmEncrypt(key, nonce, aad, plaintext);

            // Encrypt sender_data.
            ({ key: sdKey, nonce: sdNonce } = await SecretTree.senderDataKeyNonce(
                senderDataSecret, ciphertext,
            ));
            const sdAad = senderDataAadBytes(groupId, epoch, contentType);
            senderDataPlain = senderDataBytes(senderData);
            const encryptedSenderData = await aesGcmEncrypt(
                sdKey, sdNonce, sdAad, senderDataPlain,
            );

            return {
                groupId, epoch, contentType, authenticatedData,
                encryptedSenderData, ciphertext,
            };
        } finally {
            if (key) key.fill(0);
            if (baseNonce) baseNonce.fill(0);
            if (nonce) nonce.fill(0);
            if (leafSec && leafSec !== encryptionSecret) leafSec.fill(0);
            if (chainRoot) chainRoot.fill(0);
            if (plaintext) plaintext.fill(0);
            if (senderDataPlain) senderDataPlain.fill(0);
            if (sdKey) sdKey.fill(0);
            if (sdNonce) sdNonce.fill(0);
        }
    }

    return Object.freeze({
        // Wire serde
        writePrivateMessage,
        readPrivateMessage,
        privateMessageBytes,
        parsePrivateMessage,
        // Struct helpers
        senderDataBytes,
        parseSenderData,
        senderDataAadBytes,
        privateContentAadBytes,
        privateMessageContentBytes,
        parsePrivateMessageContent,
        applyReuseGuard,
        // Crypto
        decryptPrivateMessage,
        encryptPrivateMessage,
    });
});
