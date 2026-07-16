/**
 * PinChat MLS — Welcome (RFC 9420 §12.4).
 *
 * A Welcome is the message a committer sends to each new group member
 * alongside the broadcast Commit. It carries:
 *
 *   - an HPKE-encrypted `GroupSecrets` blob for every new member,
 *     keyed to that member's KeyPackage init_key
 *   - the AEAD-encrypted GroupInfo (common to all joiners)
 *
 *   struct {
 *       CipherSuite cipher_suite;
 *       EncryptedGroupSecrets secrets<V>;
 *       opaque encrypted_group_info<V>;
 *   } Welcome;
 *
 *   struct {
 *       opaque new_member<V>;           // KeyPackage reference
 *       HPKECiphertext encrypted_group_secrets;
 *   } EncryptedGroupSecrets;
 *
 *   struct {
 *       opaque joiner_secret<V>;
 *       optional<PathSecret> path_secret;
 *       PreSharedKeyID psks<V>;
 *   } GroupSecrets;
 *
 *   struct {
 *       opaque path_secret<V>;
 *   } PathSecret;
 *
 * Deriving the welcome AEAD keys:
 *   welcome_key   = ExpandWithLabel(welcome_secret, "key",   "", Nk)
 *   welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", Nn)
 *   encrypted_group_info = AES-128-GCM_Seal(welcome_key, welcome_nonce,
 *                                            aad="", GroupInfo_bytes)
 *
 * Welcome secrets are HPKE-encrypted to each joiner with:
 *   EncryptWithLabel(init_key, "Welcome",
 *                    context=encrypted_group_info_bytes,
 *                    plaintext=GroupSecrets_bytes)
 *
 * PreSharedKeyID
 * --------------
 * Full PSK serialization is deferred — PinChat does not use PSKs, so the
 * psks<V> field is always empty in our Welcome messages. Incoming PSK
 * vectors are parsed as an opaque blob (decoder reads psks<V> as a
 * vector of opaque<V> so unknown types don't abort parsing).
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(
            require('./codec.js'),
            require('./nodes.js'),
            require('./labeled.js'),
            require('./key-schedule.js'),
            require('./hpke.js'),
        );
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Welcome = factory(
            root.MLS.Codec, root.MLS.Nodes, root.MLS.Labeled,
            root.MLS.KeySchedule, root.MLS.HPKE
        );
    }
})(typeof self !== 'undefined' ? self : this, function (Codec, Nodes, Labeled, KeySchedule, HPKE) {
    'use strict';

    // --- PreSharedKeyID ---------------------------------------------------
    //
    // enum {
    //   reserved(0), external(1), resumption(2), (255)
    // } PSKType;
    //
    //   struct {
    //       PSKType psktype;
    //       select (PreSharedKeyID.psktype) {
    //           case external:   opaque psk_id<V>;
    //           case resumption: ResumptionPSKUsage usage;
    //                            opaque psk_group_id<V>;
    //                            uint64 psk_epoch;
    //       };
    //       opaque psk_nonce<V>;
    //   } PreSharedKeyID;
    //
    // PinChat never emits PSKs, but we still parse them to stay spec-
    // compliant on the receive side. We roundtrip by preserving the raw
    // serialized bytes of each entry.

    function readPreSharedKeyID(decoder) {
        const psktype = decoder.readU8();
        const out = { psktype };
        if (psktype === 1) {
            out.pskId = decoder.readOpaque();
        } else if (psktype === 2) {
            out.usage = decoder.readU8();
            out.pskGroupId = decoder.readOpaque();
            out.pskEpoch = decoder.readU64();
        } else {
            throw new Error(`psk: unsupported psktype ${psktype}`);
        }
        out.pskNonce = decoder.readOpaque();
        return out;
    }

    function writePreSharedKeyID(encoder, psk) {
        encoder.writeU8(psk.psktype);
        if (psk.psktype === 1) {
            encoder.writeOpaque(psk.pskId);
        } else if (psk.psktype === 2) {
            encoder.writeU8(psk.usage);
            encoder.writeOpaque(psk.pskGroupId);
            encoder.writeU64(psk.pskEpoch);
        } else {
            throw new Error(`psk: unsupported psktype ${psk.psktype}`);
        }
        encoder.writeOpaque(psk.pskNonce);
    }

    // --- GroupSecrets -----------------------------------------------------

    function readGroupSecrets(decoder) {
        const joinerSecret = decoder.readOpaque();
        const pathSecret = Nodes.readOptional(decoder, (d) => d.readOpaque());
        const psks = decoder.readVector(readPreSharedKeyID);
        return { joinerSecret, pathSecret, psks };
    }

    function writeGroupSecrets(encoder, gs) {
        encoder.writeOpaque(gs.joinerSecret);
        Nodes.writeOptional(encoder, gs.pathSecret, (e, v) => e.writeOpaque(v));
        encoder.writeVector(gs.psks || [], writePreSharedKeyID);
    }

    function groupSecretsBytes(gs) {
        const encoder = new Codec.Encoder();
        writeGroupSecrets(encoder, gs);
        return encoder.bytes();
    }

    function parseGroupSecrets(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const gs = readGroupSecrets(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`group_secrets: ${decoder.remaining()} trailing bytes`);
        }
        return gs;
    }

    // --- EncryptedGroupSecrets + Welcome ----------------------------------

    function readEncryptedGroupSecrets(decoder) {
        return {
            newMember: decoder.readOpaque(),
            encryptedGroupSecrets: Nodes.readHPKECiphertext(decoder),
        };
    }

    function writeEncryptedGroupSecrets(encoder, egs) {
        encoder.writeOpaque(egs.newMember);
        Nodes.writeHPKECiphertext(encoder, egs.encryptedGroupSecrets);
    }

    function readWelcome(decoder) {
        return {
            cipherSuite: decoder.readU16(),
            secrets: decoder.readVector(readEncryptedGroupSecrets),
            encryptedGroupInfo: decoder.readOpaque(),
        };
    }

    function writeWelcome(encoder, w) {
        encoder.writeU16(w.cipherSuite);
        encoder.writeVector(w.secrets, writeEncryptedGroupSecrets);
        encoder.writeOpaque(w.encryptedGroupInfo);
    }

    function welcomeBytes(w) {
        const encoder = new Codec.Encoder();
        writeWelcome(encoder, w);
        return encoder.bytes();
    }

    function parseWelcome(bytes) {
        const decoder = new Codec.Decoder(bytes);
        const w = readWelcome(decoder);
        if (decoder.remaining() !== 0) {
            throw new Error(`welcome: ${decoder.remaining()} trailing bytes`);
        }
        return w;
    }

    // --- Crypto: decrypt GroupSecrets, decrypt GroupInfo -----------------

    /**
     * HPKE-decrypt one Welcome secret for this joiner using
     *   DecryptWithLabel(init_priv, init_pub, "Welcome",
     *                    context = encrypted_group_info_bytes,
     *                    kem_output, ciphertext)
     * and return the parsed GroupSecrets.
     */
    async function decryptGroupSecrets(encryptedGroupSecrets, initPrivateKey, initPublicKeyBytes, encryptedGroupInfoBytes) {
        const pt = await Labeled.decryptWithLabel(
            initPrivateKey,
            initPublicKeyBytes,
            'Welcome',
            encryptedGroupInfoBytes,
            encryptedGroupSecrets.kemOutput,
            encryptedGroupSecrets.ciphertext,
        );
        try {
            return parseGroupSecrets(pt);
        } finally {
            // parseGroupSecrets returns independent Uint8Array fields. The
            // decrypted aggregate still contains joiner_secret/path_secret
            // and must not survive solely until garbage collection.
            pt.fill(0);
        }
    }

    /**
     * Derive the welcome AEAD key + nonce from welcome_secret. Both are
     * HKDF-Expand outputs labelled with "key" and "nonce". welcome_secret
     * itself comes from the key schedule (ExpandWithLabel of
     * KDF.Extract(joiner_secret, psk_secret) with label "welcome").
     */
    async function welcomeKeyNonce(welcomeSecret) {
        let key = null;
        let nonce = null;
        try {
            key = await KeySchedule.expandWithLabel(
                welcomeSecret, 'key', new Uint8Array(0), HPKE.Nk,
            );
            nonce = await KeySchedule.expandWithLabel(
                welcomeSecret, 'nonce', new Uint8Array(0), HPKE.Nn,
            );
            const result = { key, nonce };
            key = null;
            nonce = null;
            return result;
        } finally {
            // On success ownership transfers to the caller. On a partial KDF
            // failure, erase every output that was already derived.
            if (key) key.fill(0);
            if (nonce) nonce.fill(0);
        }
    }

    /**
     * Compute welcome_secret from joiner_secret + psk_secret.
     *   member_secret  = KDF.Extract(joiner_secret, psk_secret)
     *   welcome_secret = ExpandWithLabel(member_secret, "welcome", "", Nh)
     *
     * `pskSecret` is 32 zero bytes when no PSKs are in play (PinChat
     * default).
     */
    async function deriveWelcomeSecret(joinerSecret, pskSecret) {
        const memberSecret = await HPKE.hkdfExtract(joinerSecret, pskSecret);
        try {
            return await KeySchedule.expandWithLabel(
                memberSecret, 'welcome', new Uint8Array(0), HPKE.Nh,
            );
        } finally {
            memberSecret.fill(0);
        }
    }

    /**
     * AES-128-GCM decrypt the welcome's encrypted_group_info blob with
     * the derived welcome_key / welcome_nonce. AAD is empty. Returns the
     * plaintext GroupInfo bytes (the caller decodes via GroupInfo.parseGroupInfo).
     */
    async function openEncryptedGroupInfo(welcomeKey, welcomeNonce, encryptedGroupInfoBytes) {
        if (typeof globalThis === 'undefined' || !globalThis.crypto || !globalThis.crypto.subtle) {
            // eslint-disable-next-line global-require
            const { webcrypto } = require('crypto');
            globalThis.crypto = globalThis.crypto || webcrypto;
        }
        const subtle = globalThis.crypto.subtle;
        const k = await subtle.importKey('raw', welcomeKey, { name: 'AES-GCM' }, false, ['decrypt']);
        const pt = await subtle.decrypt(
            { name: 'AES-GCM', iv: welcomeNonce, additionalData: new Uint8Array(0), tagLength: 128 },
            k, encryptedGroupInfoBytes,
        );
        return new Uint8Array(pt);
    }

    async function sealEncryptedGroupInfo(welcomeKey, welcomeNonce, groupInfoBytes) {
        if (typeof globalThis === 'undefined' || !globalThis.crypto || !globalThis.crypto.subtle) {
            // eslint-disable-next-line global-require
            const { webcrypto } = require('crypto');
            globalThis.crypto = globalThis.crypto || webcrypto;
        }
        const subtle = globalThis.crypto.subtle;
        const k = await subtle.importKey('raw', welcomeKey, { name: 'AES-GCM' }, false, ['encrypt']);
        const ct = await subtle.encrypt(
            { name: 'AES-GCM', iv: welcomeNonce, additionalData: new Uint8Array(0), tagLength: 128 },
            k, groupInfoBytes,
        );
        return new Uint8Array(ct);
    }

    return Object.freeze({
        // Serde
        readPreSharedKeyID,
        writePreSharedKeyID,
        readGroupSecrets,
        writeGroupSecrets,
        groupSecretsBytes,
        parseGroupSecrets,
        readEncryptedGroupSecrets,
        writeEncryptedGroupSecrets,
        readWelcome,
        writeWelcome,
        welcomeBytes,
        parseWelcome,
        // Crypto
        decryptGroupSecrets,
        welcomeKeyNonce,
        deriveWelcomeSecret,
        openEncryptedGroupInfo,
        sealEncryptedGroupInfo,
    });
});
