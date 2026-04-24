/**
 * PinChat MLS — HPKE (RFC 9180) for ciphersuite 0x0002.
 *
 *   KEM   : DHKEM(P-256, HKDF-SHA256)     kem_id  = 0x0010
 *   KDF   : HKDF-SHA256                   kdf_id  = 0x0001
 *   AEAD  : AES-128-GCM                   aead_id = 0x0001
 *
 * This is a from-scratch implementation built *only* on WebCrypto primitives
 * (HMAC-SHA256, ECDH-P256, AES-GCM). There is no vendored HPKE library and
 * no cross-compile of a C/WASM implementation. Only the base mode is
 * implemented — MLS never uses PSK or auth mode at the HPKE layer.
 *
 * All labeled operations use the "HPKE-v1" prefix per RFC 9180 §4.
 *
 * Public surface
 * --------------
 *   generateKeyPair()                  -> {privateKey, publicKeyBytes}
 *   deserializePublicKey(bytes)        -> CryptoKey (ECDH public, non-extractable)
 *   seal(pkR, info, aad, plaintext)    -> {enc: Uint8Array, ct: Uint8Array}
 *   open(enc, skR, info, aad, ct)      -> Uint8Array (plaintext)
 *
 * `pkR` may be either a raw uncompressed P-256 public key (65 bytes starting
 * with 0x04) or an imported WebCrypto CryptoKey; `skR` must be the
 * deriveBits-capable ECDH private key. `info`, `aad`, `plaintext` are
 * Uint8Arrays. `enc` is the serialised ephemeral public key (65 bytes).
 *
 * Cross-checked against RFC 9180 §A.3 (DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256
 * + AES-128-GCM) test vectors — see tests/test-mls-hpke.js.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLS = root.MLS || {};
        root.MLS.HPKE = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // --- WebCrypto surface (browser + node) ---------------------------------

    function getSubtle() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        // Node <19 — should not happen in our target environments but kept for safety.
        try {
            // eslint-disable-next-line global-require
            const { webcrypto } = require('crypto');
            return webcrypto.subtle;
        } catch (_) {
            throw new Error('hpke: WebCrypto SubtleCrypto is unavailable');
        }
    }

    // --- Byte helpers -------------------------------------------------------

    const enc = new TextEncoder();
    const HPKE_VERSION = enc.encode('HPKE-v1');

    function concat(...chunks) {
        let total = 0;
        for (const c of chunks) total += c.length;
        const out = new Uint8Array(total);
        let off = 0;
        for (const c of chunks) {
            out.set(c, off);
            off += c.length;
        }
        return out;
    }

    function i2osp(v, len) {
        const out = new Uint8Array(len);
        let n = typeof v === 'bigint' ? v : BigInt(v);
        for (let i = len - 1; i >= 0; i -= 1) {
            out[i] = Number(n & 0xffn);
            n >>= 8n;
        }
        return out;
    }

    function xor(a, b) {
        if (a.length !== b.length) throw new Error('hpke.xor: length mismatch');
        const out = new Uint8Array(a.length);
        for (let i = 0; i < a.length; i += 1) out[i] = a[i] ^ b[i];
        return out;
    }

    // --- Ciphersuite constants (duplicated locally so this module is standalone) ---

    const KEM_ID = 0x0010;
    const KDF_ID = 0x0001;
    const AEAD_ID = 0x0001;
    const Nh = 32;       // HKDF-SHA256 output
    const Nk = 16;       // AES-128-GCM key
    const Nn = 12;       // AES-GCM nonce
    const Nsecret = 32;  // DHKEM shared-secret length
    const Npk = 65;      // P-256 uncompressed public key
    // const Nsk = 32;    // P-256 private scalar (unused: WebCrypto manages scalars opaquely)

    function hpkeSuiteId() {
        const prefix = enc.encode('HPKE');
        const out = new Uint8Array(prefix.length + 6);
        out.set(prefix, 0);
        out[4] = (KEM_ID >> 8) & 0xff;
        out[5] = KEM_ID & 0xff;
        out[6] = (KDF_ID >> 8) & 0xff;
        out[7] = KDF_ID & 0xff;
        out[8] = (AEAD_ID >> 8) & 0xff;
        out[9] = AEAD_ID & 0xff;
        return out;
    }

    function kemSuiteId() {
        const prefix = enc.encode('KEM');
        const out = new Uint8Array(prefix.length + 2);
        out.set(prefix, 0);
        out[3] = (KEM_ID >> 8) & 0xff;
        out[4] = KEM_ID & 0xff;
        return out;
    }

    const HPKE_SUITE_ID = hpkeSuiteId();
    const KEM_SUITE_ID = kemSuiteId();

    // --- HKDF on top of HMAC-SHA256 ----------------------------------------
    //
    // WebCrypto's HKDF lumps Extract+Expand together. HPKE needs them split
    // (the output of Extract becomes the PRK input to later Expand calls),
    // so we reconstruct HKDF manually from HMAC.

    async function hmacSha256(key, data) {
        // HMAC with a zero-length key is valid (RFC 2104) but WebCrypto
        // refuses it; pad a 0-length key to 1 zero byte (HMAC is invariant
        // under zero-padding up to the block size).
        const keyBytes = key.length === 0 ? new Uint8Array(1) : key;
        const k = await getSubtle().importKey(
            'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
        );
        const sig = await getSubtle().sign('HMAC', k, data);
        return new Uint8Array(sig);
    }

    async function hkdfExtract(salt, ikm) {
        const effectiveSalt = salt.length === 0 ? new Uint8Array(Nh) : salt;
        return hmacSha256(effectiveSalt, ikm);
    }

    async function hkdfExpand(prk, info, length) {
        if (length > 255 * Nh) throw new Error('hkdf: length too large');
        const n = Math.ceil(length / Nh);
        const output = new Uint8Array(length);
        let previous = new Uint8Array(0);
        let offset = 0;
        for (let i = 1; i <= n; i += 1) {
            const t = await hmacSha256(prk, concat(previous, info, new Uint8Array([i])));
            const take = Math.min(Nh, length - offset);
            output.set(t.subarray(0, take), offset);
            offset += take;
            previous = t;
        }
        return output;
    }

    async function labeledExtract(salt, suiteId, label, ikm) {
        const labeledIkm = concat(HPKE_VERSION, suiteId, enc.encode(label), ikm);
        return hkdfExtract(salt, labeledIkm);
    }

    async function labeledExpand(prk, suiteId, label, info, length) {
        const labeledInfo = concat(
            i2osp(length, 2),
            HPKE_VERSION,
            suiteId,
            enc.encode(label),
            info,
        );
        return hkdfExpand(prk, labeledInfo, length);
    }

    // --- DHKEM(P-256, HKDF-SHA256) -----------------------------------------

    async function generateKeyPair() {
        const keyPair = await getSubtle().generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveBits'],
        );
        const raw = await getSubtle().exportKey('raw', keyPair.publicKey);
        return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, publicKeyBytes: new Uint8Array(raw) };
    }

    async function deserializePublicKey(bytes) {
        if (!(bytes instanceof Uint8Array) || bytes.length !== Npk || bytes[0] !== 0x04) {
            throw new Error('hpke: invalid P-256 uncompressed public key');
        }
        return getSubtle().importKey(
            'raw', bytes, { name: 'ECDH', namedCurve: 'P-256' }, true, [],
        );
    }

    async function serializePublicKey(publicKey) {
        const raw = await getSubtle().exportKey('raw', publicKey);
        return new Uint8Array(raw);
    }

    async function ensurePublicKey(pk) {
        if (pk instanceof Uint8Array) return deserializePublicKey(pk);
        return pk;
    }

    async function ecdh(privateKey, publicKey) {
        const bits = await getSubtle().deriveBits(
            { name: 'ECDH', public: publicKey }, privateKey, 256,
        );
        return new Uint8Array(bits);
    }

    async function extractAndExpand(dh, kemContext) {
        const eaePrk = await labeledExtract(new Uint8Array(0), KEM_SUITE_ID, 'eae_prk', dh);
        return labeledExpand(eaePrk, KEM_SUITE_ID, 'shared_secret', kemContext, Nsecret);
    }

    async function encap(pkR) {
        const pkRKey = await ensurePublicKey(pkR);
        const pkRBytes = await serializePublicKey(pkRKey);

        const ephemeral = await generateKeyPair();
        const dh = await ecdh(ephemeral.privateKey, pkRKey);
        const kemContext = concat(ephemeral.publicKeyBytes, pkRBytes);
        const sharedSecret = await extractAndExpand(dh, kemContext);
        return { sharedSecret, enc: ephemeral.publicKeyBytes };
    }

    async function decap(encBytes, skR, pkRBytes) {
        if (!(encBytes instanceof Uint8Array) || encBytes.length !== Npk) {
            throw new Error('hpke.decap: invalid enc');
        }
        const pkE = await deserializePublicKey(encBytes);
        const dh = await ecdh(skR, pkE);
        const kemContext = concat(encBytes, pkRBytes);
        return extractAndExpand(dh, kemContext);
    }

    // --- HPKE key schedule (base mode) -------------------------------------

    const MODE_BASE = 0x00;
    const DEFAULT_PSK = new Uint8Array(0);
    const DEFAULT_PSK_ID = new Uint8Array(0);

    async function keyScheduleBase(sharedSecret, info) {
        const pskIdHash = await labeledExtract(new Uint8Array(0), HPKE_SUITE_ID, 'psk_id_hash', DEFAULT_PSK_ID);
        const infoHash = await labeledExtract(new Uint8Array(0), HPKE_SUITE_ID, 'info_hash', info);
        const ksContext = concat(new Uint8Array([MODE_BASE]), pskIdHash, infoHash);

        const secret = await labeledExtract(sharedSecret, HPKE_SUITE_ID, 'secret', DEFAULT_PSK);
        const key = await labeledExpand(secret, HPKE_SUITE_ID, 'key', ksContext, Nk);
        const baseNonce = await labeledExpand(secret, HPKE_SUITE_ID, 'base_nonce', ksContext, Nn);
        const exporterSecret = await labeledExpand(secret, HPKE_SUITE_ID, 'exp', ksContext, Nh);
        return { key, baseNonce, exporterSecret };
    }

    async function importAesKey(keyBytes) {
        if (keyBytes.length !== Nk) throw new Error('hpke: wrong AES key length');
        return getSubtle().importKey(
            'raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
        );
    }

    async function aeadSeal(keyBytes, nonce, aad, plaintext) {
        const k = await importAesKey(keyBytes);
        const ct = await getSubtle().encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
            k, plaintext,
        );
        return new Uint8Array(ct);
    }

    async function aeadOpen(keyBytes, nonce, aad, ciphertext) {
        const k = await importAesKey(keyBytes);
        const pt = await getSubtle().decrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
            k, ciphertext,
        );
        return new Uint8Array(pt);
    }

    // --- Single-shot Seal / Open ------------------------------------------

    async function seal(pkR, info, aad, plaintext) {
        const { sharedSecret, enc: encBytes } = await encap(pkR);
        const { key, baseNonce } = await keyScheduleBase(sharedSecret, info);
        // Single-shot: sequence number = 0, so nonce = baseNonce.
        const ct = await aeadSeal(key, baseNonce, aad, plaintext);
        return { enc: encBytes, ct };
    }

    async function open(encBytes, skR, pkRBytes, info, aad, ct) {
        const sharedSecret = await decap(encBytes, skR, pkRBytes);
        const { key, baseNonce } = await keyScheduleBase(sharedSecret, info);
        return aeadOpen(key, baseNonce, aad, ct);
    }

    // --- Stateful context (useful for unit tests and for the secret-tree AEAD stream) ---

    async function setupBaseSender(pkR, info) {
        const { sharedSecret, enc: encBytes } = await encap(pkR);
        const ctx = await keyScheduleBase(sharedSecret, info);
        return { enc: encBytes, context: makeSenderContext(ctx) };
    }

    async function setupBaseReceiver(encBytes, skR, pkRBytes, info) {
        const sharedSecret = await decap(encBytes, skR, pkRBytes);
        const ctx = await keyScheduleBase(sharedSecret, info);
        return makeReceiverContext(ctx);
    }

    function computeNonce(baseNonce, seq) {
        const seqBytes = i2osp(seq, Nn);
        return xor(baseNonce, seqBytes);
    }

    function makeSenderContext(schedule) {
        let seq = 0n;
        return {
            async seal(aad, plaintext) {
                const nonce = computeNonce(schedule.baseNonce, seq);
                const ct = await aeadSeal(schedule.key, nonce, aad, plaintext);
                seq += 1n;
                return ct;
            },
            async export(exporterContext, length) {
                return labeledExpand(
                    schedule.exporterSecret, HPKE_SUITE_ID, 'sec', exporterContext, length,
                );
            },
        };
    }

    function makeReceiverContext(schedule) {
        let seq = 0n;
        return {
            async open(aad, ct) {
                const nonce = computeNonce(schedule.baseNonce, seq);
                const pt = await aeadOpen(schedule.key, nonce, aad, ct);
                seq += 1n;
                return pt;
            },
            async export(exporterContext, length) {
                return labeledExpand(
                    schedule.exporterSecret, HPKE_SUITE_ID, 'sec', exporterContext, length,
                );
            },
        };
    }

    return Object.freeze({
        // KEM
        generateKeyPair,
        deserializePublicKey,
        serializePublicKey,
        encap,
        decap,
        // HPKE single-shot
        seal,
        open,
        // HPKE stateful
        setupBaseSender,
        setupBaseReceiver,
        // Exposed for the MLS layer (key schedule, secret tree, exporters)
        hkdfExtract,
        hkdfExpand,
        labeledExtract,
        labeledExpand,
        hmacSha256,
        HPKE_SUITE_ID,
        KEM_SUITE_ID,
        Nh,
        Nk,
        Nn,
        Nsecret,
        Npk,
    });
});
