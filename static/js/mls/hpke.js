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
        module.exports = factory(require('./p256.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.HPKE = factory(root.MLS.P256);
    }
})(typeof self !== 'undefined' ? self : this, function (P256) {
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
    const P256_PKCS8_SCALAR_PREFIX = Uint8Array.of(
        0x30, 0x41, 0x02, 0x01, 0x00,
        0x30, 0x13,
        0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x04, 0x27,
        0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
    );
    const PUBLIC_KEY_RECOVERY_PROBE = enc.encode(
        'PinChat HPKE DeriveKeyPair public-key recovery v1',
    );
    let generatorPublicKeyPromise = null;

    // --- HKDF on top of HMAC-SHA256 ----------------------------------------
    //
    // WebCrypto's HKDF lumps Extract+Expand together. HPKE needs them split
    // (the output of Extract becomes the PRK input to later Expand calls),
    // so we reconstruct HKDF manually from HMAC.

    async function hmacSha256(key, data) {
        // HMAC with a zero-length key is valid (RFC 2104) but WebCrypto
        // refuses it; pad a 0-length key to 1 zero byte (HMAC is invariant
        // under zero-padding up to the block size).
        const allocatedKey = key.length === 0 ? new Uint8Array(1) : null;
        const keyBytes = allocatedKey || key;
        try {
            const k = await getSubtle().importKey(
                'raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
            );
            const sig = await getSubtle().sign('HMAC', k, data);
            return new Uint8Array(sig);
        } finally {
            if (allocatedKey) allocatedKey.fill(0);
        }
    }

    async function hkdfExtract(salt, ikm) {
        const allocatedSalt = salt.length === 0 ? new Uint8Array(Nh) : null;
        const effectiveSalt = allocatedSalt || salt;
        try {
            return await hmacSha256(effectiveSalt, ikm);
        } finally {
            if (allocatedSalt) allocatedSalt.fill(0);
        }
    }

    async function hkdfExpand(prk, info, length) {
        if (length > 255 * Nh) throw new Error('hkdf: length too large');
        const n = Math.ceil(length / Nh);
        const output = new Uint8Array(length);
        let previous = new Uint8Array(0);
        let offset = 0;
        try {
            for (let i = 1; i <= n; i += 1) {
                const hmacInput = concat(
                    previous, info, new Uint8Array([i]),
                );
                let next = null;
                try {
                    next = await hmacSha256(prk, hmacInput);
                } finally {
                    hmacInput.fill(0);
                }
                const take = Math.min(Nh, length - offset);
                output.set(next.subarray(0, take), offset);
                offset += take;
                previous.fill(0);
                previous = next;
            }
            return output;
        } catch (err) {
            output.fill(0);
            throw err;
        } finally {
            previous.fill(0);
        }
    }

    async function labeledExtract(salt, suiteId, label, ikm) {
        const labeledIkm = concat(HPKE_VERSION, suiteId, enc.encode(label), ikm);
        try {
            return await hkdfExtract(salt, labeledIkm);
        } finally {
            labeledIkm.fill(0);
        }
    }

    async function labeledExpand(prk, suiteId, label, info, length) {
        const labeledInfo = concat(
            i2osp(length, 2),
            HPKE_VERSION,
            suiteId,
            enc.encode(label),
            info,
        );
        try {
            return await hkdfExpand(prk, labeledInfo, length);
        } finally {
            labeledInfo.fill(0);
        }
    }

    // --- DHKEM(P-256, HKDF-SHA256) -----------------------------------------

    async function generateKeyPair() {
        const keyPair = await getSubtle().generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            ['deriveBits'],
        );
        const raw = await getSubtle().exportKey('raw', keyPair.publicKey);
        return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey, publicKeyBytes: new Uint8Array(raw) };
    }

    /**
     * DHKEM DeriveKeyPair for P-256 — RFC 9180 §7.1.3 "rejection sampling".
     *
     *   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
     *   for counter = 0..255:
     *       bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk)
     *       bitmask = 0xFF   (P-256 scalar is 256 bits; no bits to clear)
     *       bytes[0] &= bitmask
     *       sk = OS2IP(bytes)
     *       if 0 < sk < order: return (sk, sk*G)
     *
     * Returns an ECDH CryptoKey private/public pair (imported via JWK) and
     * the 65-byte uncompressed public key. The candidate scalar and KDF
     * state are wiped before returning and are never retained in the
     * returned key-pair object. Throws if 256 consecutive candidates are
     * out of range (the probability is astronomically small).
     *
     * The secret scalar is imported directly into WebCrypto as an RFC 5915
     * ECPrivateKey inside PKCS#8. Native ECDH against the public generator
     * yields x(sk*G); p256.js decompresses that public coordinate, and a
     * native ECDSA sign/verify probe selects the correct sign of y. No secret
     * scalar enters JavaScript BigInt elliptic-curve arithmetic.
     */
    async function deriveKeyPair(ikm) {
        const dkpPrk = await labeledExtract(new Uint8Array(0), KEM_SUITE_ID, 'dkp_prk', ikm);
        try {
            for (let counter = 0; counter < 256; counter += 1) {
                const cand = await labeledExpand(
                    dkpPrk, KEM_SUITE_ID, 'candidate', new Uint8Array([counter]), 32,
                );
                try {
                    // P-256: bitmask = 0xFF, so no masking is needed. Kept
                    // explicit to match RFC 9180 pseudocode exactly.
                    cand[0] &= 0xff;
                    const keyPair = await deriveKeyPairFromScalar(cand);
                    if (keyPair) return keyPair;
                } finally {
                    cand.fill(0);
                }
            }
            throw new Error('hpke: DeriveKeyPair exhausted counter');
        } finally {
            dkpPrk.fill(0);
        }
    }

    function privateScalarPkcs8(rawScalarBytes) {
        if (!(rawScalarBytes instanceof Uint8Array)
            || rawScalarBytes.length !== 32) {
            throw new Error('hpke: private scalar must be 32 bytes');
        }
        return concat(P256_PKCS8_SCALAR_PREFIX, rawScalarBytes);
    }

    function generatorPublicKey() {
        if (!generatorPublicKeyPromise) {
            generatorPublicKeyPromise = deserializePublicKey(
                P256.generatorBytes(),
            );
        }
        return generatorPublicKeyPromise;
    }

    async function deriveKeyPairFromScalar(rawScalarBytes) {
        const pkcs8 = privateScalarPkcs8(rawScalarBytes);
        let publicX = null;
        let signature = null;
        let candidates = [];
        let selectedPublicBytes = null;
        try {
            const subtle = getSubtle();
            let privateKey;
            try {
                privateKey = await subtle.importKey(
                    'pkcs8', pkcs8,
                    { name: 'ECDH', namedCurve: 'P-256' },
                    false, ['deriveBits'],
                );
            } catch (err) {
                if (err?.name === 'DataError') {
                    // WebCrypto performs the 0 < sk < order validation inside
                    // the native EC implementation. A rejected scalar advances
                    // RFC 9180's public counter without exposing its bytes to
                    // JavaScript comparison or BigInt arithmetic.
                    return null;
                }
                throw err;
            }
            const [signingKey, generator] = await Promise.all([
                subtle.importKey(
                    'pkcs8', pkcs8,
                    { name: 'ECDSA', namedCurve: 'P-256' },
                    false, ['sign'],
                ),
                generatorPublicKey(),
            ]);
            publicX = new Uint8Array(await subtle.deriveBits(
                { name: 'ECDH', public: generator }, privateKey, 256,
            ));
            candidates = P256.publicKeyCandidatesFromX(publicX);
            signature = new Uint8Array(await subtle.sign(
                { name: 'ECDSA', hash: 'SHA-256' },
                signingKey,
                PUBLIC_KEY_RECOVERY_PROBE,
            ));
            const matches = await Promise.all(candidates.map(async (candidate) => {
                const verificationKey = await subtle.importKey(
                    'raw', candidate,
                    { name: 'ECDSA', namedCurve: 'P-256' },
                    false, ['verify'],
                );
                return subtle.verify(
                    { name: 'ECDSA', hash: 'SHA-256' },
                    verificationKey,
                    signature,
                    PUBLIC_KEY_RECOVERY_PROBE,
                );
            }));
            const matchingIndices = matches
                .map((matchesCandidate, index) =>
                    matchesCandidate ? index : -1)
                .filter((index) => index !== -1);
            if (matchingIndices.length !== 1) {
                throw new Error(
                    `hpke: native public-key recovery matched `
                    + `${matchingIndices.length} P-256 candidates`,
                );
            }
            selectedPublicBytes = candidates[matchingIndices[0]];
            const publicKey = await deserializePublicKey(selectedPublicBytes);
            return {
                privateKey,
                publicKey,
                publicKeyBytes: selectedPublicBytes,
            };
        } finally {
            pkcs8.fill(0);
            if (publicX) publicX.fill(0);
            if (signature) signature.fill(0);
            for (const candidate of candidates) {
                if (candidate !== selectedPublicBytes) candidate.fill(0);
            }
        }
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

    /**
     * Import an ECDH P-256 private key from a raw 32-byte scalar plus the
     * corresponding 65-byte uncompressed public point. WebCrypto only
     * imports private EC keys from JWK (or PKCS#8), so we build a JWK
     * with { d, x, y } from the raw inputs.
     */
    async function importPrivateKey(rawScalarBytes, rawPubBytes) {
        if (!(rawScalarBytes instanceof Uint8Array) || rawScalarBytes.length !== 32) {
            throw new Error('hpke: private scalar must be 32 bytes');
        }
        if (!(rawPubBytes instanceof Uint8Array) || rawPubBytes.length !== Npk || rawPubBytes[0] !== 0x04) {
            throw new Error('hpke: public point must be uncompressed 65 bytes');
        }
        const x = rawPubBytes.slice(1, 33);
        const y = rawPubBytes.slice(33, 65);

        // Minimal base64url encoder — we don't want to require the Codec
        // module here (would create a circular dependency with labeled.js).
        const b64url = (u8) => {
            let binary = '';
            for (let i = 0; i < u8.length; i += 1) binary += String.fromCharCode(u8[i]);
            const base64 = typeof btoa !== 'undefined'
                ? btoa(binary)
                : Buffer.from(u8).toString('base64');
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        };

        const jwk = {
            kty: 'EC', crv: 'P-256',
            d: b64url(rawScalarBytes),
            x: b64url(x), y: b64url(y),
            ext: false,
        };
        try {
            return await getSubtle().importKey(
                'jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
            );
        } finally {
            // Strings cannot be zeroized, but do not keep the base64url
            // representation reachable beyond the WebCrypto import.
            jwk.d = '';
        }
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
        try {
            return await labeledExpand(
                eaePrk, KEM_SUITE_ID, 'shared_secret', kemContext, Nsecret,
            );
        } finally {
            eaePrk.fill(0);
        }
    }

    async function encap(pkR) {
        const pkRKey = await ensurePublicKey(pkR);
        const pkRBytes = await serializePublicKey(pkRKey);

        const ephemeral = await generateKeyPair();
        const dh = await ecdh(ephemeral.privateKey, pkRKey);
        const kemContext = concat(ephemeral.publicKeyBytes, pkRBytes);
        try {
            const sharedSecret = await extractAndExpand(dh, kemContext);
            return { sharedSecret, enc: ephemeral.publicKeyBytes };
        } finally {
            dh.fill(0);
            kemContext.fill(0);
        }
    }

    async function decap(encBytes, skR, pkRBytes) {
        if (!(encBytes instanceof Uint8Array) || encBytes.length !== Npk) {
            throw new Error('hpke.decap: invalid enc');
        }
        const pkE = await deserializePublicKey(encBytes);
        const dh = await ecdh(skR, pkE);
        const kemContext = concat(encBytes, pkRBytes);
        try {
            return await extractAndExpand(dh, kemContext);
        } finally {
            dh.fill(0);
            kemContext.fill(0);
        }
    }

    // --- HPKE key schedule (base mode) -------------------------------------

    const MODE_BASE = 0x00;
    const DEFAULT_PSK = new Uint8Array(0);
    const DEFAULT_PSK_ID = new Uint8Array(0);

    async function keyScheduleBase(sharedSecret, info) {
        let pskIdHash = null;
        let infoHash = null;
        let ksContext = null;
        let secret = null;
        let key = null;
        let baseNonce = null;
        let exporterSecret = null;
        try {
            pskIdHash = await labeledExtract(
                new Uint8Array(0), HPKE_SUITE_ID,
                'psk_id_hash', DEFAULT_PSK_ID,
            );
            infoHash = await labeledExtract(
                new Uint8Array(0), HPKE_SUITE_ID, 'info_hash', info,
            );
            ksContext = concat(
                new Uint8Array([MODE_BASE]), pskIdHash, infoHash,
            );
            secret = await labeledExtract(
                sharedSecret, HPKE_SUITE_ID, 'secret', DEFAULT_PSK,
            );
            key = await labeledExpand(
                secret, HPKE_SUITE_ID, 'key', ksContext, Nk,
            );
            baseNonce = await labeledExpand(
                secret, HPKE_SUITE_ID, 'base_nonce', ksContext, Nn,
            );
            exporterSecret = await labeledExpand(
                secret, HPKE_SUITE_ID, 'exp', ksContext, Nh,
            );
            const schedule = { key, baseNonce, exporterSecret };
            key = null;
            baseNonce = null;
            exporterSecret = null;
            return schedule;
        } finally {
            for (const value of [
                pskIdHash, infoHash, ksContext, secret,
                key, baseNonce, exporterSecret,
            ]) {
                if (value instanceof Uint8Array) value.fill(0);
            }
        }
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
        let schedule = null;
        try {
            schedule = await keyScheduleBase(sharedSecret, info);
            // Single-shot: sequence number = 0, so nonce = baseNonce.
            const ct = await aeadSeal(
                schedule.key, schedule.baseNonce, aad, plaintext,
            );
            return { enc: encBytes, ct };
        } finally {
            sharedSecret.fill(0);
            destroySchedule(schedule);
        }
    }

    async function open(encBytes, skR, pkRBytes, info, aad, ct) {
        const sharedSecret = await decap(encBytes, skR, pkRBytes);
        let schedule = null;
        try {
            schedule = await keyScheduleBase(sharedSecret, info);
            return await aeadOpen(
                schedule.key, schedule.baseNonce, aad, ct,
            );
        } finally {
            sharedSecret.fill(0);
            destroySchedule(schedule);
        }
    }

    // --- Stateful context (useful for unit tests and for the secret-tree AEAD stream) ---

    async function setupBaseSender(pkR, info) {
        const { sharedSecret, enc: encBytes } = await encap(pkR);
        let schedule = null;
        try {
            schedule = await keyScheduleBase(sharedSecret, info);
            const context = makeSenderContext(schedule);
            schedule = null;
            return { enc: encBytes, context };
        } finally {
            sharedSecret.fill(0);
            destroySchedule(schedule);
        }
    }

    async function setupBaseReceiver(encBytes, skR, pkRBytes, info) {
        const sharedSecret = await decap(encBytes, skR, pkRBytes);
        let schedule = null;
        try {
            schedule = await keyScheduleBase(sharedSecret, info);
            const context = makeReceiverContext(schedule);
            schedule = null;
            return context;
        } finally {
            sharedSecret.fill(0);
            destroySchedule(schedule);
        }
    }

    function computeNonce(baseNonce, seq) {
        const seqBytes = i2osp(seq, Nn);
        try {
            return xor(baseNonce, seqBytes);
        } finally {
            seqBytes.fill(0);
        }
    }

    function destroySchedule(schedule) {
        if (!schedule) return;
        for (const value of [
            schedule.key, schedule.baseNonce, schedule.exporterSecret,
        ]) {
            if (value instanceof Uint8Array) value.fill(0);
        }
    }

    function makeSenderContext(schedule) {
        let seq = 0n;
        let destroyed = false;
        const requireLive = () => {
            if (destroyed) throw new Error('hpke: sender context destroyed');
        };
        return {
            async seal(aad, plaintext) {
                requireLive();
                const nonce = computeNonce(schedule.baseNonce, seq);
                try {
                    const ct = await aeadSeal(
                        schedule.key, nonce, aad, plaintext,
                    );
                    seq += 1n;
                    return ct;
                } finally {
                    nonce.fill(0);
                }
            },
            async export(exporterContext, length) {
                requireLive();
                return labeledExpand(
                    schedule.exporterSecret, HPKE_SUITE_ID, 'sec', exporterContext, length,
                );
            },
            destroy() {
                if (destroyed) return;
                destroyed = true;
                seq = 0n;
                destroySchedule(schedule);
            },
        };
    }

    function makeReceiverContext(schedule) {
        let seq = 0n;
        let destroyed = false;
        const requireLive = () => {
            if (destroyed) throw new Error('hpke: receiver context destroyed');
        };
        return {
            async open(aad, ct) {
                requireLive();
                const nonce = computeNonce(schedule.baseNonce, seq);
                try {
                    const pt = await aeadOpen(schedule.key, nonce, aad, ct);
                    seq += 1n;
                    return pt;
                } finally {
                    nonce.fill(0);
                }
            },
            async export(exporterContext, length) {
                requireLive();
                return labeledExpand(
                    schedule.exporterSecret, HPKE_SUITE_ID, 'sec', exporterContext, length,
                );
            },
            destroy() {
                if (destroyed) return;
                destroyed = true;
                seq = 0n;
                destroySchedule(schedule);
            },
        };
    }

    return Object.freeze({
        // KEM
        generateKeyPair,
        deriveKeyPair,
        deserializePublicKey,
        serializePublicKey,
        importPrivateKey,
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
