/**
 * PinChat MLS — ECDSA P-256 + SHA-256 signature primitives.
 *
 * Ciphersuite 0x0002 specifies `ecdsa_secp256r1_sha256` as the signature
 * scheme, with signatures serialized in the TLS 1.3 way — i.e. DER-encoded
 * ECDSA signatures (RFC 8446 §4.2.3 + ASN.1 DER). WebCrypto's `subtle.sign` / `verify`
 * for ECDSA use raw IEEE P1363 r||s instead, so we convert between the
 * two at the module boundary:
 *
 *   WebCrypto raw r||s   <->  DER SEQUENCE { INTEGER r, INTEGER s }
 *       (32+32=64 bytes)      (variable: ~70-72 bytes for P-256)
 *
 * PinChat additionally profiles ECDSA signatures to low-S. Standard ECDSA
 * accepts both (r, s) and (r, n-s), but signature bytes are included in MLS
 * authenticated/transcript structures. Requiring the unique low-S
 * representative removes that remaining byte-level malleability. This is a
 * PinChat profile restriction, not a requirement imposed by RFC 9420.
 *
 * The raw-key helpers below accept an uncompressed public point
 * (65 bytes, 0x04||X||Y) and a private scalar (32 bytes). WebCrypto only
 * imports EC private keys in JWK or PKCS#8 form, so we assemble the JWK
 * ourselves using base64url-encoded X, Y, and d.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory(require('./codec.js'));
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Signature = factory(root.MLS.Codec);
    }
})(typeof self !== 'undefined' ? self : this, function (Codec) {
    'use strict';

    function getSubtle() {
        if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
            return globalThis.crypto.subtle;
        }
        // eslint-disable-next-line global-require
        const { webcrypto } = require('crypto');
        return webcrypto.subtle;
    }

    const COORD_LEN = 32;      // P-256 coordinate / scalar length
    const RAW_SIG_LEN = 64;    // raw ECDSA r||s length
    // NIST P-256 subgroup order (RFC 6979 Appendix A.2.5).
    const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const P256_HALF_ORDER = P256_ORDER >> 1n;

    // --- Key import / generation -------------------------------------------

    async function generateKeyPair() {
        const kp = await getSubtle().generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
        );
        const rawPub = new Uint8Array(await getSubtle().exportKey('raw', kp.publicKey));
        return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicKeyBytes: rawPub };
    }

    /** Import an ECDSA P-256 public key from the 65-byte uncompressed form. */
    async function importPublicKey(rawPubBytes) {
        if (!(rawPubBytes instanceof Uint8Array) || rawPubBytes.length !== 65 || rawPubBytes[0] !== 0x04) {
            throw new Error('signature: invalid ECDSA P-256 uncompressed public key');
        }
        return getSubtle().importKey(
            'raw', rawPubBytes, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']
        );
    }

    /**
     * Import an ECDSA P-256 private key from a raw 32-byte scalar plus the
     * corresponding 65-byte uncompressed public point. WebCrypto requires
     * both `d` and the matching (x, y) to construct the JWK; callers that
     * only have the scalar must derive the point externally (e.g. via the
     * DHKEM public key import plus `exportKey('raw')`).
     */
    async function importPrivateKey(rawScalarBytes, rawPubBytes) {
        if (!(rawScalarBytes instanceof Uint8Array) || rawScalarBytes.length !== COORD_LEN) {
            throw new Error('signature: private scalar must be 32 bytes');
        }
        if (!(rawPubBytes instanceof Uint8Array) || rawPubBytes.length !== 65 || rawPubBytes[0] !== 0x04) {
            throw new Error('signature: public point must be uncompressed 65 bytes');
        }
        const x = rawPubBytes.slice(1, 1 + COORD_LEN);
        const y = rawPubBytes.slice(1 + COORD_LEN, 1 + 2 * COORD_LEN);
        const jwk = {
            kty: 'EC',
            crv: 'P-256',
            d: Codec.bytesToBase64Url(rawScalarBytes),
            x: Codec.bytesToBase64Url(x),
            y: Codec.bytesToBase64Url(y),
            ext: true,
        };
        return getSubtle().importKey(
            'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']
        );
    }

    // --- DER <-> raw r||s conversion ---------------------------------------
    //
    // DER ECDSA signature layout (RFC 3279):
    //   SEQUENCE {
    //       INTEGER r   -- variable length, leading 0x00 if high bit set
    //       INTEGER s   -- same
    //   }
    // Encoded bytes:
    //   0x30 <seq_len> 0x02 <r_len> <r_bytes> 0x02 <s_len> <s_bytes>

    function bytesToBigInt(bytes) {
        let value = 0n;
        for (const byte of bytes) value = (value << 8n) | BigInt(byte);
        return value;
    }

    function bigIntToFixed(value, length) {
        const out = new Uint8Array(length);
        let remaining = value;
        for (let i = length - 1; i >= 0; i -= 1) {
            out[i] = Number(remaining & 0xffn);
            remaining >>= 8n;
        }
        if (remaining !== 0n) throw new Error('signature: scalar does not fit fixed width');
        return out;
    }

    function validateRawSignature(raw, requireLowS) {
        if (!(raw instanceof Uint8Array) || raw.length !== RAW_SIG_LEN) {
            throw new Error('signature: expected 64-byte IEEE P1363 signature');
        }
        const r = bytesToBigInt(raw.subarray(0, COORD_LEN));
        const s = bytesToBigInt(raw.subarray(COORD_LEN, RAW_SIG_LEN));
        if (r <= 0n || r >= P256_ORDER || s <= 0n || s >= P256_ORDER) {
            throw new Error('signature: r/s outside P-256 scalar range');
        }
        if (requireLowS && s > P256_HALF_ORDER) {
            throw new Error('signature: high-S value rejected by PinChat profile');
        }
        return { r, s };
    }

    function normalizeRawLowS(raw) {
        const { s } = validateRawSignature(raw, false);
        const out = new Uint8Array(raw);
        if (s > P256_HALF_ORDER) {
            out.set(bigIntToFixed(P256_ORDER - s, COORD_LEN), COORD_LEN);
        }
        return out;
    }

    /** Encode valid raw scalars as canonical DER without changing s. */
    function encodeCanonicalDer(raw) {
        validateRawSignature(raw, false);
        const r = raw.subarray(0, COORD_LEN);
        const s = raw.subarray(COORD_LEN, RAW_SIG_LEN);

        function encodeInt(value) {
            // Strip leading zeros.
            let start = 0;
            while (start < value.length - 1 && value[start] === 0x00) start += 1;
            const stripped = value.subarray(start);
            // If high bit of first byte is set, prepend 0x00 so the INTEGER
            // is interpreted as positive.
            const needsPad = (stripped[0] & 0x80) !== 0;
            const out = new Uint8Array((needsPad ? 1 : 0) + stripped.length);
            if (needsPad) out[0] = 0x00;
            out.set(stripped, needsPad ? 1 : 0);
            return out;
        }

        const rDer = encodeInt(r);
        const sDer = encodeInt(s);
        const body = new Uint8Array(2 + rDer.length + 2 + sDer.length);
        let o = 0;
        body[o++] = 0x02; body[o++] = rDer.length;
        body.set(rDer, o); o += rDer.length;
        body[o++] = 0x02; body[o++] = sDer.length;
        body.set(sDer, o); o += sDer.length;

        // Sequence length ≤ 72 for P-256, so short form suffices.
        if (body.length > 0x7f) throw new Error('rawToDer: body too long');
        const out = new Uint8Array(2 + body.length);
        out[0] = 0x30;
        out[1] = body.length;
        out.set(body, 2);
        return out;
    }

    /**
     * Parse a complete canonical DER ECDSA-Sig-Value. This parser accepts a
     * mathematically valid high-S scalar so normalizeDerLowS() can translate
     * external standards vectors, but production derToRaw() rejects it.
     */
    function parseCanonicalDer(der) {
        if (!(der instanceof Uint8Array)) throw new Error('derToRaw: Uint8Array required');
        // P-256 DER signatures are 8..72 bytes and therefore always use the
        // one-byte DER length form. Accepting long-form here would itself be
        // a non-canonical encoding.
        if (der.length < 8 || der.length > 72 || der[0] !== 0x30) {
            throw new Error('derToRaw: not a P-256 ECDSA SEQUENCE');
        }
        if ((der[1] & 0x80) !== 0 || der[1] !== der.length - 2) {
            throw new Error('derToRaw: non-canonical or mismatched SEQUENCE length');
        }

        let p = 2;
        function readInt(name) {
            if (p + 2 > der.length || der[p] !== 0x02) {
                throw new Error(`derToRaw: expected INTEGER ${name}`);
            }
            p += 1;
            const len = der[p]; p += 1;
            if ((len & 0x80) !== 0 || len === 0 || len > COORD_LEN + 1) {
                throw new Error(`derToRaw: invalid INTEGER ${name} length`);
            }
            const end = p + len;
            if (end > der.length) throw new Error(`derToRaw: truncated INTEGER ${name}`);

            const first = der[p];
            if ((first & 0x80) !== 0) {
                throw new Error(`derToRaw: negative INTEGER ${name}`);
            }
            if (len > 1 && first === 0x00 && (der[p + 1] & 0x80) === 0) {
                throw new Error(`derToRaw: redundant INTEGER ${name} sign octet`);
            }

            const magnitudeStart = first === 0x00 ? p + 1 : p;
            const magnitudeLen = end - magnitudeStart;
            if (magnitudeLen > COORD_LEN) {
                throw new Error(`derToRaw: INTEGER ${name} too large for P-256`);
            }
            const out = new Uint8Array(COORD_LEN);
            out.set(der.subarray(magnitudeStart, end), COORD_LEN - magnitudeLen);
            p = end;
            return out;
        }

        const r = readInt('r');
        const s = readInt('s');
        if (p !== der.length) {
            throw new Error('derToRaw: unconsumed bytes inside ECDSA SEQUENCE');
        }

        const raw = new Uint8Array(RAW_SIG_LEN);
        raw.set(r, 0);
        raw.set(s, COORD_LEN);
        validateRawSignature(raw, false);

        // Defense in depth: the strict parser and canonical encoder must
        // agree byte-for-byte. This catches any overlooked alternate DER form.
        if (!Codec.bytesEqual(encodeCanonicalDer(raw), der)) {
            throw new Error('derToRaw: signature is not canonical DER');
        }
        return raw;
    }

    /** Parse canonical DER and enforce PinChat's low-S profile. */
    function derToRaw(der) {
        const raw = parseCanonicalDer(der);
        validateRawSignature(raw, true);
        return raw;
    }

    /** Serialize raw r||s as the unique canonical low-S DER form. */
    function rawToDer(raw) {
        return encodeCanonicalDer(normalizeRawLowS(raw));
    }

    /**
     * Explicit standards-vector/migration helper. Verification code must not
     * normalize received signatures: production policy is fail-closed.
     */
    function normalizeDerLowS(der) {
        return encodeCanonicalDer(normalizeRawLowS(parseCanonicalDer(der)));
    }

    // --- Raw sign / verify --------------------------------------------------

    async function signRaw(privateKey, data) {
        const sig = await getSubtle().sign(
            { name: 'ECDSA', hash: 'SHA-256' }, privateKey, data
        );
        return normalizeRawLowS(new Uint8Array(sig));
    }

    async function verifyRaw(publicKey, data, rawSignature) {
        try {
            validateRawSignature(rawSignature, true);
        } catch (_e) {
            return false;
        }
        return getSubtle().verify(
            { name: 'ECDSA', hash: 'SHA-256' }, publicKey, rawSignature, data
        );
    }

    /** Sign `data`, returning a DER-encoded signature. */
    async function sign(privateKey, data) {
        const raw = await signRaw(privateKey, data);
        return rawToDer(raw);
    }

    /** Verify a DER-encoded signature; returns boolean. */
    async function verify(publicKey, data, derSignature) {
        let raw;
        try {
            raw = derToRaw(derSignature);
        } catch (_e) {
            return false;
        }
        return verifyRaw(publicKey, data, raw);
    }

    return Object.freeze({
        generateKeyPair,
        importPublicKey,
        importPrivateKey,
        derToRaw,
        rawToDer,
        normalizeDerLowS,
        sign,
        verify,
        signRaw,
        verifyRaw,
    });
});
