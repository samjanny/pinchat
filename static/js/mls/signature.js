/**
 * PinChat MLS — ECDSA P-256 + SHA-256 signature primitives.
 *
 * Ciphersuite 0x0002 specifies `ecdsa_secp256r1_sha256` as the signature
 * scheme, with signatures serialized in the TLS 1.3 way — i.e. DER-encoded
 * ECDSA signatures (RFC 5480 + ASN.1). WebCrypto's `subtle.sign` / `verify`
 * for ECDSA use raw IEEE P1363 r||s instead, so we convert between the
 * two at the module boundary:
 *
 *   WebCrypto raw r||s   <->  DER SEQUENCE { INTEGER r, INTEGER s }
 *       (32+32=64 bytes)      (variable: ~70-72 bytes for P-256)
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

    function derToRaw(der) {
        if (!(der instanceof Uint8Array)) throw new Error('derToRaw: Uint8Array required');
        if (der.length < 8 || der[0] !== 0x30) throw new Error('derToRaw: not a SEQUENCE');

        let p = 1;
        let seqLen = der[p]; p += 1;
        if (seqLen & 0x80) {
            // Long-form length — only used for sequences > 127 bytes. P-256
            // signatures are always below that, but handle it for safety.
            const n = seqLen & 0x7f;
            if (n > 2 || p + n > der.length) throw new Error('derToRaw: bad length');
            seqLen = 0;
            for (let i = 0; i < n; i += 1) seqLen = (seqLen << 8) | der[p + i];
            p += n;
        }
        if (p + seqLen !== der.length) {
            throw new Error('derToRaw: trailing bytes in signature');
        }

        function readInt() {
            if (der[p] !== 0x02) throw new Error('derToRaw: expected INTEGER');
            p += 1;
            let len = der[p]; p += 1;
            if (len & 0x80) throw new Error('derToRaw: long INTEGER length not supported');
            // Strip an optional leading 0x00 sign byte.
            if (len > 0 && der[p] === 0x00) {
                p += 1;
                len -= 1;
            }
            if (len > COORD_LEN) throw new Error('derToRaw: INTEGER too large for P-256');
            const out = new Uint8Array(COORD_LEN);
            out.set(der.subarray(p, p + len), COORD_LEN - len);
            p += len;
            return out;
        }

        const r = readInt();
        const s = readInt();
        const raw = new Uint8Array(RAW_SIG_LEN);
        raw.set(r, 0);
        raw.set(s, COORD_LEN);
        return raw;
    }

    function rawToDer(raw) {
        if (!(raw instanceof Uint8Array) || raw.length !== RAW_SIG_LEN) {
            throw new Error('rawToDer: expected 64-byte IEEE P1363 signature');
        }
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

    // --- Raw sign / verify --------------------------------------------------

    async function signRaw(privateKey, data) {
        const sig = await getSubtle().sign(
            { name: 'ECDSA', hash: 'SHA-256' }, privateKey, data
        );
        return new Uint8Array(sig);
    }

    async function verifyRaw(publicKey, data, rawSignature) {
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
        sign,
        verify,
        signRaw,
        verifyRaw,
    });
});
