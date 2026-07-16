/**
 * PinChat MLS — public P-256 point helpers.
 *
 * TreeKEM's deterministic DHKEM DeriveKeyPair starts from a secret scalar,
 * but JavaScript must never multiply that scalar with hand-written BigInt
 * curve code. hpke.js imports the scalar as an opaque, non-extractable
 * PKCS#8 WebCrypto key and asks the native ECDH implementation for the
 * public x-coordinate.
 *
 * Recovering y from a public x-coordinate is ordinary point decompression:
 * P-256's field prime is 3 mod 4, so y = rhs^((p+1)/4) mod p. The two
 * possible signs are returned to hpke.js, which selects the matching one
 * using native ECDSA sign/verify. Every BigInt operation in this module is
 * therefore performed only on public curve coordinates or fixed constants,
 * never on a TreeKEM/path-secret scalar.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLS = root.MLS || {};
        root.MLS.P256 = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
    const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const A = P - 3n;
    const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
    const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
    const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

    function mod(value) {
        const reduced = value % P;
        return reduced < 0n ? reduced + P : reduced;
    }

    function multiply(a, b) {
        return mod(a * b);
    }

    function square(value) {
        return multiply(value, value);
    }

    // The exponent is the fixed public constant (P + 1) / 4.
    function powPublic(base, exponent) {
        let result = 1n;
        let factor = mod(base);
        let remaining = exponent;
        while (remaining > 0n) {
            if ((remaining & 1n) !== 0n) result = multiply(result, factor);
            factor = square(factor);
            remaining >>= 1n;
        }
        return result;
    }

    /** Serialize a BigInt into out[offset..offset+length] big-endian. */
    function writeBigUint(value, out, offset, length) {
        let remaining = value;
        for (let i = length - 1; i >= 0; i -= 1) {
            out[offset + i] = Number(remaining & 0xffn);
            remaining >>= 8n;
        }
        if (remaining !== 0n) {
            throw new Error('p256: value does not fit requested width');
        }
    }

    /** Parse a public big-endian byte array into a BigInt. */
    function bytesToBigInt(bytes) {
        let value = 0n;
        for (let i = 0; i < bytes.length; i += 1) {
            value = (value << 8n) | BigInt(bytes[i]);
        }
        return value;
    }

    function uncompressedPoint(x, y) {
        const out = new Uint8Array(65);
        out[0] = 0x04;
        writeBigUint(x, out, 1, 32);
        writeBigUint(y, out, 33, 32);
        return out;
    }

    function generatorBytes() {
        return uncompressedPoint(GX, GY);
    }

    /**
     * Return the two possible uncompressed P-256 points for a public
     * x-coordinate. Throws when x is out of range or not on the curve.
     */
    function publicKeyCandidatesFromX(xBytes) {
        if (!(xBytes instanceof Uint8Array) || xBytes.length !== 32) {
            throw new Error('p256: x-coordinate must be 32 bytes');
        }
        const x = bytesToBigInt(xBytes);
        if (x >= P) throw new Error('p256: x-coordinate out of range');
        const rhs = mod(multiply(square(x), x) + multiply(A, x) + B);
        const y = powPublic(rhs, (P + 1n) >> 2n);
        if (square(y) !== rhs) {
            throw new Error('p256: x-coordinate is not on the curve');
        }
        const negY = mod(-y);
        if (negY === y) {
            throw new Error('p256: ambiguous point with zero y-coordinate');
        }
        return [
            uncompressedPoint(x, y),
            uncompressedPoint(x, negY),
        ];
    }

    return Object.freeze({
        P,
        N,
        A,
        B,
        GX,
        GY,
        generatorBytes,
        publicKeyCandidatesFromX,
        bytesToBigInt,
    });
});
