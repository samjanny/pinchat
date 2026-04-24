/**
 * PinChat MLS — P-256 scalar multiplication (hand-rolled).
 *
 * WebCrypto supplies key generation, ECDH, ECDSA and JWK import for
 * P-256 — but it does *not* expose scalar multiplication of the base
 * point `G`. TreeKEM needs exactly that: given a path secret deterministic
 * scalar `d`, produce the matching public point (x, y). Without (x, y)
 * WebCrypto refuses to import the private key (the JWK import validates
 * `(x, y) = d·G`).
 *
 * This module implements the minimum needed: `scalarBaseMul(d)` returning
 * the affine `(x, y)` bytes for the point `d·G` on the NIST P-256 curve.
 * It uses BigInt throughout, Jacobian coordinates to avoid one inversion
 * per bit, and a straightforward double-and-add scalar loop. Constant-
 * time-ness is *not* claimed: BigInt's operations are data-dependent in
 * JS engines. Since scalars here come from HKDF-SHA256 output (not user
 * secrets in a classical timing-attack sense) and are used once per
 * TreeKEM path update, this is an acceptable trade-off for auditability.
 *
 * Curve parameters from FIPS 186-4 / SEC2:
 *   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *   a = -3 mod p
 *   b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
 *   G = (Gx, Gy)
 *   n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
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
    const A = P - 3n; // a = -3 mod p
    const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
    const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

    // --- Field arithmetic mod p --------------------------------------------

    function mod(x, m) {
        const r = x % m;
        return r < 0n ? r + m : r;
    }

    function fadd(a, b) { return mod(a + b, P); }
    function fsub(a, b) { return mod(a - b, P); }
    function fmul(a, b) { return mod(a * b, P); }
    function fsqr(a)    { return mod(a * a, P); }

    // Modular inverse via Fermat's little theorem: a^(p-2) mod p.
    function fpow(base, exp) {
        let result = 1n;
        let b = mod(base, P);
        let e = exp;
        while (e > 0n) {
            if (e & 1n) result = fmul(result, b);
            b = fsqr(b);
            e >>= 1n;
        }
        return result;
    }

    function finv(a) {
        if (a === 0n) throw new Error('p256: finv(0) is undefined');
        return fpow(a, P - 2n);
    }

    // --- Jacobian point ops ------------------------------------------------
    // Jacobian: (X, Y, Z) where affine (x, y) = (X/Z^2, Y/Z^3).
    // Identity / point-at-infinity: Z = 0.

    function isIdentity(p) { return p.Z === 0n; }

    function jacobianFromAffine(x, y) {
        return { X: x, Y: y, Z: 1n };
    }

    function affineFromJacobian(p) {
        if (isIdentity(p)) throw new Error('p256: affine of identity');
        const zinv = finv(p.Z);
        const zinv2 = fsqr(zinv);
        const zinv3 = fmul(zinv2, zinv);
        return { x: fmul(p.X, zinv2), y: fmul(p.Y, zinv3) };
    }

    // Point doubling in Jacobian coords (RFC 6090 appendix F / Bernstein).
    // Uses the specific a = -3 speedup: M = 3(X - Z^2)(X + Z^2).
    function jDouble(p) {
        if (isIdentity(p) || p.Y === 0n) return { X: 0n, Y: 1n, Z: 0n };
        const Y2 = fsqr(p.Y);
        const S = fmul(fmul(4n, p.X), Y2);
        const Z2 = fsqr(p.Z);
        const M = fmul(3n, fmul(fsub(p.X, Z2), fadd(p.X, Z2)));
        const X3 = fsub(fsqr(M), fmul(2n, S));
        const Y3 = fsub(fmul(M, fsub(S, X3)), fmul(8n, fsqr(Y2)));
        const Z3 = fmul(fmul(2n, p.Y), p.Z);
        return { X: X3, Y: Y3, Z: Z3 };
    }

    // Point addition (Jacobian + Jacobian). Handles identity and equal-X
    // special cases. Not constant-time.
    function jAdd(p, q) {
        if (isIdentity(p)) return q;
        if (isIdentity(q)) return p;

        const Z1Z1 = fsqr(p.Z);
        const Z2Z2 = fsqr(q.Z);
        const U1 = fmul(p.X, Z2Z2);
        const U2 = fmul(q.X, Z1Z1);
        const S1 = fmul(p.Y, fmul(Z2Z2, q.Z));
        const S2 = fmul(q.Y, fmul(Z1Z1, p.Z));
        const H = fsub(U2, U1);
        const r = fsub(S2, S1);

        if (H === 0n) {
            if (r === 0n) return jDouble(p);
            return { X: 0n, Y: 1n, Z: 0n };
        }

        const HH = fsqr(H);
        const HHH = fmul(HH, H);
        const U1HH = fmul(U1, HH);
        const X3 = fsub(fsub(fsqr(r), HHH), fmul(2n, U1HH));
        const Y3 = fsub(fmul(r, fsub(U1HH, X3)), fmul(S1, HHH));
        const Z3 = fmul(fmul(p.Z, q.Z), H);
        return { X: X3, Y: Y3, Z: Z3 };
    }

    // Left-to-right double-and-add scalar multiplication of `scalar * p`.
    function jScalarMul(scalar, p) {
        let result = { X: 0n, Y: 1n, Z: 0n }; // identity
        const bits = scalar.toString(2);
        for (let i = 0; i < bits.length; i += 1) {
            result = jDouble(result);
            if (bits[i] === '1') {
                result = jAdd(result, p);
            }
        }
        return result;
    }

    // --- Public API --------------------------------------------------------

    /**
     * Compute `scalar · G` on P-256. Input: a BigInt `d` with 0 < d < n.
     * Output: the uncompressed public key as a 65-byte Uint8Array
     * (0x04 || X || Y), each coordinate 32 bytes big-endian.
     */
    function scalarBaseMul(scalar) {
        if (typeof scalar !== 'bigint') throw new TypeError('p256: scalar must be BigInt');
        const d = mod(scalar, N);
        if (d === 0n) throw new Error('p256: scalar is a multiple of curve order');

        const G = jacobianFromAffine(GX, GY);
        const result = jScalarMul(d, G);
        const { x, y } = affineFromJacobian(result);

        const out = new Uint8Array(65);
        out[0] = 0x04;
        writeBigUint(x, out, 1, 32);
        writeBigUint(y, out, 33, 32);
        return out;
    }

    /** Serialize a BigInt into `out[offset..offset+len]` big-endian. */
    function writeBigUint(v, out, offset, len) {
        let n = v;
        for (let i = len - 1; i >= 0; i -= 1) {
            out[offset + i] = Number(n & 0xffn);
            n >>= 8n;
        }
        if (n !== 0n) throw new Error('p256: scalar does not fit in requested width');
    }

    /** Parse a big-endian byte array into a BigInt. */
    function bytesToBigInt(bytes) {
        let n = 0n;
        for (let i = 0; i < bytes.length; i += 1) {
            n = (n << 8n) | BigInt(bytes[i]);
        }
        return n;
    }

    return Object.freeze({
        P,
        N,
        A,
        GX,
        GY,
        scalarBaseMul,
        bytesToBigInt,
    });
});
