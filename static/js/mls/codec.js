/**
 * PinChat MLS — wire-format codec (RFC 9420 §2 + §B).
 *
 * MLS adopts the TLS 1.3 presentation language (RFC 8446) with a twist:
 * variable-length vectors carry an MLS variable-length integer prefix based
 * on QUIC (RFC 9000 §16), but with two security-relevant restrictions from
 * RFC 9420 §2.1.2: encodings MUST be minimal and the 8-byte form is invalid.
 * Fixed-width primitives are still big-endian.
 *
 * MLS varint layout:
 *   Two top bits of first byte  | total bytes | value range
 *   ─────────────────────────── | ─────────── | ──────────────────────
 *   00                          | 1           | 0 .. 2^6  - 1
 *   01                          | 2           | 2^6  .. 2^14 - 1
 *   10                          | 4           | 2^14 .. 2^30 - 1
 *   11                          | invalid     | —
 *
 * All encode functions produce a Uint8Array; all decode functions accept a
 * `Decoder` cursor and advance it on success, throwing on truncation.
 */
(function (root, factory) {
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = factory();
    } else {
        root.MLS = root.MLS || {};
        root.MLS.Codec = factory();
    }
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ----- Uint8Array helpers ------------------------------------------------

    function concatBytes(chunks) {
        let total = 0;
        for (const c of chunks) total += c.length;
        const out = new Uint8Array(total);
        let offset = 0;
        for (const c of chunks) {
            out.set(c, offset);
            offset += c.length;
        }
        return out;
    }

    function bytesEqual(a, b) {
        if (a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
        return diff === 0;
    }

    // ----- Encoder -----------------------------------------------------------

    class Encoder {
        constructor() {
            this.chunks = [];
            this.len = 0;
        }

        _push(chunk) {
            this.chunks.push(chunk);
            this.len += chunk.length;
        }

        writeBytes(bytes) {
            if (!(bytes instanceof Uint8Array)) {
                throw new TypeError('writeBytes: Uint8Array required');
            }
            this._push(bytes);
            return this;
        }

        writeU8(v) {
            if (v < 0 || v > 0xff) throw new RangeError('u8 out of range');
            this._push(new Uint8Array([v & 0xff]));
            return this;
        }

        writeU16(v) {
            if (v < 0 || v > 0xffff) throw new RangeError('u16 out of range');
            this._push(new Uint8Array([(v >>> 8) & 0xff, v & 0xff]));
            return this;
        }

        writeU32(v) {
            if (v < 0 || v > 0xffffffff) throw new RangeError('u32 out of range');
            const b = new Uint8Array(4);
            b[0] = (v >>> 24) & 0xff;
            b[1] = (v >>> 16) & 0xff;
            b[2] = (v >>> 8) & 0xff;
            b[3] = v & 0xff;
            this._push(b);
            return this;
        }

        writeU64(v) {
            // Accept Number up to 2^53-1 or BigInt up to 2^64-1.
            let big;
            if (typeof v === 'bigint') {
                big = v;
            } else if (typeof v === 'number' && Number.isInteger(v)) {
                big = BigInt(v);
            } else {
                throw new TypeError('u64 requires integer or bigint');
            }
            if (big < 0n || big > 0xffffffffffffffffn) {
                throw new RangeError('u64 out of range');
            }
            const b = new Uint8Array(8);
            for (let i = 7; i >= 0; i -= 1) {
                b[i] = Number(big & 0xffn);
                big >>= 8n;
            }
            this._push(b);
            return this;
        }

        writeVarint(v) {
            this._push(encodeVarint(v));
            return this;
        }

        /**
         * Write an MLS opaque<V>: varint length prefix followed by the raw
         * bytes. MLS uses this for every variable-length byte string.
         */
        writeOpaque(bytes) {
            if (!(bytes instanceof Uint8Array)) {
                throw new TypeError('writeOpaque: Uint8Array required');
            }
            this.writeVarint(bytes.length);
            this._push(bytes);
            return this;
        }

        /**
         * Write an MLS variable-length vector T<V>: length prefix is the
         * byte size of the concatenated element encodings. `writeElement`
         * is called with (elementEncoder, element) for each entry.
         */
        writeVector(items, writeElement) {
            const inner = new Encoder();
            for (const item of items) {
                writeElement(inner, item);
            }
            const encoded = inner.bytes();
            this.writeVarint(encoded.length);
            this._push(encoded);
            return this;
        }

        bytes() {
            return concatBytes(this.chunks);
        }
    }

    // ----- Decoder -----------------------------------------------------------

    class Decoder {
        constructor(buffer) {
            if (!(buffer instanceof Uint8Array)) {
                throw new TypeError('Decoder: Uint8Array required');
            }
            this.buf = buffer;
            this.pos = 0;
        }

        remaining() {
            return this.buf.length - this.pos;
        }

        _need(n) {
            if (this.remaining() < n) {
                throw new Error(
                    `Decoder: truncated at pos=${this.pos}, need ${n} bytes, have ${this.remaining()}`
                );
            }
        }

        readBytes(n) {
            this._need(n);
            const out = this.buf.subarray(this.pos, this.pos + n);
            this.pos += n;
            // Copy so callers cannot mutate the underlying buffer.
            return new Uint8Array(out);
        }

        readU8() {
            this._need(1);
            const v = this.buf[this.pos];
            this.pos += 1;
            return v;
        }

        readU16() {
            this._need(2);
            const v = (this.buf[this.pos] << 8) | this.buf[this.pos + 1];
            this.pos += 2;
            return v;
        }

        readU32() {
            this._need(4);
            // Use unsigned-right-shift to avoid sign bit issues for values >= 2^31.
            const v =
                ((this.buf[this.pos] << 24) >>> 0) |
                ((this.buf[this.pos + 1] << 16) >>> 0) |
                ((this.buf[this.pos + 2] << 8) >>> 0) |
                this.buf[this.pos + 3];
            this.pos += 4;
            return v >>> 0;
        }

        readU64() {
            this._need(8);
            let big = 0n;
            for (let i = 0; i < 8; i += 1) {
                big = (big << 8n) | BigInt(this.buf[this.pos + i]);
            }
            this.pos += 8;
            return big;
        }

        readVarint() {
            const { value, bytes } = decodeVarintAt(this.buf, this.pos);
            this.pos += bytes;
            return value;
        }

        /** Read an MLS opaque<V>: varint length then raw bytes. */
        readOpaque() {
            const len = this.readVarint();
            return this.readBytes(Number(len));
        }

        /**
         * Read an MLS variable-length vector T<V>: varint byte-length prefix
         * then repeated calls to `readElement(decoder)` until the sub-buffer
         * is fully consumed. Returns an array of decoded items.
         */
        readVector(readElement) {
            const byteLen = Number(this.readVarint());
            this._need(byteLen);
            const sub = new Decoder(this.buf.subarray(this.pos, this.pos + byteLen));
            this.pos += byteLen;
            const items = [];
            while (sub.remaining() > 0) {
                items.push(readElement(sub));
            }
            return items;
        }
    }

    // ----- Stand-alone varint helpers ---------------------------------------

    /**
     * Encode a canonical MLS variable-length integer. RFC 9420 §2.1.2
     * permits only the minimal 1-, 2-, or 4-byte form, up to 2^30-1.
     */
    function encodeVarint(v) {
        let big;
        if (typeof v === 'bigint') {
            big = v;
        } else if (typeof v === 'number' && Number.isInteger(v) && v >= 0) {
            big = BigInt(v);
        } else {
            throw new TypeError('varint requires non-negative integer or bigint');
        }
        if (big < 0n) throw new RangeError('varint: negative');
        if (big <= 0x3fn) {
            return new Uint8Array([Number(big)]);
        }
        if (big <= 0x3fffn) {
            return new Uint8Array([
                0x40 | Number((big >> 8n) & 0x3fn),
                Number(big & 0xffn),
            ]);
        }
        if (big <= 0x3fffffffn) {
            return new Uint8Array([
                0x80 | Number((big >> 24n) & 0x3fn),
                Number((big >> 16n) & 0xffn),
                Number((big >> 8n) & 0xffn),
                Number(big & 0xffn),
            ]);
        }
        throw new RangeError('varint: value exceeds MLS maximum 2^30-1');
    }

    /**
     * Decode a canonical MLS variable-length integer from `buf` at `offset`.
     * Returns {value, bytes}, with a Number value and a 1/2/4-byte length.
     * Prefix 0b11 and non-minimal encodings are malformed in MLS.
     */
    function decodeVarintAt(buf, offset) {
        if (!(buf instanceof Uint8Array)) {
            throw new TypeError('varint: Uint8Array required');
        }
        if (!Number.isInteger(offset) || offset < 0) {
            throw new RangeError('varint: offset must be a non-negative integer');
        }
        if (offset >= buf.length) throw new Error('varint: truncated');
        const first = buf[offset];
        const prefix = first >> 6;
        if (prefix === 3) {
            throw new Error('varint: invalid MLS prefix 0b11');
        }
        const length = 1 << prefix; // MLS permits only 1, 2, or 4.
        if (offset + length > buf.length) throw new Error('varint: truncated');

        let value = first & 0x3f;
        for (let i = 1; i < length; i += 1) {
            value = (value * 256) + buf[offset + i];
        }
        const minimum = length === 2 ? 0x40 : (length === 4 ? 0x4000 : 0);
        if (value < minimum) {
            throw new Error('varint: non-minimal MLS encoding');
        }
        return { value, bytes: length };
    }

    // ----- base64url helpers (used for JSON envelopes on the wire) ----------

    function bytesToBase64Url(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i += 1) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 =
            typeof btoa !== 'undefined'
                ? btoa(binary)
                : Buffer.from(bytes).toString('base64');
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function base64UrlToBytes(str) {
        const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4));
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + pad;
        if (typeof atob !== 'undefined') {
            const binary = atob(base64);
            const out = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
            return out;
        }
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }

    return Object.freeze({
        Encoder,
        Decoder,
        encodeVarint,
        decodeVarintAt,
        concatBytes,
        bytesEqual,
        bytesToBase64Url,
        base64UrlToBytes,
    });
});
