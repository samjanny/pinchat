#!/usr/bin/env node

/**
 * MLS wire-format codec test suite.
 *
 * Covers:
 *   - Fixed-width big-endian integers (u8/u16/u32/u64).
 *   - Canonical MLS variable-length integers (RFC 9420 §2.1.2).
 *   - Opaque<V> and variable-length vector T<V> round-trips.
 *   - Truncation / out-of-range error handling.
 */

const path = require('path');
const Codec = require(path.join(__dirname, '..', 'static', 'js', 'mls', 'codec.js'));

let passed = 0;
let failed = 0;

function assert(cond, name, detail) {
    if (cond) {
        console.log(`  OK   ${name}`);
        passed += 1;
    } else {
        console.log(`  FAIL ${name}${detail ? `  — ${detail}` : ''}`);
        failed += 1;
    }
}

function bytes(hex) {
    const h = hex.replace(/\s+/g, '');
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i += 1) {
        out[i] = parseInt(h.substr(i * 2, 2), 16);
    }
    return out;
}

function hex(u8) {
    return Array.from(u8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function eqHex(got, want, name) {
    const g = hex(got);
    const w = hex(want);
    assert(g === w, name, g === w ? null : `expected ${w}, got ${g}`);
}

function eq(a, b, name) {
    const ok = JSON.stringify(a) === JSON.stringify(b);
    assert(ok, name, ok ? null : `expected ${JSON.stringify(b)}, got ${JSON.stringify(a)}`);
}

function throws(fn, name) {
    let threw = false;
    try {
        fn();
    } catch (_e) {
        threw = true;
    }
    assert(threw, name, threw ? null : 'expected throw');
}

// ---------------------------------------------------------------------------
// Fixed-width integers
// ---------------------------------------------------------------------------
console.log('# fixed-width integers');
(function () {
    const enc = new Codec.Encoder();
    enc.writeU8(0x12);
    enc.writeU16(0x1234);
    enc.writeU32(0x12345678);
    enc.writeU64(0x0102030405060708n);
    eqHex(enc.bytes(), bytes('12 1234 12345678 0102030405060708'), 'encode u8/u16/u32/u64 BE');

    const dec = new Codec.Decoder(enc.bytes());
    eq(dec.readU8(), 0x12, 'decode u8');
    eq(dec.readU16(), 0x1234, 'decode u16');
    eq(dec.readU32(), 0x12345678, 'decode u32');
    assert(dec.readU64() === 0x0102030405060708n, 'decode u64 (BigInt)');
    eq(dec.remaining(), 0, 'decoder fully consumed');
})();

// ---------------------------------------------------------------------------
// MLS varint — RFC 9420 §2.1.2 reference vectors and canonicality
// ---------------------------------------------------------------------------
console.log('# canonical MLS varint reference vectors');
(function () {
    // These three examples are listed directly in RFC 9420 §2.1.2.
    const cases = [
        { hex: '25', value: 37 },              // 1-byte
        { hex: '7bbd', value: 15293 },         // 2-byte
        { hex: '9d7f3e7d', value: 494878333 }, // 4-byte
    ];
    for (const c of cases) {
        const encoded = Codec.encodeVarint(c.value);
        eqHex(encoded, bytes(c.hex), `encode varint ${c.value}`);
        const { value, bytes: consumed } = Codec.decodeVarintAt(bytes(c.hex), 0);
        eq(consumed, bytes(c.hex).length, `varint ${c.value} length`);
        assert(value === c.value, `decode varint ${c.value}`, `got ${value}`);
    }

    // Boundary values
    eqHex(Codec.encodeVarint(0), bytes('00'), 'encode varint 0');
    eqHex(Codec.encodeVarint(63), bytes('3f'), 'encode varint 63 (max 1-byte)');
    eqHex(Codec.encodeVarint(64), bytes('4040'), 'encode varint 64 (min 2-byte)');
    eqHex(Codec.encodeVarint(16383), bytes('7fff'), 'encode varint 16383 (max 2-byte)');
    eqHex(Codec.encodeVarint(16384), bytes('80004000'), 'encode varint 16384 (min 4-byte)');
    eqHex(Codec.encodeVarint(0x3fffffff), bytes('bfffffff'),
        'encode varint 2^30-1 (MLS maximum)');
    eq(Codec.decodeVarintAt(bytes('4040'), 0).value, 64,
        'decode canonical 2-byte minimum');
    eq(Codec.decodeVarintAt(bytes('80004000'), 0).value, 16384,
        'decode canonical 4-byte minimum');
    eq(Codec.decodeVarintAt(bytes('bfffffff'), 0).value, 0x3fffffff,
        'decode canonical MLS maximum');

    throws(() => Codec.encodeVarint(-1), 'varint encode rejects negative');
    throws(() => Codec.encodeVarint(0x40000000),
        'varint encode rejects value above MLS maximum');
    throws(() => Codec.encodeVarint(0x3fffffffffffffffn),
        'varint encode rejects QUIC-only 8-byte value');

    // MLS requires the shortest possible encoding for each value.
    throws(() => Codec.decodeVarintAt(bytes('4025'), 0),
        'decode rejects 2-byte encoding of 1-byte value');
    throws(() => Codec.decodeVarintAt(bytes('80000025'), 0),
        'decode rejects 4-byte encoding of 1-byte value');
    throws(() => Codec.decodeVarintAt(bytes('80003fff'), 0),
        'decode rejects 4-byte encoding of 2-byte value');
    throws(() => Codec.decodeVarintAt(bytes('c2197c5eff14e88c'), 0),
        'decode rejects invalid MLS prefix 0b11 / QUIC 8-byte form');
    throws(() => Codec.decodeVarintAt(bytes('40'), 0),
        'decode rejects truncated 2-byte varint');
    throws(() => Codec.decodeVarintAt(bytes('800040'), 0),
        'decode rejects truncated 4-byte varint');

    const rejected = new Codec.Decoder(bytes('4025aa'));
    throws(() => rejected.readVarint(),
        'Decoder.readVarint rejects non-minimal encoding');
    eq(rejected.pos, 0, 'rejected varint leaves Decoder cursor unchanged');
})();

// ---------------------------------------------------------------------------
// Opaque<V>
// ---------------------------------------------------------------------------
console.log('# opaque<V>');
(function () {
    const payload = bytes('deadbeef');
    const enc = new Codec.Encoder();
    enc.writeOpaque(payload);
    eqHex(enc.bytes(), bytes('04 deadbeef'), 'encode opaque<V> 4 bytes');

    const dec = new Codec.Decoder(enc.bytes());
    const got = dec.readOpaque();
    eqHex(got, payload, 'decode opaque<V>');
    eq(dec.remaining(), 0, 'opaque fully consumed');

    // Empty opaque encodes as a single 0x00 byte varint.
    const enc2 = new Codec.Encoder();
    enc2.writeOpaque(new Uint8Array(0));
    eqHex(enc2.bytes(), bytes('00'), 'encode empty opaque');
    const dec2 = new Codec.Decoder(enc2.bytes());
    eq(dec2.readOpaque().length, 0, 'decode empty opaque');
})();

// ---------------------------------------------------------------------------
// Variable-length vector T<V>
// ---------------------------------------------------------------------------
console.log('# vector T<V>');
(function () {
    // Encode an array of u16 values [0x1111, 0x2222, 0x3333]
    const enc = new Codec.Encoder();
    enc.writeVector([0x1111, 0x2222, 0x3333], (e, v) => e.writeU16(v));
    // 3 items * 2 bytes = 6-byte contents, varint prefix = 0x06
    eqHex(enc.bytes(), bytes('06 1111 2222 3333'), 'encode u16 vector');

    const dec = new Codec.Decoder(enc.bytes());
    const got = dec.readVector((d) => d.readU16());
    eq(got, [0x1111, 0x2222, 0x3333], 'decode u16 vector');

    // Empty vector
    const enc2 = new Codec.Encoder();
    enc2.writeVector([], () => {
        throw new Error('should not be called');
    });
    eqHex(enc2.bytes(), bytes('00'), 'encode empty vector');
    const dec2 = new Codec.Decoder(enc2.bytes());
    eq(dec2.readVector(() => 'unused'), [], 'decode empty vector');
})();

// ---------------------------------------------------------------------------
// Truncation / error handling
// ---------------------------------------------------------------------------
console.log('# truncation / errors');
(function () {
    throws(() => new Codec.Decoder(bytes('')).readU8(), 'empty u8 throws');
    throws(() => new Codec.Decoder(bytes('04 dead')).readOpaque(), 'opaque short throws');
    throws(() => new Codec.Decoder(bytes('06 1111 22')).readVector((d) => d.readU16()), 'vector short throws');

    throws(() => new Codec.Encoder().writeU8(-1), 'u8 negative throws');
    throws(() => new Codec.Encoder().writeU8(256), 'u8 overflow throws');
    throws(() => new Codec.Encoder().writeU16(0x10000), 'u16 overflow throws');
})();

// ---------------------------------------------------------------------------
// Round-trip larger structure (mimicking an MLS Proposal wrapper)
// ---------------------------------------------------------------------------
console.log('# nested round-trip');
(function () {
    const enc = new Codec.Encoder();
    enc.writeU16(0x000a);                           // proposal type
    enc.writeOpaque(bytes('aabbccdd'));             // leaf node hash
    enc.writeVector(
        [bytes('1111'), bytes('22'), bytes('333333')],
        (e, v) => e.writeOpaque(v)                   // each item is opaque<V>
    );

    const dec = new Codec.Decoder(enc.bytes());
    eq(dec.readU16(), 0x000a, 'proposal type');
    eqHex(dec.readOpaque(), bytes('aabbccdd'), 'leaf node hash');
    const items = dec.readVector((d) => d.readOpaque());
    eq(items.length, 3, 'vector item count');
    eqHex(items[0], bytes('1111'), 'vector[0]');
    eqHex(items[1], bytes('22'), 'vector[1]');
    eqHex(items[2], bytes('333333'), 'vector[2]');
    eq(dec.remaining(), 0, 'fully consumed');
})();

// ---------------------------------------------------------------------------
// base64url helpers
// ---------------------------------------------------------------------------
console.log('# base64url');
(function () {
    const payload = bytes('deadbeef');
    const encoded = Codec.bytesToBase64Url(payload);
    eq(encoded, '3q2-7w', 'base64url encode');
    const back = Codec.base64UrlToBytes(encoded);
    eqHex(back, payload, 'base64url round-trip');
})();

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log('');
console.log(`codec: ${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
