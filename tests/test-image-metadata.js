#!/usr/bin/env node

/**
 * Outgoing images lose their metadata and keep their picture.
 *
 * The files are built here, segment by segment, so that every assertion can
 * name the exact bytes it expects: what makes up the picture is copied
 * unchanged, what only describes it is gone, and nothing survives after the
 * end of the image. The payloads are not real image data; the code under
 * test walks containers and never decodes.
 */

const assert = require('assert');
const path = require('path');

const { stripImageMetadata, detectImageType, ImageMetadataError } = require(
    path.join(__dirname, '..', 'static', 'js', 'image-metadata.js'),
);

let passed = 0;
let failed = 0;
function test(name, body) {
    try {
        body();
        console.log(`PASSED: ${name}`);
        passed += 1;
    } catch (error) {
        console.log(`FAILED: ${name}\n    ${error.stack.split('\n').slice(0, 3).join('\n    ')}`);
        failed += 1;
    }
}

const ascii = (text) => Uint8Array.from(text, (character) => character.charCodeAt(0));
const bytes = (...parts) => {
    const flat = [];
    for (const part of parts) {
        if (typeof part === 'number') flat.push(part);
        else if (typeof part === 'string') flat.push(...ascii(part));
        else flat.push(...part);
    }
    return Uint8Array.from(flat);
};
const hex = (data) => Buffer.from(data).toString('hex');
const sameBytes = (actual, expected, message) => assert.strictEqual(hex(actual), hex(expected), message);
const containsText = (data, text) => Buffer.from(data).toString('latin1').includes(text);
const strip = (data) => stripImageMetadata(data).bytes;

// A TIFF block as cameras write it: several tags, a pointer to a GPS
// directory, and the orientation somewhere in between.
function cameraTiff(orientation, { little = true } = {}) {
    const u16 = (value) => (little ? [value & 0xff, value >> 8] : [value >> 8, value & 0xff]);
    const u32 = (value) => (little
        ? [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, value >>> 24]
        : [value >>> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff]);
    const entry = (tag, type, count, value) => [...u16(tag), ...u16(type), ...u32(count), ...value];
    const makeOffset = 8 + 2 + 3 * 12 + 4;
    return bytes(
        little ? 'II' : 'MM', u16(42), u32(8),
        u16(3),
        entry(0x010f, 2, 10, u32(makeOffset)),                // Make, ASCII, stored after the directory
        entry(0x0112, 3, 1, [...u16(orientation), 0, 0]),     // Orientation
        entry(0x8825, 4, 1, u32(makeOffset + 10)),            // pointer to the GPS directory
        u32(0),
        'SECRETCAM\0',
        'GPS-SECRET-POSITION',
    );
}

const minimalTiff = (orientation) => bytes(
    'MM', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orientation, 0, 0, 0, 0, 0, 0,
);

// -----------------------------------------------------------------------------
// JPEG
// -----------------------------------------------------------------------------

const segment = (marker, payload) => {
    const data = bytes(payload);
    return bytes(0xff, marker, (data.length + 2) >> 8, (data.length + 2) & 0xff, data);
};
const SOI = [0xff, 0xd8];
const EOI = [0xff, 0xd9];
const JFIF = segment(0xe0, bytes('JFIF\0', 1, 1, 0, 0, 1, 0, 1, 0, 0));
const JFXX = segment(0xe0, bytes('JFXX\0', 0x10, 'SECRET-THUMBNAIL'));
const exif = (orientation, options) => segment(0xe1, bytes('Exif\0\0', cameraTiff(orientation, options)));
const XMP = segment(0xe1, 'http://ns.adobe.com/xap/1.0/\0<x:xmpmeta>SECRET-XMP</x:xmpmeta>');
const ICC = segment(0xe2, bytes('ICC_PROFILE\0', 1, 1, 'colour profile data'));
const MPF = segment(0xe2, bytes('MPF\0', 'SECRET-SECOND-IMAGE-INDEX'));
const IPTC = segment(0xed, 'Photoshop 3.0\x008BIM SECRET-IPTC-BYLINE');
const ADOBE = segment(0xee, bytes('Adobe', 0, 100, 0, 0, 0, 0, 1));
const COMMENT = segment(0xfe, 'SECRET-COMMENT');
const DQT = segment(0xdb, bytes(0, new Array(64).fill(7)));
const SOF = segment(0xc0, [8, 0, 16, 0, 16, 1, 1, 0x11, 0]);
const DHT = segment(0xc4, bytes(0, new Array(16).fill(0), 0xaa));
const SOS = segment(0xda, [1, 1, 0, 0, 63, 0]);
// Entropy-coded data with a stuffed 0xff, restart markers and fill bytes.
const SCAN1 = [0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56, 0xff, 0xd7, 0x78];
const SCAN2 = [0x9a, 0xff, 0x00, 0xff, 0x00, 0xbc];
const EXIF_ONLY_ORIENTATION = (orientation) => segment(0xe1, bytes('Exif\0\0', minimalTiff(orientation)));

test('a JPEG keeps its picture and loses everything that describes it', () => {
    const input = bytes(
        SOI, JFIF, JFXX, exif(6), XMP, ICC, MPF, IPTC, ADOBE, COMMENT,
        DQT, SOF, DHT, SOS, SCAN1, DHT, COMMENT, SOS, SCAN2, EOI,
        'SECRET-TRAILER-AFTER-THE-IMAGE',
    );
    const output = stripImageMetadata(input);
    assert.strictEqual(output.mimeType, 'image/jpeg');
    sameBytes(output.bytes, bytes(
        SOI, JFIF, EXIF_ONLY_ORIENTATION(6), ICC, ADOBE,
        DQT, SOF, DHT, SOS, SCAN1, DHT, SOS, SCAN2, EOI,
    ));
    assert(!containsText(output.bytes, 'SECRET'), 'no descriptive data is left');
    sameBytes(strip(output.bytes), output.bytes, 'stripping again changes nothing');
});

test('a thumbnail stored in the JFIF header itself is left out, and the header kept', () => {
    // Xthumbnail 2, Ythumbnail 1: six bytes of RGB pixels follow the fixed fields.
    const withThumbnail = segment(0xe0, bytes('JFIF\0', 1, 1, 0, 0, 1, 0, 1, 2, 1, 'SECRET'));
    const picture = [DQT, SOF, DHT, SOS, SCAN1, EOI];
    const output = strip(bytes(SOI, withThumbnail, exif(6), ...picture));
    sameBytes(output, bytes(SOI, JFIF, EXIF_ONLY_ORIENTATION(6), ...picture));
    assert(!containsText(output, 'SECRET'), 'the thumbnail pixels are gone');
    // A JFIF header too short for its own fixed fields is not kept at all.
    sameBytes(strip(bytes(SOI, segment(0xe0, bytes('JFIF\0', 1, 1)), ...picture)), bytes(SOI, ...picture));
});

test('a JPEG without a JFIF header gets its orientation right after the start marker', () => {
    const input = bytes(SOI, exif(8, { little: false }), DQT, SOF, DHT, SOS, SCAN1, EOI);
    sameBytes(strip(input), bytes(SOI, EXIF_ONLY_ORIENTATION(8), DQT, SOF, DHT, SOS, SCAN1, EOI));
});

test('an upright or unreadable orientation adds no Exif block at all', () => {
    const picture = [DQT, SOF, DHT, SOS, SCAN1, EOI];
    sameBytes(strip(bytes(SOI, JFIF, exif(1), ...picture)), bytes(SOI, JFIF, ...picture));
    sameBytes(strip(bytes(SOI, JFIF, exif(9), ...picture)), bytes(SOI, JFIF, ...picture));
    sameBytes(strip(bytes(SOI, JFIF, segment(0xe1, 'Exif\0\0garbage'), ...picture)), bytes(SOI, JFIF, ...picture));
    // A directory offset that points outside the block is not followed.
    const wild = segment(0xe1, bytes('Exif\0\0', 'II', 42, 0, 0xff, 0xff, 0xff, 0x7f));
    sameBytes(strip(bytes(SOI, JFIF, wild, ...picture)), bytes(SOI, JFIF, ...picture));
});

test('a JPEG that cannot be followed to its end is refused', () => {
    const good = bytes(SOI, JFIF, DQT, SOF, DHT, SOS, SCAN1, EOI);
    for (const [name, input] of [
        ['no end-of-image marker', good.subarray(0, good.length - 2)],
        ['ends inside the scan', good.subarray(0, good.length - 6)],
        ['ends before the scan', bytes(SOI, JFIF, DQT)],
        ['no image data', bytes(SOI, JFIF, EOI)],
        ['segment longer than the file', bytes(SOI, 0xff, 0xe0, 0xff, 0xff, 1, 2, 3)],
        ['segment length below two', bytes(SOI, 0xff, 0xe0, 0, 1, SOS, SCAN1, EOI)],
        ['garbage where a marker belongs', bytes(SOI, 0x12, 0x34, 0x56, 0x78, SOS, SCAN1, EOI)],
    ]) {
        assert.throws(() => strip(input), ImageMetadataError, name);
    }
});

// -----------------------------------------------------------------------------
// PNG
// -----------------------------------------------------------------------------

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
// The checksum is not looked at by the code under test; chunks that are kept
// are copied with whatever checksum they came with.
const chunk = (type, payload = []) => {
    const data = bytes(payload);
    return bytes(0, 0, data.length >> 8, data.length & 0xff, type, data, 0xc0, 0xff, 0xee, 0x00);
};
const IHDR = chunk('IHDR', [0, 0, 0, 16, 0, 0, 0, 16, 8, 3, 0, 0, 0]);
const IDAT = (fill) => chunk('IDAT', new Array(40).fill(fill));
const IEND = chunk('IEND');

/** CRC-32 as the PNG specification gives it, written out independently. */
function referenceCrc(data) {
    let crc = 0xffffffff;
    for (const byte of data) {
        crc ^= byte;
        for (let k = 0; k < 8; k += 1) crc = (crc & 1) ? ((crc >>> 1) ^ 0xedb88320) : (crc >>> 1);
    }
    return (crc ^ 0xffffffff) >>> 0;
}

test('a PNG keeps picture and colour chunks and loses text, time and Exif', () => {
    const kept = {
        iCCP: chunk('iCCP', 'profile\0\0compressed'),
        gAMA: chunk('gAMA', [0, 0, 0xb1, 0x8f]),
        PLTE: chunk('PLTE', [1, 2, 3, 4, 5, 6]),
        tRNS: chunk('tRNS', [0, 255]),
        pHYs: chunk('pHYs', [0, 0, 0x0b, 0x13, 0, 0, 0x0b, 0x13, 1]),
        acTL: chunk('acTL', [0, 0, 0, 2, 0, 0, 0, 0]),
        fcTL: chunk('fcTL', new Array(26).fill(1)),
        fdAT: chunk('fdAT', new Array(12).fill(2)),
    };
    const input = bytes(
        PNG_SIGNATURE, IHDR,
        chunk('tEXt', 'Comment\0SECRET-TEXT'), kept.iCCP, kept.gAMA,
        chunk('eXIf', cameraTiff(1)), chunk('tIME', [7, 234, 11, 19, 12, 0, 0]),
        kept.PLTE, kept.tRNS, kept.pHYs, chunk('iTXt', 'XML:com.adobe.xmp\0\0\0\0\0SECRET-XMP'),
        kept.acTL, kept.fcTL, IDAT(9), chunk('zTXt', 'Author\0\0SECRET-ZTXT'), IDAT(8),
        kept.fcTL, kept.fdAT, chunk('prVt', 'SECRET-PRIVATE-CHUNK'), IEND,
        'SECRET-TRAILER',
    );
    const output = stripImageMetadata(input);
    assert.strictEqual(output.mimeType, 'image/png');
    sameBytes(output.bytes, bytes(
        PNG_SIGNATURE, IHDR, kept.iCCP, kept.gAMA, kept.PLTE, kept.tRNS, kept.pHYs,
        kept.acTL, kept.fcTL, IDAT(9), IDAT(8), kept.fcTL, kept.fdAT, IEND,
    ));
    assert(!containsText(output.bytes, 'SECRET'));
});

test('a rotated PNG keeps its orientation in a new chunk with a valid checksum', () => {
    const input = bytes(PNG_SIGNATURE, IHDR, chunk('eXIf', cameraTiff(3)), IDAT(1), IEND);
    const output = strip(input);
    const tiff = minimalTiff(3);
    const typeAndData = bytes('eXIf', tiff);
    const crc = referenceCrc(typeAndData);
    const rebuilt = bytes(0, 0, 0, tiff.length, typeAndData, crc >>> 24, (crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff);
    sameBytes(output, bytes(PNG_SIGNATURE, IHDR, rebuilt, IDAT(1), IEND));
    assert(!containsText(output, 'SECRET'));
    sameBytes(strip(output), output, 'stripping again changes nothing');
});

test('a PNG with a broken structure or an unknown critical chunk is refused', () => {
    const good = bytes(PNG_SIGNATURE, IHDR, IDAT(1), IEND);
    for (const [name, input] of [
        ['no end chunk', good.subarray(0, good.length - 12)],
        ['ends inside a chunk', good.subarray(0, good.length - 20)],
        ['does not start with the header', bytes(PNG_SIGNATURE, IDAT(1), IHDR, IEND)],
        ['chunk longer than the file', bytes(PNG_SIGNATURE, IHDR, 0x7f, 0, 0, 0, 'IDAT', 1, 2, 3, 4, IEND)],
        ['chunk type that is not four letters', bytes(PNG_SIGNATURE, IHDR, chunk('ID\x01T'), IEND)],
        ['unknown critical chunk', bytes(PNG_SIGNATURE, IHDR, chunk('CgBI', [1, 2, 3, 4]), IDAT(1), IEND)],
    ]) {
        assert.throws(() => strip(input), ImageMetadataError, name);
    }
});

// -----------------------------------------------------------------------------
// GIF
// -----------------------------------------------------------------------------

const subBlocks = (...blocks) => bytes(...blocks.map((block) => bytes(bytes(block).length, block)), 0);
const GIF_HEADER = bytes('GIF89a', 16, 0, 16, 0, 0x80, 0, 0, [0, 0, 0, 255, 255, 255]); // two-colour global table
const LOOP = bytes(0x21, 0xff, subBlocks('NETSCAPE2.0', [1, 0, 0]));
const GIF_XMP = bytes(0x21, 0xff, subBlocks('XMP DataXMP', 'SECRET-XMP-PACKET'));
const GIF_COMMENT = bytes(0x21, 0xfe, subBlocks('SECRET-COMMENT', 'SECRET-MORE'));
const GIF_TEXT = bytes(0x21, 0x01, subBlocks(new Array(12).fill(0), 'SECRET-PLAIN-TEXT'));
const CONTROL = bytes(0x21, 0xf9, subBlocks([4, 10, 0, 0]));
const FRAME = bytes(0x2c, 0, 0, 0, 0, 16, 0, 16, 0, 0, 2, subBlocks([0x4c, 0x01], [0x3b, 0x21, 0x2c]));
const FRAME_LOCAL = bytes(0x2c, 0, 0, 0, 0, 16, 0, 16, 0, 0x80, [1, 2, 3, 4, 5, 6], 2, subBlocks([0x4c]));

test('a GIF keeps frames, timing and looping and loses comments and other extensions', () => {
    const input = bytes(
        GIF_HEADER, LOOP, GIF_COMMENT, GIF_XMP, CONTROL, FRAME, GIF_TEXT,
        CONTROL, FRAME_LOCAL, GIF_COMMENT, 0x3b, 'SECRET-TRAILER',
    );
    const output = stripImageMetadata(input);
    assert.strictEqual(output.mimeType, 'image/gif');
    sameBytes(output.bytes, bytes(GIF_HEADER, LOOP, CONTROL, FRAME, CONTROL, FRAME_LOCAL, 0x3b));
    assert(!containsText(output.bytes, 'SECRET'));
});

test('a GIF that cannot be followed to its trailer is refused', () => {
    const good = bytes(GIF_HEADER, CONTROL, FRAME, 0x3b);
    for (const [name, input] of [
        ['no trailer', good.subarray(0, good.length - 1)],
        ['ends inside the image data', good.subarray(0, good.length - 4)],
        ['ends inside the colour table', bytes('GIF89a', 16, 0, 16, 0, 0x87, 0, 0, 1, 2, 3)],
        ['unknown block', bytes(GIF_HEADER, 0x42, 0x3b)],
        ['shorter than the header', bytes('GIF89a', 1, 2)],
    ]) {
        assert.throws(() => strip(input), ImageMetadataError, name);
    }
});

// -----------------------------------------------------------------------------
// WebP
// -----------------------------------------------------------------------------

const le32 = (value) => [value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, value >>> 24];
const riffChunk = (type, payload) => {
    const data = bytes(payload);
    return bytes(type, le32(data.length), data, data.length & 1 ? [0] : []);
};
const webp = (...chunks) => {
    const body = bytes(...chunks);
    return bytes('RIFF', le32(4 + body.length), 'WEBP', body);
};
const FLAG = { ICC: 0x20, ALPHA: 0x10, EXIF: 0x08, XMP: 0x04, ANIM: 0x02 };
const vp8x = (flags) => riffChunk('VP8X', [flags, 0, 0, 0, 15, 0, 0, 15, 0, 0]);
const VP8 = riffChunk('VP8 ', new Array(31).fill(0x5a)); // odd length: padded
const ALPH = riffChunk('ALPH', [0, 1, 2, 3]);
const ICCP = riffChunk('ICCP', 'colour profile');
const WEBP_XMP = riffChunk('XMP ', '<x:xmpmeta>SECRET-XMP</x:xmpmeta>');

test('a WebP keeps picture, alpha and colour and loses Exif and XMP', () => {
    const input = bytes(
        webp(vp8x(FLAG.ICC | FLAG.ALPHA | FLAG.EXIF | FLAG.XMP), ICCP, ALPH, VP8,
            riffChunk('EXIF', cameraTiff(1)), WEBP_XMP, riffChunk('JUNK', 'SECRET-UNKNOWN-CHUNK')),
        'SECRET-TRAILER',
    );
    const output = stripImageMetadata(input);
    assert.strictEqual(output.mimeType, 'image/webp');
    sameBytes(output.bytes, webp(vp8x(FLAG.ICC | FLAG.ALPHA), ICCP, ALPH, VP8));
    assert(!containsText(output.bytes, 'SECRET'));
});

test('a rotated WebP keeps its orientation, with or without the JPEG prefix on the block', () => {
    const expected = webp(vp8x(FLAG.EXIF), VP8, riffChunk('EXIF', minimalTiff(6)));
    const plain = webp(vp8x(FLAG.EXIF | FLAG.XMP), VP8, riffChunk('EXIF', cameraTiff(6)), WEBP_XMP);
    const prefixed = webp(vp8x(FLAG.EXIF), VP8, riffChunk('EXIF', bytes('Exif\0\0', cameraTiff(6, { little: false }))));
    sameBytes(strip(plain), expected);
    sameBytes(strip(prefixed), expected);
    sameBytes(strip(expected), expected, 'stripping again changes nothing');
});

const VP8L = riffChunk('VP8L', [0x2f, 1, 2, 3, 4]);
const ANIM = riffChunk('ANIM', [0, 0, 0, 0, 0, 0]);
// An animation frame: position, size, duration and flags, then its own chunks.
const anmf = (...frameChunks) => riffChunk('ANMF', bytes(new Array(15).fill(1), 2, ...frameChunks));

test('an animated WebP keeps its frames and loses what is nested inside them', () => {
    const input = webp(vp8x(FLAG.ANIM | FLAG.ALPHA | FLAG.EXIF), ANIM,
        anmf(riffChunk('XYZW', 'SECRET-GPS 45.1,7.6'), ALPH, VP8),
        anmf(VP8L, riffChunk('EXIF', cameraTiff(1)), riffChunk('XMP ', 'SECRET-XMP')));
    const output = strip(input);
    sameBytes(output, webp(vp8x(FLAG.ANIM | FLAG.ALPHA), ANIM, anmf(ALPH, VP8), anmf(VP8L)));
    assert(!containsText(output, 'SECRET'), 'nothing nested in a frame survives');
    sameBytes(strip(output), output, 'stripping again changes nothing');
});

test('an animation frame that cannot be followed, or holds no picture, is refused', () => {
    for (const [name, frame] of [
        ['frame shorter than its header', riffChunk('ANMF', new Array(10).fill(0))],
        ['frame without image data', anmf(ALPH)],
        ['nested chunk larger than the frame', riffChunk('ANMF', bytes(new Array(16).fill(0), 'VP8L', le32(400), 1, 2))],
        ['frame ends inside a nested chunk header', riffChunk('ANMF', bytes(new Array(16).fill(0), 'VP8'))],
    ]) {
        assert.throws(() => strip(webp(vp8x(FLAG.ANIM), ANIM, frame)), ImageMetadataError, name);
    }
});

test('a simple WebP, which has no room for metadata, passes through unchanged', () => {
    sameBytes(strip(webp(VP8)), webp(VP8));
    sameBytes(strip(webp(riffChunk('VP8L', [0x2f, 1, 2, 3, 4]))), webp(riffChunk('VP8L', [0x2f, 1, 2, 3, 4])));
});

test('a WebP whose sizes do not add up is refused', () => {
    const good = webp(vp8x(0), VP8);
    for (const [name, input] of [
        ['size field larger than the file', good.subarray(0, good.length - 4)],
        ['chunk larger than the container', bytes('RIFF', le32(20), 'WEBP', 'VP8 ', le32(400), 1, 2, 3, 4, 5, 6, 7, 8)],
        ['ends inside a chunk header', bytes('RIFF', le32(8), 'WEBP', 'VP8 ')],
        ['no image data', webp(riffChunk('XMP ', 'only metadata'))],
        ['two extended headers', webp(vp8x(0), vp8x(0), VP8)],
    ]) {
        assert.throws(() => strip(input), ImageMetadataError, name);
    }
});

// -----------------------------------------------------------------------------
// Everything else
// -----------------------------------------------------------------------------

test('the type comes from the content, and anything else is refused', () => {
    assert.strictEqual(detectImageType(bytes(SOI, JFIF)), 'image/jpeg');
    assert.strictEqual(detectImageType(bytes(PNG_SIGNATURE)), 'image/png');
    assert.strictEqual(detectImageType(bytes('GIF87a')), 'image/gif');
    assert.strictEqual(detectImageType(webp(VP8)), 'image/webp');
    for (const other of [
        bytes('<svg xmlns="http://www.w3.org/2000/svg"></svg>'),
        bytes('BM', new Array(30).fill(0)),
        bytes('RIFF', le32(4), 'WAVE'),
        bytes(),
    ]) {
        assert.strictEqual(detectImageType(other), null);
        assert.throws(() => strip(other), ImageMetadataError);
    }
    assert.throws(() => stripImageMetadata('not bytes'), ImageMetadataError);
    assert.throws(() => stripImageMetadata(new ArrayBuffer(8)), ImageMetadataError);
});

test('damaged files are refused or cleaned, never passed on with something added', () => {
    // A small deterministic generator: the test must not depend on luck.
    let seed = 0x2f6e2b1;
    const random = (limit) => {
        seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
        return seed % limit;
    };
    const samples = [
        bytes(SOI, JFIF, exif(6), XMP, ICC, COMMENT, DQT, SOF, DHT, SOS, SCAN1, DHT, SOS, SCAN2, EOI, 'tail'),
        bytes(PNG_SIGNATURE, IHDR, chunk('tEXt', 'k\0v'), chunk('eXIf', cameraTiff(3)), IDAT(1), IEND, 'tail'),
        bytes(GIF_HEADER, LOOP, GIF_COMMENT, CONTROL, FRAME, CONTROL, FRAME_LOCAL, 0x3b, 'tail'),
        bytes(webp(vp8x(FLAG.EXIF | FLAG.XMP), VP8, riffChunk('EXIF', cameraTiff(6)), WEBP_XMP), 'tail'),
        bytes(webp(vp8x(FLAG.ANIM), ANIM, anmf(riffChunk('XYZW', 'k'), ALPH, VP8), anmf(VP8L)), 'tail'),
    ];
    // The most a file can grow by: a new orientation block where the old
    // one was missing its container (WebP chunk header plus padding).
    const GROWTH_LIMIT = 40;
    let refused = 0;
    let cleaned = 0;
    for (let round = 0; round < 6000; round += 1) {
        const original = samples[round % samples.length];
        let mutated = Uint8Array.from(original);
        const kind = random(4);
        if (kind === 0) {
            mutated = mutated.subarray(0, random(mutated.length + 1));
        } else if (kind === 1) {
            for (let flips = 1 + random(4); flips > 0; flips -= 1) mutated[random(mutated.length)] = random(256);
        } else if (kind === 2) {
            const at = random(mutated.length);
            mutated = bytes(mutated.subarray(0, at), new Array(1 + random(6)).fill(random(256)), mutated.subarray(at));
        } else {
            const at = random(mutated.length);
            mutated = bytes(mutated.subarray(0, at), mutated.subarray(Math.min(mutated.length, at + 1 + random(8))));
        }
        let output;
        try {
            output = strip(mutated);
        } catch (error) {
            assert(error instanceof ImageMetadataError,
                `round ${round}: a damaged file must be refused cleanly, got ${error.stack}`);
            refused += 1;
            continue;
        }
        cleaned += 1;
        assert(output.length <= mutated.length + GROWTH_LIMIT, `round ${round}: output grew`);
        sameBytes(strip(output), output, `round ${round}: output is not stable`);
        assert(!containsText(output, 'tail'), `round ${round}: data after the image survived`);
    }
    assert(refused > 500 && cleaned > 500, `both outcomes are exercised (${refused} refused, ${cleaned} cleaned)`);
});

console.log(`\n${passed} image metadata tests passed${failed ? `, ${failed} failed` : ''}`);
process.exit(failed === 0 ? 0 : 1);
