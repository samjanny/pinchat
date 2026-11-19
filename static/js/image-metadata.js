/**
 * Removes metadata from an image before it is sent.
 *
 * A photo carries more than its pixels: where and when it was taken, the
 * device and its serial number, the software that touched it, sometimes a
 * thumbnail of the uncropped original. End-to-end encryption hides all of
 * that from the server and hands it to the recipient intact. The sender
 * meant to share a picture.
 *
 * The file is not decoded and re-encoded. Its container is walked, the parts
 * that only describe the picture are left out, and everything that makes up
 * the picture is copied byte for byte, so quality, animation and colour
 * rendering do not change.
 *
 * Kept on purpose:
 * - colour information (ICC profiles, gamma, the Adobe transform marker),
 *   which decides what the pixels look like;
 * - the orientation, and nothing else, from the Exif block of a JPEG, PNG
 *   or WebP file. Browsers rotate by it; without it a portrait photo
 *   arrives lying on its side. It is written into a new, minimal Exif block.
 *
 * Anything this code does not recognise as part of the picture is dropped,
 * and so is everything that follows the end of the image. A file whose
 * structure cannot be followed to that end is refused, not passed on: the
 * caller shows an error instead of sending something unexamined.
 */

const IMAGE_METADATA_TYPES = Object.freeze({
    JPEG: 'image/jpeg',
    PNG: 'image/png',
    GIF: 'image/gif',
    WEBP: 'image/webp',
});

class ImageMetadataError extends Error {
    constructor(message) {
        super(message);
        this.name = 'ImageMetadataError';
    }
}

function imageMetadataFail(message) {
    throw new ImageMetadataError(message);
}

function startsWithBytes(bytes, offset, expected) {
    if (offset < 0 || offset + expected.length > bytes.length) return false;
    for (let i = 0; i < expected.length; i += 1) {
        if (bytes[offset + i] !== expected[i]) return false;
    }
    return true;
}

function asciiBytes(text) {
    return Array.from(text, (character) => character.charCodeAt(0));
}

function concatBytes(parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/** The format a file actually is, from its first bytes; null if none of the four. */
function detectImageType(bytes) {
    if (startsWithBytes(bytes, 0, [0xff, 0xd8, 0xff])) return IMAGE_METADATA_TYPES.JPEG;
    if (startsWithBytes(bytes, 0, PNG_SIGNATURE)) return IMAGE_METADATA_TYPES.PNG;
    if (startsWithBytes(bytes, 0, asciiBytes('GIF87a')) || startsWithBytes(bytes, 0, asciiBytes('GIF89a'))) {
        return IMAGE_METADATA_TYPES.GIF;
    }
    if (startsWithBytes(bytes, 0, asciiBytes('RIFF')) && startsWithBytes(bytes, 8, asciiBytes('WEBP'))) {
        return IMAGE_METADATA_TYPES.WEBP;
    }
    return null;
}

// -----------------------------------------------------------------------------
// Exif: read the orientation, write a block that holds only that
// -----------------------------------------------------------------------------

/**
 * Orientation (1 to 8) from a TIFF structure, or null. Reads the first
 * directory only and never follows a pointer out of the block.
 */
function readTiffOrientation(tiff) {
    if (tiff.length < 8) return null;
    let little;
    if (tiff[0] === 0x49 && tiff[1] === 0x49) little = true;
    else if (tiff[0] === 0x4d && tiff[1] === 0x4d) little = false;
    else return null;
    const u16 = (offset) => (little
        ? tiff[offset] | (tiff[offset + 1] << 8)
        : (tiff[offset] << 8) | tiff[offset + 1]);
    const u32 = (offset) => (little
        ? (tiff[offset] | (tiff[offset + 1] << 8) | (tiff[offset + 2] << 16) | (tiff[offset + 3] << 24)) >>> 0
        : ((tiff[offset] << 24) | (tiff[offset + 1] << 16) | (tiff[offset + 2] << 8) | tiff[offset + 3]) >>> 0);
    if (u16(2) !== 42) return null;
    const directory = u32(4);
    if (directory + 2 > tiff.length) return null;
    const entries = u16(directory);
    for (let i = 0; i < entries; i += 1) {
        const entry = directory + 2 + i * 12;
        if (entry + 12 > tiff.length) return null;
        // Tag 0x0112, type SHORT, one value, stored in the entry itself.
        if (u16(entry) === 0x0112 && u16(entry + 2) === 3 && u32(entry + 4) === 1) {
            const value = u16(entry + 8);
            return value >= 1 && value <= 8 ? value : null;
        }
    }
    return null;
}

/** A TIFF structure with one directory and one entry: the orientation. */
function minimalTiff(orientation) {
    return new Uint8Array([
        0x4d, 0x4d, 0x00, 0x2a,             // big-endian TIFF
        0x00, 0x00, 0x00, 0x08,             // first directory at offset 8
        0x00, 0x01,                         // one entry
        0x01, 0x12, 0x00, 0x03,             // Orientation, SHORT
        0x00, 0x00, 0x00, 0x01,             // one value
        0x00, orientation, 0x00, 0x00,      // the value
        0x00, 0x00, 0x00, 0x00,             // no further directory
    ]);
}

const EXIF_HEADER = [0x45, 0x78, 0x69, 0x66, 0x00, 0x00]; // "Exif\0\0"

// -----------------------------------------------------------------------------
// JPEG
// -----------------------------------------------------------------------------

function stripJpeg(bytes) {
    const parts = [bytes.subarray(0, 2)];
    let orientation = null;
    let offset = 2;
    let insertExifAt = 1;

    // Segments up to the first scan.
    for (;;) {
        if (offset + 4 > bytes.length) imageMetadataFail('JPEG ends before its image data');
        if (bytes[offset] !== 0xff) imageMetadataFail('JPEG segment does not start with a marker');
        // Fill bytes before a marker are allowed.
        while (bytes[offset + 1] === 0xff) {
            offset += 1;
            if (offset + 4 > bytes.length) imageMetadataFail('JPEG ends before its image data');
        }
        const marker = bytes[offset + 1];
        if (marker === 0xd9) imageMetadataFail('JPEG has no image data');
        if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
            imageMetadataFail('JPEG has an unexpected marker before its image data');
        }
        const length = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (length < 2 || offset + 2 + length > bytes.length) imageMetadataFail('JPEG segment runs past the file');
        const segment = bytes.subarray(offset, offset + 2 + length);
        const payload = offset + 4;

        if (marker === 0xda) break; // start of scan: handled below

        let keep = true;
        if (marker === 0xe1) {
            // APP1: Exif or XMP. Only the orientation survives, re-encoded.
            keep = false;
            if (orientation === null && startsWithBytes(bytes, payload, EXIF_HEADER)) {
                orientation = readTiffOrientation(bytes.subarray(payload + 6, offset + 2 + length));
            }
        } else if (marker === 0xe0) {
            // APP0: the JFIF header. Its extension (JFXX) is a thumbnail.
            keep = startsWithBytes(bytes, payload, asciiBytes('JFIF\0'));
            if (keep && parts.length === 1) insertExifAt = 2;
        } else if (marker === 0xe2) {
            keep = startsWithBytes(bytes, payload, asciiBytes('ICC_PROFILE\0'));
        } else if (marker === 0xee) {
            keep = startsWithBytes(bytes, payload, asciiBytes('Adobe'));
        } else if ((marker >= 0xe3 && marker <= 0xef) || marker === 0xfe) {
            keep = false; // other application segments, comments
        }
        if (keep) parts.push(segment);
        offset += 2 + length;
    }

    // From the first scan to the end of the image. Entropy-coded data runs
    // until a marker that is neither a stuffed byte nor a restart marker;
    // tables and further scans may follow, then the end-of-image marker.
    for (;;) {
        // offset is at a marker with a length: a scan header or a table.
        if (offset + 4 > bytes.length) imageMetadataFail('JPEG ends inside its image data');
        const marker = bytes[offset + 1];
        const length = (bytes[offset + 2] << 8) | bytes[offset + 3];
        if (bytes[offset] !== 0xff || length < 2 || offset + 2 + length > bytes.length) {
            imageMetadataFail('JPEG image data is malformed');
        }
        const start = offset;
        offset += 2 + length;
        if (marker === 0xda) {
            for (;;) {
                const next = bytes.indexOf(0xff, offset);
                if (next === -1 || next + 1 >= bytes.length) imageMetadataFail('JPEG has no end-of-image marker');
                const following = bytes[next + 1];
                if (following === 0x00 || (following >= 0xd0 && following <= 0xd7)) {
                    offset = next + 2;
                } else if (following === 0xff) {
                    offset = next + 1;
                } else {
                    offset = next;
                    break;
                }
            }
        }
        // Application segments and comments can sit between scans as well.
        const describesOnly = (marker >= 0xe0 && marker <= 0xef) || marker === 0xfe;
        if (!describesOnly) parts.push(bytes.subarray(start, offset));
        if (offset + 2 > bytes.length) imageMetadataFail('JPEG has no end-of-image marker');
        if (bytes[offset] === 0xff && bytes[offset + 1] === 0xd9) {
            parts.push(bytes.subarray(offset, offset + 2)); // and nothing after it
            break;
        }
    }

    if (orientation !== null && orientation !== 1) {
        const tiff = minimalTiff(orientation);
        const length = 2 + EXIF_HEADER.length + tiff.length;
        const segment = concatBytes([
            new Uint8Array([0xff, 0xe1, length >> 8, length & 0xff]),
            new Uint8Array(EXIF_HEADER),
            tiff,
        ]);
        parts.splice(insertExifAt, 0, segment);
    }
    return concatBytes(parts);
}

// -----------------------------------------------------------------------------
// PNG
// -----------------------------------------------------------------------------

// Chunks that are, or decide the look of, the picture. Text, time stamps,
// Exif and every chunk not listed here are left out.
const PNG_KEPT_CHUNKS = new Set([
    'IHDR', 'PLTE', 'IDAT', 'IEND',
    'tRNS', 'gAMA', 'cHRM', 'sRGB', 'iCCP', 'cICP', 'sBIT', 'bKGD', 'pHYs',
    'acTL', 'fcTL', 'fdAT',
]);

let pngCrcTable = null;

/** CRC-32 as PNG defines it, over a chunk's type and data. */
function pngCrc(bytes) {
    if (!pngCrcTable) {
        pngCrcTable = new Uint32Array(256);
        for (let n = 0; n < 256; n += 1) {
            let c = n;
            for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
            pngCrcTable[n] = c >>> 0;
        }
    }
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i += 1) crc = pngCrcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
    const chunk = new Uint8Array(12 + data.length);
    chunk[2] = (data.length >> 8) & 0xff;
    chunk[3] = data.length & 0xff;
    chunk.set(asciiBytes(type), 4);
    chunk.set(data, 8);
    const crc = pngCrc(chunk.subarray(4, 8 + data.length));
    chunk[8 + data.length] = crc >>> 24;
    chunk[9 + data.length] = (crc >> 16) & 0xff;
    chunk[10 + data.length] = (crc >> 8) & 0xff;
    chunk[11 + data.length] = crc & 0xff;
    return chunk;
}

function stripPng(bytes) {
    const parts = [bytes.subarray(0, 8)];
    let offset = 8;
    let first = true;
    let orientation = null;
    for (;;) {
        if (offset + 12 > bytes.length) imageMetadataFail('PNG ends before its last chunk');
        const length = ((bytes[offset] << 24) | (bytes[offset + 1] << 16)
            | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
        const type = String.fromCharCode(bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7]);
        if (!/^[A-Za-z]{4}$/.test(type)) imageMetadataFail('PNG chunk has an invalid type');
        const end = offset + 12 + length;
        if (length > 0x7fffffff || end > bytes.length) imageMetadataFail('PNG chunk runs past the file');
        if (first && type !== 'IHDR') imageMetadataFail('PNG does not start with its header chunk');
        first = false;
        if (PNG_KEPT_CHUNKS.has(type)) {
            parts.push(bytes.subarray(offset, end));
        } else if (type === 'eXIf') {
            if (orientation === null) orientation = readTiffOrientation(bytes.subarray(offset + 8, end - 4));
        } else if (type[0] === type[0].toUpperCase()) {
            // A critical chunk this code does not know: the picture cannot
            // be shown without it, and what it holds cannot be judged.
            imageMetadataFail(`PNG uses an unknown critical chunk (${type})`);
        }
        offset = end;
        if (type === 'IEND') break; // nothing after the end of the image
    }
    if (orientation !== null && orientation !== 1) {
        parts.splice(2, 0, pngChunk('eXIf', minimalTiff(orientation))); // right after the header chunk
    }
    return concatBytes(parts);
}

// -----------------------------------------------------------------------------
// GIF
// -----------------------------------------------------------------------------

function stripGif(bytes) {
    const parts = [];
    if (bytes.length < 13) imageMetadataFail('GIF is shorter than its header');
    let offset = 13;
    if (bytes[10] & 0x80) offset += 3 * (2 << (bytes[10] & 0x07)); // global colour table
    if (offset > bytes.length) imageMetadataFail('GIF ends inside its colour table');
    parts.push(bytes.subarray(0, offset));

    /** Offset just past a run of data sub-blocks, terminator included. */
    const skipSubBlocks = (from) => {
        let at = from;
        for (;;) {
            if (at >= bytes.length) imageMetadataFail('GIF ends inside a data block');
            const size = bytes[at];
            at += 1 + size;
            if (size === 0) return at;
        }
    };

    for (;;) {
        if (offset >= bytes.length) imageMetadataFail('GIF has no trailer');
        const start = offset;
        const introducer = bytes[offset];
        if (introducer === 0x3b) {
            parts.push(bytes.subarray(start, start + 1));
            break; // nothing after the trailer
        }
        if (introducer === 0x2c) {
            // Image descriptor, optional local colour table, image data.
            if (offset + 10 > bytes.length) imageMetadataFail('GIF ends inside an image descriptor');
            const packed = bytes[offset + 9];
            offset += 10;
            if (packed & 0x80) offset += 3 * (2 << (packed & 0x07));
            offset = skipSubBlocks(offset + 1); // LZW code size, then the data
            parts.push(bytes.subarray(start, offset));
        } else if (introducer === 0x21) {
            if (offset + 2 > bytes.length) imageMetadataFail('GIF ends inside an extension');
            const label = bytes[offset + 1];
            offset = skipSubBlocks(offset + 2);
            // Graphic control (timing, transparency) is part of the picture.
            // Of the application extensions only the loop count is.
            const loops = label === 0xff && bytes[start + 2] === 11
                && (startsWithBytes(bytes, start + 3, asciiBytes('NETSCAPE2.0'))
                    || startsWithBytes(bytes, start + 3, asciiBytes('ANIMEXTS1.0')));
            if (label === 0xf9 || loops) parts.push(bytes.subarray(start, offset));
            // Comments, plain text and every other extension are left out.
        } else {
            imageMetadataFail('GIF has an unknown block');
        }
    }
    return concatBytes(parts);
}

// -----------------------------------------------------------------------------
// WebP
// -----------------------------------------------------------------------------

const WEBP_KEPT_CHUNKS = new Set(['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ANIM', 'ANMF', 'ICCP']);
const WEBP_FLAG_EXIF = 0x08;
const WEBP_FLAG_XMP = 0x04;

function stripWebp(bytes) {
    if (bytes.length < 12) imageMetadataFail('WebP is shorter than its header');
    const u32 = (offset) => (bytes[offset] | (bytes[offset + 1] << 8)
        | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
    const end = 8 + u32(4);
    if (end > bytes.length || end < 12) imageMetadataFail('WebP size field does not match the file');

    const chunks = [];
    let orientation = null;
    let extended = null;
    let offset = 12;
    while (offset < end) { // what follows the declared size is not part of the image
        if (offset + 8 > end) imageMetadataFail('WebP ends inside a chunk header');
        const type = String.fromCharCode(bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]);
        const size = u32(offset + 4);
        const padded = size + (size & 1);
        if (offset + 8 + size > end) imageMetadataFail('WebP chunk runs past the file');
        const chunkEnd = Math.min(offset + 8 + padded, end);
        if (type === 'EXIF') {
            if (orientation === null) {
                let tiff = bytes.subarray(offset + 8, offset + 8 + size);
                // Some writers put the JPEG "Exif\0\0" prefix in front.
                if (startsWithBytes(tiff, 0, EXIF_HEADER)) tiff = tiff.subarray(6);
                orientation = readTiffOrientation(tiff);
            }
        } else if (WEBP_KEPT_CHUNKS.has(type)) {
            const chunk = new Uint8Array(8 + padded);
            chunk.set(bytes.subarray(offset, offset + 8 + size));
            if (type === 'VP8X') {
                if (size < 10 || extended) imageMetadataFail('WebP has a malformed extended header');
                extended = chunk;
            }
            chunks.push(chunk);
        }
        offset = chunkEnd;
    }
    if (chunks.length === 0) imageMetadataFail('WebP has no image data');

    const keepOrientation = orientation !== null && orientation !== 1 && extended !== null;
    if (extended) {
        extended[8] &= ~(WEBP_FLAG_EXIF | WEBP_FLAG_XMP);
        if (keepOrientation) extended[8] |= WEBP_FLAG_EXIF;
    }
    if (keepOrientation) {
        const tiff = minimalTiff(orientation);
        const chunk = new Uint8Array(8 + tiff.length + (tiff.length & 1));
        chunk.set(asciiBytes('EXIF'));
        chunk[4] = tiff.length;
        chunk.set(tiff, 8);
        chunks.push(chunk);
    }
    const body = concatBytes(chunks);
    const header = new Uint8Array(12);
    header.set(asciiBytes('RIFF'));
    const riffSize = 4 + body.length;
    header[4] = riffSize & 0xff;
    header[5] = (riffSize >> 8) & 0xff;
    header[6] = (riffSize >> 16) & 0xff;
    header[7] = (riffSize >>> 24) & 0xff;
    header.set(asciiBytes('WEBP'), 8);
    return concatBytes([header, body]);
}

// -----------------------------------------------------------------------------

/**
 * @param {Uint8Array} bytes  the image file
 * @returns {{ bytes: Uint8Array, mimeType: string }} the same picture without
 *   its metadata, and the type the file actually is
 * @throws {ImageMetadataError} when the file is none of the four supported
 *   formats or its structure cannot be followed to the end of the image
 */
function stripImageMetadata(bytes) {
    if (!(bytes instanceof Uint8Array)) imageMetadataFail('image data must be a byte array');
    const mimeType = detectImageType(bytes);
    let stripped;
    switch (mimeType) {
    case IMAGE_METADATA_TYPES.JPEG: stripped = stripJpeg(bytes); break;
    case IMAGE_METADATA_TYPES.PNG: stripped = stripPng(bytes); break;
    case IMAGE_METADATA_TYPES.GIF: stripped = stripGif(bytes); break;
    case IMAGE_METADATA_TYPES.WEBP: stripped = stripWebp(bytes); break;
    default: imageMetadataFail('not a PNG, JPEG, GIF or WebP file');
    }
    return { bytes: stripped, mimeType };
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = { stripImageMetadata, detectImageType, ImageMetadataError };
}
