#!/usr/bin/env node
'use strict';

/**
 * What the chat page does with images, on the real store code:
 *
 * - the size limit a relay announces is used only inside the range a relay
 *   is allowed to configure, because that limit is also the largest
 *   decrypted image the client accepts from a peer;
 * - an image picked for sending is stripped of its metadata before it is
 *   previewed, measured or encrypted, and a file that cannot be cleaned is
 *   not sent.
 */

const assert = require('assert');
const { createChatPair } = require('./helpers/chat-pair');

const KIB = 1024;
const MIB = 1024 * 1024;

const ascii = (text) => Array.from(text, (character) => character.charCodeAt(0));
const segment = (marker, payload) => [0xff, marker, (payload.length + 2) >> 8, (payload.length + 2) & 0xff, ...payload];
// Orientation 6 in a block that also names a camera.
const TIFF = [
    0x4d, 0x4d, 0, 42, 0, 0, 0, 8, 0, 2,
    0x01, 0x0f, 0, 2, 0, 0, 0, 10, 0, 0, 0, 38,
    0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0,
    0, 0, 0, 0,
    ...ascii('SECRETCAM\0'),
];
const PICTURE = [
    ...segment(0xdb, [0, ...new Array(64).fill(7)]),
    ...segment(0xc0, [8, 0, 16, 0, 16, 1, 1, 0x11, 0]),
    ...segment(0xc4, [0, ...new Array(16).fill(0), 0xaa]),
    ...segment(0xda, [1, 1, 0, 0, 63, 0]),
    0x12, 0xff, 0x00, 0x34,
    0xff, 0xd9,
];
const PHOTO = Uint8Array.from([
    0xff, 0xd8,
    ...segment(0xe0, [...ascii('JFIF\0'), 1, 1, 0, 0, 1, 0, 1, 0, 0]),
    ...segment(0xe1, [...ascii('Exif\0\0'), ...TIFF]),
    ...segment(0xfe, ascii('SECRET-COMMENT')),
    ...PICTURE,
    ...ascii('SECRET-TRAILER'),
]);

const fileOf = (bytes, type, name = 'photo.jpg') => ({
    name, type, size: bytes.length,
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
});
const text = (bytes) => Buffer.from(bytes).toString('latin1');

async function announce(client, maxImageSize) {
    client.store.transportReconnectPending = true;
    await client.store.handleWebSocketMessage({
        type: 'connected', user_id: client.store.userId,
        room_type: 'onetoone', participant_count: 2, resumed: true,
        max_image_size: maxImageSize,
    });
    return client.store.maxImageSize;
}

async function run() {
    const { alice, bob, deliver } = await createChatPair();
    await alice.store.handleSasVerified();
    await bob.store.handleSasVerified();

    // --- the limit announced by the relay ---------------------------------
    assert.strictEqual(alice.store.maxImageSize, 300 * KIB, 'default before the relay says anything');
    assert.strictEqual(await announce(alice, 500 * KIB), 500 * KIB, 'a value in range is used');
    assert.strictEqual(await announce(alice, 2 * MIB), 2 * MIB, 'the top of the range is used');
    assert.strictEqual(await announce(alice, 2 * MIB + 1), 2 * MIB, 'one byte above the range is not');
    assert.strictEqual(await announce(alice, 2 ** 40), 2 * MIB, 'a relay cannot make the client accept anything');
    assert.strictEqual(await announce(alice, 100), KIB, 'nor go below what a relay may configure');
    await announce(alice, 700 * KIB);
    for (const invalid of [0, -5, 1.5, NaN, Infinity, '2097152', null, undefined, {}, 2 ** 60]) {
        assert.strictEqual(await announce(alice, invalid), 700 * KIB,
            `${String(invalid)} is not a size and leaves the limit alone`);
    }
    console.log('PASSED: the relay sets the image limit only inside the configurable range');

    // --- selecting an image -------------------------------------------------
    await announce(alice, 300 * KIB);
    await announce(bob, 300 * KIB);
    const validated = [];
    alice.store._validateImageBlob = async (blob) => {
        validated.push(new Uint8Array(await blob.arrayBuffer()));
        return { width: 16, height: 16 };
    };
    const input = { files: [fileOf(PHOTO, 'image/jpeg')], value: 'C:\\fakepath\\photo.jpg' };
    await alice.store.handleImageSelect({ target: input });

    const pending = alice.store.pendingImage;
    assert(pending, `the image is accepted (${alice.store.error})`);
    const outgoing = new Uint8Array(pending.arrayBuffer);
    assert(text(PHOTO).includes('SECRETCAM') && text(PHOTO).includes('SECRET-COMMENT'), 'the file carried metadata');
    assert(!text(outgoing).includes('SECRET'), 'what is queued for sending carries none');
    assert.strictEqual(pending.size, outgoing.length, 'the size shown is the size sent');
    assert(pending.size < PHOTO.length);
    assert.strictEqual(pending.mimeType, 'image/jpeg');
    assert.strictEqual(validated.length, 1);
    assert.deepStrictEqual(validated[0], outgoing, 'the decoder check and the preview see the cleaned bytes');
    // The orientation is the one thing kept from the Exif block.
    const exifAt = text(outgoing).indexOf('Exif\0\0');
    assert(exifAt > 0 && outgoing[exifAt + 6 + 19] === 6, 'the orientation survives');
    assert.strictEqual(input.value, '', 'the file input is reset');
    console.log('PASSED: a selected image is cleaned before it is previewed, measured or queued');

    // --- and what the peer receives ----------------------------------------
    let received = null;
    bob.store._validateImageBlob = async (blob) => {
        received = new Uint8Array(await blob.arrayBuffer());
        return { width: 16, height: 16 };
    };
    await alice.store.sendImage();
    await deliver();
    assert(received, `the peer received the image (${bob.store.error})`);
    assert.deepStrictEqual(received, outgoing, 'the peer gets exactly the cleaned bytes');
    assert(!text(received).includes('SECRET'));
    console.log('PASSED: the peer receives the picture without the metadata');

    // --- files that are refused --------------------------------------------
    const damaged = PHOTO.subarray(0, PHOTO.length - 20); // no end-of-image marker
    const refusedInput = { files: [fileOf(damaged, 'image/jpeg')], value: 'x' };
    await alice.store.handleImageSelect({ target: refusedInput });
    assert.strictEqual(alice.store.pendingImage, null, 'a file that cannot be cleaned is not queued');
    assert(/could not be prepared/.test(alice.store.error), alice.store.error);
    assert.strictEqual(refusedInput.value, '');

    // The declared type is not what decides: the content is.
    const svg = Uint8Array.from(ascii('<svg xmlns="http://www.w3.org/2000/svg"></svg>'));
    await alice.store.handleImageSelect({ target: { files: [fileOf(svg, 'image/png', 'drawing.png')], value: 'x' } });
    assert.strictEqual(alice.store.pendingImage, null, 'a file that only claims to be a PNG is not queued');
    assert(/could not be prepared/.test(alice.store.error), alice.store.error);

    // A PNG named and typed as a JPEG is sent as what it is.
    const png = Uint8Array.from([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 13, ...ascii('IHDR'), 0, 0, 0, 16, 0, 0, 0, 16, 8, 2, 0, 0, 0, 1, 2, 3, 4,
        0, 0, 0, 9, ...ascii('tEXt'), ...ascii('k\0SECRET!'), 1, 2, 3, 4,
        0, 0, 0, 4, ...ascii('IDAT'), 9, 9, 9, 9, 1, 2, 3, 4,
        0, 0, 0, 0, ...ascii('IEND'), 1, 2, 3, 4,
    ]);
    await alice.store.handleImageSelect({ target: { files: [fileOf(png, 'image/jpeg')], value: 'x' } });
    assert(alice.store.pendingImage, alice.store.error);
    assert.strictEqual(alice.store.pendingImage.mimeType, 'image/png', 'the type sent is the type the file is');
    assert(!text(new Uint8Array(alice.store.pendingImage.arrayBuffer)).includes('SECRET'));
    console.log('PASSED: files that cannot be cleaned are refused, and the type comes from the content');

    console.log('\n4 chat image tests passed');
}

run().catch((error) => {
    console.error('FAILED:', error.stack);
    process.exit(1);
});
