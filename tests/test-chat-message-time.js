#!/usr/bin/env node
'use strict';

/**
 * The time shown next to a received message.
 *
 * The relay puts no timestamp on what it relays. The client used to read
 * one anyway, so every received message and image carried an invalid date
 * and showed "NaN:NaN" where the time belongs. A received message is
 * stamped with the time it arrived.
 */

const assert = require('assert');
const { createChatPair } = require('./helpers/chat-pair');

// The store runs in a context of its own, so its dates are not instances of
// this file's Date.
const isDate = (value) => Object.prototype.toString.call(value) === '[object Date]';

async function run() {
    const { alice, bob, deliver } = await createChatPair();
    await alice.store.handleSasVerified(alice.store.sas.hex);
    await bob.store.handleSasVerified(bob.store.sas.hex);

    const before = Date.now();
    alice.store.messageInput = 'what time is it';
    await alice.store.sendMessage();
    await deliver();
    const after = Date.now();

    const received = bob.store.messages.at(-1);
    assert.strictEqual(received.text, 'what time is it');
    assert(isDate(received.timestamp), 'the message carries a date');
    assert(!Number.isNaN(received.timestamp.getTime()), 'and the date is a valid one');
    assert(received.timestamp.getTime() >= before && received.timestamp.getTime() <= after,
        'it is the time the message arrived');
    assert(/^\d\d:\d\d$/.test(bob.store.formatTimestamp(received.timestamp)),
        `shown as hours and minutes, got "${bob.store.formatTimestamp(received.timestamp)}"`);
    console.log('PASSED: a received message is stamped with its time of arrival');

    // An image goes through a different handler with the same field.
    const png = Uint8Array.from([
        0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
        0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 16, 0, 0, 0, 16, 8, 2, 0, 0, 0, 1, 2, 3, 4,
        0, 0, 0, 4, 0x49, 0x44, 0x41, 0x54, 9, 9, 9, 9, 1, 2, 3, 4,
        0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 1, 2, 3, 4,
    ]);
    for (const client of [alice, bob]) {
        client.store._validateImageBlob = async () => ({ width: 16, height: 16 });
    }
    await alice.store.handleImageSelect({
        target: {
            files: [{ name: 'p.png', type: 'image/png', size: png.length, arrayBuffer: async () => png.buffer.slice(0) }],
            value: 'x',
        },
    });
    assert(alice.store.pendingImage, alice.store.error);
    await alice.store.sendImage();
    await deliver();
    const image = bob.store.messages.at(-1);
    assert.strictEqual(image.type, 'image', bob.store.error);
    assert(isDate(image.timestamp) && !Number.isNaN(image.timestamp.getTime()),
        'a received image carries a valid date as well');
    console.log('PASSED: a received image is stamped with its time of arrival');

    // Whatever reaches the formatter, it never prints "NaN:NaN".
    for (const bad of [new Date(undefined), new Date('nonsense'), undefined, null, '12:00', 0]) {
        assert.strictEqual(bob.store.formatTimestamp(bad), '', `formatTimestamp(${String(bad)})`);
    }
    console.log('PASSED: an unusable time is shown as nothing, not as NaN:NaN');

    console.log('\n3 chat message time tests passed');
}

run().catch((error) => {
    console.error('FAILED:', error.stack);
    process.exit(1);
});
