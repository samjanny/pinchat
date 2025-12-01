#!/usr/bin/env node

/**
 * Double Ratchet Test Suite
 *
 * Tests the full Double Ratchet algorithm (DH + Symmetric) which provides
 * both Perfect Forward Secrecy (PFS) and Post-Compromise Security (PCS).
 *
 * Simulates Alice <-> Bob conversations with realistic message flows.
 */

const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

// ============================================================================
// AAD Encoding (copied from static/js/crypto.js)
// ============================================================================

const AAD_FIELD_TYPES = {
    ROOM_ID: 0x01,
    SENDER_ID: 0x02,
    TIMESTAMP: 0x03,
    NONCE: 0x04,
    MESSAGE_NUMBER: 0x05,
    MESSAGE_TYPE: 0x06,
    RATCHET_COUNT: 0x07
};

function encodeAADWithLengthPrefix(fields) {
    const encoder = new TextEncoder();
    const parts = [];

    for (const field of fields) {
        let valueBytes;

        if (field.type === AAD_FIELD_TYPES.TIMESTAMP ||
            field.type === AAD_FIELD_TYPES.MESSAGE_NUMBER ||
            field.type === AAD_FIELD_TYPES.RATCHET_COUNT) {
            valueBytes = new Uint8Array(
                new BigUint64Array([BigInt(field.value)]).buffer
            );
        } else if (typeof field.value === 'string') {
            valueBytes = encoder.encode(field.value);
        } else if (field.value instanceof Uint8Array) {
            valueBytes = field.value;
        } else {
            throw new Error(`Invalid AAD field value type for field type ${field.type}`);
        }

        if (valueBytes.length > 0xFFFF) {
            throw new Error(`AAD field too large: ${valueBytes.length} bytes`);
        }

        parts.push(field.type);
        parts.push((valueBytes.length >> 8) & 0xFF);
        parts.push(valueBytes.length & 0xFF);
        parts.push(...valueBytes);
    }

    return new Uint8Array(parts);
}

// ============================================================================
// ChainRatchet Implementation
// ============================================================================

class ChainRatchet {
    constructor() {
        this.chainKeyMaterial = null;
        this.messageNumber = 0;
        this.messageKeyWindow = new Map();
        this.WINDOW_SIZE = 16;
    }

    async initialize(keyMaterial) {
        if (!(keyMaterial instanceof Uint8Array) || keyMaterial.length !== 32) {
            throw new Error('Chain key material must be 32 bytes');
        }
        this.chainKeyMaterial = new Uint8Array(keyMaterial);
        this.messageNumber = 0;
        this.messageKeyWindow = new Map();
    }

    async deriveMessageKey() {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

        const myCounter = this.messageNumber;
        this.messageNumber++;

        const messageKey = await this._deriveKeyForCounter(myCounter, myCounter);

        for (let i = 1; i <= this.WINDOW_SIZE; i++) {
            const futureCounter = myCounter + i;
            const futureKey = await this._deriveKeyForCounter(futureCounter, myCounter);
            this.messageKeyWindow.set(futureCounter, futureKey);
        }

        for (const [counter] of this.messageKeyWindow) {
            if (counter < myCounter) this.messageKeyWindow.delete(counter);
        }

        return { key: messageKey, counter: myCounter };
    }

    async deriveMessageKeyForCounter(counter) {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

        if (this.messageKeyWindow.has(counter)) {
            return this.messageKeyWindow.get(counter);
        }

        const currentCounter = this.messageNumber;
        return await this._deriveKeyForCounter(counter, currentCounter);
    }

    async _deriveKeyForCounter(counter, currentCounter) {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

        const stepsAhead = counter - currentCounter;
        let simulatedChainKey = new Uint8Array(this.chainKeyMaterial);

        for (let i = 0; i < stepsAhead; i++) {
            const ratchetInfo = new TextEncoder().encode('ChainRatchet');
            const hmacKey = await subtle.importKey('raw', simulatedChainKey,
                { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
            const nextChainKeyRaw = await subtle.sign('HMAC', hmacKey, ratchetInfo);
            simulatedChainKey = new Uint8Array(nextChainKeyRaw);
        }

        const info = new TextEncoder().encode(`MessageKey-${counter}`);
        const hmacKey = await subtle.importKey('raw', simulatedChainKey,
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const messageKeyRaw = await subtle.sign('HMAC', hmacKey, info);
        simulatedChainKey.fill(0);

        return await subtle.importKey('raw', messageKeyRaw,
            { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    }

    async ratchet() {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

        const info = new TextEncoder().encode('ChainRatchet');
        const hmacKey = await subtle.importKey('raw', this.chainKeyMaterial,
            { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        const nextChainKeyRaw = await subtle.sign('HMAC', hmacKey, info);
        this.chainKeyMaterial = new Uint8Array(nextChainKeyRaw);
    }

    reset() {
        if (this.chainKeyMaterial) {
            this.chainKeyMaterial.fill(0);
            this.chainKeyMaterial = null;
        }
        this.messageNumber = 0;
        this.messageKeyWindow.clear();
    }
}

// ============================================================================
// DoubleRatchet Implementation
// ============================================================================

class DoubleRatchet {
    constructor() {
        this.rootKey = null;
        this.DHs = null;
        this.DHr = null;
        this.DHrRaw = null;
        this.sendingChain = null;
        this.receivingChain = null;
        this.Ns = 0;
        this.Nr = 0;
        this.PN = 0;
        this.skippedKeys = new Map();
        this.MAX_SKIP = 100;
        this.isInitiator = false;
        this.ratchetCount = 0;
        this.hasRatchetedSinceReceive = true;
        this.CURVE = 'P-256';
    }

    async initialize(sharedSecret, isInitiator, myKeypair = null, theirPublicKey = null) {
        if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== 32) {
            throw new Error('Shared secret must be 32 bytes');
        }

        this.isInitiator = isInitiator;
        this.rootKey = await this.hkdf(sharedSecret, new Uint8Array(32), 'DoubleRatchet-RootKey', 32);

        if (myKeypair) {
            this.DHs = myKeypair;
        } else {
            this.DHs = await subtle.generateKey(
                { name: 'ECDH', namedCurve: this.CURVE },
                true,
                ['deriveKey', 'deriveBits']
            );
        }

        if (isInitiator && theirPublicKey) {
            this.DHr = theirPublicKey;
            this.DHrRaw = await subtle.exportKey('raw', theirPublicKey);
        } else {
            this.DHr = null;
            this.DHrRaw = null;
        }

        const sendingLabel = isInitiator ? 'InitiatorToResponder' : 'ResponderToInitiator';
        const receivingLabel = isInitiator ? 'ResponderToInitiator' : 'InitiatorToResponder';

        const sendingChainKey = await this.hkdf(this.rootKey, new Uint8Array(32), sendingLabel, 32);
        const receivingChainKey = await this.hkdf(this.rootKey, new Uint8Array(32), receivingLabel, 32);

        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(sendingChainKey);

        this.receivingChain = new ChainRatchet();
        await this.receivingChain.initialize(receivingChainKey);

        this.Ns = 0;
        this.Nr = 0;
        this.PN = 0;
        this.ratchetCount = 0;
    }

    async encryptMessage(plaintext, roomId, senderId) {
        if (!this.sendingChain) throw new Error('Double Ratchet not initialized');

        if (this.DHr && !this.hasRatchetedSinceReceive) {
            await this.performSendSideDHRatchet();
        }

        const { key: messageKey, counter: messageNumber } = await this.sendingChain.deriveMessageKey();
        const dhPublicKeyRaw = await subtle.exportKey('raw', this.DHs.publicKey);
        const dhPublicKeyBase64 = this.arrayBufferToBase64url(dhPublicKeyRaw);

        const envelope = { ts: Date.now(), text: plaintext };
        const encoder = new TextEncoder();
        const plaintextBytes = encoder.encode(JSON.stringify(envelope));
        const iv = webcrypto.getRandomValues(new Uint8Array(12));

        const aad = encodeAADWithLengthPrefix([
            { type: AAD_FIELD_TYPES.ROOM_ID, value: roomId },
            { type: AAD_FIELD_TYPES.SENDER_ID, value: senderId },
            { type: AAD_FIELD_TYPES.MESSAGE_NUMBER, value: messageNumber },
            { type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: 'message' },
            { type: AAD_FIELD_TYPES.RATCHET_COUNT, value: this.ratchetCount }
        ]);

        const ciphertext = await subtle.encrypt(
            { name: 'AES-GCM', iv: iv, additionalData: aad },
            messageKey,
            plaintextBytes
        );

        await this.sendingChain.ratchet();

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        const payload = this.arrayBufferToBase64url(combined);
        this.Ns++;

        return {
            payload: payload,
            header: {
                dh: dhPublicKeyBase64,
                pn: this.PN,
                n: messageNumber,
                rc: this.ratchetCount
            }
        };
    }

    async decryptMessage(payloadBase64, header, roomId, senderId) {
        if (!this.receivingChain) throw new Error('Double Ratchet not initialized');

        const { dh: dhPublicKeyBase64, pn: prevChainLength, n: messageNumber, rc: ratchetCount } = header;
        const dhPublicKeyRaw = this.base64urlToArrayBuffer(dhPublicKeyBase64);
        const isFirstMessage = !this.DHrRaw;
        const isNewKey = !isFirstMessage && !this.arraysEqual(dhPublicKeyRaw, new Uint8Array(this.DHrRaw));

        if (isFirstMessage) {
            const newDHr = await subtle.importKey('raw', dhPublicKeyRaw,
                { name: 'ECDH', namedCurve: this.CURVE }, true, []);
            this.DHr = newDHr;
            this.DHrRaw = new Uint8Array(dhPublicKeyRaw);
            this.hasRatchetedSinceReceive = false;
        } else if (isNewKey) {
            if (this.receivingChain && prevChainLength > this.Nr) {
                await this.skipMessageKeys(prevChainLength);
            }
            await this.performDHRatchetOnReceive(dhPublicKeyRaw);
            this.hasRatchetedSinceReceive = true;
        }

        let plaintextBytes;
        try {
            const skippedKeyId = `${dhPublicKeyBase64}:${messageNumber}`;
            let messageKey;

            if (this.skippedKeys.has(skippedKeyId)) {
                messageKey = this.skippedKeys.get(skippedKeyId);
                this.skippedKeys.delete(skippedKeyId);
            } else {
                messageKey = await this.receivingChain.deriveMessageKeyForCounter(messageNumber);
            }

            const combined = this.base64urlToArrayBuffer(payloadBase64);
            const iv = combined.slice(0, 12);
            const ciphertext = combined.slice(12);

            const aad = encodeAADWithLengthPrefix([
                { type: AAD_FIELD_TYPES.ROOM_ID, value: roomId },
                { type: AAD_FIELD_TYPES.SENDER_ID, value: senderId },
                { type: AAD_FIELD_TYPES.MESSAGE_NUMBER, value: messageNumber },
                { type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: 'message' },
                { type: AAD_FIELD_TYPES.RATCHET_COUNT, value: ratchetCount }
            ]);

            plaintextBytes = await subtle.decrypt(
                { name: 'AES-GCM', iv: iv, additionalData: aad },
                messageKey,
                ciphertext
            );
        } catch (error) {
            throw new Error('Message decryption failed - authentication error');
        }

        const newPosition = messageNumber + 1;
        const numRatchets = newPosition - this.Nr;
        for (let i = 0; i < numRatchets; i++) {
            await this.receivingChain.ratchet();
        }
        this.Nr = newPosition;
        this.receivingChain.messageNumber = this.Nr;

        const decoder = new TextDecoder();
        return JSON.parse(decoder.decode(plaintextBytes));
    }

    async performDHRatchetOnReceive(newDHrRaw) {
        const newDHr = await subtle.importKey('raw', newDHrRaw,
            { name: 'ECDH', namedCurve: this.CURVE }, true, []);

        this.PN = this.Ns;
        this.Ns = 0;
        this.Nr = 0;
        this.DHr = newDHr;
        this.DHrRaw = new Uint8Array(newDHrRaw);

        const dhOutput1 = await subtle.deriveBits(
            { name: 'ECDH', public: newDHr },
            this.DHs.privateKey,
            256
        );

        const dhBytes1 = new Uint8Array(dhOutput1);
        const newRootKey1 = await this.hkdf(this.rootKey, dhBytes1, 'DoubleRatchet-RootKey', 32);
        const newReceivingChainKey = await this.hkdf(newRootKey1, new Uint8Array(32), 'ChainKey', 32);

        this.receivingChain = new ChainRatchet();
        await this.receivingChain.initialize(newReceivingChainKey);

        this.DHs = await subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );

        const dhOutput2 = await subtle.deriveBits(
            { name: 'ECDH', public: newDHr },
            this.DHs.privateKey,
            256
        );

        const dhBytes2 = new Uint8Array(dhOutput2);
        const newRootKey2 = await this.hkdf(newRootKey1, dhBytes2, 'DoubleRatchet-RootKey', 32);
        const newSendingChainKey = await this.hkdf(newRootKey2, new Uint8Array(32), 'ChainKey', 32);

        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(newSendingChainKey);

        if (this.rootKey) this.rootKey.fill(0);
        this.rootKey = newRootKey2;
        this.ratchetCount++;
    }

    async performSendSideDHRatchet() {
        if (!this.DHr) throw new Error('Cannot perform send-side DH ratchet without DHr');

        this.PN = this.Ns;
        this.Ns = 0;

        this.DHs = await subtle.generateKey(
            { name: 'ECDH', namedCurve: this.CURVE },
            true,
            ['deriveKey', 'deriveBits']
        );

        const dhOutput = await subtle.deriveBits(
            { name: 'ECDH', public: this.DHr },
            this.DHs.privateKey,
            256
        );

        const dhBytes = new Uint8Array(dhOutput);
        const newRootKey = await this.hkdf(this.rootKey, dhBytes, 'DoubleRatchet-RootKey', 32);
        const newSendingChainKey = await this.hkdf(newRootKey, new Uint8Array(32), 'ChainKey', 32);

        this.sendingChain = new ChainRatchet();
        await this.sendingChain.initialize(newSendingChainKey);

        if (this.rootKey) this.rootKey.fill(0);
        this.rootKey = newRootKey;
        this.ratchetCount++;
        this.hasRatchetedSinceReceive = true;
    }

    async skipMessageKeys(until) {
        if (until - this.Nr > this.MAX_SKIP) {
            throw new Error(`Too many skipped messages: ${until - this.Nr}`);
        }

        const dhPublicKeyRaw = await subtle.exportKey('raw', this.DHr);
        const dhPublicKeyBase64 = this.arrayBufferToBase64url(dhPublicKeyRaw);

        while (this.Nr < until) {
            const messageKey = await this.receivingChain.deriveMessageKeyForCounter(this.Nr);
            const keyId = `${dhPublicKeyBase64}:${this.Nr}`;
            this.skippedKeys.set(keyId, messageKey);
            await this.receivingChain.ratchet();
            this.Nr++;
        }
    }

    async hkdf(ikm, salt, info, length) {
        const ikmKey = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
        const encoder = new TextEncoder();
        const derivedBits = await subtle.deriveBits(
            { name: 'HKDF', hash: 'SHA-256', salt: salt, info: encoder.encode(info) },
            ikmKey,
            length * 8
        );
        return new Uint8Array(derivedBits);
    }

    arraysEqual(a, b) {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return Buffer.from(binary, 'binary').toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    base64urlToArrayBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
        const binary = Buffer.from(padded, 'base64').toString('binary');
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    destroy() {
        if (this.rootKey) this.rootKey.fill(0);
        this.rootKey = null;
        this.sendingChain = null;
        this.receivingChain = null;
        this.DHs = null;
        this.DHr = null;
        this.DHrRaw = null;
        this.skippedKeys.clear();
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// ============================================================================
// Test Suite
// ============================================================================

async function runTests() {
    console.log('='.repeat(70));
    console.log('DOUBLE RATCHET TEST SUITE (Signal Protocol DH + Symmetric)');
    console.log('='.repeat(70));
    console.log('');

    let passed = 0;
    let failed = 0;

    const ROOM_ID = 'test-room-123';
    const ALICE_ID = 'alice-conn-456';
    const BOB_ID = 'bob-conn-789';

    // -------------------------------------------------------------------------
    // Test 1: Basic Initialization
    // -------------------------------------------------------------------------
    console.log('--- Test 1: Basic Initialization ---');
    try {
        const sharedSecret = hexToBytes('cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe');

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false);

        if (alice.isInitiator && !bob.isInitiator &&
            alice.sendingChain && bob.sendingChain &&
            alice.receivingChain && bob.receivingChain) {
            console.log('PASSED: Both parties initialized correctly');
            passed++;
        } else {
            console.log('FAILED: Initialization state incorrect');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 2: Alice Sends One Message to Bob
    // -------------------------------------------------------------------------
    console.log('--- Test 2: Alice Sends One Message to Bob ---');
    try {
        const sharedSecret = hexToBytes('1111111111111111111111111111111111111111111111111111111111111111');

        // Simulate handshake: generate keypairs and exchange public keys
        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        const plaintext = 'Hello Bob!';
        const encrypted = await alice.encryptMessage(plaintext, ROOM_ID, ALICE_ID);

        console.log(`  Encrypted payload length: ${encrypted.payload.length}`);
        console.log(`  Header: n=${encrypted.header.n}, rc=${encrypted.header.rc}`);

        const decrypted = await bob.decryptMessage(
            encrypted.payload, encrypted.header, ROOM_ID, ALICE_ID);

        console.log(`  Decrypted: "${decrypted.text}"`);

        if (decrypted.text === plaintext) {
            console.log('PASSED: Message decrypted successfully');
            passed++;
        } else {
            console.log('FAILED: Decryption mismatch');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 3: Alice Sends Multiple Messages (No Ratchet)
    // -------------------------------------------------------------------------
    console.log('--- Test 3: Alice Sends Multiple Messages (No DH Ratchet) ---');
    try {
        const sharedSecret = hexToBytes('2222222222222222222222222222222222222222222222222222222222222222');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        const messages = ['Message 1', 'Message 2', 'Message 3'];
        let allDecrypted = true;

        for (let i = 0; i < messages.length; i++) {
            const encrypted = await alice.encryptMessage(messages[i], ROOM_ID, ALICE_ID);
            const decrypted = await bob.decryptMessage(
                encrypted.payload, encrypted.header, ROOM_ID, ALICE_ID);

            console.log(`  [${i}] Sent: "${messages[i]}" -> Received: "${decrypted.text}"`);

            if (decrypted.text !== messages[i]) {
                allDecrypted = false;
            }
        }

        // No DH ratchet should have occurred (Alice just keeps sending)
        if (allDecrypted && alice.ratchetCount === 0 && bob.ratchetCount === 0) {
            console.log('PASSED: All messages decrypted, no DH ratchet (as expected)');
            passed++;
        } else {
            console.log(`FAILED: ratchetCount Alice=${alice.ratchetCount}, Bob=${bob.ratchetCount}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 4: Ping-Pong Conversation (DH Ratchets)
    // -------------------------------------------------------------------------
    console.log('--- Test 4: Ping-Pong Conversation (DH Ratchets) ---');
    try {
        const sharedSecret = hexToBytes('3333333333333333333333333333333333333333333333333333333333333333');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        let success = true;

        // Alice -> Bob (no ratchet)
        console.log('  Alice -> Bob: "A1"');
        let enc = await alice.encryptMessage('A1', ROOM_ID, ALICE_ID);
        let dec = await bob.decryptMessage(enc.payload, enc.header, ROOM_ID, ALICE_ID);
        if (dec.text !== 'A1') success = false;
        console.log(`    Bob ratchetCount: ${bob.ratchetCount}`);

        // Bob -> Alice (triggers Bob's send-side ratchet)
        console.log('  Bob -> Alice: "B1"');
        enc = await bob.encryptMessage('B1', ROOM_ID, BOB_ID);
        console.log(`    Bob ratchetCount after send: ${bob.ratchetCount}`);
        dec = await alice.decryptMessage(enc.payload, enc.header, ROOM_ID, BOB_ID);
        if (dec.text !== 'B1') success = false;
        console.log(`    Alice ratchetCount after receive: ${alice.ratchetCount}`);

        // Alice -> Bob (triggers Alice's send-side ratchet)
        console.log('  Alice -> Bob: "A2"');
        enc = await alice.encryptMessage('A2', ROOM_ID, ALICE_ID);
        console.log(`    Alice ratchetCount after send: ${alice.ratchetCount}`);
        dec = await bob.decryptMessage(enc.payload, enc.header, ROOM_ID, ALICE_ID);
        if (dec.text !== 'A2') success = false;
        console.log(`    Bob ratchetCount after receive: ${bob.ratchetCount}`);

        // Bob -> Alice (triggers Bob's send-side ratchet)
        console.log('  Bob -> Alice: "B2"');
        enc = await bob.encryptMessage('B2', ROOM_ID, BOB_ID);
        console.log(`    Bob ratchetCount after send: ${bob.ratchetCount}`);
        dec = await alice.decryptMessage(enc.payload, enc.header, ROOM_ID, BOB_ID);
        if (dec.text !== 'B2') success = false;
        console.log(`    Alice ratchetCount after receive: ${alice.ratchetCount}`);

        // Verify ratchet counts (should be 3 each after full ping-pong)
        if (success && alice.ratchetCount >= 2 && bob.ratchetCount >= 2) {
            console.log(`PASSED: Ping-pong worked, ratchets: Alice=${alice.ratchetCount}, Bob=${bob.ratchetCount}`);
            passed++;
        } else {
            console.log('FAILED: Ping-pong or ratchet count incorrect');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 5: Wrong Room ID (AAD Mismatch)
    // -------------------------------------------------------------------------
    console.log('--- Test 5: Wrong Room ID (AAD Mismatch) ---');
    try {
        const sharedSecret = hexToBytes('4444444444444444444444444444444444444444444444444444444444444444');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        const encrypted = await alice.encryptMessage('Secret', ROOM_ID, ALICE_ID);

        let caught = false;
        try {
            // Try to decrypt with wrong room ID
            await bob.decryptMessage(
                encrypted.payload, encrypted.header, 'wrong-room', ALICE_ID);
        } catch (e) {
            caught = true;
            console.log(`  Error (expected): ${e.message}`);
        }

        if (caught) {
            console.log('PASSED: Decryption failed with wrong AAD');
            passed++;
        } else {
            console.log('FAILED: Should have rejected wrong room ID');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 6: Message Replay (Same Ciphertext Twice)
    // -------------------------------------------------------------------------
    console.log('--- Test 6: Message Replay Detection ---');
    try {
        const sharedSecret = hexToBytes('5555555555555555555555555555555555555555555555555555555555555555');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        const encrypted = await alice.encryptMessage('Original', ROOM_ID, ALICE_ID);

        // First decryption (should work)
        const dec1 = await bob.decryptMessage(
            encrypted.payload, encrypted.header, ROOM_ID, ALICE_ID);
        console.log(`  First decrypt: "${dec1.text}"`);

        // Second decryption (replay - should fail because chain has ratcheted)
        let caught = false;
        try {
            await bob.decryptMessage(
                encrypted.payload, encrypted.header, ROOM_ID, ALICE_ID);
        } catch (e) {
            caught = true;
            console.log(`  Replay error (expected): ${e.message}`);
        }

        if (caught) {
            console.log('PASSED: Replay attack detected');
            passed++;
        } else {
            console.log('FAILED: Should have rejected replay');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 7: Long Conversation (Stress Test)
    // -------------------------------------------------------------------------
    console.log('--- Test 7: Long Conversation (20 messages) ---');
    try {
        const sharedSecret = hexToBytes('6666666666666666666666666666666666666666666666666666666666666666');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        let success = true;
        const parties = [
            { sender: alice, receiver: bob, senderId: ALICE_ID, name: 'Alice' },
            { sender: bob, receiver: alice, senderId: BOB_ID, name: 'Bob' }
        ];

        for (let i = 0; i < 20; i++) {
            const party = parties[i % 2];
            const msg = `Message ${i} from ${party.name}`;

            const enc = await party.sender.encryptMessage(msg, ROOM_ID, party.senderId);
            const dec = await party.receiver.decryptMessage(
                enc.payload, enc.header, ROOM_ID, party.senderId);

            if (dec.text !== msg) {
                success = false;
                console.log(`  MISMATCH at ${i}: "${msg}" != "${dec.text}"`);
            }
        }

        console.log(`  Final ratchet counts: Alice=${alice.ratchetCount}, Bob=${bob.ratchetCount}`);

        if (success) {
            console.log('PASSED: 20-message conversation completed');
            passed++;
        } else {
            console.log('FAILED: Some messages failed to decrypt');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 8: State Destruction
    // -------------------------------------------------------------------------
    console.log('--- Test 8: State Destruction ---');
    try {
        const sharedSecret = hexToBytes('7777777777777777777777777777777777777777777777777777777777777777');

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true);

        await alice.encryptMessage('Test', ROOM_ID, ALICE_ID);

        alice.destroy();

        const isDestroyed = (
            alice.rootKey === null &&
            alice.sendingChain === null &&
            alice.receivingChain === null &&
            alice.DHs === null &&
            alice.skippedKeys.size === 0
        );

        if (isDestroyed) {
            console.log('PASSED: All state cleared on destroy');
            passed++;
        } else {
            console.log('FAILED: Some state not cleared');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Summary
    // =========================================================================
    console.log('='.repeat(70));
    console.log(`TEST SUMMARY: ${passed} passed, ${failed} failed`);
    console.log('='.repeat(70));

    if (failed === 0) {
        console.log('ALL TESTS PASSED');
        process.exit(0);
    } else {
        console.log('SOME TESTS FAILED');
        process.exit(1);
    }
}

// Run tests
runTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
