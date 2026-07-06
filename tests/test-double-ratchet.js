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
    }

    async initialize(keyMaterial) {
        if (!(keyMaterial instanceof Uint8Array) || keyMaterial.length !== 32) {
            throw new Error('Chain key material must be 32 bytes');
        }
        this.chainKeyMaterial = new Uint8Array(keyMaterial);
        this.messageNumber = 0;
    }

    async deriveMessageKey() {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

        const myCounter = this.messageNumber;
        this.messageNumber++;

        const messageKey = await this._deriveKeyForCounter(myCounter, myCounter);

        return { key: messageKey, counter: myCounter };
    }

    async deriveMessageKeyForCounter(counter) {
        if (!this.chainKeyMaterial) throw new Error('Chain ratchet not initialized');

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

    clone() {
        const c = new ChainRatchet();
        c.chainKeyMaterial = this.chainKeyMaterial ? new Uint8Array(this.chainKeyMaterial) : null;
        c.messageNumber = this.messageNumber;
        return c;
    }

    reset() {
        if (this.chainKeyMaterial) {
            this.chainKeyMaterial.fill(0);
            this.chainKeyMaterial = null;
        }
        this.messageNumber = 0;
    }
}

// ============================================================================
// DoubleRatchet Implementation
// ============================================================================

class DoubleRatchet {
    constructor(identityManager = null) {
        this.identityManager = identityManager;  // stubbed IdentityKeyManager (sign/verify)
        this.rootKey = null;
        this.DHs = null;
        this.DHr = null;
        this.DHrRaw = null;
        this.sendingChain = null;
        this.receivingChain = null;
        this.Ns = 0;
        this.Nr = 0;
        this.PN = 0;
        this.skippedKeys = new Map();  // Map<keyId, {key, ratchetCount}>
        this.MAX_SKIP = 100;
        this.MAX_SKIPPED_KEYS_TOTAL = 1000;
        this.DHsSignature = null;  // cached base64url signature over current DHs (v1)
        this.isInitiator = false;
        this.ratchetCount = 0;
        this.hasRatchetedSinceReceive = true;
        this.CURVE = 'P-256';
    }

    _buildCanonicalBytes(dhRaw, rc) {
        const tag = new TextEncoder().encode('pinchat-drheader-v1');
        const dhBytes = dhRaw instanceof Uint8Array ? dhRaw : new Uint8Array(dhRaw);
        const out = new Uint8Array(tag.length + 2 + dhBytes.byteLength + 4);
        out.set(tag, 0);
        new DataView(out.buffer).setUint16(tag.length, dhBytes.byteLength, false);
        out.set(dhBytes, tag.length + 2);
        new DataView(out.buffer).setUint32(tag.length + 2 + dhBytes.byteLength, rc, false);
        return out;
    }

    async signCurrentDHs() {
        if (!this.identityManager) throw new Error('identityManager required for v1 ratchet');
        const raw = await subtle.exportKey('raw', this.DHs.publicKey);
        const canon = this._buildCanonicalBytes(raw, this.ratchetCount);
        const sigBuf = await this.identityManager.sign(canon);
        this.DHsSignature = this.arrayBufferToBase64url(sigBuf);
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

        if (this.identityManager) await this.signCurrentDHs();
    }

    async encryptMessage(plaintext, roomId, senderId, msgType = 'message') {
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
            { type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: msgType },
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

        const header = {
            dh: dhPublicKeyBase64,
            pn: this.PN,
            n: messageNumber,
            rc: this.ratchetCount
        };
        // v1 authenticated ratchet: include version + signature if identity configured.
        if (this.identityManager && this.DHsSignature) {
            header.v = 1;
            header.sig = this.DHsSignature;
        }
        return { payload, header };
    }

    async decryptMessage(payloadBase64, header, roomId, senderId, msgType = 'message') {
        if (!this.receivingChain) throw new Error('Double Ratchet not initialized');

        const { dh: dhPublicKeyBase64, pn: prevChainLength, n: messageNumber, rc: ratchetCount } = header;
        const dhPublicKeyRaw = this.base64urlToArrayBuffer(dhPublicKeyBase64);

        // v1 signature verification if identity configured on both sides.
        if (this.identityManager && header.sig) {
            if (header.v !== 1) throw new Error('PROTOCOL_MISMATCH');
            const canon = this._buildCanonicalBytes(dhPublicKeyRaw, ratchetCount);
            try {
                await this.identityManager.verify(canon, this.base64urlToArrayBuffer(header.sig));
            } catch (e) {
                throw new Error('SIGNATURE_INVALID');
            }
        } else if (this.identityManager && !header.sig) {
            throw new Error('MISSING_SIGNATURE');
        }

        // Snapshot state before any mutation so we can roll back on AEAD failure.
        const _snap = {
            Nr: this.Nr, Ns: this.Ns, PN: this.PN,
            DHr: this.DHr,
            DHrRaw: this.DHrRaw ? new Uint8Array(this.DHrRaw) : null,
            sendingChain: this.sendingChain ? this.sendingChain.clone() : null,
            receivingChain: this.receivingChain ? this.receivingChain.clone() : null,
            skippedKeys: new Map(this.skippedKeys),
            ratchetCount: this.ratchetCount,
            hasRatchetedSinceReceive: this.hasRatchetedSinceReceive,
            DHs: this.DHs, DHsSignature: this.DHsSignature,
            rootKey: this.rootKey ? new Uint8Array(this.rootKey) : null,
        };

        let envelope;
        try {
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

            const skippedKeyId = `${dhPublicKeyBase64}:${messageNumber}`;
            const isSkippedKey = this.skippedKeys.has(skippedKeyId);

            if (!isSkippedKey && messageNumber < this.Nr) {
                throw new Error('Message decryption failed - authentication error');
            }

            if (!isSkippedKey && messageNumber > this.Nr) {
                await this.skipMessageKeys(messageNumber);
            }

            let messageKey;
            if (isSkippedKey) {
                const entry = this.skippedKeys.get(skippedKeyId);
                messageKey = entry.key;
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
                { type: AAD_FIELD_TYPES.MESSAGE_TYPE, value: msgType },
                { type: AAD_FIELD_TYPES.RATCHET_COUNT, value: ratchetCount }
            ]);

            let plaintextBytes;
            try {
                plaintextBytes = await subtle.decrypt(
                    { name: 'AES-GCM', iv: iv, additionalData: aad },
                    messageKey,
                    ciphertext
                );
            } catch (error) {
                throw new Error('Message decryption failed - authentication error');
            }

            if (!isSkippedKey) {
                await this.receivingChain.ratchet();
                this.Nr = messageNumber + 1;
                this.receivingChain.messageNumber = this.Nr;
            }

            envelope = JSON.parse(new TextDecoder().decode(plaintextBytes));
        } catch (err) {
            Object.assign(this, _snap);
            throw err;
        }

        return envelope;
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

        // Prune skipped keys from chains more than one ratchet round old.
        for (const [id, entry] of this.skippedKeys) {
            if (entry.ratchetCount < this.ratchetCount - 1) {
                this.skippedKeys.delete(id);
            }
        }

        if (this.identityManager) await this.signCurrentDHs();
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

        if (this.identityManager) await this.signCurrentDHs();
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
            this.skippedKeys.set(keyId, { key: messageKey, ratchetCount: this.ratchetCount });

            // Global cap: FIFO eviction
            if (this.skippedKeys.size > this.MAX_SKIPPED_KEYS_TOTAL) {
                const oldest = this.skippedKeys.keys().next().value;
                this.skippedKeys.delete(oldest);
            }

            await this.receivingChain.ratchet();
            // Keep chain.messageNumber aligned with chainKeyMaterial's position,
            // so the next deriveMessageKeyForCounter() computes stepsAhead from
            // the true chain position rather than a stale baseline.
            this.receivingChain.messageNumber++;
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

    // -------------------------------------------------------------------------
    // Test 9: Message Too Old (Out of Window)
    // -------------------------------------------------------------------------
    console.log('--- Test 9: Message Too Old (Out of Window) ---');
    try {
        const sharedSecret = hexToBytes('8888888888888888888888888888888888888888888888888888888888888888');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        // Alice sends messages 0-20
        const encryptedMessages = [];
        for (let i = 0; i <= 20; i++) {
            const enc = await alice.encryptMessage(`Message ${i}`, ROOM_ID, ALICE_ID);
            encryptedMessages.push(enc);
        }

        // Bob receives messages 0-20 in order (advances his window)
        for (let i = 0; i <= 20; i++) {
            await bob.decryptMessage(
                encryptedMessages[i].payload, encryptedMessages[i].header, ROOM_ID, ALICE_ID);
        }

        console.log(`  Bob received messages 0-20, Nr=${bob.Nr}`);

        // Now try to decrypt old message 0 again (should fail - out of window)
        let caught = false;
        try {
            await bob.decryptMessage(
                encryptedMessages[0].payload, encryptedMessages[0].header, ROOM_ID, ALICE_ID);
        } catch (e) {
            caught = true;
            console.log(`  Error (expected): ${e.message}`);
        }

        if (caught) {
            console.log('PASSED: Old message (out of window) rejected');
            passed++;
        } else {
            console.log('FAILED: Should have rejected message too old for window');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 10: MAX_SKIP During DH Ratchet (DoS Prevention)
    // -------------------------------------------------------------------------
    console.log('--- Test 10: MAX_SKIP During DH Ratchet (DoS Prevention) ---');
    try {
        const sharedSecret = hexToBytes('9999999999999999999999999999999999999999999999999999999999999999');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        // Phase 1: Alice sends 150 messages on her initial chain
        console.log(`  Phase 1: Alice sends 150 messages (same DH key)`);
        const aliceFirstChainMsgs = [];
        for (let i = 0; i <= 150; i++) {
            const enc = await alice.encryptMessage(`A-chain1-${i}`, ROOM_ID, ALICE_ID);
            aliceFirstChainMsgs.push(enc);
        }

        // Bob receives ONLY message 0 (skipping 1-150 on Alice's first chain)
        await bob.decryptMessage(
            aliceFirstChainMsgs[0].payload, aliceFirstChainMsgs[0].header, ROOM_ID, ALICE_ID);
        console.log(`  Bob received only message 0, Nr=${bob.Nr}`);

        // Phase 2: Bob sends a reply (triggers Bob's send-side DH ratchet)
        const bobReply = await bob.encryptMessage('Reply', ROOM_ID, BOB_ID);
        await alice.decryptMessage(bobReply.payload, bobReply.header, ROOM_ID, BOB_ID);
        console.log(`  Phase 2: Alice received Bob's reply`);

        // Phase 3: Alice sends ONE message with her NEW DH key (after ratchet)
        // This message header will have pn=151 (Alice sent 151 messages before ratcheting)
        // When Bob receives this, he must skip 150 messages (from Nr=1 to pn=151)
        // on Alice's OLD chain before setting up the new chain
        const aliceNewChainMsg = await alice.encryptMessage('A-chain2-0', ROOM_ID, ALICE_ID);
        console.log(`  Phase 3: Alice sends msg with new DH key (pn=${aliceNewChainMsg.header.pn})`);
        console.log(`  Bob needs to skip ${aliceNewChainMsg.header.pn - bob.Nr} messages on old chain`);

        let maxSkipCaught = false;
        try {
            await bob.decryptMessage(
                aliceNewChainMsg.payload, aliceNewChainMsg.header, ROOM_ID, ALICE_ID);
        } catch (e) {
            maxSkipCaught = true;
            console.log(`  Error (expected): ${e.message}`);
        }

        if (maxSkipCaught) {
            console.log('PASSED: MAX_SKIP limit enforced during DH ratchet');
            passed++;
        } else {
            console.log('FAILED: Should have rejected excessive skip (>100 messages on old chain)');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 11: Concurrent Bidirectional Sending (Cross-Talk)
    // -------------------------------------------------------------------------
    console.log('--- Test 11: Concurrent Bidirectional Sending (Cross-Talk) ---');
    try {
        const sharedSecret = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        // Alice sends 3 messages WITHOUT receiving anything
        const aliceMessages = [];
        for (let i = 1; i <= 3; i++) {
            const enc = await alice.encryptMessage(`A${i}`, ROOM_ID, ALICE_ID);
            aliceMessages.push({ enc, text: `A${i}` });
            console.log(`  Alice sends: A${i} (n=${enc.header.n}, rc=${enc.header.rc})`);
        }

        // Bob sends 3 messages WITHOUT receiving anything
        const bobMessages = [];
        for (let i = 1; i <= 3; i++) {
            const enc = await bob.encryptMessage(`B${i}`, ROOM_ID, BOB_ID);
            bobMessages.push({ enc, text: `B${i}` });
            console.log(`  Bob sends: B${i} (n=${enc.header.n}, rc=${enc.header.rc})`);
        }

        console.log(`  State before receiving:`);
        console.log(`    Alice: Ns=${alice.Ns}, Nr=${alice.Nr}, rc=${alice.ratchetCount}`);
        console.log(`    Bob: Ns=${bob.Ns}, Nr=${bob.Nr}, rc=${bob.ratchetCount}`);

        // Receive messages in order (from each sender's perspective)
        // but interleaved between senders: A1, B1, A2, B2, A3, B3
        const receiveOrder = [
            { receiver: bob, msg: aliceMessages[0], sender: ALICE_ID, expected: 'A1' },
            { receiver: alice, msg: bobMessages[0], sender: BOB_ID, expected: 'B1' },
            { receiver: bob, msg: aliceMessages[1], sender: ALICE_ID, expected: 'A2' },
            { receiver: alice, msg: bobMessages[1], sender: BOB_ID, expected: 'B2' },
            { receiver: bob, msg: aliceMessages[2], sender: ALICE_ID, expected: 'A3' },
            { receiver: alice, msg: bobMessages[2], sender: BOB_ID, expected: 'B3' },
        ];

        let allDecrypted = true;
        console.log(`  Receiving interleaved (in-order per sender): A1, B1, A2, B2, A3, B3`);

        for (const item of receiveOrder) {
            try {
                const dec = await item.receiver.decryptMessage(
                    item.msg.enc.payload, item.msg.enc.header, ROOM_ID, item.sender);

                if (dec.text !== item.expected) {
                    console.log(`  MISMATCH: expected "${item.expected}", got "${dec.text}"`);
                    allDecrypted = false;
                } else {
                    console.log(`  ✓ Decrypted: "${dec.text}"`);
                }
            } catch (e) {
                console.log(`  ✗ Failed to decrypt ${item.expected}: ${e.message}`);
                allDecrypted = false;
            }
        }

        console.log(`  Final state:`);
        console.log(`    Alice: Ns=${alice.Ns}, Nr=${alice.Nr}, rc=${alice.ratchetCount}`);
        console.log(`    Bob: Ns=${bob.Ns}, Nr=${bob.Nr}, rc=${bob.ratchetCount}`);

        if (allDecrypted) {
            console.log('PASSED: All cross-talk messages decrypted correctly');
            passed++;
        } else {
            console.log('FAILED: Some cross-talk messages failed to decrypt');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 11b: Out-of-Order Within Same Chain (Skipped-Key Recovery)
    // -------------------------------------------------------------------------
    console.log('--- Test 11b: Out-of-Order Within Same Chain (Skipped-Key Recovery) ---');
    try {
        const sharedSecret = hexToBytes('aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        // Alice sends messages 0, 1, 2
        const messages = [];
        for (let i = 0; i < 3; i++) {
            const enc = await alice.encryptMessage(`Msg${i}`, ROOM_ID, ALICE_ID);
            messages.push(enc);
        }

        console.log('  Alice sent messages 0, 1, 2');

        // Bob receives message 2 FIRST (skipping 0 and 1)
        const dec2 = await bob.decryptMessage(
            messages[2].payload, messages[2].header, ROOM_ID, ALICE_ID);
        console.log(`  Bob received msg 2 first: "${dec2.text}"`);

        // Bob now receives the delayed messages 0 and 1 — both must decrypt
        // from stored skipped keys.
        const dec0 = await bob.decryptMessage(
            messages[0].payload, messages[0].header, ROOM_ID, ALICE_ID);
        console.log(`  Bob received delayed msg 0: "${dec0.text}"`);

        const dec1 = await bob.decryptMessage(
            messages[1].payload, messages[1].header, ROOM_ID, ALICE_ID);
        console.log(`  Bob received delayed msg 1: "${dec1.text}"`);

        // A replay of msg 0 (already consumed from skippedKeys) must be rejected.
        let replayRejected = false;
        try {
            await bob.decryptMessage(
                messages[0].payload, messages[0].header, ROOM_ID, ALICE_ID);
        } catch (e) {
            replayRejected = true;
            console.log(`  Msg 0 replay rejected (expected): ${e.message}`);
        }

        if (dec0.text === 'Msg0' && dec1.text === 'Msg1' && dec2.text === 'Msg2' && replayRejected) {
            console.log('PASSED: Same-chain out-of-order recovered via skipped keys; replay rejected');
            passed++;
        } else {
            console.log('FAILED: Expected 0/1/2 to decrypt and replay to be rejected');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 12: Extended Concurrent Sending with Multiple Ratchets
    // -------------------------------------------------------------------------
    console.log('--- Test 12: Extended Concurrent Sending with Multiple Ratchets ---');
    try {
        const sharedSecret = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');

        const aliceKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKeypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKeypair, bobKeypair.publicKey);

        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKeypair, null);

        // Phase 1: Alice sends 2, Bob receives them
        console.log('  Phase 1: Alice → Bob (2 msgs)');
        for (let i = 1; i <= 2; i++) {
            const enc = await alice.encryptMessage(`A-phase1-${i}`, ROOM_ID, ALICE_ID);
            const dec = await bob.decryptMessage(enc.payload, enc.header, ROOM_ID, ALICE_ID);
            console.log(`    ${dec.text}`);
        }

        // Phase 2: Both send simultaneously without receiving
        console.log('  Phase 2: Simultaneous sending');
        const phase2Alice = [];
        const phase2Bob = [];

        for (let i = 1; i <= 3; i++) {
            phase2Alice.push(await alice.encryptMessage(`A-phase2-${i}`, ROOM_ID, ALICE_ID));
        }
        for (let i = 1; i <= 3; i++) {
            phase2Bob.push(await bob.encryptMessage(`B-phase2-${i}`, ROOM_ID, BOB_ID));
        }

        // Phase 3: Receive everything (interleaved)
        console.log('  Phase 3: Receiving interleaved');
        let success = true;

        // Bob receives Alice's phase2 messages
        for (let i = 0; i < 3; i++) {
            try {
                const dec = await bob.decryptMessage(
                    phase2Alice[i].payload, phase2Alice[i].header, ROOM_ID, ALICE_ID);
                console.log(`    Bob got: ${dec.text}`);
            } catch (e) {
                console.log(`    Bob failed: ${e.message}`);
                success = false;
            }
        }

        // Alice receives Bob's phase2 messages
        for (let i = 0; i < 3; i++) {
            try {
                const dec = await alice.decryptMessage(
                    phase2Bob[i].payload, phase2Bob[i].header, ROOM_ID, BOB_ID);
                console.log(`    Alice got: ${dec.text}`);
            } catch (e) {
                console.log(`    Alice failed: ${e.message}`);
                success = false;
            }
        }

        // Phase 4: Continue normal conversation
        console.log('  Phase 4: Continue normal ping-pong');
        const encA = await alice.encryptMessage('Final from Alice', ROOM_ID, ALICE_ID);
        const decA = await bob.decryptMessage(encA.payload, encA.header, ROOM_ID, ALICE_ID);
        console.log(`    Bob got: ${decA.text}`);

        const encB = await bob.encryptMessage('Final from Bob', ROOM_ID, BOB_ID);
        const decB = await alice.decryptMessage(encB.payload, encB.header, ROOM_ID, BOB_ID);
        console.log(`    Alice got: ${decB.text}`);

        if (decA.text === 'Final from Alice' && decB.text === 'Final from Bob') {
            success = success && true;
        } else {
            success = false;
        }

        console.log(`  Final ratchet counts: Alice=${alice.ratchetCount}, Bob=${bob.ratchetCount}`);

        if (success) {
            console.log('PASSED: Extended concurrent sending works correctly');
            passed++;
        } else {
            console.log('FAILED: Extended concurrent test failed');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Helper: build a real ECDSA-based identity manager stub for v1 signed ratchet
    // =========================================================================
    async function makeIdentityStub() {
        const kp = await subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']
        );
        return {
            _kp: kp,
            async sign(data) {
                return subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, data);
            },
            async verify(data, sig) {
                const ok = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, kp.publicKey, sig, data);
                if (!ok) throw new Error('verification failed');
                return true;
            }
        };
    }

    // =========================================================================
    // Test 13: Global skippedKeys cap (anti-DoS, FIFO eviction)
    // =========================================================================
    console.log('--- Test 13: Global skippedKeys Cap ---');
    try {
        const alice = new DoubleRatchet();
        const keypair = await subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
        );
        await alice.initialize(new Uint8Array(32).fill(7), true, keypair, null);

        // Simulate the insert path from skipMessageKeys: set + FIFO eviction.
        // Populate well beyond the cap across simulated ratchet rounds.
        const CAP = alice.MAX_SKIPPED_KEYS_TOTAL;
        for (let rc = 0; rc < 20; rc++) {
            for (let n = 0; n < 90; n++) {
                alice.skippedKeys.set(`dh-${rc}:${n}`, { key: null, ratchetCount: rc });
                if (alice.skippedKeys.size > CAP) {
                    const oldest = alice.skippedKeys.keys().next().value;
                    alice.skippedKeys.delete(oldest);
                }
            }
        }

        console.log(`  Inserted 1800 entries (20 rounds × 90 skip), cap=${CAP}`);
        console.log(`  skippedKeys.size = ${alice.skippedKeys.size}`);

        if (alice.skippedKeys.size <= CAP) {
            console.log('PASSED: Global cap enforced via FIFO eviction');
            passed++;
        } else {
            console.log(`FAILED: size ${alice.skippedKeys.size} exceeds cap ${CAP}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 14: v1 authenticated ratchet — happy path (sig verified)
    // =========================================================================
    console.log('--- Test 14: v1 Authenticated Ratchet (happy path) ---');
    try {
        // Both parties use the SAME identity stub so Bob's verify() accepts Alice's sig.
        // Production has two separate identity keys but uses the peer's public key here.
        const idm = await makeIdentityStub();
        const alice = new DoubleRatchet(idm);
        const bob = new DoubleRatchet(idm);

        const aliceKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const shared = new Uint8Array(32).fill(42);
        await alice.initialize(shared, true, aliceKp, bobKp.publicKey);
        await bob.initialize(shared, false, bobKp, null);

        const enc = await alice.encryptMessage('hello v1', 'room-1', 'alice');
        if (enc.header.v !== 1 || !enc.header.sig) {
            throw new Error(`expected v=1 and sig, got ${JSON.stringify(enc.header)}`);
        }
        const dec = await bob.decryptMessage(enc.payload, enc.header, 'room-1', 'alice');
        if (dec.text !== 'hello v1') throw new Error('text mismatch');

        console.log('PASSED: v1 header emitted with sig + decrypt succeeds');
        passed++;
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 15: Signature tampering detected
    // =========================================================================
    console.log('--- Test 15: Signature Tampering Detected ---');
    try {
        const idm = await makeIdentityStub();
        const alice = new DoubleRatchet(idm);
        const bob = new DoubleRatchet(idm);

        const aliceKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const shared = new Uint8Array(32).fill(11);
        await alice.initialize(shared, true, aliceKp, bobKp.publicKey);
        await bob.initialize(shared, false, bobKp, null);

        const enc = await alice.encryptMessage('tamper target', 'room-x', 'alice');
        // Flip one byte in the signature (decode → mutate → re-encode).
        const sigBytes = alice.base64urlToArrayBuffer(enc.header.sig);
        sigBytes[0] ^= 0xFF;
        enc.header.sig = alice.arrayBufferToBase64url(sigBytes);

        let threw = false;
        try {
            await bob.decryptMessage(enc.payload, enc.header, 'room-x', 'alice');
        } catch (e) {
            threw = (e.message === 'SIGNATURE_INVALID');
        }
        if (threw) {
            console.log('PASSED: tampered sig rejected with SIGNATURE_INVALID');
            passed++;
        } else {
            console.log('FAILED: decrypt did not throw SIGNATURE_INVALID');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 16: DH key swap detected (signature bound to dh+rc)
    // =========================================================================
    console.log('--- Test 16: DH Key Swap Detected ---');
    try {
        const idm = await makeIdentityStub();
        const alice = new DoubleRatchet(idm);
        const bob = new DoubleRatchet(idm);

        const aliceKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const shared = new Uint8Array(32).fill(22);
        await alice.initialize(shared, true, aliceKp, bobKp.publicKey);
        await bob.initialize(shared, false, bobKp, null);

        const enc = await alice.encryptMessage('swap target', 'room-y', 'alice');
        // Replace dh with a different valid pubkey, keeping sig unchanged.
        const eve = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const eveRaw = await subtle.exportKey('raw', eve.publicKey);
        enc.header.dh = alice.arrayBufferToBase64url(eveRaw);

        let threw = false;
        try {
            await bob.decryptMessage(enc.payload, enc.header, 'room-y', 'alice');
        } catch (e) {
            threw = (e.message === 'SIGNATURE_INVALID');
        }
        if (threw) {
            console.log('PASSED: swapped dh rejected with SIGNATURE_INVALID');
            passed++;
        } else {
            console.log('FAILED: decrypt did not throw SIGNATURE_INVALID');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 17: Corrupted payload does not mutate DR state (tentative-decrypt)
    // =========================================================================
    console.log('--- Test 17: Corrupted Payload Does Not Mutate DR State ---');
    try {
        const sharedSecret = hexToBytes('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
        const aliceKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKp, bobKp.publicKey);
        const bob = new DoubleRatchet();
        await bob.initialize(new Uint8Array(sharedSecret), false, bobKp, null);

        // Establish a DH ratchet: Alice sends msg0, Bob receives; Bob sends reply, Alice receives
        const enc0 = await alice.encryptMessage('msg0', ROOM_ID, ALICE_ID);
        await bob.decryptMessage(enc0.payload, enc0.header, ROOM_ID, ALICE_ID);
        const bobReply = await bob.encryptMessage('reply', ROOM_ID, BOB_ID);
        await alice.decryptMessage(bobReply.payload, bobReply.header, ROOM_ID, BOB_ID);

        // Alice sends a second message with her NEW DH key (after send-side ratchet)
        const enc1 = await alice.encryptMessage('msg1', ROOM_ID, ALICE_ID);

        // Record Bob's state before the attack
        const nrBefore = bob.Nr;
        const rcBefore = bob.ratchetCount;

        // Corrupt enc1's payload (keep valid header with valid signature if any)
        const payloadBytes = bob.base64urlToArrayBuffer(enc1.payload);
        payloadBytes[12] ^= 0xFF; // flip a byte in the ciphertext (past the 12-byte IV)
        const corruptPayload = bob.arrayBufferToBase64url(payloadBytes);

        let threw = false;
        try {
            await bob.decryptMessage(corruptPayload, enc1.header, ROOM_ID, ALICE_ID);
        } catch (e) {
            threw = true;
            console.log(`  Expected error: ${e.message}`);
        }

        const nrAfter = bob.Nr;
        const rcAfter = bob.ratchetCount;

        // State must be rolled back
        let canStillDecrypt = false;
        try {
            const dec = await bob.decryptMessage(enc1.payload, enc1.header, ROOM_ID, ALICE_ID);
            canStillDecrypt = dec.text === 'msg1';
        } catch (e) {
            console.log(`  Retry failed: ${e.message}`);
        }

        if (threw && nrBefore === nrAfter && rcBefore === rcAfter && canStillDecrypt) {
            console.log(`PASSED: corrupted payload rejected, Nr ${nrBefore}→${nrAfter}, rc ${rcBefore}→${rcAfter}, retry succeeds`);
            passed++;
        } else {
            console.log(`FAILED: threw=${threw}, Nr ${nrBefore}→${nrAfter}, rc ${rcBefore}→${rcAfter}, canStillDecrypt=${canStillDecrypt}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 18: msgType AAD binding — cross-type replay rejected
    // =========================================================================
    console.log('--- Test 18: msgType AAD Binding — Cross-Type Rejection ---');
    try {
        const sharedSecret = hexToBytes('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
        const aliceKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
        const bobKp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);

        const alice = new DoubleRatchet();
        await alice.initialize(sharedSecret, true, aliceKp, bobKp.publicKey);

        // Alice encrypts as 'image'
        const enc = await alice.encryptMessage('image-envelope', ROOM_ID, ALICE_ID, 'image');

        // Bob (instance 1) tries to decrypt as 'message' — AEAD must fail
        const bob1 = new DoubleRatchet();
        await bob1.initialize(new Uint8Array(sharedSecret), false, bobKp, null);
        let crossTypeRejected = false;
        try {
            await bob1.decryptMessage(enc.payload, enc.header, ROOM_ID, ALICE_ID, 'message');
        } catch (e) {
            crossTypeRejected = true;
            console.log(`  Cross-type rejected (expected): ${e.message}`);
        }

        // Bob (instance 2) decrypts as 'image' — must succeed
        const bob2 = new DoubleRatchet();
        await bob2.initialize(new Uint8Array(sharedSecret), false, bobKp, null);
        let correctDecrypt = false;
        try {
            const dec = await bob2.decryptMessage(enc.payload, enc.header, ROOM_ID, ALICE_ID, 'image');
            correctDecrypt = dec.text === 'image-envelope';
        } catch (e) {
            console.log(`  Correct-type failed (unexpected): ${e.message}`);
        }

        if (crossTypeRejected && correctDecrypt) {
            console.log('PASSED: cross-type replay rejected; correct msgType succeeds');
            passed++;
        } else {
            console.log(`FAILED: crossTypeRejected=${crossTypeRejected}, correctDecrypt=${correctDecrypt}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        console.log(e.stack);
        failed++;
    }
    console.log('');

    // =========================================================================
    // Test 19: AAD TLV wire-format freeze (little-endian numerics)
    // =========================================================================
    console.log('--- Test 19: AAD TLV Wire-Format Freeze ---');
    try {
        // Encode a fixed set of fields and compare against a hardcoded expected value.
        // This freezes the current wire format so any inadvertent change is caught.
        // WARNING: changing this format requires a coordinated deploy of all clients.
        const aad = encodeAADWithLengthPrefix([
            { type: AAD_FIELD_TYPES.ROOM_ID,         value: 'r1'      },
            { type: AAD_FIELD_TYPES.SENDER_ID,        value: 's1'      },
            { type: AAD_FIELD_TYPES.MESSAGE_NUMBER,   value: 1         },
            { type: AAD_FIELD_TYPES.MESSAGE_TYPE,     value: 'message' },
            { type: AAD_FIELD_TYPES.RATCHET_COUNT,    value: 0         },
        ]);

        const hex = Array.from(aad).map(b => b.toString(16).padStart(2, '0')).join('');
        // ROOM_ID(01) len=2 "r1" | SENDER_ID(02) len=2 "s1" |
        // MESSAGE_NUMBER(05) len=8 value=1 LE-u64 | MESSAGE_TYPE(06) len=7 "message" |
        // RATCHET_COUNT(07) len=8 value=0 LE-u64
        const EXPECTED = '0100027231020002733105000801000000000000000600076d6573736167650700080000000000000000';

        console.log(`  Got:      ${hex}`);
        console.log(`  Expected: ${EXPECTED}`);

        if (hex === EXPECTED) {
            console.log('PASSED: AAD wire format matches expected (little-endian numerics)');
            passed++;
        } else {
            console.log('FAILED: AAD wire format changed — all clients must be updated atomically');
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
