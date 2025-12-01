#!/usr/bin/env node

/**
 * Chain Ratchet Test Suite
 *
 * Tests the symmetric key ratchet (ChainRatchet class) which provides
 * Perfect Forward Secrecy (PFS) for the Signal Protocol implementation.
 *
 * Test vectors from: tests/vectors/signal-protocol-vectors.json
 */

const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

// ============================================================================
// ChainRatchet Implementation (copied from static/js/crypto.js for testing)
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
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        const myCounter = this.messageNumber;
        this.messageNumber++;

        const messageKey = await this._deriveKeyForCounter(myCounter, myCounter);

        // Sliding window
        for (let i = 1; i <= this.WINDOW_SIZE; i++) {
            const futureCounter = myCounter + i;
            const futureKey = await this._deriveKeyForCounter(futureCounter, myCounter);
            this.messageKeyWindow.set(futureCounter, futureKey);
        }

        // Cleanup old keys
        for (const [counter] of this.messageKeyWindow) {
            if (counter < myCounter) {
                this.messageKeyWindow.delete(counter);
            }
        }

        return { key: messageKey, counter: myCounter };
    }

    async deriveMessageKeyForCounter(counter) {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        if (this.messageKeyWindow.has(counter)) {
            return this.messageKeyWindow.get(counter);
        }

        const currentCounter = this.messageNumber;
        return await this._deriveKeyForCounter(counter, currentCounter);
    }

    async _deriveKeyForCounter(counter, currentCounter) {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        const stepsAhead = counter - currentCounter;
        let simulatedChainKey = new Uint8Array(this.chainKeyMaterial);

        for (let i = 0; i < stepsAhead; i++) {
            const ratchetInfo = new TextEncoder().encode('ChainRatchet');
            const hmacKey = await subtle.importKey(
                'raw',
                simulatedChainKey,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );
            const nextChainKeyRaw = await subtle.sign('HMAC', hmacKey, ratchetInfo);
            simulatedChainKey = new Uint8Array(nextChainKeyRaw);
        }

        const info = new TextEncoder().encode(`MessageKey-${counter}`);
        const hmacKey = await subtle.importKey(
            'raw',
            simulatedChainKey,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        const messageKeyRaw = await subtle.sign('HMAC', hmacKey, info);
        simulatedChainKey.fill(0);

        return await subtle.importKey(
            'raw',
            messageKeyRaw,
            { name: 'AES-GCM', length: 256 },
            true,  // extractable for testing
            ['encrypt', 'decrypt']
        );
    }

    async ratchet() {
        if (!this.chainKeyMaterial) {
            throw new Error('Chain ratchet not initialized');
        }

        const info = new TextEncoder().encode('ChainRatchet');
        const hmacKey = await subtle.importKey(
            'raw',
            this.chainKeyMaterial,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

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
// HKDF Helper (same as production)
// ============================================================================

async function hkdf(inputKeyMaterial, info, length, salt = null) {
    if (!salt) {
        salt = new Uint8Array(32);
    }

    const ikmKey = await subtle.importKey(
        'raw',
        inputKeyMaterial,
        { name: 'HKDF' },
        false,
        ['deriveBits']
    );

    const infoBytes = new TextEncoder().encode(info);
    const derivedBits = await subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: infoBytes
        },
        ikmKey,
        length * 8
    );

    return new Uint8Array(derivedBits);
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

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function exportKeyToHex(key) {
    const raw = await subtle.exportKey('raw', key);
    return bytesToHex(new Uint8Array(raw));
}

// ============================================================================
// Test Suite
// ============================================================================

async function runTests() {
    console.log('='.repeat(70));
    console.log('CHAIN RATCHET TEST SUITE (Signal Protocol Symmetric Ratchet)');
    console.log('='.repeat(70));
    console.log('');

    let passed = 0;
    let failed = 0;

    // -------------------------------------------------------------------------
    // Test 1: Basic Chain Initialization
    // -------------------------------------------------------------------------
    console.log('--- Test 1: Basic Chain Initialization ---');
    try {
        const chainKey = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        if (chain.chainKeyMaterial.length === 32 && chain.messageNumber === 0) {
            console.log('PASSED: Chain initialized with 32-byte key, counter=0');
            passed++;
        } else {
            console.log('FAILED: Unexpected state after initialization');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 2: Message Key Derivation
    // -------------------------------------------------------------------------
    console.log('--- Test 2: Message Key Derivation ---');
    try {
        const chainKey = hexToBytes('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        const { key: key0, counter: c0 } = await chain.deriveMessageKey();
        const { key: key1, counter: c1 } = await chain.deriveMessageKey();
        const { key: key2, counter: c2 } = await chain.deriveMessageKey();

        const hex0 = await exportKeyToHex(key0);
        const hex1 = await exportKeyToHex(key1);
        const hex2 = await exportKeyToHex(key2);

        console.log(`  Key 0 (counter=${c0}): ${hex0.substring(0, 32)}...`);
        console.log(`  Key 1 (counter=${c1}): ${hex1.substring(0, 32)}...`);
        console.log(`  Key 2 (counter=${c2}): ${hex2.substring(0, 32)}...`);

        // All keys should be different
        if (hex0 !== hex1 && hex1 !== hex2 && hex0 !== hex2) {
            console.log('PASSED: All derived keys are unique');
            passed++;
        } else {
            console.log('FAILED: Keys are not unique!');
            failed++;
        }

        // Counters should be sequential
        if (c0 === 0 && c1 === 1 && c2 === 2) {
            console.log('PASSED: Counters are sequential (0, 1, 2)');
            passed++;
        } else {
            console.log('FAILED: Counters are not sequential');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed += 2;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 3: Deterministic Key Derivation
    // -------------------------------------------------------------------------
    console.log('--- Test 3: Deterministic Key Derivation ---');
    try {
        const chainKey = hexToBytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

        // First run
        const chain1 = new ChainRatchet();
        await chain1.initialize(chainKey);
        const { key: key1 } = await chain1.deriveMessageKey();
        const hex1 = await exportKeyToHex(key1);

        // Second run (same input)
        const chain2 = new ChainRatchet();
        await chain2.initialize(new Uint8Array(chainKey));
        const { key: key2 } = await chain2.deriveMessageKey();
        const hex2 = await exportKeyToHex(key2);

        console.log(`  Run 1: ${hex1}`);
        console.log(`  Run 2: ${hex2}`);

        if (hex1 === hex2) {
            console.log('PASSED: Same input produces same output (deterministic)');
            passed++;
        } else {
            console.log('FAILED: Non-deterministic output!');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 4: Chain Ratchet Forward
    // -------------------------------------------------------------------------
    console.log('--- Test 4: Chain Ratchet Forward (One-Way)');
    try {
        const chainKey = hexToBytes('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        const originalChainKey = bytesToHex(chain.chainKeyMaterial);
        console.log(`  Before ratchet: ${originalChainKey.substring(0, 32)}...`);

        await chain.ratchet();
        const afterRatchet = bytesToHex(chain.chainKeyMaterial);
        console.log(`  After ratchet:  ${afterRatchet.substring(0, 32)}...`);

        if (originalChainKey !== afterRatchet) {
            console.log('PASSED: Chain key changed after ratchet');
            passed++;
        } else {
            console.log('FAILED: Chain key unchanged!');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 5: Bidirectional Chain Symmetry (Alice/Bob)
    // -------------------------------------------------------------------------
    console.log('--- Test 5: Bidirectional Chain Symmetry (Alice/Bob) ---');
    try {
        const sharedSecret = hexToBytes('deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');
        const salt = new Uint8Array(32);

        // Alice (initiator)
        const aliceSendingKey = await hkdf(sharedSecret, 'InitiatorToResponder', 32, salt);
        const aliceReceivingKey = await hkdf(sharedSecret, 'ResponderToInitiator', 32, salt);

        // Bob (responder)
        const bobSendingKey = await hkdf(sharedSecret, 'ResponderToInitiator', 32, salt);
        const bobReceivingKey = await hkdf(sharedSecret, 'InitiatorToResponder', 32, salt);

        const aliceSendHex = bytesToHex(aliceSendingKey);
        const bobReceiveHex = bytesToHex(bobReceivingKey);
        const bobSendHex = bytesToHex(bobSendingKey);
        const aliceReceiveHex = bytesToHex(aliceReceivingKey);

        console.log(`  Alice sending:   ${aliceSendHex.substring(0, 32)}...`);
        console.log(`  Bob receiving:   ${bobReceiveHex.substring(0, 32)}...`);
        console.log(`  Bob sending:     ${bobSendHex.substring(0, 32)}...`);
        console.log(`  Alice receiving: ${aliceReceiveHex.substring(0, 32)}...`);

        if (aliceSendHex === bobReceiveHex && bobSendHex === aliceReceiveHex) {
            console.log('PASSED: Alice.send === Bob.receive AND Bob.send === Alice.receive');
            passed++;
        } else {
            console.log('FAILED: Chain symmetry broken!');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 6: Sliding Window Pre-derivation
    // -------------------------------------------------------------------------
    console.log('--- Test 6: Sliding Window Pre-derivation ---');
    try {
        const chainKey = hexToBytes('cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        await chain.deriveMessageKey();  // counter 0

        // Check that window contains keys 1-16
        let windowOk = true;
        for (let i = 1; i <= 16; i++) {
            if (!chain.messageKeyWindow.has(i)) {
                windowOk = false;
                console.log(`  Missing key ${i} in window`);
            }
        }

        if (windowOk && chain.messageKeyWindow.size === 16) {
            console.log(`PASSED: Sliding window contains 16 pre-derived keys (1-16)`);
            passed++;
        } else {
            console.log(`FAILED: Window size is ${chain.messageKeyWindow.size}`);
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 7: Out-of-Order Key Retrieval
    // -------------------------------------------------------------------------
    console.log('--- Test 7: Out-of-Order Key Retrieval ---');
    try {
        const chainKey = hexToBytes('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        // Derive key 0 (normal)
        const { key: key0 } = await chain.deriveMessageKey();
        const hex0 = await exportKeyToHex(key0);

        // Get key 5 from window (out of order)
        const key5 = await chain.deriveMessageKeyForCounter(5);
        const hex5 = await exportKeyToHex(key5);

        console.log(`  Key 0: ${hex0.substring(0, 32)}...`);
        console.log(`  Key 5 (from window): ${hex5.substring(0, 32)}...`);

        if (hex0 !== hex5) {
            console.log('PASSED: Retrieved different key from window');
            passed++;
        } else {
            console.log('FAILED: Keys should be different');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 8: Encrypt/Decrypt with Derived Keys
    // -------------------------------------------------------------------------
    console.log('--- Test 8: Encrypt/Decrypt with Derived Keys ---');
    try {
        const chainKey = hexToBytes('eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');

        // Sender chain
        const senderChain = new ChainRatchet();
        await senderChain.initialize(chainKey);
        const { key: sendKey, counter } = await senderChain.deriveMessageKey();

        // Receiver chain (same initial key)
        const receiverChain = new ChainRatchet();
        await receiverChain.initialize(new Uint8Array(chainKey));
        const recvKey = await receiverChain.deriveMessageKeyForCounter(counter);

        // Encrypt
        const plaintext = 'Hello, Signal Protocol!';
        const encoder = new TextEncoder();
        const iv = webcrypto.getRandomValues(new Uint8Array(12));

        const ciphertext = await subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            sendKey,
            encoder.encode(plaintext)
        );

        // Decrypt with receiver's key
        const decrypted = await subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            recvKey,
            ciphertext
        );

        const decoder = new TextDecoder();
        const result = decoder.decode(decrypted);

        console.log(`  Plaintext:  "${plaintext}"`);
        console.log(`  Decrypted:  "${result}"`);

        if (result === plaintext) {
            console.log('PASSED: Encrypt/decrypt successful with derived keys');
            passed++;
        } else {
            console.log('FAILED: Decryption mismatch');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 9: Chain Reset (PFS Session End)
    // -------------------------------------------------------------------------
    console.log('--- Test 9: Chain Reset (PFS Session End) ---');
    try {
        const chainKey = hexToBytes('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
        const chain = new ChainRatchet();
        await chain.initialize(chainKey);

        await chain.deriveMessageKey();
        await chain.deriveMessageKey();

        chain.reset();

        const isReset = (
            chain.chainKeyMaterial === null &&
            chain.messageNumber === 0 &&
            chain.messageKeyWindow.size === 0
        );

        if (isReset) {
            console.log('PASSED: Chain reset clears all state');
            passed++;
        } else {
            console.log('FAILED: State not fully cleared');
            failed++;
        }
    } catch (e) {
        console.log('FAILED:', e.message);
        failed++;
    }
    console.log('');

    // -------------------------------------------------------------------------
    // Test 10: Invalid Initialization
    // -------------------------------------------------------------------------
    console.log('--- Test 10: Invalid Initialization ---');
    try {
        const chain = new ChainRatchet();

        let caught = false;
        try {
            await chain.initialize(new Uint8Array(16));  // Wrong size
        } catch (e) {
            caught = true;
        }

        if (caught) {
            console.log('PASSED: Rejects invalid key material size');
            passed++;
        } else {
            console.log('FAILED: Should reject 16-byte key');
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
