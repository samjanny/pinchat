/**
 * Proof-of-Work (PoW) solver for DoS protection
 *
 * Based on SHA-256 hash puzzles with configurable difficulty.
 * Client must find a nonce such that: SHA256(challenge + nonce) & mask == mask
 */

class ProofOfWork {
    /**
     * Creates a new PoW solver
     *
     * @param {string} challenge - Server-provided challenge string
     * @param {string} mask - Hexadecimal mask defining difficulty
     * @param {string} algorithm - Hash algorithm (default: 'SHA-256')
     */
    constructor(challenge, mask, algorithm = 'SHA-256') {
        this.challenge = challenge;
        this.mask = this.hexToBytes(mask);
        this.algorithm = algorithm;
    }

    /**
     * Converts hexadecimal string to byte array
     *
     * @param {string} hex - Hexadecimal string
     * @returns {Uint8Array} Byte array
     */
    hexToBytes(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return new Uint8Array(bytes);
    }

    /**
     * Solves the PoW challenge by brute-forcing nonces
     *
     * @param {function} onProgress - Optional callback for progress updates (nonce)
     * @returns {Promise<number>} The valid nonce
     */
    async solve(onProgress = null) {
        let nonce = 0;
        const encoder = new TextEncoder();

        while (true) {
            nonce++;

            // Compute hash of challenge + nonce
            const data = encoder.encode(this.challenge + nonce);
            const hashBuffer = await crypto.subtle.digest(this.algorithm, data);
            const hash = new Uint8Array(hashBuffer);

            // Check if hash satisfies mask constraint
            if (this.checkMask(hash)) {
                return nonce;
            }

            // Progress callback every 100,000 attempts
            if (onProgress && nonce % 100000 === 0) {
                onProgress(nonce);
            }

            // Yield to prevent blocking UI (every 1000 attempts)
            if (nonce % 1000 === 0) {
                await this.sleep(0);
            }
        }
    }

    /**
     * Checks if hash satisfies the mask constraint
     *
     * @param {Uint8Array} hash - SHA-256 hash to check
     * @returns {boolean} True if (hash & mask) == mask
     */
    checkMask(hash) {
        for (let i = 0; i < this.mask.length; i++) {
            const maskByte = this.mask[i];
            const hashByte = hash[i];

            // Check if (hash & mask) == mask for this byte
            if ((hashByte & maskByte) !== maskByte) {
                return false;
            }
        }
        return true;
    }

    /**
     * Sleep helper for yielding control to event loop
     *
     * @param {number} ms - Milliseconds to sleep
     * @returns {Promise<void>}
     */
    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Generates a binary mask based on difficulty level
     *
     * @param {number} difficulty - Number of leading bits that must be 1
     * @returns {string} Hexadecimal string representing the 32-byte mask
     *
     * @example
     * - difficulty = 8  → mask = "ff000000..." (first byte must be 0xff)
     * - difficulty = 12 → mask = "fff00000..." (first 12 bits must be 1)
     */
    static generateMask(difficulty) {
        difficulty = Math.min(difficulty, 255); // Cap at SHA-256 output size

        const fullBytes = Math.floor(difficulty / 8);
        const remainingBits = difficulty % 8;

        const mask = [];

        // Add full 0xFF bytes
        for (let i = 0; i < fullBytes; i++) {
            mask.push(0xFF);
        }

        // Add partial byte with leading 1s
        if (remainingBits > 0) {
            // JavaScript shift doesn't truncate to 8 bits, so we need to AND with 0xFF
            const partialByte = (0xFF << (8 - remainingBits)) & 0xFF;
            mask.push(partialByte);
        }

        // Pad to 32 bytes (SHA-256 output size)
        while (mask.length < 32) {
            mask.push(0x00);
        }

        // Convert to hex string
        return mask.map(byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Estimates average solve time based on difficulty
     *
     * @param {number} difficulty - Number of bits required
     * @returns {string} Human-readable time estimate
     */
    static estimateSolveTime(difficulty) {
        // Average attempts needed: 2^difficulty
        // Average hash rate on modern browser: ~500k hashes/sec
        const avgAttempts = Math.pow(2, difficulty);
        const hashRate = 500000; // Conservative estimate
        const seconds = avgAttempts / hashRate;

        if (seconds < 1) {
            return `~${Math.round(seconds * 1000)}ms`;
        } else if (seconds < 60) {
            return `~${Math.round(seconds)}s`;
        } else if (seconds < 120) {
            return `~${Math.round(seconds / 60)} minute`;
        } else {
            return `~${Math.round(seconds / 60)} minutes`;
        }
    }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ProofOfWork;
}
