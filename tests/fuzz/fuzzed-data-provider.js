'use strict';

/**
 * Small dependency-free byte consumer for the decrypt fuzz target.
 * It deliberately exposes only the operations used by this repository.
 */
class FuzzedDataProvider {
    constructor(data) {
        this.data = Buffer.from(data || []);
        this.offset = 0;
    }

    consumeBytes(count) {
        const safeCount = Math.max(0, Number(count) || 0);
        const end = Math.min(this.offset + safeCount, this.data.length);
        const consumed = this.data.subarray(this.offset, end);
        this.offset = end;
        if (consumed.length === safeCount) return new Uint8Array(consumed);

        const padded = new Uint8Array(safeCount);
        padded.set(consumed);
        return padded;
    }

    consumeIntegralInRange(min, max) {
        if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || max < min) {
            throw new RangeError('Invalid integral range');
        }
        const width = max - min + 1;
        let value = 0;
        for (const byte of this.consumeBytes(4)) {
            value = ((value * 256) + byte) >>> 0;
        }
        return min + (value % width);
    }
}

module.exports = { FuzzedDataProvider };
