/**
 * PinChat.io Integrity Verification Module
 *
 * This module fetches a signed hash list from GitHub, verifies the signature,
 * then compares the hashes against files served by pinchat.io
 */

// Configuration - UPDATE THESE VALUES
const CONFIG = {
    // GitHub raw URL for the signed hash list
    HASH_LIST_URL: 'https://raw.githubusercontent.com/samjanny/pinchat/main/hashes.json.signed',

    // Base URL of the site to verify
    SITE_URL: 'https://pinchat.io',

    // Public key for signature verification (PEM format, base64 encoded)
    // IMPORTANT: Replace this with your actual public key
    PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPLACE_YOUR_ACTUAL_PUBLIC_KEY_HERE
-----END PUBLIC KEY-----`
};

/**
 * Import the public key for signature verification
 */
async function importPublicKey(pemKey) {
    // Remove PEM headers and decode base64
    const pemContents = pemKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');

    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

    return await crypto.subtle.importKey(
        'spki',
        binaryKey,
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        false,
        ['verify']
    );
}

/**
 * Verify the signature of the hash list
 */
async function verifySignature(data, signature, publicKey) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const signatureBuffer = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

    return await crypto.subtle.verify(
        {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        publicKey,
        signatureBuffer,
        dataBuffer
    );
}

/**
 * Calculate SHA-256 hash of content
 */
async function calculateHash(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Fetch the signed hash list from GitHub
 */
async function fetchHashList() {
    const response = await fetch(CONFIG.HASH_LIST_URL, {
        cache: 'no-store'
    });

    if (!response.ok) {
        throw new Error(`Failed to fetch hash list: ${response.status}`);
    }

    return await response.json();
}

/**
 * Fetch a file from pinchat.io and calculate its hash
 */
async function fetchAndHashFile(path) {
    const url = `${CONFIG.SITE_URL}${path}`;

    try {
        const response = await fetch(url, {
            cache: 'no-store'
        });

        if (!response.ok) {
            return { path, error: `HTTP ${response.status}`, hash: null };
        }

        const content = await response.text();
        const hash = await calculateHash(content);

        return { path, hash, error: null };
    } catch (error) {
        return { path, error: error.message, hash: null };
    }
}

/**
 * Main verification function
 * Returns: { verified: boolean, errors: string[], details: object }
 */
async function verifyIntegrity() {
    const result = {
        verified: false,
        signatureValid: false,
        errors: [],
        mismatches: [],
        details: {
            filesChecked: 0,
            filesMatched: 0,
            filesFailed: 0
        }
    };

    try {
        // Step 1: Fetch the signed hash list
        console.log('[PinChat Verify] Fetching hash list from GitHub...');
        const signedData = await fetchHashList();

        if (!signedData.data || !signedData.signature) {
            result.errors.push('Invalid hash list format: missing data or signature');
            return result;
        }

        // Step 2: Verify the signature
        console.log('[PinChat Verify] Verifying signature...');
        const publicKey = await importPublicKey(CONFIG.PUBLIC_KEY);
        const dataString = JSON.stringify(signedData.data);
        const isSignatureValid = await verifySignature(dataString, signedData.signature, publicKey);

        if (!isSignatureValid) {
            result.errors.push('SIGNATURE VERIFICATION FAILED - Hash list may be tampered!');
            return result;
        }

        result.signatureValid = true;
        console.log('[PinChat Verify] Signature verified successfully');

        // Step 3: Verify each file's hash
        const hashList = signedData.data.files;
        console.log(`[PinChat Verify] Checking ${hashList.length} files...`);

        for (const fileEntry of hashList) {
            result.details.filesChecked++;

            const fetchResult = await fetchAndHashFile(fileEntry.path);

            if (fetchResult.error) {
                result.details.filesFailed++;
                result.mismatches.push({
                    path: fileEntry.path,
                    expected: fileEntry.hash,
                    actual: null,
                    error: fetchResult.error
                });
                continue;
            }

            if (fetchResult.hash !== fileEntry.hash) {
                result.details.filesFailed++;
                result.mismatches.push({
                    path: fileEntry.path,
                    expected: fileEntry.hash,
                    actual: fetchResult.hash,
                    error: 'Hash mismatch'
                });
            } else {
                result.details.filesMatched++;
            }
        }

        // Final verdict
        result.verified = result.mismatches.length === 0;

        if (!result.verified) {
            result.errors.push(`${result.mismatches.length} file(s) failed verification`);
        }

        console.log(`[PinChat Verify] Verification complete: ${result.verified ? 'PASSED' : 'FAILED'}`);

    } catch (error) {
        result.errors.push(`Verification error: ${error.message}`);
        console.error('[PinChat Verify] Error:', error);
    }

    return result;
}

// Export for use in extension
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { verifyIntegrity, CONFIG };
}
