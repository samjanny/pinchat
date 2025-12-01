/**
 * PinChat Integrity Verifier - Firefox Background Script
 */

// Configuration
const CONFIG = {
    HASH_LIST_URL: 'https://raw.githubusercontent.com/samjanny/pinchat/main/hashes.json.signed',
    SITE_URL: 'https://pinchat.io',
    // IMPORTANT: Replace with your actual ECDSA P-256 public key
    PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExkuEOYHEQQfDqsyO+uamOnf5b/AH
OqRJNIZ5zBHCr2HbJsHCtrPQUOKd4cBqfDZlQZ62rzF7ofA39ITBUyLxaA==
-----END PUBLIC KEY-----`,
    CHECK_INTERVAL_MINUTES: 5
};

// State management
let verificationState = {
    status: 'unknown',
    lastCheck: null,
    errors: [],
    mismatches: [],
    details: null
};

/**
 * Import the public key for signature verification
 */
async function importPublicKey(pemKey) {
    const pemContents = pemKey
        .replace('-----BEGIN PUBLIC KEY-----', '')
        .replace('-----END PUBLIC KEY-----', '')
        .replace(/\s/g, '');

    const binaryKey = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

    return await crypto.subtle.importKey(
        'spki',
        binaryKey,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
    );
}

/**
 * Verify signature using ECDSA
 */
async function verifySignature(data, signature, publicKey) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const signatureBuffer = Uint8Array.from(atob(signature), c => c.charCodeAt(0));

    return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        signatureBuffer,
        dataBuffer
    );
}

/**
 * Calculate SHA-256 hash
 */
async function calculateHash(content) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Fetch and verify a single file
 */
async function fetchAndHashFile(path) {
    const url = `${CONFIG.SITE_URL}${path}`;
    try {
        const response = await fetch(url, { cache: 'no-store' });
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
 */
async function verifyIntegrity() {
    console.log('[PinChat Verify] Starting verification...');

    verificationState = {
        status: 'checking',
        lastCheck: new Date().toISOString(),
        errors: [],
        mismatches: [],
        details: { filesChecked: 0, filesMatched: 0, filesFailed: 0 }
    };

    updateBadge('checking');
    await notifyContentScripts();

    try {
        // Fetch hash list from GitHub
        const response = await fetch(CONFIG.HASH_LIST_URL, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Failed to fetch hash list: ${response.status}`);
        }

        const signedData = await response.json();

        if (!signedData.data || !signedData.signature) {
            throw new Error('Invalid hash list format');
        }

        // Verify signature
        const publicKey = await importPublicKey(CONFIG.PUBLIC_KEY);
        const dataString = JSON.stringify(signedData.data);
        const isSignatureValid = await verifySignature(dataString, signedData.signature, publicKey);

        if (!isSignatureValid) {
            verificationState.status = 'failed';
            verificationState.errors.push('SIGNATURE VERIFICATION FAILED');
            updateBadge('failed');
            await notifyContentScripts();
            return verificationState;
        }

        // Verify each file
        const hashList = signedData.data.files;

        for (const fileEntry of hashList) {
            verificationState.details.filesChecked++;

            const result = await fetchAndHashFile(fileEntry.path);

            if (result.error) {
                verificationState.details.filesFailed++;
                verificationState.mismatches.push({
                    path: fileEntry.path,
                    expected: fileEntry.hash,
                    actual: null,
                    error: result.error
                });
                continue;
            }

            if (result.hash !== fileEntry.hash) {
                verificationState.details.filesFailed++;
                verificationState.mismatches.push({
                    path: fileEntry.path,
                    expected: fileEntry.hash,
                    actual: result.hash,
                    error: 'Hash mismatch'
                });
            } else {
                verificationState.details.filesMatched++;
            }
        }

        // Update final status
        if (verificationState.mismatches.length > 0) {
            verificationState.status = 'failed';
            verificationState.errors.push(`${verificationState.mismatches.length} file(s) failed verification`);
        } else {
            verificationState.status = 'verified';
        }

    } catch (error) {
        verificationState.status = 'error';
        verificationState.errors.push(error.message);
        console.error('[PinChat Verify] Error:', error);
    }

    updateBadge(verificationState.status);
    await notifyContentScripts();
    await browser.storage.local.set({ verificationState });

    console.log('[PinChat Verify] Verification complete:', verificationState.status);
    return verificationState;
}

/**
 * Update the extension badge based on status
 */
function updateBadge(status) {
    const badges = {
        verified: { text: '✓', color: '#22c55e' },
        failed: { text: '!', color: '#ef4444' },
        error: { text: '?', color: '#f59e0b' },
        checking: { text: '...', color: '#3b82f6' },
        unknown: { text: '', color: '#6b7280' }
    };

    const badge = badges[status] || badges.unknown;

    browser.browserAction.setBadgeText({ text: badge.text });
    browser.browserAction.setBadgeBackgroundColor({ color: badge.color });
}

/**
 * Notify all pinchat.io tabs of the current verification status
 */
async function notifyContentScripts() {
    try {
        const tabs = await browser.tabs.query({ url: 'https://pinchat.io/*' });
        for (const tab of tabs) {
            browser.tabs.sendMessage(tab.id, {
                type: 'VERIFICATION_STATUS',
                state: verificationState
            }).catch(() => {
                // Tab might not have content script loaded yet
            });
        }
    } catch (error) {
        console.error('[PinChat Verify] Error notifying tabs:', error);
    }
}

// Message handler
browser.runtime.onMessage.addListener((message, sender) => {
    if (message.type === 'GET_STATUS') {
        return Promise.resolve(verificationState);
    }

    if (message.type === 'VERIFY_NOW') {
        return verifyIntegrity();
    }
});

// Run verification when extension is installed or updated
browser.runtime.onInstalled.addListener(() => {
    console.log('[PinChat Verify] Extension installed/updated');
    verifyIntegrity();

    // Set up periodic verification
    browser.alarms.create('verify-integrity', {
        periodInMinutes: CONFIG.CHECK_INTERVAL_MINUTES
    });
});

// Run verification on alarm
browser.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'verify-integrity') {
        verifyIntegrity();
    }
});

// Run verification when background script starts
verifyIntegrity();
