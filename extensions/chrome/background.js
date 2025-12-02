/**
 * PinChat Integrity Verifier - Chrome Background Service Worker
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
    status: 'unknown', // 'verified', 'failed', 'error', 'checking', 'unknown'
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
 * Convert DER-encoded ECDSA signature to IEEE P1363 format (raw r||s)
 * OpenSSL and Node.js produce DER format, but WebCrypto expects P1363
 * DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
 * P1363 format for P-256: 32 bytes r || 32 bytes s (64 bytes total)
 */
function derToP1363(derSignature) {
    const der = new Uint8Array(derSignature);

    // Skip SEQUENCE tag (0x30) and length byte
    let offset = 2;

    // Read r INTEGER
    if (der[offset] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER tag for r');
    offset++;
    let rLength = der[offset++];
    // Skip leading zero padding (used for positive integers in DER)
    while (der[offset] === 0x00 && rLength > 32) {
        offset++;
        rLength--;
    }
    const r = der.slice(offset, offset + Math.min(rLength, 32));
    offset += rLength;

    // Read s INTEGER
    if (der[offset] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER tag for s');
    offset++;
    let sLength = der[offset++];
    // Skip leading zero padding
    while (der[offset] === 0x00 && sLength > 32) {
        offset++;
        sLength--;
    }
    const s = der.slice(offset, offset + Math.min(sLength, 32));

    // Pad r and s to 32 bytes each (P-256 curve order)
    const rPadded = new Uint8Array(32);
    const sPadded = new Uint8Array(32);
    rPadded.set(r, 32 - r.length);
    sPadded.set(s, 32 - s.length);

    // Concatenate r || s
    const p1363 = new Uint8Array(64);
    p1363.set(rPadded, 0);
    p1363.set(sPadded, 32);

    return p1363;
}

/**
 * Verify signature using ECDSA
 * Handles DER-encoded signatures from OpenSSL/Node.js
 */
async function verifySignature(data, signatureBase64, publicKey) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const derSignature = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

    // Convert DER to P1363 format for WebCrypto
    const p1363Signature = derToP1363(derSignature);

    return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        p1363Signature,
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

    await updateAllTabsBadges();
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
            await updateAllTabsBadges();
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

    await updateAllTabsBadges();
    await notifyContentScripts();
    await chrome.storage.local.set({ verificationState });

    console.log('[PinChat Verify] Verification complete:', verificationState.status);
    return verificationState;
}

/**
 * Badge configurations for different states
 */
const BADGES = {
    verified: { text: '✓', color: '#22c55e' },
    failed: { text: '!', color: '#ef4444' },
    error: { text: '?', color: '#f59e0b' },
    checking: { text: '...', color: '#3b82f6' },
    unknown: { text: '', color: '#6b7280' },
    inactive: { text: '', color: '#6b7280' }
};

/**
 * Check if a URL is pinchat.io
 */
function isPinChatUrl(url) {
    if (!url) return false;
    try {
        const parsed = new URL(url);
        return parsed.hostname === 'pinchat.io' || parsed.hostname === 'www.pinchat.io';
    } catch {
        return false;
    }
}

/**
 * Update the extension badge based on status
 */
function updateBadge(status) {
    const badge = BADGES[status] || BADGES.unknown;
    chrome.action.setBadgeText({ text: badge.text });
    chrome.action.setBadgeBackgroundColor({ color: badge.color });
}

/**
 * Update badge for a specific tab based on its URL
 */
async function updateBadgeForTab(tabId) {
    try {
        const tab = await chrome.tabs.get(tabId);
        if (isPinChatUrl(tab.url)) {
            // On pinchat.io - show verification status
            const badge = BADGES[verificationState.status] || BADGES.unknown;
            chrome.action.setBadgeText({ text: badge.text, tabId });
            chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId });
        } else {
            // Not on pinchat.io - show inactive/empty badge
            chrome.action.setBadgeText({ text: '', tabId });
            chrome.action.setBadgeBackgroundColor({ color: BADGES.inactive.color, tabId });
        }
    } catch {
        // Tab might not exist anymore
    }
}

/**
 * Update badge for all tabs
 */
async function updateAllTabsBadges() {
    try {
        const tabs = await chrome.tabs.query({});
        for (const tab of tabs) {
            await updateBadgeForTab(tab.id);
        }
    } catch {
        // Ignore errors
    }
}

/**
 * Notify all pinchat.io tabs of the current verification status
 */
async function notifyContentScripts() {
    try {
        const tabs = await chrome.tabs.query({ url: 'https://pinchat.io/*' });
        for (const tab of tabs) {
            chrome.tabs.sendMessage(tab.id, {
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
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_STATUS') {
        sendResponse(verificationState);
        return true;
    }

    if (message.type === 'VERIFY_NOW') {
        verifyIntegrity().then(sendResponse);
        return true;
    }
});

// Run verification when extension is installed or updated
chrome.runtime.onInstalled.addListener(() => {
    console.log('[PinChat Verify] Extension installed/updated');
    verifyIntegrity();

    // Set up periodic verification
    chrome.alarms.create('verify-integrity', {
        periodInMinutes: CONFIG.CHECK_INTERVAL_MINUTES
    });
});

// Run verification on alarm
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'verify-integrity') {
        verifyIntegrity();
    }
});

// Listen for tab activation changes
chrome.tabs.onActivated.addListener((activeInfo) => {
    updateBadgeForTab(activeInfo.tabId);
});

// Listen for tab URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url || changeInfo.status === 'complete') {
        updateBadgeForTab(tabId);
    }
});

// Run verification when service worker starts
verifyIntegrity();
