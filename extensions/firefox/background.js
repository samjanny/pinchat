/**
 * PinChat Integrity Verifier - Chrome Background Service Worker
 *
 * Security model with SRI:
 * 1. Fetch signed manifest from GitHub (hashes.json.signed)
 * 2. Verify ECDSA signature with embedded public key
 * 3. Send manifest to content scripts
 * 4. Content scripts verify SRI attributes in actual DOM match manifest
 * 5. Browser enforces SRI (blocks tampered files)
 */

// Configuration
const CONFIG = {
    HASH_LIST_URL: 'https://raw.githubusercontent.com/pinchat-io/pinchat/main/hashes.json.signed',
    SITE_URL: 'https://pinchat.io',
    // IMPORTANT: Replace with your actual ECDSA P-256 public key
    PUBLIC_KEY: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExkuEOYHEQQfDqsyO+uamOnf5b/AH
OqRJNIZ5zBHCr2HbJsHCtrPQUOKd4cBqfDZlQZ62rzF7ofA39ITBUyLxaA==
-----END PUBLIC KEY-----`,
    CHECK_INTERVAL_MINUTES: 5,
    FETCH_TIMEOUT_MS: 10000
};

// State management
let verificationState = {
    status: 'unknown', // 'verified', 'failed', 'error', 'checking', 'unknown'
    lastCheck: null,
    errors: [],
    manifest: null  // Store manifest for content scripts
};

/**
 * Fetch with timeout support
 */
async function fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT_MS);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        return response;
    } finally {
        clearTimeout(timeout);
    }
}

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
 * Convert DER-encoded ECDSA signature to IEEE P1363 format
 */
function derToP1363(derSignature) {
    const der = new Uint8Array(derSignature);

    let offset = 2;

    if (der[offset] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER tag for r');
    offset++;
    let rLength = der[offset++];
    while (der[offset] === 0x00 && rLength > 32) {
        offset++;
        rLength--;
    }
    const r = der.slice(offset, offset + Math.min(rLength, 32));
    offset += rLength;

    if (der[offset] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER tag for s');
    offset++;
    let sLength = der[offset++];
    while (der[offset] === 0x00 && sLength > 32) {
        offset++;
        sLength--;
    }
    const s = der.slice(offset, offset + Math.min(sLength, 32));

    const rPadded = new Uint8Array(32);
    const sPadded = new Uint8Array(32);
    rPadded.set(r, 32 - r.length);
    sPadded.set(s, 32 - s.length);

    const p1363 = new Uint8Array(64);
    p1363.set(rPadded, 0);
    p1363.set(sPadded, 32);

    return p1363;
}

/**
 * Verify signature using ECDSA
 */
async function verifySignature(data, signatureBase64, publicKey) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const derSignature = Uint8Array.from(atob(signatureBase64), c => c.charCodeAt(0));

    const p1363Signature = derToP1363(derSignature);

    return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        p1363Signature,
        dataBuffer
    );
}

/**
 * Main verification function
 * Fetches signed manifest and verifies signature
 * Actual file verification is done by content scripts via SRI
 */
async function verifyIntegrity() {
    console.log('[PinChat Verify] Starting verification...');

    verificationState = {
        status: 'checking',
        lastCheck: new Date().toISOString(),
        errors: [],
        manifest: null
    };

    await updateAllTabsBadges();
    await notifyContentScripts();

    try {
        // Fetch signed manifest from GitHub
        const response = await fetchWithTimeout(CONFIG.HASH_LIST_URL, { cache: 'no-store' });
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
            verificationState.errors.push('SIGNATURE VERIFICATION FAILED - Manifest may be tampered');
            await updateAllTabsBadges();
            await notifyContentScripts();
            return verificationState;
        }

        // Signature valid - store manifest for content scripts
        verificationState.manifest = signedData.data;
        verificationState.status = 'verified';

        console.log('[PinChat Verify] Manifest signature verified successfully');
        console.log(`[PinChat Verify] Manifest contains ${signedData.data.files.length} files`);

    } catch (error) {
        verificationState.status = 'error';
        const errorMsg = error.name === 'AbortError' ? 'Request timeout' : error.message;
        verificationState.errors.push(errorMsg);
        console.error('[PinChat Verify] Error:', error);
    }

    await updateAllTabsBadges();
    await notifyContentScripts();
    await browser.storage.local.set({ verificationState });

    console.log('[PinChat Verify] Verification complete:', verificationState.status);
    return verificationState;
}

/**
 * Badge configurations
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
 * Update badge for a specific tab
 */
async function updateBadgeForTab(tabId) {
    try {
        const tab = await browser.tabs.get(tabId);
        if (isPinChatUrl(tab.url)) {
            const badge = BADGES[verificationState.status] || BADGES.unknown;
            browser.action.setBadgeText({ text: badge.text, tabId });
            browser.action.setBadgeBackgroundColor({ color: badge.color, tabId });
        } else {
            browser.action.setBadgeText({ text: '', tabId });
            browser.action.setBadgeBackgroundColor({ color: BADGES.inactive.color, tabId });
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
        const tabs = await browser.tabs.query({});
        for (const tab of tabs) {
            await updateBadgeForTab(tab.id);
        }
    } catch {
        // Ignore errors
    }
}

/**
 * Notify all pinchat.io tabs of verification status and manifest
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
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_STATUS') {
        // Return full state including manifest
        sendResponse(verificationState);
        return true;
    }

    if (message.type === 'VERIFY_NOW') {
        verifyIntegrity().then(sendResponse);
        return true;
    }
});

// Run verification when extension is installed/updated
browser.runtime.onInstalled.addListener(() => {
    console.log('[PinChat Verify] Extension installed/updated');
    verifyIntegrity();

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

// Listen for tab activation
browser.tabs.onActivated.addListener((activeInfo) => {
    updateBadgeForTab(activeInfo.tabId);
});

// Listen for tab URL changes
browser.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url || changeInfo.status === 'complete') {
        updateBadgeForTab(tabId);
    }
});

// Run verification when service worker starts
verifyIntegrity();
