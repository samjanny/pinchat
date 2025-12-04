/**
 * PinChat Integrity Verifier - Firefox Background Script
 *
 * Security model with SRI:
 * 1. Fetch signed manifest from GitHub (hashes.json.signed)
 * 2. Verify ECDSA signature with embedded public key
 * 3. Send manifest to content scripts
 * 4. Content scripts verify SRI attributes in actual DOM match manifest
 * 5. Browser enforces SRI (blocks tampered files)
 */

// =============================================================================
// OFFICIAL PINCHAT.IO HARDCODED SECURITY CONFIGURATION
// =============================================================================
//
// SECURITY NOTE: These values are intentionally hardcoded in the extension code.
// This is a critical security feature, NOT a configuration option.
//
// WHY HARDCODING IS SECURE:
// 1. The extension code is distributed through browser extension stores (Chrome/Firefox)
// 2. Users can verify the extension code matches the open-source repository
// 3. An attacker who compromises only the server CANNOT change these values
// 4. The public key can only be changed by releasing a new extension version
// 5. This creates a "trust anchor" that is independent of the pinchat.io server
//
// FOR SELF-HOSTED INSTANCES:
// If you are running your own PinChat instance, you MUST:
// 1. Generate your own ECDSA P-256 key pair (see README.md)
// 2. Replace PINCHAT_PUBLIC_KEY with your public key
// 3. Replace OFFICIAL_DOMAIN with your domain
// 4. Build and distribute your own extension
//
// =============================================================================

// Official PinChat.io public key - DO NOT MODIFY for official pinchat.io usage
const PINCHAT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExkuEOYHEQQfDqsyO+uamOnf5b/AH
OqRJNIZ5zBHCr2HbJsHCtrPQUOKd4cBqfDZlQZ62rzF7ofA39ITBUyLxaA==
-----END PUBLIC KEY-----`;

// Official domain - DO NOT MODIFY for official pinchat.io usage
const OFFICIAL_DOMAIN = 'pinchat.io';

// Official GitHub repository for manifest - DO NOT MODIFY for official pinchat.io usage
const GITHUB_REPO = 'samjanny/pinchat';
const GITHUB_BRANCH = 'main';

// Configuration
const CONFIG = {
    HASH_LIST_URL: `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_BRANCH}/hashes.json.signed`,
    SITE_URL: `https://${OFFICIAL_DOMAIN}`,
    PUBLIC_KEY: PINCHAT_PUBLIC_KEY,
    CHECK_INTERVAL_MINUTES: 5,
    FETCH_TIMEOUT_MS: 10000
};

// State management
let verificationState = {
    status: 'unknown', // 'verified', 'failed', 'error', 'checking', 'unknown'
    signatureStatus: 'unknown', // 'valid', 'invalid', 'checking', 'error', 'unknown'
    fileStatus: 'pending', // 'verified', 'failed', 'checking', 'pending', 'error'
    lastCheck: null,
    errors: [],
    manifest: null,  // Store manifest for content scripts
    debug: {
        manifestReceived: false,
        signatureCheckCompleted: false,
        fileHashCheckRequested: false,
        fileHashCheckCompleted: false,
        lastError: null
    }
};

let fileVerificationTimeout = null;

/**
 * Calculate overall verification status from signature and file statuses
 */
function calculateOverallStatus() {
    const { signatureStatus, fileStatus } = verificationState;

    // If either is checking, overall is checking
    if (signatureStatus === 'checking' || fileStatus === 'checking') {
        return 'checking';
    }

    // If signature failed, overall fails (critical)
    if (signatureStatus === 'invalid') {
        return 'failed';
    }

    // If signature errored, overall is error
    if (signatureStatus === 'error') {
        return 'error';
    }

    // If files failed, overall fails
    if (fileStatus === 'failed') {
        return 'failed';
    }

    // If files errored, overall is error
    if (fileStatus === 'error') {
        return 'error';
    }

    // If signature is valid but files still pending, checking
    if (signatureStatus === 'valid' && fileStatus === 'pending') {
        return 'checking';
    }

    // Both valid = verified
    if (signatureStatus === 'valid' && fileStatus === 'verified') {
        return 'verified';
    }

    // Default to unknown
    return 'unknown';
}

/**
 * Update overall status and notify all components
 */
async function updateOverallStatus() {
    verificationState.status = calculateOverallStatus();
    await updateAllTabsBadges();
    await notifyContentScripts();
    await browser.storage.local.set({ verificationState });
}

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
 * Check if there are any pinchat.io tabs open
 */
async function hasPinChatTabOpen() {
    try {
        const tabs = await browser.tabs.query({ url: [`https://${OFFICIAL_DOMAIN}/*`, `https://www.${OFFICIAL_DOMAIN}/*`] });
        return tabs.length > 0;
    } catch {
        return false;
    }
}

/**
 * Main verification function
 * Fetches signed manifest and verifies signature
 * File verification is only done when on pinchat.io (by content scripts)
 */
async function verifyIntegrity() {
    console.log('[PinChat Verify] Starting verification...');

    // Clear any existing timeout
    if (fileVerificationTimeout) {
        clearTimeout(fileVerificationTimeout);
        fileVerificationTimeout = null;
    }

    // Check if we're on pinchat.io
    const onPinChat = await hasPinChatTabOpen();

    // Reset state
    verificationState.signatureStatus = 'checking';
    verificationState.fileStatus = onPinChat ? 'pending' : 'verified'; // Skip file check if not on site
    verificationState.lastCheck = new Date().toISOString();
    verificationState.errors = [];
    verificationState.manifest = null;
    verificationState.fileVerification = undefined;
    verificationState.debug = {
        manifestReceived: false,
        signatureCheckCompleted: false,
        fileHashCheckRequested: false,
        fileHashCheckCompleted: !onPinChat, // Already "done" if not on site
        lastError: null,
        onPinChat: onPinChat
    };

    await updateOverallStatus();

    try {
        // Fetch signed manifest from GitHub
        console.log('[PinChat Verify] Fetching manifest from GitHub...');
        const response = await fetchWithTimeout(CONFIG.HASH_LIST_URL, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Failed to fetch hash list: ${response.status}`);
        }

        const signedData = await response.json();

        if (!signedData.data || !signedData.signature) {
            throw new Error('Invalid hash list format');
        }

        verificationState.debug.manifestReceived = true;

        // Verify signature
        console.log('[PinChat Verify] Verifying signature...');
        const publicKey = await importPublicKey(CONFIG.PUBLIC_KEY);
        const dataString = JSON.stringify(signedData.data);
        const isSignatureValid = await verifySignature(dataString, signedData.signature, publicKey);

        verificationState.debug.signatureCheckCompleted = true;

        if (!isSignatureValid) {
            verificationState.signatureStatus = 'invalid';
            verificationState.errors.push('SIGNATURE VERIFICATION FAILED - Manifest may be tampered');
            verificationState.debug.lastError = 'Signature invalid';
            await updateOverallStatus();
            return verificationState;
        }

        // Signature valid - now check sequence number for anti-downgrade
        const manifestSequence = signedData.data.sequence || 0;
        const stored = await browser.storage.local.get('lastKnownSequence');
        const lastKnownSequence = stored.lastKnownSequence || 0;

        console.log(`[PinChat Verify] Manifest sequence: ${manifestSequence}, Last known: ${lastKnownSequence}`);

        if (manifestSequence < lastKnownSequence) {
            // Possible downgrade attack!
            verificationState.signatureStatus = 'invalid';
            verificationState.errors.push(`DOWNGRADE ATTACK DETECTED - Manifest sequence (${manifestSequence}) < stored sequence (${lastKnownSequence})`);
            verificationState.debug.lastError = 'Manifest downgrade detected';
            console.error(`[PinChat Verify] ✗ DOWNGRADE ATTACK: manifest sequence ${manifestSequence} < stored ${lastKnownSequence}`);
            await updateOverallStatus();
            return verificationState;
        }

        // Update stored sequence if new is higher
        if (manifestSequence > lastKnownSequence) {
            await browser.storage.local.set({ lastKnownSequence: manifestSequence });
            console.log(`[PinChat Verify] Updated stored sequence to ${manifestSequence}`);
        }

        // Store manifest for content scripts
        verificationState.manifest = signedData.data;
        verificationState.signatureStatus = 'valid';

        console.log('[PinChat Verify] ✓ Manifest signature and sequence verified successfully');
        console.log(`[PinChat Verify] Manifest contains ${signedData.data.files.length} files (sequence: ${manifestSequence})`);

        // Only request file verification if on pinchat.io
        if (onPinChat) {
            verificationState.fileStatus = 'checking';
            console.log('[PinChat Verify] On pinchat.io - requesting SRI verification from content scripts...');
            verificationState.debug.fileHashCheckRequested = true;

            // Notify content scripts to start file verification
            await updateOverallStatus();

            // Set timeout for file verification (15 seconds)
            fileVerificationTimeout = setTimeout(() => {
                if (verificationState.fileStatus === 'checking' || verificationState.fileStatus === 'pending') {
                    console.error('[PinChat Verify] File verification timeout - no response from content script');
                    verificationState.fileStatus = 'error';
                    verificationState.errors.push('File verification timeout - content script did not respond');
                    verificationState.debug.lastError = 'File verification timeout';
                    updateOverallStatus();
                }
            }, 15000);
        } else {
            // Not on pinchat.io - signature check is sufficient
            verificationState.fileStatus = 'verified';
            console.log('[PinChat Verify] Not on pinchat.io - signature verification only (SRI check skipped)');
            await updateOverallStatus();
        }

    } catch (error) {
        verificationState.signatureStatus = 'error';
        verificationState.fileStatus = 'error';
        const errorMsg = error.name === 'AbortError' ? 'Request timeout' : error.message;
        verificationState.errors.push(errorMsg);
        verificationState.debug.lastError = errorMsg;
        console.error('[PinChat Verify] Error:', error);
        await updateOverallStatus();
    }

    console.log('[PinChat Verify] Signature verification complete:', verificationState.signatureStatus);
    console.log('[PinChat Verify] File verification status:', verificationState.fileStatus);
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
        return parsed.hostname === OFFICIAL_DOMAIN || parsed.hostname === `www.${OFFICIAL_DOMAIN}`;
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
        const tabs = await browser.tabs.query({ url: [`https://${OFFICIAL_DOMAIN}/*`, `https://www.${OFFICIAL_DOMAIN}/*`] });
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

    // Handle complete file hash verification results from content script
    if (message.type === 'FILE_HASH_VERIFICATION_COMPLETE') {
        console.log('[PinChat Verify] Content script reported file verification complete:', message.summary);

        // Clear timeout since we got a response
        if (fileVerificationTimeout) {
            clearTimeout(fileVerificationTimeout);
            fileVerificationTimeout = null;
        }

        // Store file verification results
        verificationState.fileVerification = {
            files: message.files,
            summary: message.summary,
            timestamp: new Date().toISOString()
        };

        verificationState.debug.fileHashCheckCompleted = true;

        if (!message.success) {
            verificationState.fileStatus = 'failed';
            verificationState.errors = message.issues.map(i => `${i.path}: ${i.error}`);
            verificationState.mismatches = message.issues;
            console.error('[PinChat Verify] ✗ File verification FAILED');
            console.error('[PinChat Verify] Failed files:', message.issues.map(i => i.path).join(', '));
        } else {
            verificationState.fileStatus = 'verified';
            console.log('[PinChat Verify] ✓ All file hashes verified successfully');
        }

        updateOverallStatus();

        // Broadcast status update to popup (if open)
        browser.runtime.sendMessage({
            type: 'VERIFICATION_STATUS',
            state: verificationState
        }).catch(() => {
            // Popup might not be open
        });

        sendResponse({ received: true });
        return true;
    }

    // Handle file hash verification failure from content script (legacy support)
    if (message.type === 'FILE_HASH_VERIFICATION_FAILED') {
        console.error('[PinChat Verify] Content script reported hash verification failure:', message.issues);

        // Clear timeout since we got a response
        if (fileVerificationTimeout) {
            clearTimeout(fileVerificationTimeout);
            fileVerificationTimeout = null;
        }

        verificationState.fileStatus = 'failed';
        verificationState.errors = message.issues.map(i => `${i.path}: ${i.error}`);
        verificationState.mismatches = message.issues;
        verificationState.debug.fileHashCheckCompleted = true;

        updateOverallStatus();
        sendResponse({ received: true });
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
