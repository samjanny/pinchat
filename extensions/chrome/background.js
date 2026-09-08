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
// F-15: pin the manifest URL to a release tag, not a mutable branch.
// Rationale: an attacker with GitHub-write access (account takeover, malicious
// PR merge, stolen PAT) could otherwise push a freshly-signed-with-stolen-key
// manifest to `main` and have every installed extension fetch it on the next
// refresh. Pinning to a tag moves the trust anchor onto a string that cannot
// be silently rewritten - a tag rebase shows up in `git log --tags --graph`
// and the manifest is immutable at the GitHub raw URL once the tag is pushed.
// Lifecycle: this constant MUST be bumped to the new tag on every extension
// release. A server-side release that does NOT ship a new extension keeps
// using the previous pinned manifest - that is the intended behaviour and
// reinforces the trust anchor.
const GITHUB_TAG = 'v0.8.1';

// Minimum acceptable manifest sequence: a hardcoded floor that defeats replay
// attacks against fresh installs, where lastKnownSequence in storage is 0.
// A manifest whose sequence is below this constant is rejected even on a
// first install.
//
// COUPLING, read before changing either constant. This floor is checked
// against the manifest fetched from GITHUB_TAG above, NOT against the
// working tree. Setting the floor higher than the sequence of the manifest
// at that tag makes this build reject every manifest it can fetch, which
// disables verification for everyone running it. The two constants must
// therefore move together: a build carrying floor N must point at a tag
// whose hashes.json.signed is at sequence N or higher.
//
// tests/test-security.js pins the floor to the sequence in the working-tree
// manifest, so a server-side re-sign bumps this number. That is safe for
// already-installed builds (they carry their own baked-in floor and tag) but
// it means the NEXT extension release must cut a tag containing the current
// manifest and update GITHUB_TAG in the same commit.
const MIN_KNOWN_SEQUENCE = 48;

// Configuration
const CONFIG = {
    HASH_LIST_URL: `https://raw.githubusercontent.com/${GITHUB_REPO}/${GITHUB_TAG}/hashes.json.signed`,
    SITE_URL: `https://${OFFICIAL_DOMAIN}`,
    PUBLIC_KEY: PINCHAT_PUBLIC_KEY,
    CHECK_INTERVAL_MINUTES: 5,
    FETCH_TIMEOUT_MS: 10000
};

// Storage key holding the last signed manifest that passed verification.
// See cacheSignedManifest for why an offline copy is a security control
// and not just a convenience.
const MANIFEST_CACHE_KEY = 'cachedSignedManifest';

// Smallest gap between two live manifest fetches driven by anything other
// than an explicit user action. Bounds how often a busy tab re-contacts
// the manifest host.
const MIN_LIVE_FETCH_INTERVAL_MS = 60 * 1000;

// State management
let verificationState = {
    status: 'unknown', // 'verified', 'failed', 'error', 'checking', 'unknown'
    signatureStatus: 'unknown', // 'valid', 'invalid', 'checking', 'error', 'unknown'
    fileStatus: 'pending', // 'verified', 'failed', 'checking', 'pending', 'error'
    lastCheck: null,
    errors: [],
    manifest: null,  // Store manifest for content scripts
    usingCachedManifest: false,  // True when the live fetch failed and the stored copy is in use
    manifestCachedAt: null,      // When that stored copy was written (ms epoch)
    debug: {
        manifestReceived: false,
        signatureCheckCompleted: false,
        fileHashCheckRequested: false,
        fileHashCheckCompleted: false,
        lastError: null
    }
};

let fileVerificationTimeout = null;
let lastLiveFetchAt = 0;

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
    await chrome.storage.local.set({ verificationState });
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
        const tabs = await chrome.tabs.query({ url: [`https://${OFFICIAL_DOMAIN}/*`, `https://www.${OFFICIAL_DOMAIN}/*`] });
        return tabs.length > 0;
    } catch {
        return false;
    }
}

/**
 * Validate a signed manifest document against the two gates that matter:
 * the ECDSA signature under the pinned trust anchor, then the monotonic
 * sequence floor.
 *
 * Returns { ok: true, data, sequence, lastKnownSequence } or
 * { ok: false, kind, reason }, where `kind` is 'invalid' for a bad signature
 * or a downgrade (both are attack signals) and 'error' for a malformed
 * document.
 */
async function validateSignedManifest(signedData) {
    if (!signedData || !signedData.data || !signedData.signature) {
        return { ok: false, kind: 'error', reason: 'Invalid hash list format' };
    }

    const publicKey = await importPublicKey(CONFIG.PUBLIC_KEY);
    const dataString = JSON.stringify(signedData.data);
    const isSignatureValid = await verifySignature(dataString, signedData.signature, publicKey);
    if (!isSignatureValid) {
        return {
            ok: false,
            kind: 'invalid',
            reason: 'SIGNATURE VERIFICATION FAILED - Manifest may be tampered'
        };
    }

    const manifestSequence = signedData.data.sequence || 0;
    const stored = await chrome.storage.local.get('lastKnownSequence');
    const lastKnownSequence = stored.lastKnownSequence || 0;
    const minAcceptable = Math.max(lastKnownSequence, MIN_KNOWN_SEQUENCE);

    if (manifestSequence < minAcceptable) {
        const detail = manifestSequence < lastKnownSequence
            ? `manifest sequence (${manifestSequence}) < stored sequence (${lastKnownSequence})`
            : `manifest sequence (${manifestSequence}) < hardcoded floor (${MIN_KNOWN_SEQUENCE})`;
        return { ok: false, kind: 'invalid', reason: `DOWNGRADE ATTACK DETECTED - ${detail}` };
    }

    return { ok: true, data: signedData.data, sequence: manifestSequence, lastKnownSequence };
}

/**
 * Persist the last manifest that cleared both gates.
 *
 * Threat model: without a stored copy, anyone able to drop the connection to
 * the manifest host (a hostile network, a filtering proxy, a state-level
 * block, or simply a GitHub outage) turns the whole detection layer off just
 * by making the fetch fail. That is the cheapest possible attack against a
 * verifier and it leaves no trace on the page. The stored document is
 * re-validated on every read, so writing to extension storage buys an
 * attacker nothing that forging a signature would not already require.
 *
 * The packaged declarativeNetRequest CSP is unaffected either way: it ships
 * inside the extension and keeps blocking unpinned scripts even with no
 * manifest at all. What the cache preserves is the SRI/hash detection layer.
 */
async function cacheSignedManifest(signedData) {
    try {
        await chrome.storage.local.set({
            [MANIFEST_CACHE_KEY]: { signed: signedData, cachedAt: Date.now() }
        });
    } catch (error) {
        console.warn('[PinChat Verify] Could not cache manifest:', error);
    }
}

/**
 * Load the cached manifest and put it back through validateSignedManifest.
 * Returns null when absent or when it no longer passes, dropping the entry
 * in that case so a stale reject is not re-tested on every tick.
 */
async function loadCachedManifest() {
    let entry;
    try {
        const stored = await chrome.storage.local.get(MANIFEST_CACHE_KEY);
        entry = stored[MANIFEST_CACHE_KEY];
    } catch {
        return null;
    }
    if (!entry || !entry.signed) return null;

    let result;
    try {
        result = await validateSignedManifest(entry.signed);
    } catch (error) {
        result = { ok: false, kind: 'error', reason: error.message };
    }
    if (!result.ok) {
        console.error('[PinChat Verify] Cached manifest failed re-validation:', result.reason);
        try {
            await chrome.storage.local.remove(MANIFEST_CACHE_KEY);
        } catch {
            /* storage unavailable; nothing further to do */
        }
        return null;
    }
    return { data: result.data, cachedAt: entry.cachedAt || null };
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
    verificationState.usingCachedManifest = false;
    verificationState.manifestCachedAt = null;
    verificationState.debug = {
        manifestReceived: false,
        signatureCheckCompleted: false,
        fileHashCheckRequested: false,
        fileHashCheckCompleted: !onPinChat, // Already "done" if not on site
        lastError: null,
        onPinChat: onPinChat
    };

    await updateOverallStatus();

    // The fetch and the cryptographic gates are kept apart on purpose: a
    // transport failure is recoverable from the stored copy, a signature or
    // sequence failure never is.
    let signedData = null;
    let fetchError = null;

    try {
        console.log('[PinChat Verify] Fetching manifest from GitHub...');
        const response = await fetchWithTimeout(CONFIG.HASH_LIST_URL, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Failed to fetch hash list: ${response.status}`);
        }
        signedData = await response.json();
        verificationState.debug.manifestReceived = true;
    } catch (error) {
        fetchError = error.name === 'AbortError' ? 'Request timeout' : error.message;
        console.warn('[PinChat Verify] Manifest fetch failed:', fetchError);
    }

    if (signedData) {
        console.log('[PinChat Verify] Verifying signature...');
        let result;
        try {
            result = await validateSignedManifest(signedData);
        } catch (error) {
            result = { ok: false, kind: 'error', reason: error.message };
        }
        verificationState.debug.signatureCheckCompleted = true;

        if (!result.ok) {
            // A bad signature or a downgrade is an attack signal, never a
            // transport problem. Do NOT paper over it with the cached copy.
            verificationState.signatureStatus = result.kind === 'invalid' ? 'invalid' : 'error';
            verificationState.errors.push(result.reason);
            verificationState.debug.lastError = result.reason;
            console.error(`[PinChat Verify] REJECTED: ${result.reason}`);
            await updateOverallStatus();
            console.log('[PinChat Verify] Signature verification complete:', verificationState.signatureStatus);
            console.log('[PinChat Verify] File verification status:', verificationState.fileStatus);
            return verificationState;
        }

        if (result.sequence > result.lastKnownSequence) {
            await chrome.storage.local.set({ lastKnownSequence: result.sequence });
            console.log(`[PinChat Verify] Updated stored sequence to ${result.sequence}`);
        }
        await cacheSignedManifest(signedData);
        lastLiveFetchAt = Date.now();

        verificationState.manifest = result.data;
        verificationState.signatureStatus = 'valid';

        console.log('[PinChat Verify] Manifest signature and sequence verified successfully');
        console.log(`[PinChat Verify] Manifest contains ${result.data.files.length} files (sequence: ${result.sequence})`);
    } else {
        // Transport failure only. Fall back to the last manifest that cleared
        // both gates rather than leaving the page unverifiable, which is
        // precisely the outcome a network-level attacker is aiming for.
        const cached = await loadCachedManifest();
        verificationState.debug.signatureCheckCompleted = true;

        if (!cached) {
            verificationState.signatureStatus = 'error';
            verificationState.fileStatus = 'error';
            const message = `${fetchError} (no cached manifest available)`;
            verificationState.errors.push(message);
            verificationState.debug.lastError = message;
            await updateOverallStatus();
            console.log('[PinChat Verify] Signature verification complete:', verificationState.signatureStatus);
            console.log('[PinChat Verify] File verification status:', verificationState.fileStatus);
            return verificationState;
        }

        verificationState.manifest = cached.data;
        verificationState.signatureStatus = 'valid';
        verificationState.usingCachedManifest = true;
        verificationState.manifestCachedAt = cached.cachedAt;
        verificationState.debug.lastError = `Update host unreachable: ${fetchError}`;
        const cachedOn = cached.cachedAt ? new Date(cached.cachedAt).toISOString() : 'an unknown date';
        console.warn(`[PinChat Verify] Update host unreachable (${fetchError}); using manifest cached on ${cachedOn}`);
    }

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

    console.log('[PinChat Verify] Signature verification complete:', verificationState.signatureStatus);
    console.log('[PinChat Verify] File verification status:', verificationState.fileStatus);
    return verificationState;
}

/**
 * Verification triggered by something other than an explicit user action
 * (alarm tick, background start, navigation to pinchat.io).
 *
 * The gate exists because the previous behaviour was an unconditional fetch
 * every CHECK_INTERVAL_MINUTES for the lifetime of the profile, whether or
 * not a pinchat.io tab existed. That is a periodic beacon: it tells the host
 * serving the manifest, and every network observer between, that this
 * browser has the extension installed and roughly when it is running. For a
 * product whose whole point is not leaking metadata, an idle extension
 * should be silent.
 *
 * Two skip conditions, both safe:
 *   - no pinchat.io tab open and a usable cached manifest already stored:
 *     there is nothing to verify right now, and the navigation hook below
 *     refreshes before the user can trust a page.
 *   - a live fetch already succeeded within MIN_LIVE_FETCH_INTERVAL_MS:
 *     re-push the state so a freshly loaded content script gets the
 *     manifest, but do not re-contact the host.
 *
 * The popup's "Verify Now" and the install/update hook call verifyIntegrity
 * directly and bypass both gates.
 */
async function verifyIfRelevant(trigger) {
    const onPinChat = await hasPinChatTabOpen();

    if (!onPinChat) {
        const cached = await loadCachedManifest();
        if (cached) {
            console.log(`[PinChat Verify] ${trigger}: no pinchat.io tab open, keeping cached manifest`);
            return verificationState;
        }
        // Nothing usable stored yet. Fetch once so the first navigation to
        // pinchat.io is not left waiting on the network.
    } else if (
        verificationState.manifest
        && verificationState.signatureStatus === 'valid'
        && !verificationState.usingCachedManifest
        && Date.now() - lastLiveFetchAt < MIN_LIVE_FETCH_INTERVAL_MS
    ) {
        const ageSecs = Math.round((Date.now() - lastLiveFetchAt) / 1000);
        console.log(`[PinChat Verify] ${trigger}: live manifest is ${ageSecs}s old, reusing it`);
        await updateOverallStatus();
        return verificationState;
    }

    return verifyIntegrity();
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
        const tab = await chrome.tabs.get(tabId);
        if (isPinChatUrl(tab.url)) {
            const badge = BADGES[verificationState.status] || BADGES.unknown;
            chrome.action.setBadgeText({ text: badge.text, tabId });
            chrome.action.setBadgeBackgroundColor({ color: badge.color, tabId });
        } else {
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
 * Notify all pinchat.io tabs of verification status and manifest
 */
async function notifyContentScripts() {
    try {
        const tabs = await chrome.tabs.query({ url: [`https://${OFFICIAL_DOMAIN}/*`, `https://www.${OFFICIAL_DOMAIN}/*`] });
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

/**
 * Validate that a runtime message originates from a trusted sender.
 *
 * Two profiles:
 *  - 'popup': sender is the popup or another extension page (no sender.tab,
 *    no sender.url pointing to a web page). Only GET_STATUS / VERIFY_NOW.
 *  - 'content': sender is a content script running on a pinchat.io tab
 *    (sender.tab.url points to OFFICIAL_DOMAIN). Used for FILE_HASH_*.
 *
 * Without externally_connectable, web pages cannot reach onMessage at all -
 * but we still validate sender to harden against future regressions and to
 * reject content scripts that somehow run on the wrong origin.
 */
function isSenderTrusted(sender, profile) {
    if (sender.id && sender.id !== chrome.runtime.id) return false;

    const fromPinChatContentScript = () => {
        if (!sender.tab || !sender.tab.url) return false;
        try {
            const u = new URL(sender.tab.url);
            return u.hostname === OFFICIAL_DOMAIN || u.hostname === `www.${OFFICIAL_DOMAIN}`;
        } catch {
            return false;
        }
    };

    const fromExtensionPage = () => {
        if (sender.tab) return false;
        if (sender.url && !sender.url.startsWith('moz-extension://') && !sender.url.startsWith('chrome-extension://')) {
            return false;
        }
        return true;
    };

    if (profile === 'content') return fromPinChatContentScript();
    if (profile === 'popup') return fromExtensionPage();

    // 'status' is the read-only view of verificationState. Both the popup and
    // the content script legitimately need it: the content script pulls the
    // manifest on page load, because the background push
    // (notifyContentScripts) can land before the content script has
    // registered its listener. Under the previous 'popup' profile that pull
    // was always rejected - a content script always carries sender.tab - so
    // the page silently depended on winning that race.
    if (profile === 'status') return fromExtensionPage() || fromPinChatContentScript();

    return false;
}

// Message handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'GET_STATUS') {
        if (!isSenderTrusted(sender, 'status')) {
            console.warn('[PinChat Verify] Rejected GET_STATUS from untrusted sender');
            return false;
        }
        sendResponse(verificationState);
        return true;
    }

    if (message.type === 'VERIFY_NOW') {
        if (!isSenderTrusted(sender, 'popup')) {
            console.warn('[PinChat Verify] Rejected VERIFY_NOW from untrusted sender');
            return false;
        }
        verifyIntegrity().then(sendResponse);
        return true;
    }

    // Handle complete file hash verification results from content script
    if (message.type === 'FILE_HASH_VERIFICATION_COMPLETE') {
        if (!isSenderTrusted(sender, 'content')) {
            console.warn('[PinChat Verify] Rejected FILE_HASH_VERIFICATION_COMPLETE from untrusted sender:', sender);
            return false;
        }
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
        chrome.runtime.sendMessage({
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
        if (!isSenderTrusted(sender, 'content')) {
            console.warn('[PinChat Verify] Rejected FILE_HASH_VERIFICATION_FAILED from untrusted sender:', sender);
            return false;
        }
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

// Run verification when extension is installed/updated. Unconditional: this
// is what seeds the manifest cache on a fresh profile.
chrome.runtime.onInstalled.addListener(() => {
    console.log('[PinChat Verify] Extension installed/updated');
    verifyIntegrity();

    chrome.alarms.create('verify-integrity', {
        periodInMinutes: CONFIG.CHECK_INTERVAL_MINUTES
    });
});

// Run verification on alarm, gated so an idle browser stays off the network.
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'verify-integrity') {
        verifyIfRelevant('alarm tick');
    }
});

// Listen for tab activation
chrome.tabs.onActivated.addListener((activeInfo) => {
    updateBadgeForTab(activeInfo.tabId);
});

// Listen for tab URL changes
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url || changeInfo.status === 'complete') {
        updateBadgeForTab(tabId);
    }

    // A navigation to pinchat.io is the moment the manifest actually matters.
    // With the idle beacon gone this is what keeps it fresh for the page the
    // user is about to trust, and it bounds fetches to real navigations
    // instead of wall-clock time.
    if ((changeInfo.status === 'loading' || changeInfo.url) && isPinChatUrl(tab.url)) {
        verifyIfRelevant('pinchat.io navigation');
    }
});

// Run verification when the background context starts. Gated: an MV3
// service worker restarts often, and each restart used to mean another
// unconditional request to the manifest host.
verifyIfRelevant('background start');
