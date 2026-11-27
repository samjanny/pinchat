/**
 * PinChat Integrity Verifier - background script
 *
 * The same file runs as the service worker in Chromium and as the event page
 * in Firefox. What it does:
 *
 * 1. Fetches the signed release manifest (hashes.json.signed) from the main
 *    branch of the repository, verifies its ECDSA signature against the
 *    embedded key and refuses a sequence lower than the last one seen
 *    (anti-rollback). The script policy of every page is then built from that
 *    manifest and put in force in place of the packaged one, so a new release
 *    of the site needs a new signature, not a new extension.
 * 2. Keeps one state per tab and per document. A result obtained for one
 *    document is never shown for another.
 * 3. Where the browser lets an extension hold a response body (Firefox),
 *    compares the bytes of every document navigation on the site with the
 *    signed hash before the parser sees them, and replaces anything else
 *    with a block page. The data files a page fetches (operator.json) are
 *    held the same way and withheld unless they match.
 * 4. Refuses redirects that would take a document navigation off the site:
 *    an invite link carries its key in the URL fragment, and browsers carry
 *    the fragment across redirects.
 *
 * The script policy is a set of declarativeNetRequest rules, which the browser
 * applies whether or not this script is running: the packaged ones
 * (rules.json) until a manifest has been verified, the ones built from it
 * (csp-rules.js) afterwards. The meaning of every state is defined in
 * verdict.js.
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
// 5. This creates a "trust anchor" that is independent of the pinchat.im server
//
// FOR SELF-HOSTED INSTANCES:
// If you are running your own PinChat instance, you MUST:
// 1. Generate your own ECDSA P-256 key pair (see README.md)
// 2. Replace PINCHAT_PUBLIC_KEY with your public key
// 3. Replace OFFICIAL_DOMAIN with your domain
// 4. Build and distribute your own extension
//
// =============================================================================

// Official PinChat public key - DO NOT MODIFY for official pinchat.im usage
const PINCHAT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAExkuEOYHEQQfDqsyO+uamOnf5b/AH
OqRJNIZ5zBHCr2HbJsHCtrPQUOKd4cBqfDZlQZ62rzF7ofA39ITBUyLxaA==
-----END PUBLIC KEY-----`;

// Official domain - DO NOT MODIFY for official pinchat.im usage
const OFFICIAL_DOMAIN = 'pinchat.im';
// The only origins whose pages are treated as PinChat. Keep in step with
// OFFICIAL_ORIGINS in content.js and popup.js.
const OFFICIAL_ORIGINS = [`https://${OFFICIAL_DOMAIN}`, `https://www.${OFFICIAL_DOMAIN}`];

// Official GitHub repository for manifest - DO NOT MODIFY for official pinchat.im usage
const GITHUB_REPO = 'samjanny/pinchat';
// The manifest is read from the main branch: the latest release is the one
// the site should be serving, and a release of the site no longer needs a
// release of the extension.
//
// What makes a manifest trustworthy is its signature under the key above,
// made offline, not where it is read from. Up to 1.7.0 the address named a
// release tag (F-15), against an attacker who can write to the repository and
// also holds the signing key. A tag stops nobody who can write to the
// repository either, so what the tag added was the store: new code reached
// users only once a new extension had been reviewed. Reading main gives that
// up, deliberately, and leaves the offline key as the one gate. Against
// replays, a manifest must also carry a sequence no lower than the last one
// seen and than MIN_KNOWN_SEQUENCE below.
const MANIFEST_BRANCH = 'main';

// Minimum acceptable manifest sequence: a hardcoded floor that defeats replay
// attacks against fresh installs, where lastKnownSequence in storage is 0.
// A manifest whose sequence is below this constant is rejected even on a
// first install.
//
// It is the sequence of the manifest the packaged rules.json was built from,
// set by finish-release.sh when the extension itself is released. It must not
// be higher than the manifest on MANIFEST_BRANCH: a build that rejects every
// manifest it can fetch verifies nothing for anyone running it.
const MIN_KNOWN_SEQUENCE = 60;

// Configuration
const CONFIG = {
    HASH_LIST_URL: `https://raw.githubusercontent.com/${GITHUB_REPO}/${MANIFEST_BRANCH}/hashes.json.signed`,
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

// The same source runs in both browsers. Firefox exposes `browser`, Chromium
// exposes `chrome`; under Manifest V3 both return promises.
const ext = globalThis.browser || globalThis.chrome;

// In Chromium this file is the service worker and loads its two companions
// itself; Firefox loads them first, from the manifest's background scripts.
// csp-rules.js needs verdict.js.
if (typeof importScripts === 'function') {
    if (typeof PinChatVerdict === 'undefined') importScripts('verdict.js');
    if (typeof PinChatRules === 'undefined') importScripts('csp-rules.js');
}
const V = globalThis.PinChatVerdict;
const R = globalThis.PinChatRules;

// Whether this browser lets an extension hold the body of a navigation
// response until it has been checked. Firefox does (filterResponseData);
// Chromium has no equivalent in Manifest V3, and there the best state a
// document can reach is PARTIAL.
const CAN_ATTEST = !!(ext.webRequest && typeof ext.webRequest.filterResponseData === 'function');

// Match patterns ignore the port; every use is followed by an origin check.
const SITE_PATTERNS = OFFICIAL_ORIGINS.map((origin) => `${origin}/*`);

// No signed page is anywhere near this size. A response that exceeds it is
// not buffered further and is replaced by the block page.
const MAX_DOCUMENT_BYTES = 2 * 1024 * 1024;

// The redirects Firefox follows. A response with any other 3xx status is
// shown as a page, its body included, Location header or not.
const FOLLOWED_REDIRECTS = new Set([301, 302, 303, 307, 308]);

// The packaged rules, read from the extension's own files, so that the
// content script can tell the packaged policy from another one.
let packagedRules = null;
const packagedRulesLoaded = fetch(ext.runtime.getURL('rules.json'))
    .then((response) => response.json())
    .then((rules) => { packagedRules = rules; })
    .catch(() => { /* the content script then compares nothing */ });

// =============================================================================
// The script policy in force
// =============================================================================
//
// One set of rules is in force at a time: the packaged ruleset until a
// manifest has been verified, then dynamic rules built from that manifest,
// with the packaged ruleset disabled. Both are declarativeNetRequest rules,
// which the browser applies to a response before the page is parsed, whether
// or not this script is running, and both carry the same fixed policy around
// the script hashes (csp-rules.js). The browser keeps dynamic rules across
// restarts and updates of the extension, but turns the packaged ruleset back
// on after an update; reconcileRules puts the two back in step at every start.

const PACKAGED_RULESET = 'pinchat_preventive_csp';

// The two redirect rules match a response header, which only Chromium's
// declarativeNetRequest supports; the Firefox build enforces the same rule in
// onDocumentHeaders below. The browser that can hold a response body is
// Firefox.
const RULES_BROWSER = CAN_ATTEST ? 'firefox' : 'chrome';

// A document whose response went through the rules just before they were
// replaced is under the policy of the replaced release. For this long, its
// content script is told that policy too, so the change does not pass for a
// policy that is not in force.
const REPLACED_POLICY_GRACE_MS = 30 * 1000;

const rulesInForce = {
    rules: null,      // what the browser applies now (null: not established yet)
    sequence: null,   // the manifest they were built from; null for the packaged ruleset
    replaced: null,   // the rules in force before the last change
    replacedAt: 0,
};

let rulesQueue = Promise.resolve();

/** Changes to the rules run one at a time, in the order they were asked for. */
function serializeRules(task) {
    const run = rulesQueue.then(task);
    rulesQueue = run.catch(() => {});
    return run;
}

function recordRulesInForce(rules, sequence) {
    if (rulesInForce.rules && JSON.stringify(rulesInForce.rules) !== JSON.stringify(rules)) {
        rulesInForce.replaced = rulesInForce.rules;
        rulesInForce.replacedAt = Date.now();
    }
    rulesInForce.rules = rules;
    rulesInForce.sequence = sequence;
}

/** Back to the packaged ruleset alone. */
async function usePackagedRules() {
    await packagedRulesLoaded;
    const dnr = ext.declarativeNetRequest;
    const installed = await dnr.getDynamicRules();
    if (installed.length > 0) {
        await dnr.updateDynamicRules({ removeRuleIds: installed.map((rule) => rule.id) });
    }
    await dnr.updateEnabledRulesets({ enableRulesetIds: [PACKAGED_RULESET] });
    recordRulesInForce(packagedRules, null);
}

/**
 * Put the rules of a verified manifest in force, in place of the packaged
 * ones or of those of an earlier manifest. Never goes back to an older
 * manifest than the one in force. If the browser refuses the change, the
 * packaged ruleset is put back: a page is never left with no policy, only
 * with one that may not run the latest release.
 */
function applyManifestRules(data) {
    return serializeRules(async () => {
        if (rulesInForce.sequence !== null && data.sequence <= rulesInForce.sequence) return;
        const dnr = ext.declarativeNetRequest;
        try {
            const rules = R.buildRules(data, RULES_BROWSER);
            const installed = await dnr.getDynamicRules();
            await dnr.updateDynamicRules({
                removeRuleIds: installed.map((rule) => rule.id),
                addRules: rules,
            });
            await dnr.updateEnabledRulesets({ disableRulesetIds: [PACKAGED_RULESET] });
            recordRulesInForce(rules, data.sequence);
        } catch (error) {
            console.error('[PinChat Verify] Could not put the rules of the signed manifest in force:', error);
            try {
                await usePackagedRules();
            } catch {
                /* the browser keeps whatever it has; the packaged ruleset is on by default */
            }
        }
    });
}

/** At every start: the rules of the stored manifest, or the packaged ones. */
async function reconcileRules() {
    await packagedRulesLoaded;
    const cached = await loadCachedManifest();
    if (cached) {
        await applyManifestRules(cached.data);
        return;
    }
    await serializeRules(async () => {
        // A manifest fetched meanwhile has put its own rules in force.
        if (rulesInForce.sequence === null) await usePackagedRules();
    });
}

/**
 * The policies a document at this address may be under: the one the rules in
 * force give it and, just after a change, the one the replaced rules gave it.
 */
function expectedPolicies(url) {
    const policies = [];
    const add = (rules) => {
        const policy = V.packagedPolicy(rules, url);
        if (policy !== null && !policies.includes(policy)) policies.push(policy);
    };
    add(rulesInForce.rules || packagedRules);
    if (rulesInForce.replaced && Date.now() - rulesInForce.replacedAt < REPLACED_POLICY_GRACE_MS) {
        add(rulesInForce.replaced);
    }
    return policies;
}

/**
 * Whether the extension may act on the site right now. Without it the
 * browser applies none of the packaged rules to the site's responses, so no
 * positive state can be based on them. A user can withhold it, or grant it
 * only on request, in the browser's settings for the extension.
 */
async function hasHostAccess(url) {
    try {
        return await ext.permissions.contains({ origins: [`${new URL(url).origin}/*`] }) === true;
    } catch {
        return false;
    }
}

// State of the signed manifest. One per extension, not per tab: it says
// whether the yardstick is available, never whether a page measured up.
let verificationState = {
    signatureStatus: 'unknown', // 'valid', 'invalid', 'unusable', 'error', 'checking', 'unknown'
    lastCheck: null,
    errors: [],
    manifest: null,
    usingCachedManifest: false,  // True when the live fetch failed and the stored copy is in use
    manifestCachedAt: null,      // When that stored copy was written (ms epoch)
};

let lastLiveFetchAt = 0;
let manifestInFlight = null;

/** 'valid' | 'invalid' | 'unavailable' | 'unknown', as verdict.js expects. */
function manifestVerdict() {
    switch (verificationState.signatureStatus) {
    case 'valid': return 'valid';
    case 'invalid': return 'invalid';
    case 'unusable':
    case 'error': return 'unavailable';
    default: return 'unknown';
    }
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
 * Validate a signed manifest document against the two gates that matter:
 * the ECDSA signature under the pinned trust anchor, then the monotonic
 * sequence floor.
 *
 * Returns { ok: true, data, sequence, lastKnownSequence } or
 * { ok: false, kind, reason }, where `kind` is 'invalid' for a bad signature
 * or a downgrade (both are attack signals), 'unusable' for a signed manifest
 * whose page lists this version cannot use, and 'error' for a malformed
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
    const stored = await ext.storage.local.get('lastKnownSequence');
    const lastKnownSequence = stored.lastKnownSequence || 0;
    const minAcceptable = Math.max(lastKnownSequence, MIN_KNOWN_SEQUENCE);

    if (manifestSequence < minAcceptable) {
        const detail = manifestSequence < lastKnownSequence
            ? `manifest sequence (${manifestSequence}) < stored sequence (${lastKnownSequence})`
            : `manifest sequence (${manifestSequence}) < hardcoded floor (${MIN_KNOWN_SEQUENCE})`;
        return { ok: false, kind: 'invalid', reason: `DOWNGRADE ATTACK DETECTED - ${detail}` };
    }

    // The script policy of every page is built from the manifest. One that
    // does not allow it, signed as it is, is a broken release, not an attack,
    // and nothing is vouched for with it.
    try {
        R.pageScriptLists(signedData.data);
    } catch (error) {
        return { ok: false, kind: 'unusable', reason: `Signed manifest is unusable: ${error.message}` };
    }

    return { ok: true, data: signedData.data, sequence: manifestSequence, lastKnownSequence };
}

/**
 * Persist the last manifest that cleared both gates.
 *
 * Threat model: without a stored copy, anyone able to drop the connection to
 * the manifest host (a hostile network, a filtering proxy, a state-level
 * block, or simply a GitHub outage) turns the whole verification off just by
 * making the fetch fail. That is the cheapest possible attack against a
 * verifier and it leaves no trace on the page. The stored document is
 * re-validated on every read, so writing to extension storage buys an
 * attacker nothing that forging a signature would not already require.
 *
 * The script policy is unaffected either way: the rules in force, those of
 * the last verified manifest or the packaged ones, stay with the browser and
 * keep blocking unpinned scripts even with no manifest at all.
 */
async function cacheSignedManifest(signedData) {
    try {
        await ext.storage.local.set({
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
        const stored = await ext.storage.local.get(MANIFEST_CACHE_KEY);
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
            await ext.storage.local.remove(MANIFEST_CACHE_KEY);
        } catch {
            /* storage unavailable; nothing further to do */
        }
        return null;
    }
    return { data: result.data, cachedAt: entry.cachedAt || null };
}

/**
 * Fetch the signed manifest from the release host and validate it.
 *
 * A manifest that fails its signature or the sequence floor is an attack
 * signal and is never rescued by the stored copy. Only a transport failure
 * falls back to it.
 *
 * `bypassCache` asks past the release host's own cache, which keeps a copy of
 * the main branch for a few minutes: for when a page has just turned out not
 * to match, and a release signed in those minutes is the likely reason.
 */
async function verifyIntegrity({ bypassCache = false } = {}) {
    verificationState.lastCheck = new Date().toISOString();
    verificationState.errors = [];

    let signedData = null;
    let fetchError = null;
    try {
        const url = bypassCache ? `${CONFIG.HASH_LIST_URL}?t=${Date.now()}` : CONFIG.HASH_LIST_URL;
        const response = await fetchWithTimeout(url, { cache: 'no-store' });
        if (!response.ok) {
            throw new Error(`Failed to fetch hash list: ${response.status}`);
        }
        signedData = await response.json();
    } catch (error) {
        fetchError = error.name === 'AbortError' ? 'Request timeout' : error.message;
        console.warn('[PinChat Verify] Manifest fetch failed:', fetchError);
    }

    if (signedData) {
        let result;
        try {
            result = await validateSignedManifest(signedData);
        } catch (error) {
            result = { ok: false, kind: 'error', reason: error.message };
        }

        if (!result.ok) {
            verificationState.signatureStatus = result.kind;
            verificationState.manifest = null;
            verificationState.errors.push(result.reason);
            console.error(`[PinChat Verify] REJECTED: ${result.reason}`);
            await reevaluateAllDocuments();
            return verificationState;
        }

        if (result.sequence > result.lastKnownSequence) {
            await ext.storage.local.set({ lastKnownSequence: result.sequence });
        }
        await cacheSignedManifest(signedData);
        lastLiveFetchAt = Date.now();

        verificationState.manifest = result.data;
        verificationState.signatureStatus = 'valid';
        verificationState.usingCachedManifest = false;
        verificationState.manifestCachedAt = null;
        await applyManifestRules(result.data);
    } else {
        const cached = await loadCachedManifest();
        if (!cached) {
            verificationState.signatureStatus = 'error';
            verificationState.manifest = null;
            verificationState.errors.push(`${fetchError} (no cached manifest available)`);
            await reevaluateAllDocuments();
            return verificationState;
        }
        verificationState.manifest = cached.data;
        verificationState.signatureStatus = 'valid';
        verificationState.usingCachedManifest = true;
        verificationState.manifestCachedAt = cached.cachedAt;
        verificationState.errors.push(`Update host unreachable: ${fetchError}`);
        await applyManifestRules(cached.data);
    }

    await reevaluateAllDocuments();
    return verificationState;
}

// How often a page that does not match may make the extension ask the release
// host again, past its cache. Bounds what a page that never matches costs.
const MISMATCH_RECHECK_INTERVAL_MS = 30 * 1000;
let lastMismatchRecheckAt = 0;

/**
 * A document did not match the manifest in force. If a newer release was
 * signed since the extension last asked, that is the likely reason: ask the
 * release host again before the mismatch stands. True when a newer manifest
 * is now in force, with its rules.
 */
async function newerReleaseSigned() {
    const now = Date.now();
    if (now - lastMismatchRecheckAt < MISMATCH_RECHECK_INTERVAL_MS) return false;
    lastMismatchRecheckAt = now;
    const before = verificationState.manifest ? verificationState.manifest.sequence : null;
    await verifyIntegrity({ bypassCache: true });
    return manifestVerdict() === 'valid'
        && !verificationState.usingCachedManifest
        && !!verificationState.manifest
        && (before === null || verificationState.manifest.sequence > before);
}

/** tabId -> sequence of the release the tab was last reloaded for. */
const releaseReloads = new Map();

/**
 * Load a tab again under the rules of a newer release, once per release: a
 * page that matches no release must not reload for ever.
 */
function reloadForRelease(tabId) {
    const sequence = verificationState.manifest ? verificationState.manifest.sequence : null;
    if (sequence === null || releaseReloads.get(tabId) === sequence) return false;
    releaseReloads.set(tabId, sequence);
    ext.tabs.reload(tabId).catch(() => {});
    return true;
}

// What a page of a release the extension does not know yet looks like from
// its content script: its scripts are not signed (and the policy blocks
// them), its files and stylesheets differ.
const RELEASE_MISMATCH_CODES = new Set([
    'document-hash-mismatch', 'file-hash-mismatch', 'blocked-script', 'unsigned-stylesheet',
]);

/** After a content script reported its document: reload it for a newer release, if there is one. */
async function recheckReleaseFor(record) {
    if (!record.official || !record.findings.some((entry) => RELEASE_MISMATCH_CODES.has(entry.code))) return;
    if (await newerReleaseSigned()) reloadForRelease(record.tabId);
}

/**
 * Make a validated manifest available, without contacting the release host
 * more often than needed.
 *
 * A document navigation waits on this, so the stored copy is used first: it
 * passes the same signature and sequence gates as a fresh download. The
 * release host is asked again in the background when the last live answer
 * is older than MIN_LIVE_FETCH_INTERVAL_MS.
 */
function ensureManifest() {
    if (verificationState.signatureStatus === 'valid' && verificationState.manifest) {
        if (Date.now() - lastLiveFetchAt >= MIN_LIVE_FETCH_INTERVAL_MS && !manifestInFlight) {
            manifestInFlight = verifyIntegrity().finally(() => { manifestInFlight = null; });
        }
        return Promise.resolve(verificationState);
    }
    if (verificationState.signatureStatus === 'invalid') {
        return Promise.resolve(verificationState);
    }
    if (!manifestInFlight) {
        manifestInFlight = (async () => {
            const cached = await loadCachedManifest();
            if (cached) {
                verificationState.manifest = cached.data;
                verificationState.signatureStatus = 'valid';
                verificationState.usingCachedManifest = true;
                verificationState.manifestCachedAt = cached.cachedAt;
                // Refresh from the release host without making the caller wait.
                verifyIntegrity().catch(() => {});
                return verificationState;
            }
            return verifyIntegrity();
        })().finally(() => { manifestInFlight = null; });
    }
    return manifestInFlight;
}

/**
 * Background-driven refresh, gated so an idle browser does not contact the
 * release host every few minutes.
 */
async function verifyIfRelevant(trigger) {
    const tabs = await siteTabs();
    if (tabs.length === 0) {
        const cached = await loadCachedManifest();
        if (cached) return verificationState;
    } else if (
        verificationState.manifest
        && verificationState.signatureStatus === 'valid'
        && !verificationState.usingCachedManifest
        && Date.now() - lastLiveFetchAt < MIN_LIVE_FETCH_INTERVAL_MS
    ) {
        return verificationState;
    }
    console.log(`[PinChat Verify] ${trigger}: refreshing the signed manifest`);
    return verifyIntegrity();
}

// =============================================================================
// Per-document state
// =============================================================================

/**
 * tabId -> record of the top-level document currently shown in that tab.
 *
 * A record belongs to one document, identified by a random token its content
 * script generates at document_start. Reports carrying another token are for
 * another document and never touch this record.
 */
const documents = new Map();

/**
 * `${tabId}:${frameId}` -> result of checking the response body of the last
 * document navigation in that frame (browsers with CAN_ATTEST only). A
 * receipt is claimed by the first document that presents its URL and cannot
 * be claimed twice, so a document restored from the back/forward cache or a
 * second load of the same address does not inherit it.
 */
const receipts = new Map();

/** tabId -> timestamps of reloads requested after removing a service worker. */
const workerReloads = new Map();

let restored = null;

function restoreSessionState() {
    if (!restored) {
        restored = (async () => {
            try {
                const stored = await ext.storage.session.get(['documents', 'receipts']);
                for (const [key, value] of stored.documents || []) documents.set(key, value);
                for (const [key, value] of stored.receipts || []) receipts.set(key, value);
            } catch {
                /* session storage unavailable: start empty, which is the safe side */
            }
        })();
    }
    return restored;
}

function persistSessionState() {
    try {
        const pending = ext.storage.session.set({
            documents: [...documents],
            receipts: [...receipts],
        });
        if (pending && pending.catch) pending.catch(() => {});
    } catch {
        /* see restoreSessionState */
    }
}

function isPinChatUrl(url) {
    if (!url) return false;
    try {
        // Compare the whole origin. Hostname alone also accepted
        // http://pinchat.im and https://pinchat.im:<any port>, which are
        // other origins: the packaged CSP rules do not cover them and the
        // signed manifest says nothing about what they serve.
        return OFFICIAL_ORIGINS.includes(new URL(url).origin);
    } catch {
        return false;
    }
}

async function siteTabs() {
    try {
        return (await ext.tabs.query({ url: SITE_PATTERNS })).filter((tab) => isPinChatUrl(tab.url));
    } catch {
        return [];
    }
}

/** Recompute a record's state from its facts. The only place states are assigned. */
function evaluate(record) {
    const verdict = V.decide({
        manifest: manifestVerdict(),
        official: record.official,
        topLevel: true,
        checksDone: record.checksDone,
        policyInForce: record.policyInForce,
        workerControlled: record.workerControlled,
        canAttest: CAN_ATTEST,
        attested: record.attested,
        findings: record.findings,
    });
    record.integrity = verdict.integrity;
    record.attention = verdict.attention;
    return record;
}

function publicView(record) {
    return {
        tabId: record.tabId,
        url: record.url,
        integrity: record.integrity,
        attention: record.attention,
        headline: V.headline(record.integrity),
        canAttest: CAN_ATTEST,
        attested: record.attested,
        reasons: record.findings.filter((entry) => entry.class !== V.CLASS.ENVIRONMENT),
        environment: record.environment,
        files: record.files || null,
        manifest: {
            status: verificationState.signatureStatus,
            sequence: verificationState.manifest ? verificationState.manifest.sequence : null,
            usingCached: verificationState.usingCachedManifest,
            cachedAt: verificationState.manifestCachedAt,
            lastCheck: verificationState.lastCheck,
            errors: verificationState.errors,
        },
    };
}

function setBadge(tabId, record) {
    const badge = record
        ? V.badge(record.integrity, record.attention)
        : { text: '', color: '#6b7280', textColor: '#ffffff' };
    try {
        ext.action.setBadgeText({ text: badge.text, tabId });
        ext.action.setBadgeBackgroundColor({ color: badge.color, tabId });
        // Set for every state, not only the yellow one: the color is kept
        // per tab, and a dark text must not stay on the next badge.
        if (typeof ext.action.setBadgeTextColor === 'function') {
            ext.action.setBadgeTextColor({ color: badge.textColor, tabId });
        }
    } catch {
        /* tab closed */
    }
}

/** Tell a tab's content script what the verdict for its document is. */
function pushVerdict(record) {
    setBadge(record.tabId, record);
    ext.tabs.sendMessage(record.tabId, {
        type: 'VERDICT',
        token: record.token,
        verdict: publicView(record),
    }, { frameId: 0 }).catch(() => {
        /* the document is gone or not listening yet; it will ask */
    });
}

async function reevaluateAllDocuments() {
    await restoreSessionState();
    for (const record of documents.values()) {
        evaluate(record);
        pushVerdict(record);
    }
    persistSessionState();
}

function forgetTab(tabId) {
    documents.delete(tabId);
    workerReloads.delete(tabId);
    releaseReloads.delete(tabId);
    for (const key of [...receipts.keys()]) {
        if (key.startsWith(`${tabId}:`)) receipts.delete(key);
    }
    persistSessionState();
}

/**
 * A content script announces its document. Creates the record, attaching the
 * receipt of the response body check if this browser produced one.
 */
function openDocument(sender, message, hostAccess) {
    const tabId = sender.tab.id;
    const url = V.documentUrl(sender.url || sender.tab.url);
    const record = {
        tabId,
        token: String(message.token),
        url,
        official: isPinChatUrl(url),
        startedAt: Date.now(),
        policyInForce: message.policyInForce === true,
        workerControlled: message.workerControlled === true,
        checksDone: false,
        attested: false,
        findings: [],
        reported: [],
        environment: [],
        files: null,
    };
    record.own = [];
    if (record.policyInForce !== true) record.own.push(V.finding('policy-not-in-force'));
    if (record.workerControlled) record.own.push(V.finding('service-worker-controlled'));
    if (hostAccess !== true) record.own.push(V.finding('no-host-access'));

    if (CAN_ATTEST) {
        const receipt = receipts.get(`${tabId}:0`);
        if (receipt && receipt.url === url && !receipt.claimedBy) {
            receipt.claimedBy = record.token;
            record.attested = receipt.verified === true;
            if (!receipt.verified) record.own.push(V.finding(receipt.code, receipt.detail));
        } else {
            // No response of this document went through the filter: restored
            // from the back/forward cache, loaded before the extension
            // started, or served in a way the filter does not see.
            record.own.push(V.finding('document-not-attested'));
        }
    }
    record.findings = [...record.own];
    documents.set(tabId, evaluate(record));
    persistSessionState();
    setBadge(tabId, record);
    return record;
}

/** A content script reports the outcome of its inspection. */
function updateDocument(sender, message) {
    const record = documents.get(sender.tab.id);
    if (!record || record.token !== String(message.token)) return null;
    const accept = (entries, classes) => (Array.isArray(entries) ? entries : [])
        .filter((entry) => entry && V.FINDINGS[entry.code] && classes.includes(V.FINDINGS[entry.code][0]))
        .slice(0, 200)
        .map((entry) => V.finding(entry.code, entry.detail));
    record.reported = accept(message.findings, [V.CLASS.CONFIRMED, V.CLASS.SUSPICIOUS, V.CLASS.LIMIT]);
    record.environment = accept(message.environment, [V.CLASS.ENVIRONMENT]);
    record.findings = [...record.own, ...record.reported];
    if (message.checksDone === true) record.checksDone = true;
    if (message.files && typeof message.files === 'object') {
        record.files = {
            checked: Number(message.files.checked) || 0,
            failed: Number(message.files.failed) || 0,
        };
    }
    evaluate(record);
    persistSessionState();
    setBadge(record.tabId, record);
    return record;
}

// =============================================================================
// Response body verification and redirect guard (browsers with CAN_ATTEST)
// =============================================================================

/** requestId -> bookkeeping for a document response being buffered. */
const inflight = new Map();

/**
 * The document shown instead of a response that failed the check. It is
 * delivered at the site's own address and therefore under the packaged
 * policy, which allows neither scripts nor inline styles: plain markup only.
 * Nothing the server sent is included.
 */
function blockPageBytes(code, detail) {
    const entry = V.FINDINGS[code] || V.FINDINGS['document-not-attested'];
    const escape = (text) => String(text).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`);
    // An error answer is not a page that was stopped: say what it is.
    const heading = code === 'error-response'
        ? 'The server answered with an error'
        : 'Page blocked by the PinChat Integrity Verifier';
    const html = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
        + `<title>${escape(heading)}</title></head><body>`
        + `<h1>${escape(heading)}</h1>`
        + `<p id="verifier-block-reason">${escape(entry[1])}</p>`
        + (detail ? `<p>${escape(detail)}</p>` : '')
        + '<p>Shown by the PinChat Integrity Verifier. Nothing the server sent for this address is shown.</p>'
        + '</body></html>';
    return new TextEncoder().encode(html);
}

/**
 * Headers for a response whose body the filter is going to release.
 *
 * What is released is the signed page or the block page, never anything
 * else, and both are HTML in UTF-8. The server's own description of the body
 * is therefore replaced. Left alone, a block page standing in for a
 * plain-text error was displayed as its source, and the signed bytes could
 * be given another character encoding or be sent as a download.
 */
function asHtmlDocument(headers) {
    const kept = (headers || []).filter((header) => !['content-type', 'content-disposition']
        .includes(header.name.toLowerCase()));
    kept.push({ name: 'Content-Type', value: 'text/html; charset=utf-8' });
    return kept;
}

function toHex(buffer) {
    return [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/** Replace a refused top-level navigation with the extension's own page. */
function showBlockedPage(details, code) {
    if (details.frameId !== 0 || details.tabId < 0) return;
    const page = `${ext.runtime.getURL('blocked.html')}?reason=${encodeURIComponent(code)}`;
    ext.tabs.update(details.tabId, { url: page }).catch(() => {});
}

function onDocumentRequest(details) {
    try {
        // A new navigation in this frame: whatever was verified before does
        // not describe the document that is about to load.
        const superseded = inflight.get(details.requestId);
        if (superseded) superseded.superseded = true;
        receipts.delete(`${details.tabId}:${details.frameId}`);

        if (!isPinChatUrl(details.url)) {
            // Another port of the host. The catch-all policy denies every
            // script there and the content script warns; nothing to verify.
            return {};
        }

        const track = {
            requestId: details.requestId,
            tabId: details.tabId,
            frameId: details.frameId,
            url: details.url,
            status: null,
            chunks: [],
            size: 0,
            tooLarge: false,
            filterFailed: false,
            superseded: false,
        };
        const stream = ext.webRequest.filterResponseData(details.requestId);
        track.stream = stream;
        stream.ondata = (event) => {
            track.size += event.data.byteLength;
            if (track.size > MAX_DOCUMENT_BYTES) {
                track.tooLarge = true;
                track.chunks = [];
            } else {
                track.chunks.push(new Uint8Array(event.data));
            }
        };
        stream.onstop = () => { finishDocument(track); };
        stream.onerror = () => { track.filterFailed = true; };
        inflight.set(details.requestId, track);
        return {};
    } catch (error) {
        // Never let a request through because the verifier itself failed.
        console.error('[PinChat Verify] Could not set up the response filter:', error);
        showBlockedPage(details, 'document-not-attested');
        return { cancel: true };
    }
}

function onDocumentHeaders(details) {
    try {
        if (!isPinChatUrl(details.url)) return {};

        const location = (details.responseHeaders || [])
            .find((header) => header.name.toLowerCase() === 'location');
        if (details.statusCode >= 300 && details.statusCode < 400 && location) {
            if (!V.isAllowedRedirect(details.url, location.value || '', OFFICIAL_ORIGINS,
                V.EXTERNAL_REDIRECT_TARGETS)) {
                console.error('[PinChat Verify] Refused a redirect that leaves the site');
                inflight.delete(details.requestId);
                showBlockedPage(details, 'redirect-off-site');
                return { cancel: true };
            }
            // Only a redirect the browser follows has no body to check. A
            // 300, a 304 or a 399 with a Location header is displayed, and
            // goes through the same check as any other answer below.
            if (FOLLOWED_REDIRECTS.has(details.statusCode) && String(location.value || '').trim() !== '') {
                return {};
            }
        }

        // The body of this response is about to arrive. If the filter is not
        // attached to it, the body would reach the parser unchecked: the
        // filter does not attach to navigations started from some internal
        // pages, nor to documents answered by a service worker.
        const track = inflight.get(details.requestId);
        if (!track || track.url !== details.url || track.filterFailed
            || (track.stream && track.stream.status === 'failed')) {
            inflight.delete(details.requestId);
            showBlockedPage(details, 'document-not-attested');
            return { cancel: true };
        }
        track.status = details.statusCode;
        return { responseHeaders: asHtmlDocument(details.responseHeaders) };
    } catch (error) {
        console.error('[PinChat Verify] Header check failed:', error);
        showBlockedPage(details, 'document-not-attested');
        return { cancel: true };
    }
}

/**
 * The whole response body is buffered and nothing has been handed to the
 * parser yet. Compare it with the signed hash for this address and release
 * either those exact bytes or the block page.
 */
async function finishDocument(track) {
    const stream = track.stream;
    if (track.superseded) {
        try { stream.close(); } catch { /* already closed */ }
        return;
    }
    let outcome = { verified: false, code: 'document-not-attested', detail: '' };
    let body = null;
    let reloadTab = false;
    try {
        await restoreSessionState();
        await ensureManifest();
        const status = manifestVerdict();
        if (status === 'invalid') {
            outcome = { verified: false, code: 'manifest-invalid', detail: '' };
        } else if (status !== 'valid') {
            // Obtained and signed, but not usable by this version, is not
            // the same as never obtained: say which.
            const code = verificationState.signatureStatus === 'unusable' ? 'manifest-unusable' : 'manifest-unavailable';
            outcome = { verified: false, code, detail: '' };
        } else if (track.tooLarge) {
            outcome = { verified: false, code: 'document-too-large', detail: '' };
        } else {
            body = new Uint8Array(track.size);
            let offset = 0;
            for (const chunk of track.chunks) {
                body.set(chunk, offset);
                offset += chunk.byteLength;
            }
            const pathname = new URL(track.url).pathname;
            const actual = toHex(await crypto.subtle.digest('SHA-256', body));
            const expected = V.documentHashes(verificationState.manifest).get(pathname);
            if (expected && actual === expected) {
                outcome = { verified: true, code: null, detail: '' };
            } else if (track.status >= 400) {
                // The server says itself that this is not the page: a room
                // that no longer exists, a rate limit, a gateway error
                // during a restart. It is withheld like anything else that
                // is not the signed page, but it is not a mismatch.
                outcome = { verified: false, code: 'error-response', detail: `HTTP status ${track.status}` };
            } else {
                outcome = expected
                    ? { verified: false, code: 'document-hash-mismatch', detail: '' }
                    : { verified: false, code: 'unlisted-document', detail: `HTTP status ${track.status}` };
                // The page of a release signed after the extension last
                // asked. Its response already carries the policy of the
                // release before, which runs none of its scripts: it is
                // withheld, and loaded again under the policy of its own.
                if (track.frameId === 0 && await newerReleaseSigned()
                    && V.documentHashes(verificationState.manifest).get(pathname) === actual) {
                    outcome = {
                        verified: false,
                        code: 'document-not-attested',
                        detail: 'A newer release has just been signed. The page is being loaded again under its policy.',
                    };
                    reloadTab = true;
                }
            }
        }
    } catch (error) {
        console.error('[PinChat Verify] Document check failed:', error);
        outcome = { verified: false, code: 'document-not-attested', detail: '' };
    }

    // The receipt has to exist before the first byte is released, so that it
    // is there when the document's content script asks for it.
    receipts.set(`${track.tabId}:${track.frameId}`, {
        url: V.documentUrl(track.url),
        verified: outcome.verified,
        code: outcome.code,
        detail: outcome.detail,
        claimedBy: null,
    });
    persistSessionState();

    try {
        stream.write(outcome.verified ? body : blockPageBytes(outcome.code, outcome.detail));
    } catch (error) {
        console.error('[PinChat Verify] Could not release the response:', error);
    }
    try { stream.close(); } catch { /* already closed */ }
    inflight.delete(track.requestId);
    if (reloadTab) reloadForRelease(track.tabId);
}

/**
 * Files of the signed release that a page reads as data: the legal pages
 * fetch /static/operator.json for the operator's name and contacts. A script
 * is held to its signed hash by the packaged policy and a stylesheet by the
 * integrity attribute of an attested page, but nothing holds a fetched
 * file, and a re-download by the content script proves nothing about the
 * bytes the page was given. Where a response body can be held, a page is
 * given such a file only if it matches the signed hash, and nothing
 * otherwise. Keep in step with DATA_FILES in generate-hashes.js.
 */
const DATA_FILES = ['/static/operator.json'];

/** requestId -> HTTP status of a data file response. */
const dataFileStatus = new Map();

function onDataFileRequest(details) {
    try {
        if (!isPinChatUrl(details.url)) return {};
        const stream = ext.webRequest.filterResponseData(details.requestId);
        const chunks = [];
        let size = 0;
        stream.ondata = (event) => {
            size += event.data.byteLength;
            if (size <= MAX_DOCUMENT_BYTES) chunks.push(new Uint8Array(event.data));
        };
        stream.onstop = () => { finishDataFile(details, stream, chunks, size); };
        stream.onerror = () => { dataFileStatus.delete(details.requestId); };
        return {};
    } catch (error) {
        console.error('[PinChat Verify] Could not hold a data file:', error);
        return { cancel: true };
    }
}

async function finishDataFile(details, stream, chunks, size) {
    const path = new URL(details.url).pathname;
    const status = dataFileStatus.get(details.requestId);
    dataFileStatus.delete(details.requestId);
    let released = new Uint8Array(0);
    let differs = false;
    try {
        await ensureManifest();
        const entry = manifestVerdict() === 'valid'
            ? (verificationState.manifest.files || []).find((file) => file.path === path) : null;
        if (entry && size <= MAX_DOCUMENT_BYTES) {
            const body = new Uint8Array(size);
            let offset = 0;
            for (const chunk of chunks) {
                body.set(chunk, offset);
                offset += chunk.byteLength;
            }
            if (toHex(await crypto.subtle.digest('SHA-256', body)) === String(entry.hash).toLowerCase()) {
                released = body;
            } else {
                // An error answer is not the file; it is withheld, not failed.
                differs = !(status >= 400);
            }
        }
    } catch (error) {
        console.error('[PinChat Verify] Data file check failed:', error);
    }
    try { stream.write(released); } catch { /* the request is gone */ }
    try { stream.close(); } catch { /* already closed */ }
    if (differs) failDocumentForDataFile(details, path);
}

/** The page shown in the tab was handed a data file that is not the signed one. */
function failDocumentForDataFile(details, path) {
    restoreSessionState().then(() => {
        const record = documents.get(details.tabId);
        if (!record || record.url !== V.documentUrl(details.documentUrl || details.originUrl || '')) return;
        const entry = V.finding('file-hash-mismatch', `${path}: the page was given other bytes, which were withheld`);
        if (record.own.some((own) => own.code === entry.code && own.detail === entry.detail)) return;
        record.own.push(entry);
        record.findings = [...record.own, ...record.reported];
        evaluate(record);
        persistSessionState();
        pushVerdict(record);
    });
}

if (CAN_ATTEST) {
    // Registered synchronously at start-up so that a navigation which wakes
    // the event page is already covered.
    const documentRequests = { urls: SITE_PATTERNS, types: ['main_frame', 'sub_frame'] };
    ext.webRequest.onBeforeRequest.addListener(onDocumentRequest, documentRequests, ['blocking']);
    ext.webRequest.onHeadersReceived.addListener(
        onDocumentHeaders, documentRequests, ['blocking', 'responseHeaders'],
    );
    const dataFileRequests = {
        urls: OFFICIAL_ORIGINS.flatMap((origin) => DATA_FILES.map((file) => `${origin}${file}*`)),
        types: ['xmlhttprequest'],
    };
    ext.webRequest.onBeforeRequest.addListener(onDataFileRequest, dataFileRequests, ['blocking']);
    ext.webRequest.onHeadersReceived.addListener((details) => {
        dataFileStatus.set(details.requestId, details.statusCode);
    }, dataFileRequests);
    const forget = (details) => {
        const track = inflight.get(details.requestId);
        if (track && (track.filterFailed || !track.stream || track.stream.status !== 'transferringdata')) {
            inflight.delete(details.requestId);
        }
    };
    ext.webRequest.onErrorOccurred.addListener(forget, documentRequests);
}

// =============================================================================
// Messages
// =============================================================================

/**
 * Validate that a runtime message originates from a trusted sender.
 *
 *  - 'popup': an extension page (no sender.tab, or a tab showing one of this
 *    extension's own pages).
 *  - 'content': a content script running in the top-level document of a tab
 *    on one of the official origins.
 *  - 'status': the read-only view, for both of the above.
 *
 * Without externally_connectable, web pages cannot reach onMessage at all -
 * but the sender is still validated, to harden against future regressions
 * and to reject content scripts that run on any other origin, another port
 * of the host included.
 */
function isSenderTrusted(sender, profile) {
    if (sender.id && sender.id !== ext.runtime.id) return false;

    const ownPagePrefix = ext.runtime.getURL('');
    const fromPinChatContentScript = () => {
        if (!sender.tab || !sender.url) return false;
        return isPinChatUrl(sender.url) && sender.frameId === 0;
    };
    const fromExtensionPage = () => {
        if (!sender.url) return !sender.tab;
        return sender.url.startsWith(ownPagePrefix);
    };

    if (profile === 'content') return fromPinChatContentScript();
    if (profile === 'popup') return fromExtensionPage();
    if (profile === 'status') return fromExtensionPage() || fromPinChatContentScript();
    return false;
}

function manifestForContent() {
    return {
        manifestStatus: manifestVerdict(),
        manifest: verificationState.manifest,
        canAttest: CAN_ATTEST,
    };
}

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message.type !== 'string') return false;

    if (message.type === 'GET_STATUS') {
        if (!isSenderTrusted(sender, 'status')) {
            console.warn('[PinChat Verify] Rejected GET_STATUS from untrusted sender');
            return false;
        }
        ensureManifest().then(() => sendResponse(manifestForContent()));
        return true;
    }

    if (message.type === 'DOCUMENT_OPENED') {
        if (!isSenderTrusted(sender, 'content')) return false;
        Promise.all([
            restoreSessionState(), ensureManifest(), hasHostAccess(sender.url), packagedRulesLoaded, rulesReady,
        ]).then(([, , hostAccess]) => {
            const record = openDocument(sender, message, hostAccess);
            const policies = expectedPolicies(record.url);
            sendResponse({
                ...manifestForContent(),
                expectedPolicy: policies.length > 0 ? policies[0] : null,
                expectedPolicies: policies,
                verdict: publicView(record),
            });
        });
        return true;
    }

    if (message.type === 'DOCUMENT_REPORT') {
        if (!isSenderTrusted(sender, 'content')) return false;
        restoreSessionState().then(() => {
            const record = updateDocument(sender, message);
            sendResponse(record ? { verdict: publicView(record) } : { verdict: null });
            if (record) recheckReleaseFor(record).catch(() => {});
        });
        return true;
    }

    if (message.type === 'WORKER_RELOAD_ALLOWED') {
        // After removing a service worker the content script reloads once,
        // so the page is fetched from the network. Bounded per tab, or a
        // page that keeps re-registering one would reload forever.
        if (!isSenderTrusted(sender, 'content')) return false;
        const now = Date.now();
        const recent = (workerReloads.get(sender.tab.id) || []).filter((at) => now - at < 60000);
        const allowed = recent.length < 2;
        if (allowed) recent.push(now);
        workerReloads.set(sender.tab.id, recent);
        sendResponse({ allowed });
        return true;
    }

    if (message.type === 'GET_TAB_STATE') {
        if (!isSenderTrusted(sender, 'popup')) return false;
        Promise.all([restoreSessionState(), ensureManifest()]).then(async () => {
            let tab = null;
            try { tab = await ext.tabs.get(message.tabId); } catch { /* closed */ }
            const record = documents.get(message.tabId);
            const current = tab && record && V.documentUrl(tab.url) === record.url ? record : null;
            sendResponse({
                onSite: !!tab && isPinChatUrl(tab.url),
                canAttest: CAN_ATTEST,
                verdict: current ? publicView(current) : null,
                manifest: publicView({ findings: [], environment: [] }).manifest,
            });
        });
        return true;
    }

    if (message.type === 'GET_ALL_STATES') {
        if (!isSenderTrusted(sender, 'popup')) return false;
        restoreSessionState().then(() => {
            sendResponse([...documents.values()].map(publicView));
        });
        return true;
    }

    if (message.type === 'VERIFY_NOW') {
        if (!isSenderTrusted(sender, 'popup')) {
            console.warn('[PinChat Verify] Rejected VERIFY_NOW from untrusted sender');
            return false;
        }
        verifyIntegrity().then(async () => {
            // Have the document in the active tab inspected again.
            if (typeof message.tabId === 'number') {
                ext.tabs.sendMessage(message.tabId, { type: 'RECHECK' }, { frameId: 0 }).catch(() => {});
            }
            sendResponse({ done: true });
        });
        return true;
    }

    return false;
});

// =============================================================================
// Lifecycle
// =============================================================================

ext.runtime.onInstalled.addListener(() => {
    console.log('[PinChat Verify] Extension installed/updated');
    verifyIntegrity();
    ext.alarms.create('verify-integrity', {
        periodInMinutes: CONFIG.CHECK_INTERVAL_MINUTES
    });
});

ext.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'verify-integrity') {
        verifyIfRelevant('alarm tick');
    }
});

ext.tabs.onRemoved.addListener((tabId) => {
    restoreSessionState().then(() => forgetTab(tabId));
});

/**
 * Whether the document a record describes is still the one shown in its tab.
 * Its content script answers with the token it announced itself with; a new
 * document has another token, and a tab with no content script does not
 * answer at all.
 */
async function documentStillShown(tabId, token) {
    try {
        const reply = await ext.tabs.sendMessage(tabId, { type: 'IDENTIFY' }, { frameId: 0 });
        return !!reply && reply.token === token;
    } catch {
        return false;
    }
}

ext.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (!changeInfo.url) return;
    restoreSessionState().then(async () => {
        const record = documents.get(tabId);
        const url = V.documentUrl(changeInfo.url);
        if (!record || record.url === url) return;

        // The address of the tab changed. Usually another document is
        // loading, and it will announce itself. But a page can also rewrite
        // its own address without loading anything (the login page drops
        // its error parameter that way): the document is then the same one,
        // and what was established about it still describes it.
        const sameDocument = isPinChatUrl(url) && await documentStillShown(tabId, record.token);
        if (documents.get(tabId) !== record) return; // replaced while waiting
        if (sameDocument) {
            record.url = url;
            persistSessionState();
            setBadge(tabId, record);
            return;
        }
        // The record describes a document that is no longer there.
        documents.delete(tabId);
        persistSessionState();
        setBadge(tabId, null);
    });
});

restoreSessionState();
const rulesReady = reconcileRules().catch((error) => {
    console.error('[PinChat Verify] Could not establish the rules in force:', error);
});
verifyIfRelevant('background start');
