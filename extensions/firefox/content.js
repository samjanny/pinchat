/**
 * PinChat Integrity Verifier - content script
 *
 * Runs at document_start in every document on the site's host names. For the
 * top-level document of an official origin it:
 *
 * 1. Probes, synchronously and before the page has parsed anything, whether
 *    the packaged script policy is in force and whether a service worker
 *    controls the document. Either one failing means nothing the verifier
 *    promises holds for this document.
 * 2. Announces the document to the background script and receives the signed
 *    manifest and, where the browser can provide it, the result of the check
 *    of the navigation response itself.
 * 3. Inspects the DOM and listens for policy violations.
 * 4. Reports what it saw. The background script decides the state; this
 *    script only displays it.
 *
 * What it deliberately does not do is decide that an element in the DOM is
 * "unauthorized". Other extensions add elements, script elements included,
 * and nothing in the DOM says who added a node. What can run is decided by
 * the script policy, which the browser enforces. An inline script element is
 * therefore recorded as an unattested change to the page, not as tampering,
 * and never changes the integrity state on its own. See verdict.js.
 */

const ext = globalThis.browser || globalThis.chrome;
const V = globalThis.PinChatVerdict;

// The origins this extension vouches for. The signed manifest and the
// packaged Content-Security-Policy rules describe exactly these two. The
// content script's match patterns ignore the port, so it is also injected on
// https://pinchat.im:<any port>, which is a different origin that the server
// operator controls just as well: a redirect is enough to send a visitor
// there. Such a page must never be treated as PinChat.
const OFFICIAL_ORIGINS = ['https://pinchat.im', 'https://www.pinchat.im'];
const ON_OFFICIAL_ORIGIN = OFFICIAL_ORIGINS.includes(window.location.origin);
const IS_TOP_LEVEL = window.top === window;

// Identifies this document towards the background script. A report carrying
// this token can only ever update the record of this document.
const DOCUMENT_TOKEN = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');

let manifestData = null;
let manifestSRIMap = {};
let inspectionTimer = null;
let fileCheck = null;          // { checked, failed, issues } once the files were re-fetched
let checksDone = false;
// Begins the handler of the policy probe, so that its violation, if the
// browser reports it, is told from the page's own. See V.isProbeViolation.
const PROBE_MARKER = Array.from(crypto.getRandomValues(new Uint8Array(V.PROBE_MARKER_LENGTH / 2)))
    .map((byte) => byte.toString(16).padStart(2, '0')).join('');
// The policy the packaged rules give this address, from the background
// script, and the policies the browser named for blocking the probe.
let expectedPolicy = null;
const canaryPolicies = [];
// Whether the background script compared the bytes of this document with
// the signed page before the parser saw them (Firefox).
let documentAttested = false;

// code + detail -> finding. Kept for the life of the document: an element
// that was added and removed again is still something that happened.
const findings = new Map();
const environment = new Map();

// What decides a state is kept even when a page has produced many lesser
// findings to crowd it out.
const DECISIVE = [V.CLASS.CONFIRMED, V.CLASS.LIMIT];

function note(entry) {
    const target = entry.class === V.CLASS.ENVIRONMENT ? environment : findings;
    const key = `${entry.code}\n${entry.detail}`;
    const limit = DECISIVE.includes(entry.class) ? 400 : 200;
    if (target.size >= limit || target.has(key)) return false;
    target.set(key, entry);
    return true;
}

/** Findings for a report, the decisive ones first. */
function reportedFindings(extra) {
    const all = [...findings.values(), ...extra];
    return [...all.filter((entry) => DECISIVE.includes(entry.class)),
        ...all.filter((entry) => !DECISIVE.includes(entry.class))];
}

// =============================================================================
// Probes
// =============================================================================

/**
 * Is the packaged script policy in force for this document?
 *
 * The policy forbids inline event handlers. An element with one is created
 * here and clicked: if the handler runs, no such policy applies, whatever
 * the reason (a document answered by a service worker never receives the
 * extension's response header rules, for one). The answer is available
 * synchronously, before the parser has produced a single element of the
 * page. It cannot tell a weakened policy from the intact one, only an absent
 * one from a present one.
 *
 * Its violation may or may not be reported: Chromium reports none that an
 * extension causes. When one is, it is recognised by the marker the handler
 * begins with, and by nothing else, so that no violation of the page's own
 * is ever taken for it.
 */
function policyIsInForce() {
    const probe = document.createElement('div');
    probe.setAttribute('onclick', V.probeHandler(PROBE_MARKER));
    try {
        probe.click();
    } catch {
        /* a throwing dispatch is not an executed handler */
    }
    return probe.getAttribute('data-ran') !== '1';
}

/**
 * The probe only learns that an inline handler was blocked, and a policy of
 * the server's own blocks one too: script-src 'self' does, while it runs any
 * script the server cares to serve. That is exactly the situation when the
 * packaged rules were not applied, for instance because the extension may
 * act on the site only on request. The browser names the policy it applied
 * in the violation, and that is compared with the packaged one.
 *
 * Only a reported violation counts; no report proves nothing either way.
 * Chromium reports no violation that an extension's own code causes, the
 * probe's included, so there the comparison never takes place, and what
 * keeps a page whose packaged rules were not applied from a positive state
 * is the background script's check of the extension's access to the site.
 */
let otherPolicyFound = false;

function checkPolicyIsPackaged() {
    if (otherPolicyFound || !expectedPolicy || canaryPolicies.length === 0) return;
    if (canaryPolicies.some((policy) => V.sameScriptPolicy(policy, expectedPolicy))) return;
    otherPolicyFound = true;
    const entry = V.finding('policy-not-in-force',
        `the browser applied another policy: ${canaryPolicies[0].slice(0, 120)}`);
    note(entry);
    stopDocument();
    applyVerdict({ integrity: V.INTEGRITY.FAILED, reasons: [entry] });
    scheduleInspection();
}

function workerControlsDocument() {
    try {
        return !!(navigator.serviceWorker && navigator.serviceWorker.controller);
    } catch {
        return false;
    }
}

/**
 * Remove every service worker registered for the origin. The site uses
 * none, and under the packaged policy a page cannot register one, so a
 * registration dates from a visit made without the extension, or with it
 * disabled. Returns how many were removed.
 */
async function removeServiceWorkers() {
    try {
        if (!navigator.serviceWorker) return 0;
        const registrations = await navigator.serviceWorker.getRegistrations();
        await Promise.all(registrations.map((registration) => registration.unregister()));
        return registrations.length;
    } catch {
        return 0;
    }
}

// =============================================================================
// DOM inspection
// =============================================================================

/**
 * Whether an element is a stylesheet link.
 *
 * `rel` is a list of space-separated, case-insensitive tokens. A link with
 * rel="stylesheet nofollow" or rel="StyleSheet" loads its stylesheet exactly
 * like rel="stylesheet", so comparing the attribute to that one string let a
 * tampered page load an unsigned stylesheet without it ever being checked.
 */
function isStylesheetLink(element) {
    if (!element || element.tagName !== 'LINK') return false;
    const rel = element.getAttribute('rel') || '';
    return rel.toLowerCase().split(/\s+/).includes('stylesheet');
}

function getPathFromUrl(url) {
    if (!url) return null;
    try {
        const parsed = new URL(url, window.location.href);
        if (parsed.origin === window.location.origin) {
            return parsed.pathname;
        }
        return parsed.href;
    } catch {
        return url;
    }
}

function hexToSRI(hexHash) {
    const bytes = new Uint8Array(hexHash.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
    return `sha256-${btoa(String.fromCharCode(...bytes))}`;
}

function buildManifestSRIMap(manifest) {
    manifestSRIMap = {};
    for (const file of (manifest && manifest.files) || []) {
        if (file.path && file.hash) manifestSRIMap[file.path] = hexToSRI(file.hash);
    }
}

/**
 * Compare one script or stylesheet element with the signed manifest.
 * Returns null when there is nothing to say about it, or an issue whose
 * `type` verdict.js maps to a finding.
 */
function inspectResourceElement(element) {
    const isScript = element.tagName === 'SCRIPT';
    const isStylesheet = isStylesheetLink(element);
    if (!isScript && !isStylesheet) return null;

    const url = element.getAttribute(isScript ? 'src' : 'href');
    if (!url) {
        const type = (element.getAttribute('type') || '').toLowerCase();
        const dataBlock = type.includes('json') || type === 'text/plain' || type.includes('template');
        if (isScript && (element.textContent || '').trim() && !dataBlock) {
            // The policy does not run inline scripts. Who added the element
            // is not knowable from here.
            return { path: '[inline script]', error: 'inline script element', type: 'inline-script' };
        }
        return null;
    }

    let absolute = url;
    try {
        absolute = new URL(url, window.location.href).href;
    } catch {
        /* judged below as written */
    }
    if (V.isExtensionUrl(absolute)) {
        return {
            path: absolute.split('/').slice(0, 3).join('/'),
            error: `${isScript ? 'script' : 'stylesheet'} of another extension`,
            type: 'extension-script',
        };
    }

    const lower = url.trim().toLowerCase();
    for (const scheme of ['data:', 'blob:', 'javascript:', 'filesystem:']) {
        if (lower.startsWith(scheme)) {
            return {
                path: url.substring(0, 50),
                error: `'${scheme}' URL`,
                type: isScript ? 'dangerous-script' : 'dangerous-stylesheet',
            };
        }
    }

    const path = getPathFromUrl(url);
    if (!path || !path.startsWith('/')) {
        return {
            path: String(path).slice(0, 120),
            error: `${isScript ? 'script' : 'stylesheet'} from another origin`,
            type: isScript ? 'external-script' : 'external-stylesheet',
        };
    }
    if (!path.startsWith('/static/')) {
        return {
            path,
            error: `site ${isScript ? 'script' : 'stylesheet'} outside /static/`,
            type: isScript ? 'unauthorized-script' : 'unauthorized-stylesheet',
        };
    }

    // A script element must point at a .js file and a stylesheet at a .css
    // file. Otherwise a tampered page could load another signed file, such
    // as a JSON document, as code under that file's valid hash.
    const pathLower = path.toLowerCase();
    if (isScript && !pathLower.endsWith('.js')) {
        return { path, error: 'script element pointing at a non-script file', type: 'type-confusion-script' };
    }
    if (isStylesheet && !pathLower.endsWith('.css')) {
        return { path, error: 'stylesheet link pointing at a non-stylesheet file', type: 'type-confusion-stylesheet' };
    }

    // No verdict without the manifest; the inspection runs again once it is
    // here.
    if (!manifestData) return null;

    const expected = manifestSRIMap[path];
    if (!expected) {
        return { path, error: 'not in the signed manifest', type: isScript ? 'unknown-script' : 'unknown-stylesheet' };
    }
    const integrity = element.getAttribute('integrity');
    if (!integrity) {
        return { path, error: 'no integrity attribute', type: isScript ? 'missing-sri' : 'stylesheet-missing-sri' };
    }
    if (integrity !== expected) {
        return {
            path,
            error: 'integrity attribute differs from the signed hash',
            type: isScript ? 'sri-mismatch' : 'stylesheet-sri-mismatch',
        };
    }
    return null;
}

function inspectBaseElement(element) {
    const href = element.getAttribute('href');
    if (!href) return null;
    let origin = null;
    try {
        origin = new URL(href, window.location.href).origin;
    } catch {
        return { path: href.slice(0, 120), error: 'invalid <base href>', type: 'base-invalid' };
    }
    return origin !== window.location.origin
        ? { path: href.slice(0, 120), error: '<base href> to another origin', type: 'base-cross-origin' }
        : { path: href.slice(0, 120), error: 'unexpected <base> element', type: 'base-unexpected' };
}

/** A <meta http-equiv="refresh">: a navigation no script policy can stop. */
function isRefresh(element) {
    return element.tagName === 'META'
        && (element.getAttribute('http-equiv') || '').trim().toLowerCase() === 'refresh';
}

/**
 * Issues for one element and everything under it. `root` may also be a
 * shadow root, whose contents no query on the document reaches.
 */
function inspectSubtree(root) {
    const issues = [];
    const visit = (element) => {
        // Only the overlay this script made is skipped: an id can be copied.
        if (element === overlayElement) return;
        const tag = element.tagName;
        let issue = null;
        if (isRefresh(element)) {
            issue = {
                path: (element.getAttribute('content') || '').slice(0, 120),
                error: '<meta http-equiv="refresh">',
                type: 'meta-refresh',
            };
        } else if (tag === 'SCRIPT' || tag === 'LINK') {
            issue = inspectResourceElement(element);
        } else if (tag === 'BASE') {
            issue = inspectBaseElement(element);
        } else if (tag === 'STYLE') {
            if ((element.textContent || '').trim()) {
                issue = { path: '[inline style]', error: 'inline style element', type: 'css-import' };
            }
        } else if (tag === 'IFRAME' || tag === 'FRAME' || tag === 'EMBED' || tag === 'OBJECT') {
            const src = element.getAttribute('src') || element.getAttribute('data') || '';
            let absolute = src;
            try {
                absolute = new URL(src, window.location.href).href;
            } catch {
                /* judged as written */
            }
            issue = V.isExtensionUrl(absolute)
                ? { path: absolute.split('/').slice(0, 3).join('/'), error: 'frame of another extension', type: 'extension-frame' }
                : { path: (src || `<${tag.toLowerCase()}>`).slice(0, 120), error: 'embedded document', type: 'external-iframe' };
        } else if (tag === 'FORM' && element.hasAttribute('action')) {
            try {
                const action = element.getAttribute('action');
                if (new URL(action, window.location.href).origin !== window.location.origin) {
                    issue = { path: action.slice(0, 120), error: 'form submitting to another origin', type: 'external-form' };
                }
            } catch {
                /* unparsable action: the browser will not submit it anywhere */
            }
        }
        if (issue) issues.push(issue);
    };
    if (root.nodeType === Node.ELEMENT_NODE) visit(root);
    if (root.querySelectorAll) {
        root.querySelectorAll('script, link, base, style, iframe, frame, embed, object, form[action], meta')
            .forEach(visit);
    }
    return issues;
}

let refreshStopped = false;

function recordIssues(issues) {
    let changed = false;
    for (const issue of issues) {
        if (note(V.findingForIssue(issue))) changed = true;
        // Removing the element does not cancel a refresh it scheduled;
        // stopping the document does. Once is enough.
        if (issue.type === 'meta-refresh' && !refreshStopped) {
            refreshStopped = true;
            stopDocument();
        }
    }
    return changed;
}

// =============================================================================
// Shadow roots
// =============================================================================
//
// What sits in a shadow tree is out of reach of every query on the document,
// the page's own included, and a closed one cannot even be seen by the page.
// The parser builds one from served markup (<template shadowrootmode>), with
// stylesheets, forms and anything else in it, and nothing in this script
// would otherwise look inside. The extension can: through
// chrome.dom.openOrClosedShadowRoot in Chromium and
// element.openOrClosedShadowRoot() in Firefox.

/** Shadow roots seen in this document, kept so that later checks still reach them. */
const shadowRoots = new Set();
/** Where each one was found -> whether the parser could have made it. */
const shadowHosts = new Map();
/** Set once the document has been parsed and scanned for shadow roots. */
let parsingScanned = false;

function shadowRootOf(element) {
    try {
        const dom = globalThis.chrome && globalThis.chrome.dom;
        if (dom && typeof dom.openOrClosedShadowRoot === 'function') {
            return dom.openOrClosedShadowRoot(element) || null;
        }
        if (typeof element.openOrClosedShadowRoot === 'function') {
            return element.openOrClosedShadowRoot() || null;
        }
        return element.shadowRoot || null;
    } catch {
        return null;
    }
}

function describeHost(element) {
    const id = element.getAttribute('id');
    return `<${String(element.tagName).toLowerCase()}${id ? ` id="${id.slice(0, 40)}"` : ''}>`;
}

/**
 * Take note of the shadow root of one element, if it has one not seen
 * before: record where it is, inspect what it holds, watch it from now on.
 * Returns whether it was new.
 */
function adoptShadowRoot(element) {
    if (element === overlayElement) return false;
    const shadow = shadowRootOf(element);
    if (!shadow || shadowRoots.has(shadow) || shadowRoots.size >= 200) return false;
    shadowRoots.add(shadow);
    const where = describeHost(element);
    // Until the document has been parsed, a shadow root may be one the
    // parser built from the served markup. After that only a script can
    // attach one, and the signed client attaches none.
    if (!shadowHosts.has(where)) shadowHosts.set(where, !parsingScanned);
    if (documentObserver) documentObserver.observe(shadow, OBSERVED);
    recordIssues(inspectSubtree(shadow));
    scanShadowRoots(shadow);
    return true;
}

/** adoptShadowRoot for `root` and everything under it. */
function scanShadowRoots(root) {
    let changed = false;
    if (root.nodeType === Node.ELEMENT_NODE && adoptShadowRoot(root)) changed = true;
    if (root.querySelectorAll) {
        for (const element of root.querySelectorAll('*')) {
            if (adoptShadowRoot(element)) changed = true;
        }
    }
    return changed;
}

/** Shadow roots as findings: the class depends on what could have made them. */
function shadowFindings() {
    return [...shadowHosts].map(([where, duringParsing]) => V.finding(
        // A document whose bytes were compared with the signed page holds
        // no shadow root of the server's.
        duringParsing && !documentAttested ? 'shadow-root' : 'shadow-root-added',
        `on ${where}`,
    ));
}

async function sha256Hex(buffer) {
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Download every file of the signed manifest again and compare hashes.
 *
 * This is a second request, separate from whatever the page itself loaded,
 * and a server can answer the two differently. So a match proves only that
 * the server is able to serve the signed file. It is never counted towards
 * a positive state. A mismatch, on the other hand, is real: the server
 * handed this extension bytes that are not the signed ones.
 */
async function recheckFiles(manifest) {
    const expected = new Map();
    for (const file of manifest.files || []) {
        if (file.path && file.hash && file.path.startsWith('/static/')) expected.set(file.path, file.hash);
    }
    const issues = [];
    await Promise.all([...expected].map(async ([path, hash]) => {
        try {
            const response = await fetch(new URL(path, window.location.origin).href, {
                cache: 'no-store',
                credentials: 'omit',
            });
            if (!response.ok) {
                issues.push({ path, error: `HTTP ${response.status}`, type: 'fetch-error' });
            } else if (await sha256Hex(await response.arrayBuffer()) !== hash) {
                issues.push({ path, error: 'differs from the signed hash', type: 'hash-mismatch' });
            }
        } catch (error) {
            issues.push({ path, error: String(error.message || error).slice(0, 80), type: 'fetch-error' });
        }
    }));
    return { checked: expected.size, failed: issues.length, issues };
}

// =============================================================================
// Reporting
// =============================================================================

function sendMessage(message) {
    return ext.runtime.sendMessage(message).catch(() => null);
}

async function report() {
    const shadow = shadowFindings();
    const response = await sendMessage({
        type: 'DOCUMENT_REPORT',
        token: DOCUMENT_TOKEN,
        checksDone,
        findings: reportedFindings(shadow.filter((entry) => entry.class !== V.CLASS.ENVIRONMENT)),
        environment: [...environment.values(), ...shadow.filter((entry) => entry.class === V.CLASS.ENVIRONMENT)],
        files: fileCheck ? { checked: fileCheck.checked, failed: fileCheck.failed } : null,
    });
    if (response && response.verdict) applyVerdict(response.verdict);
}

/** Inspect the whole document and report. Debounced by scheduleInspection. */
async function inspect({ files = false } = {}) {
    if (!manifestData) return;
    for (const node of unjudged.splice(0)) recordIssues(inspectSubtree(node));
    recordIssues(inspectSubtree(document.documentElement));
    scanShadowRoots(document.documentElement);
    // Every shadow root seen, also one that is no longer in the document:
    // what it loaded while it was there was loaded all the same.
    for (const shadow of shadowRoots) recordIssues(inspectSubtree(shadow));
    if (files || !fileCheck) {
        fileCheck = fileCheck || { checked: 0, failed: 0, issues: [] };
        fileCheck = await recheckFiles(manifestData);
        recordIssues(fileCheck.issues);
    }
    if (document.readyState !== 'loading') checksDone = true;
    await report();
}

function scheduleInspection() {
    if (inspectionTimer) clearTimeout(inspectionTimer);
    inspectionTimer = setTimeout(() => {
        inspectionTimer = null;
        inspect();
    }, 300);
}

// Elements added before the manifest was here, judged once it is: by then
// the page may have removed them, as the framework does with served markup
// when it starts.
const unjudged = [];

let documentObserver = null;
const OBSERVED = {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['src', 'href', 'integrity', 'type', 'rel', 'action', 'data', 'http-equiv', 'content'],
};

function watchDocument() {
    documentObserver = new MutationObserver((mutations) => {
        let changed = false;
        for (const mutation of mutations) {
            if (mutation.type === 'attributes') {
                if (recordIssues(inspectSubtree(mutation.target))) changed = true;
                continue;
            }
            // The parser attaches a declared shadow root to its host after
            // the host was inserted; what it inserts next has the host as
            // its parent.
            if (mutation.target.nodeType === Node.ELEMENT_NODE && adoptShadowRoot(mutation.target)) changed = true;
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                // Recorded when seen: a node that is removed again right
                // away is still reported, as what it was.
                if (recordIssues(inspectSubtree(node))) changed = true;
                if (scanShadowRoots(node)) changed = true;
                if (!manifestData && unjudged.length < 1000) unjudged.push(node);
            }
        }
        if (changed) scheduleInspection();
        restoreOverlayIfTampered();
    });
    documentObserver.observe(document.documentElement, OBSERVED);

    // At the end of parsing, before any listener of the page: by then every
    // shadow root the parser could build exists, and the application's
    // framework has not yet replaced the body that may carry one.
    const scanParsed = () => {
        if (scanShadowRoots(document.documentElement)) scheduleInspection();
        parsingScanned = true;
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scanParsed, { once: true });
    } else {
        scanParsed();
    }

    document.addEventListener('securitypolicyviolation', (event) => {
        if (V.isProbeViolation(event, PROBE_MARKER)) {
            // The probe in policyIsInForce, not the page. The policy the
            // browser names says whether it is the packaged one.
            if (event.originalPolicy && canaryPolicies.length < 8) canaryPolicies.push(String(event.originalPolicy));
            checkPolicyIsPackaged();
            return;
        }
        const entry = V.findingForViolation({
            sourceFile: event.sourceFile,
            blockedURI: event.blockedURI,
            effectiveDirective: event.effectiveDirective,
            violatedDirective: event.violatedDirective,
        }, window.location.href);
        if (note(entry)) scheduleInspection();
    });
}

// =============================================================================
// Display
// =============================================================================

let overlayElement = null;
let overlayState = null;        // what is shown, so the watchdog can restore it
let overlayWatchdogTimer = null;
let noticeDismissed = false;

function stopDocument() {
    try {
        window.stop();
    } catch {
        /* nothing left to stop */
    }
}

/**
 * Decide what to show for a verdict.
 *
 * - FAILED: a blocking overlay that cannot be dismissed. An established
 *   mismatch with the signed release is not something to click through.
 * - UNVERIFIABLE where the browser could have attested the document: also
 *   blocking, with a reload, because the page was not checked at all.
 * - UNVERIFIABLE elsewhere, and suspicious findings: a notice bar. The
 *   script policy is still in force; this is information, not an alarm.
 * - Changes of unattested origin: nothing on the page. They are listed in
 *   the popup.
 */
function applyVerdict(verdict) {
    const reasons = verdict.reasons || [];
    if (verdict.integrity === V.INTEGRITY.FAILED) {
        const confirmed = reasons.filter((entry) => entry.class === V.CLASS.CONFIRMED);
        showOverlay({
            kind: 'failed',
            title: 'This page does not match the signed PinChat release',
            lead: 'Do not enter anything here. Close this page.',
            items: confirmed.length ? confirmed : reasons,
        });
        return;
    }
    if (verdict.integrity === V.INTEGRITY.UNVERIFIABLE && verdict.canAttest) {
        const serverError = reasons.some((entry) => entry.code === 'error-response');
        showOverlay({
            kind: 'unverifiable',
            title: serverError ? 'The server answered with an error' : 'This page could not be verified',
            lead: serverError
                ? 'What the server sent is not a PinChat page and is not shown. '
                    + 'If this was a link to a room, the room may no longer exist.'
                : 'Nothing was found wrong, but the page was not checked. Reload it.',
            items: reasons,
        });
        return;
    }
    const worthANotice = reasons.filter((entry) => entry.class !== V.CLASS.CONFIRMED);
    const noticeDue = verdict.integrity === V.INTEGRITY.UNVERIFIABLE || verdict.attention;
    if (noticeDue && worthANotice.length && !noticeDismissed) {
        showOverlay({
            kind: 'notice',
            title: verdict.integrity === V.INTEGRITY.UNVERIFIABLE
                ? 'PinChat Verifier: this page could not be fully checked'
                : 'PinChat Verifier: something on this page was blocked',
            lead: 'Only signed code can run here. Details are in the extension popup.',
            items: worthANotice.slice(0, 3),
        });
        return;
    }
    if (overlayState && overlayState.kind !== 'foreign') hideOverlay();
}

function showOverlay(state) {
    const same = overlayState && overlayElement && document.contains(overlayElement)
        && JSON.stringify(overlayState) === JSON.stringify(state);
    if (same) return;
    overlayState = state;
    if (overlayElement) overlayElement.remove();
    if (!document.documentElement) return;

    // The host element carries no inline style; everything comes from the
    // stylesheet loaded inside the closed shadow tree.
    overlayElement = document.createElement('div');
    overlayElement.id = 'pinchat-integrity-warning-host';
    overlayElement.setAttribute('data-kind', state.kind);
    const shadow = overlayElement.attachShadow({ mode: 'closed' });

    const link = document.createElement('link');
    link.setAttribute('rel', 'stylesheet');
    link.setAttribute('href', ext.runtime.getURL('warning.css'));
    shadow.appendChild(link);

    const box = document.createElement('div');
    box.className = `overlay overlay-${state.kind}`;
    const add = (tag, className, text) => {
        const element = document.createElement(tag);
        if (className) element.className = className;
        if (text) element.textContent = text;
        box.appendChild(element);
        return element;
    };
    add('h1', '', state.title);
    add('p', 'description', state.lead);
    if (state.items && state.items.length) {
        const list = add('ul', 'file-list');
        for (const item of state.items.slice(0, 12)) {
            const entry = document.createElement('li');
            entry.textContent = item.detail ? `${item.message} (${item.detail})` : item.message;
            list.appendChild(entry);
        }
    }
    const buttons = add('div', 'buttons');
    const button = (label, className, action) => {
        const element = document.createElement('button');
        element.className = className;
        element.textContent = label;
        element.addEventListener('click', action);
        buttons.appendChild(element);
    };
    if (state.kind === 'notice') {
        button('Dismiss', 'btn-dismiss', () => {
            noticeDismissed = true;
            hideOverlay();
        });
    } else {
        if (state.kind === 'unverifiable') {
            button('Reload', 'btn-leave', () => window.location.reload());
        }
        button('Leave this site', state.kind === 'unverifiable' ? 'btn-dismiss' : 'btn-leave', () => {
            window.location.href = 'about:blank';
        });
    }
    add('p', 'footer', 'Shown by the PinChat Integrity Verifier extension.');
    shadow.appendChild(box);

    (document.body || document.documentElement).appendChild(overlayElement);
    if (state.kind !== 'notice' && overlayWatchdogTimer === null) {
        overlayWatchdogTimer = setInterval(restoreOverlayIfTampered, 500);
    }
}

function hideOverlay() {
    overlayState = null;
    if (overlayElement) {
        overlayElement.remove();
        overlayElement = null;
    }
    if (overlayWatchdogTimer !== null) {
        clearInterval(overlayWatchdogTimer);
        overlayWatchdogTimer = null;
    }
}

/**
 * A page could try to remove or hide a blocking overlay. Put it back.
 */
function restoreOverlayIfTampered() {
    if (!overlayState || overlayState.kind === 'notice') return;
    if (!overlayElement || !document.contains(overlayElement)) {
        const state = overlayState;
        overlayElement = null;
        overlayState = null;
        showOverlay(state);
        return;
    }
    if (overlayElement.hasAttribute('style')) overlayElement.removeAttribute('style');
    if (overlayElement.hidden) overlayElement.hidden = false;
    if (overlayElement.getAttribute('class')) overlayElement.removeAttribute('class');
    if (overlayElement.getAttribute('data-kind') !== overlayState.kind) {
        overlayElement.setAttribute('data-kind', overlayState.kind);
    }
}

// =============================================================================
// Start
// =============================================================================

function warnForeignOrigin() {
    if (!document.documentElement) return;
    showOverlay({
        kind: 'foreign',
        title: 'This is not the verified PinChat address',
        lead: 'This page uses the PinChat name on an address the extension does not verify. '
            + 'Nothing on it has been checked, and it may have been sent here to get around the verification.',
        items: [{ message: window.location.origin, detail: `not one of ${OFFICIAL_ORIGINS.join(', ')}` }],
    });
}

async function start({ restored = false } = {}) {
    const policyInForce = policyIsInForce();
    const workerControlled = workerControlsDocument();

    if (!restored) watchDocument();

    if (!policyInForce || workerControlled) {
        // Nothing constrains this document. Stop it before it does anything
        // and say so without waiting for the background script.
        stopDocument();
        applyVerdict({
            integrity: V.INTEGRITY.FAILED,
            reasons: [V.finding(workerControlled ? 'service-worker-controlled' : 'policy-not-in-force')],
        });
    }

    const opened = await sendMessage({
        type: 'DOCUMENT_OPENED',
        token: DOCUMENT_TOKEN,
        policyInForce,
        workerControlled,
    });

    // The site registers no service worker. Remove any that exists, whether
    // or not it answered this navigation.
    const removed = await removeServiceWorkers();
    if (removed > 0) {
        if (!workerControlled) note(V.finding('service-worker-removed', `${removed} registration(s)`));
        if (workerControlled) {
            // Load the page again, from the network this time.
            const reply = await sendMessage({ type: 'WORKER_RELOAD_ALLOWED' });
            if (reply && reply.allowed) {
                window.location.reload();
                return;
            }
        }
    }

    if (!opened) {
        // The background script did not answer. Without it there is no
        // manifest and no state to show.
        applyVerdict({
            integrity: V.INTEGRITY.UNVERIFIABLE,
            canAttest: false,
            reasons: [V.finding('manifest-unavailable', 'the extension background did not respond')],
        });
        return;
    }
    if (opened.manifest) {
        manifestData = opened.manifest;
        buildManifestSRIMap(manifestData);
    }
    documentAttested = !!(opened.verdict && opened.verdict.attested === true);
    expectedPolicy = typeof opened.expectedPolicy === 'string' ? opened.expectedPolicy : null;
    if (opened.verdict) applyVerdict(opened.verdict);
    checkPolicyIsPackaged();

    const run = () => {
        if (manifestData) {
            inspect();
        } else {
            checksDone = true;
            report();
        }
    };
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run, { once: true });
    } else {
        run();
    }
}

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!ON_OFFICIAL_ORIGIN || !IS_TOP_LEVEL || !message) return;
    if (message.type === 'IDENTIFY') {
        // The background script asks which document this is, to tell a page
        // that rewrote its own address from a new document at that address.
        sendResponse({ token: DOCUMENT_TOKEN });
        return;
    }
    if (message.type === 'VERDICT' && message.token === DOCUMENT_TOKEN) {
        applyVerdict(message.verdict);
    }
    if (message.type === 'RECHECK') {
        sendMessage({ type: 'GET_STATUS' }).then((status) => {
            if (status && status.manifest) {
                manifestData = status.manifest;
                buildManifestSRIMap(manifestData);
                inspect({ files: true });
            }
        });
    }
});

window.addEventListener('pageshow', (event) => {
    // A document brought back from the back/forward cache was not fetched
    // again, so no response passed through the verifier this time and the
    // record of this tab now describes the page that was shown in between.
    // Announce the document again; whatever was established for it earlier
    // is not carried over.
    if (event.persisted && ON_OFFICIAL_ORIGIN && IS_TOP_LEVEL) {
        checksDone = false;
        start({ restored: true });
    }
});

if (!ON_OFFICIAL_ORIGIN) {
    // Not an origin the manifest or the packaged policy covers. Ask for no
    // state and report none: say so, and keep saying so. The catch-all rule
    // denies every script here; this covers the case where it did not apply.
    warnForeignOrigin();
    document.addEventListener('DOMContentLoaded', warnForeignOrigin);
    overlayWatchdogTimer = setInterval(restoreOverlayIfTampered, 500);
} else if (IS_TOP_LEVEL) {
    start();
}
// A framed document on the site is not inspected on its own: the policy
// allows no frames, and the top-level document's inspection reports any.
