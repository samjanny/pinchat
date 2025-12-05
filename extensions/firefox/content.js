/**
 * PinChat Integrity Verifier - Content Script
 * Verifies SRI (Subresource Integrity) attributes in the actual DOM
 *
 * Security model:
 * - Extension fetches signed manifest from GitHub
 * - Manifest contains expected SRI hashes for all JS/CSS files
 * - Content script verifies that DOM has correct integrity attributes
 * - Browser enforces SRI (blocks tampered files)
 * - This prevents bypass attacks where server serves different content
 */

let overlayElement = null;
let domObserver = null;
let unauthorizedResources = [];
let manifestData = null;  // Will be populated from background script
let fileHashVerificationDone = false;  // Track if we've verified file hashes
let manifestSRIMap = {};  // Map of path -> expected SRI for O(1) lookups
let reVerifyTimeout = null;  // Debounce timer for re-verification

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} - HTML-safe escaped text
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

// Allowed resource paths (JS/CSS that should have SRI)
const ALLOWED_PATHS = [
    '/static/css/style.css',
    '/static/js/alpine-csp.min.js',
    '/static/js/app.js',
    '/static/js/crypto.js',
    '/static/js/double-ratchet.js',
    '/static/js/ecdh.js',
    '/static/js/emoji.js',
    '/static/js/homepage.js',
    '/static/js/identity.js',
    '/static/js/login.js',
    '/static/js/nicknames.js',
    '/static/js/pow.js',
    '/static/js/websocket.js',
    '/static/js/debug.js'
];

/**
 * Extract pathname from a URL
 */
function getPathFromUrl(url) {
    if (!url) return null;
    try {
        if (url.startsWith('/')) {
            return url.split('?')[0].split('#')[0];
        }
        const parsed = new URL(url, window.location.origin);
        if (parsed.origin === window.location.origin) {
            return parsed.pathname;
        }
        return url;
    } catch (e) {
        return url;
    }
}

/**
 * Check if path is an internal resource that should have SRI
 */
function isInternalResource(path) {
    if (!path) return false;
    if (path.startsWith('http://') || path.startsWith('https://')) {
        return false;
    }
    return path.startsWith('/static/');
}

/**
 * Convert hex hash to SRI format (sha256-base64)
 */
function hexToSRI(hexHash) {
    // Convert hex to bytes
    const bytes = new Uint8Array(hexHash.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    // Convert to base64
    const base64 = btoa(String.fromCharCode(...bytes));
    return `sha256-${base64}`;
}

/**
 * Build the SRI map from manifest for O(1) lookups
 * Should be called whenever manifest is updated
 */
function buildManifestSRIMap(manifest) {
    manifestSRIMap = {};
    if (manifest && manifest.files) {
        manifest.files.forEach(file => {
            if (file.path && file.hash) {
                manifestSRIMap[file.path] = hexToSRI(file.hash);
            }
        });
    }
    console.log(`[PinChat Verify] Built SRI map with ${Object.keys(manifestSRIMap).length} entries`);
}

/**
 * Validate a single resource element against the manifest
 * Returns null if valid, or an issue object if invalid
 *
 * @param {HTMLElement} element - Script or Link element to validate
 * @returns {Object|null} - Issue object or null if valid
 */
function validateResourceAgainstManifest(element) {
    const isScript = element.tagName === 'SCRIPT';
    const isStylesheet = element.tagName === 'LINK' && element.rel === 'stylesheet';

    if (!isScript && !isStylesheet) {
        return null;
    }

    const urlAttr = isScript ? 'src' : 'href';
    const url = element.getAttribute(urlAttr);

    if (!url) {
        // Inline script without src
        if (isScript && element.textContent?.trim() && !element.type?.includes('application/json')) {
            return {
                path: '[inline]',
                error: 'Dynamic inline script injection',
                type: 'inline-script'
            };
        }
        return null;
    }

    const path = getPathFromUrl(url);
    const integrity = element.getAttribute('integrity');

    // Block dangerous URL schemes that could execute arbitrary code
    const dangerousSchemes = ['data:', 'blob:', 'javascript:', 'filesystem:'];
    const urlLower = url.toLowerCase();
    for (const scheme of dangerousSchemes) {
        if (urlLower.startsWith(scheme)) {
            return {
                path: url.substring(0, 50) + (url.length > 50 ? '...' : ''),
                error: `Dangerous URL scheme '${scheme}' not allowed`,
                type: isScript ? 'dangerous-script' : 'dangerous-stylesheet'
            };
        }
    }

    // Check external resources
    if (path && (path.startsWith('http://') || path.startsWith('https://'))) {
        return {
            path: path,
            error: isScript ? 'External script not allowed' : 'External stylesheet not allowed',
            type: isScript ? 'external-script' : 'external-stylesheet'
        };
    }

    // Check same-origin resources outside /static/
    if (path && path.startsWith('/') && !path.startsWith('/static/')) {
        return {
            path: path,
            error: `Unauthorized same-origin ${isScript ? 'script' : 'stylesheet'} (not in /static/)`,
            type: isScript ? 'unauthorized-script' : 'unauthorized-stylesheet'
        };
    }

    // Validate internal resources against manifest
    if (isInternalResource(path)) {
        const expectedSRI = manifestSRIMap[path];

        if (!expectedSRI) {
            return {
                path: path,
                error: `${isScript ? 'Script' : 'Stylesheet'} not in manifest`,
                type: isScript ? 'unknown-script' : 'unknown-stylesheet'
            };
        }

        if (!integrity) {
            return {
                path: path,
                error: 'Missing integrity attribute',
                type: 'missing-sri'
            };
        }

        if (integrity !== expectedSRI) {
            return {
                path: path,
                error: `SRI mismatch (expected ${expectedSRI.substring(0, 25)}...)`,
                type: 'sri-mismatch'
            };
        }
    }

    return null; // Valid resource
}

/**
 * Schedule a full re-verification with debouncing
 * Prevents excessive re-checks when multiple mutations occur
 */
function scheduleReVerification() {
    if (reVerifyTimeout) {
        clearTimeout(reVerifyTimeout);
    }
    reVerifyTimeout = setTimeout(() => {
        reVerifyTimeout = null;
        console.log('[PinChat Verify] Scheduled re-verification triggered');
        fileHashVerificationDone = false;
        performDOMSecurityCheck();
    }, 500); // 500ms debounce
}

/**
 * Calculate SHA-256 hash of content
 * @param {ArrayBuffer} buffer - Content to hash
 * @returns {Promise<string>} - Hex-encoded hash
 */
async function calculateHash(buffer) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Fetch a file and calculate its hash
 * @param {string} path - Path to fetch
 * @returns {Promise<{path: string, hash: string, error?: string}>}
 */
async function fetchAndHashFile(path) {
    try {
        const url = new URL(path, window.location.origin);
        const response = await fetch(url.href, {
            cache: 'no-store',
            credentials: 'omit' // Don't send cookies - static files should be public
        });

        if (!response.ok) {
            return { path, hash: null, error: `HTTP ${response.status}` };
        }

        const buffer = await response.arrayBuffer();
        const hash = await calculateHash(buffer);
        return { path, hash, error: null };
    } catch (e) {
        return { path, hash: null, error: e.message };
    }
}

/**
 * Verify file hashes by fetching and comparing with manifest
 * This is the definitive check - it catches:
 * - Server serving modified files (even if SRI in DOM is correct)
 * - Files blocked by browser SRI (we'll get the actual content and see mismatch)
 *
 * @param {Object} manifest - Manifest with expected hashes
 * @returns {Promise<{issues: Array, verified: Array}>}
 */
async function verifyFileHashes(manifest) {
    const issues = [];
    const verified = [];

    if (!manifest || !manifest.files) {
        return { issues: [{ path: 'manifest', error: 'No manifest data', type: 'no-manifest' }], verified: [] };
    }

    // Build expected hash map from manifest and get all files to check
    const expectedHashes = {};
    const resourcesToCheck = [];

    manifest.files.forEach(file => {
        if (file.path && file.hash) {
            expectedHashes[file.path] = file.hash;
            // Iterate on ALL manifest files, not just DOM nodes
            if (isInternalResource(file.path)) {
                resourcesToCheck.push(file.path);
            }
        }
    });

    console.log(`[PinChat Verify] Fetching and hashing ${resourcesToCheck.length} files from manifest...`);

    // Fetch and hash all files in parallel
    const results = await Promise.all(resourcesToCheck.map(fetchAndHashFile));

    for (const result of results) {
        const expectedHash = expectedHashes[result.path];

        if (result.error) {
            // Failed to fetch file
            issues.push({
                path: result.path,
                error: `Failed to fetch: ${result.error}`,
                type: 'fetch-error'
            });
            console.error(`[PinChat Verify] ✗ ${result.path}: fetch failed - ${result.error}`);
        } else if (!expectedHash) {
            // File not in manifest
            issues.push({
                path: result.path,
                error: 'File not in manifest',
                type: 'unknown-file'
            });
            console.warn(`[PinChat Verify] ? ${result.path}: not in manifest`);
        } else if (result.hash !== expectedHash) {
            // Hash mismatch - this is the critical security check
            issues.push({
                path: result.path,
                error: 'Hash mismatch - file may have been tampered',
                type: 'hash-mismatch',
                expected: expectedHash,
                actual: result.hash
            });
            console.error(`[PinChat Verify] ✗ ${result.path}: HASH MISMATCH`);
            console.error(`[PinChat Verify]   Expected: ${expectedHash}`);
            console.error(`[PinChat Verify]   Actual:   ${result.hash}`);
        } else {
            // Hash matches
            verified.push({ path: result.path, hash: result.hash });
            console.log(`[PinChat Verify] ✓ ${result.path}: hash verified`);
        }
    }

    return { issues, verified };
}

/**
 * Verify SRI attributes in the DOM against manifest
 */
function verifySRIInDOM(manifest) {
    const issues = [];

    // Build a map of path -> expected SRI from manifest
    const expectedSRI = {};
    if (manifest && manifest.files) {
        manifest.files.forEach(file => {
            if (file.path && file.hash) {
                // Convert hex hash to SRI format
                expectedSRI[file.path] = hexToSRI(file.hash);
            }
        });
    }

    // Dangerous URL schemes that could execute arbitrary code
    const dangerousSchemes = ['data:', 'blob:', 'javascript:', 'filesystem:'];

    // Check all script tags
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
        const src = script.getAttribute('src');
        const path = getPathFromUrl(src);
        const integrity = script.getAttribute('integrity');

        // Block dangerous URL schemes
        const srcLower = (src || '').toLowerCase();
        for (const scheme of dangerousSchemes) {
            if (srcLower.startsWith(scheme)) {
                issues.push({
                    path: src.substring(0, 50) + (src.length > 50 ? '...' : ''),
                    error: `Dangerous URL scheme '${scheme}' not allowed`,
                    type: 'dangerous-script'
                });
                return; // Continue to next script
            }
        }

        if (isInternalResource(path)) {
            const expected = expectedSRI[path];

            if (!expected) {
                // Unknown script - not in manifest
                issues.push({
                    path: path,
                    error: 'Script not in manifest',
                    type: 'unknown-script'
                });
            } else if (!integrity) {
                // Missing SRI attribute
                issues.push({
                    path: path,
                    error: 'Missing integrity attribute',
                    type: 'missing-sri'
                });
            } else if (integrity !== expected) {
                // SRI mismatch - server may have modified HTML
                issues.push({
                    path: path,
                    error: `SRI mismatch (expected ${expected.substring(0, 20)}...)`,
                    type: 'sri-mismatch'
                });
            }
        } else if (path && (path.startsWith('http://') || path.startsWith('https://'))) {
            // External script - flag it
            issues.push({
                path: path,
                error: 'External script not allowed',
                type: 'external-script'
            });
        } else if (path && path.startsWith('/')) {
            // Same-origin script outside /static/ - unauthorized
            issues.push({
                path: path,
                error: 'Unauthorized same-origin script (not in /static/)',
                type: 'unauthorized-script'
            });
        }
    });

    // Check for inline scripts (always unauthorized)
    const allScripts = document.querySelectorAll('script');
    allScripts.forEach(script => {
        if (!script.getAttribute('src')) {
            const content = (script.textContent || '').trim();
            // Skip JSON data scripts and empty scripts
            if (content.length > 0 && !script.type?.includes('application/json')) {
                issues.push({
                    path: '[inline]',
                    error: 'Inline script not allowed',
                    type: 'inline-script'
                });
            }
        }
    });

    // Check all stylesheet links
    const stylesheets = document.querySelectorAll('link[rel="stylesheet"]');
    stylesheets.forEach(link => {
        const href = link.getAttribute('href');
        const path = getPathFromUrl(href);
        const integrity = link.getAttribute('integrity');

        // Block dangerous URL schemes
        const hrefLower = (href || '').toLowerCase();
        for (const scheme of dangerousSchemes) {
            if (hrefLower.startsWith(scheme)) {
                issues.push({
                    path: href.substring(0, 50) + (href.length > 50 ? '...' : ''),
                    error: `Dangerous URL scheme '${scheme}' not allowed`,
                    type: 'dangerous-stylesheet'
                });
                return; // Continue to next stylesheet
            }
        }

        if (isInternalResource(path)) {
            const expected = expectedSRI[path];

            if (!expected) {
                issues.push({
                    path: path,
                    error: 'Stylesheet not in manifest',
                    type: 'unknown-stylesheet'
                });
            } else if (!integrity) {
                issues.push({
                    path: path,
                    error: 'Missing integrity attribute',
                    type: 'missing-sri'
                });
            } else if (integrity !== expected) {
                issues.push({
                    path: path,
                    error: `SRI mismatch`,
                    type: 'sri-mismatch'
                });
            }
        } else if (path && (path.startsWith('http://') || path.startsWith('https://'))) {
            issues.push({
                path: path,
                error: 'External stylesheet not allowed',
                type: 'external-stylesheet'
            });
        } else if (path && path.startsWith('/')) {
            // Same-origin stylesheet outside /static/ - unauthorized
            issues.push({
                path: path,
                error: 'Unauthorized same-origin stylesheet (not in /static/)',
                type: 'unauthorized-stylesheet'
            });
        }
    });

    // Check for CSS @import in style tags
    const styles = document.querySelectorAll('style');
    styles.forEach(style => {
        const content = style.textContent || '';
        if (/@import/i.test(content)) {
            issues.push({
                path: '[style @import]',
                error: 'CSS @import not allowed',
                type: 'css-import'
            });
        }
    });

    // Check for iframes (potential phishing)
    const iframes = document.querySelectorAll('iframe');
    iframes.forEach(iframe => {
        // Skip our own warning iframe
        if (iframe.id === 'pinchat-integrity-warning-frame') {
            return;
        }
        const src = iframe.getAttribute('src');
        if (src) {
            // Skip extension URLs (chrome-extension:// or moz-extension://)
            if (src.startsWith('chrome-extension://') || src.startsWith('moz-extension://')) {
                return;
            }
            try {
                const parsed = new URL(src, window.location.origin);
                if (parsed.origin !== window.location.origin) {
                    issues.push({
                        path: src,
                        error: 'External iframe detected',
                        type: 'external-iframe'
                    });
                }
            } catch (e) {
                // Invalid URL
            }
        }
    });

    // Check for forms pointing to external URLs
    const forms = document.querySelectorAll('form[action]');
    forms.forEach(form => {
        const action = form.getAttribute('action');
        if (action) {
            try {
                const parsed = new URL(action, window.location.origin);
                if (parsed.origin !== window.location.origin) {
                    issues.push({
                        path: action,
                        error: 'Form submits to external URL',
                        type: 'external-form'
                    });
                }
            } catch (e) {
                // Invalid URL
            }
        }
    });

    return issues;
}

/**
 * Setup MutationObserver to detect dynamically injected resources
 * and attribute modifications that could bypass initial verification
 *
 * Monitors:
 * - New script/link elements (childList)
 * - Changes to src, href, integrity, type attributes (attributes)
 */
function setupDOMObserver() {
    if (domObserver) {
        domObserver.disconnect();
    }

    domObserver = new MutationObserver((mutations) => {
        let foundUnauthorized = false;
        let needsReVerification = false;

        mutations.forEach(mutation => {
            // Handle attribute changes on existing elements
            if (mutation.type === 'attributes') {
                const target = mutation.target;
                const attrName = mutation.attributeName;

                // Only process script and stylesheet elements
                if (target.tagName === 'SCRIPT' || (target.tagName === 'LINK' && target.rel === 'stylesheet')) {
                    console.log(`[PinChat Verify] Attribute '${attrName}' modified on ${target.tagName}`);

                    // Critical attribute changed - validate against manifest
                    const issue = validateResourceAgainstManifest(target);
                    if (issue) {
                        console.warn(`[PinChat Verify] Resource validation failed after attribute change:`, issue);
                        unauthorizedResources.push(issue);
                        foundUnauthorized = true;
                    }

                    // Schedule full re-verification for thorough check
                    needsReVerification = true;
                }
            }

            // Handle new nodes
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType !== Node.ELEMENT_NODE) return;

                    // Validate the node itself if it's a resource element
                    if (node.tagName === 'SCRIPT' || (node.tagName === 'LINK' && node.rel === 'stylesheet')) {
                        const issue = validateResourceAgainstManifest(node);
                        if (issue) {
                            console.warn(`[PinChat Verify] Dynamic resource injection detected:`, issue);
                            unauthorizedResources.push(issue);
                            foundUnauthorized = true;
                        }
                    }

                    // Check children recursively for nested resource elements
                    if (node.querySelectorAll) {
                        node.querySelectorAll('script, link[rel="stylesheet"]').forEach(el => {
                            const issue = validateResourceAgainstManifest(el);
                            if (issue) {
                                console.warn(`[PinChat Verify] Nested resource injection detected:`, issue);
                                unauthorizedResources.push(issue);
                                foundUnauthorized = true;
                            }
                        });
                    }
                });
            }
        });

        if (foundUnauthorized) {
            showWarningOverlay(unauthorizedResources, true);
        }

        if (needsReVerification) {
            scheduleReVerification();
        }
    });

    domObserver.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['src', 'href', 'integrity', 'type']
    });
}

/**
 * Perform DOM security verification
 * Only runs if manifest is available
 *
 * Security model:
 * 1. Verify SRI attributes in DOM match the signed manifest
 * 2. Fetch each file and verify its hash matches the manifest
 *
 * This dual approach catches:
 * - Server modifying HTML (SRI attributes different from manifest)
 * - Server modifying files (hash different from manifest)
 * - Browser blocking files due to SRI mismatch (we fetch and see the bad hash)
 */
async function performDOMSecurityCheck() {
    // Don't verify without manifest - wait for it
    if (!manifestData || !manifestData.files) {
        console.log('[PinChat Verify] Waiting for manifest...');
        return;
    }

    // Prevent concurrent verifications
    if (fileHashVerificationDone) {
        console.log('[PinChat Verify] Verification already completed, skipping...');
        return;
    }

    console.log('[PinChat Verify] Starting security verification...');

    // Step 1: Verify SRI attributes in DOM
    console.log('[PinChat Verify] Step 1: Checking SRI attributes in DOM...');
    const domIssues = verifySRIInDOM(manifestData);

    if (domIssues.length > 0) {
        console.warn('[PinChat Verify] DOM SRI issues found:', domIssues);
    } else {
        console.log('[PinChat Verify] ✓ DOM SRI attributes match manifest');
    }

    // Step 2: Fetch files and verify hashes
    console.log('[PinChat Verify] Step 2: Fetching and verifying file hashes...');
    const { issues: hashIssues, verified } = await verifyFileHashes(manifestData);

    // Combine all issues
    const allIssues = [...domIssues, ...hashIssues];

    // Mark verification as done
    fileHashVerificationDone = true;

    // Build complete file list with all statuses (passed, failed, errors)
    const allFiles = [
        ...verified.map(v => ({ path: v.path, status: 'ok' })),
        ...hashIssues.map(i => ({ path: i.path, status: 'failed', error: i.error, type: i.type })),
        ...domIssues.map(i => ({ path: i.path, status: 'dom-issue', error: i.error, type: i.type }))
    ];

    // Build summary with correct totals (include domIssues in failed count)
    const summary = {
        total: manifestData.files ? manifestData.files.length : (verified.length + hashIssues.length),
        checked: verified.length + hashIssues.length,
        passed: verified.length,
        failed: hashIssues.length + domIssues.length,  // Include DOM issues in failed count
        hashMismatches: hashIssues.filter(i => i.type === 'hash-mismatch').length,
        fetchErrors: hashIssues.filter(i => i.type === 'fetch-error').length,
        domIssues: domIssues.length
    };

    console.log('[PinChat Verify] ========================================');
    console.log('[PinChat Verify] VERIFICATION COMPLETE');
    console.log(`[PinChat Verify] Files checked: ${summary.checked}/${summary.total}`);
    console.log(`[PinChat Verify] Passed: ${summary.passed}, Failed: ${summary.failed}`);
    if (domIssues.length > 0) {
        console.log(`[PinChat Verify] DOM issues: ${domIssues.length}`);
    }
    if (hashIssues.length > 0) {
        console.log(`[PinChat Verify] Hash issues: ${hashIssues.length}`);
    }
    console.log('[PinChat Verify] ========================================');

    // Notify background script with results (include ALL files, not just passed)
    browser.runtime.sendMessage({
        type: 'FILE_HASH_VERIFICATION_COMPLETE',
        success: allIssues.length === 0,
        files: allFiles,  // Complete list with all statuses
        issues: allIssues,
        summary: summary
    });

    // Handle all issues
    if (allIssues.length > 0) {
        console.warn('[PinChat Verify] Security issues detected:', allIssues);
        unauthorizedResources = allIssues;
        showWarningOverlay(allIssues, true);
    } else {
        console.log('[PinChat Verify] ✓ All files verified successfully');
        hideWarningOverlay();
    }
}

// Security verification now uses a dual approach:
// 1. SRI verification in DOM (check integrity attributes match manifest)
// 2. File hash verification (fetch files and compare hash with manifest)
// This catches both HTML tampering and file tampering.

/**
 * Create and show the warning overlay using Shadow DOM
 * Shadow DOM isolates styles from page CSP and allows direct content injection
 *
 * Note: Firefox MV2 requires web_accessible_resources for the CSS file.
 * This creates a minor fingerprinting vector, but only on pinchat.io domain.
 * The adoptedStyleSheets API doesn't work in Firefox content scripts due to Xray wrappers.
 */
async function showWarningOverlay(mismatches = [], isUnauthorized = false) {
    if (overlayElement) {
        overlayElement.remove();
    }

    const title = isUnauthorized
        ? 'UNAUTHORIZED RESOURCES DETECTED!'
        : 'POSSIBLE SERVER COMPROMISE!';

    const description = isUnauthorized
        ? 'This page contains scripts or stylesheets that are not in the authorized whitelist. This could indicate a compromised server or malicious injection.'
        : 'The files served by this website do not match the verified hashes.';

    const listTitle = isUnauthorized
        ? 'Unauthorized Resources:'
        : 'Failed Files:';

    // Create host element
    overlayElement = document.createElement('div');
    overlayElement.id = 'pinchat-integrity-warning-host';

    // Create closed Shadow DOM
    const shadow = overlayElement.attachShadow({ mode: 'closed' });

    // Get CSS URL from extension
    const cssUrl = browser.runtime.getURL('warning.css');

    // Build DOM structure with external stylesheet link
    // Using <link> is CSP-safe and works with Firefox Xray wrappers (unlike adoptedStyleSheets)
    shadow.innerHTML = `
        <link rel="stylesheet" href="${cssUrl}">
        <div class="overlay">
            <div class="icon">⚠️</div>
            <h1></h1>
            <p class="description"></p>
            <div class="file-list">
                <h3></h3>
                <ul></ul>
            </div>
            <div class="buttons">
                <button class="btn-leave">Leave This Site</button>
                <button class="btn-dismiss">Dismiss (Unsafe)</button>
            </div>
            <p class="footer">This warning is shown by the PinChat Integrity Verifier extension.</p>
        </div>
    `;

    // Set text content safely (prevents XSS)
    shadow.querySelector('h1').textContent = title;
    shadow.querySelector('.description').innerHTML = escapeHtml(description) + '<br><strong>Do not enter any sensitive information.</strong>';
    shadow.querySelector('.file-list h3').textContent = listTitle;

    // Build file list with proper sanitization
    const ul = shadow.querySelector('.file-list ul');
    mismatches.forEach(m => {
        const li = document.createElement('li');
        li.textContent = `${m.path}: ${m.error}`;
        ul.appendChild(li);
    });

    // Event listeners
    shadow.querySelector('.btn-leave').addEventListener('click', () => {
        window.location.href = 'about:blank';
    });

    shadow.querySelector('.btn-dismiss').addEventListener('click', () => {
        if (confirm('WARNING: You are choosing to ignore a security warning. Continue at your own risk.')) {
            hideWarningOverlay();
        }
    });

    // Append to DOM
    (document.body || document.documentElement).appendChild(overlayElement);
}

/**
 * Hide the warning overlay
 */
function hideWarningOverlay() {
    if (overlayElement) {
        overlayElement.remove();
        overlayElement = null;
    }
}

/**
 * Handle verification status from background script
 */
function handleVerificationStatus(state) {
    // Store manifest if present (regardless of overall status)
    // This is critical: signature may be valid (manifest available) while file check is still pending/checking
    if (state.manifest) {
        const isNewManifest = !manifestData ||
                             state.manifest.version !== manifestData.version ||
                             state.manifest.generated !== manifestData.generated;

        if (isNewManifest) {
            console.log('[PinChat Verify] Received new manifest from background, starting verification...');
            manifestData = state.manifest;
            // Build SRI map for O(1) lookups in MutationObserver
            buildManifestSRIMap(manifestData);
            // Reset the flag to allow new verification
            fileHashVerificationDone = false;
            // Start DOM and file hash checks
            performDOMSecurityCheck();
        } else if (fileHashVerificationDone && state.signatureStatus === 'valid' && state.fileStatus === 'checking') {
            // User pressed "Verify Now" again - reset and re-verify
            console.log('[PinChat Verify] Re-verification requested, resetting flag...');
            fileHashVerificationDone = false;
            performDOMSecurityCheck();
        }
    }

    // Handle final failure/error status with overlay
    // Show overlay for both 'failed' (verification failed) and 'error' (system errors)
    if (state.status === 'failed' || state.status === 'error') {
        if (state.mismatches && state.mismatches.length > 0) {
            // File verification failures - show specific mismatches
            showWarningOverlay(state.mismatches, false);
        } else if (state.errors && state.errors.length > 0) {
            // Global failures/errors (signature invalid, network errors, timeouts, etc.)
            // Convert errors array to mismatch format for overlay display
            const errorItems = state.errors.map(err => ({
                path: state.status === 'error' ? 'System Error' : 'Verification Error',
                error: err
            }));
            showWarningOverlay(errorItems, true);
        }
    }
}

// Listen for messages from background script
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'VERIFICATION_STATUS') {
        handleVerificationStatus(message.state);
    }
    if (message.type === 'MANIFEST_DATA') {
        manifestData = message.manifest;
        buildManifestSRIMap(manifestData);
        performDOMSecurityCheck();
    }
});

// Request current status and manifest when page loads
browser.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
    if (response) {
        if (response.manifest) {
            manifestData = response.manifest;
            buildManifestSRIMap(manifestData);
        }
        handleVerificationStatus(response);
    }
});

// Initialize DOM security monitoring
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        performDOMSecurityCheck();
        setupDOMObserver();
    });
} else {
    performDOMSecurityCheck();
    setupDOMObserver();
}

// Delayed check for late-loaded resources
setTimeout(() => {
    performDOMSecurityCheck();
}, 2000);

console.log('[PinChat Verify] Content script loaded with SRI verification');
