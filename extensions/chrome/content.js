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
    '/static/js/websocket.js'
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

    // Check all script tags
    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
        const src = script.getAttribute('src');
        const path = getPathFromUrl(src);
        const integrity = script.getAttribute('integrity');

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
        const src = iframe.getAttribute('src');
        if (src) {
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
 */
function setupDOMObserver() {
    if (domObserver) {
        domObserver.disconnect();
    }

    domObserver = new MutationObserver((mutations) => {
        let foundUnauthorized = false;

        mutations.forEach(mutation => {
            mutation.addedNodes.forEach(node => {
                if (node.nodeType !== Node.ELEMENT_NODE) return;

                // Check if the added node is a script
                if (node.tagName === 'SCRIPT') {
                    const src = node.getAttribute('src');
                    if (src) {
                        const path = getPathFromUrl(src);
                        const integrity = node.getAttribute('integrity');

                        if (isInternalResource(path) && !integrity) {
                            unauthorizedResources.push({
                                path: path,
                                error: 'Dynamic script without SRI'
                            });
                            foundUnauthorized = true;
                        }
                    } else if (node.textContent?.trim() && !node.type?.includes('application/json')) {
                        unauthorizedResources.push({
                            path: '[inline]',
                            error: 'Dynamic inline script'
                        });
                        foundUnauthorized = true;
                    }
                }

                // Check for dynamic stylesheets
                if (node.tagName === 'LINK' && node.rel === 'stylesheet') {
                    const href = node.getAttribute('href');
                    const path = getPathFromUrl(href);
                    const integrity = node.getAttribute('integrity');

                    if (isInternalResource(path) && !integrity) {
                        unauthorizedResources.push({
                            path: path,
                            error: 'Dynamic stylesheet without SRI'
                        });
                        foundUnauthorized = true;
                    }
                }

                // Check children recursively
                if (node.querySelectorAll) {
                    node.querySelectorAll('script, link[rel="stylesheet"]').forEach(el => {
                        if (el.tagName === 'SCRIPT') {
                            const src = el.getAttribute('src');
                            if (src && isInternalResource(getPathFromUrl(src)) && !el.getAttribute('integrity')) {
                                unauthorizedResources.push({
                                    path: getPathFromUrl(src),
                                    error: 'Injected script without SRI'
                                });
                                foundUnauthorized = true;
                            }
                        }
                    });
                }
            });
        });

        if (foundUnauthorized) {
            showWarningOverlay(unauthorizedResources, true);
        }
    });

    domObserver.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
}

/**
 * Perform DOM security verification
 * Only runs if manifest is available
 */
function performDOMSecurityCheck() {
    // Don't verify without manifest - wait for it
    if (!manifestData || !manifestData.files) {
        console.log('[PinChat Verify] Waiting for manifest...');
        return;
    }

    const issues = verifySRIInDOM(manifestData);

    if (issues.length > 0) {
        console.warn('[PinChat Verify] Security issues detected:', issues);
        unauthorizedResources = issues;
        showWarningOverlay(issues, true);
    } else {
        console.log('[PinChat Verify] DOM security check passed');
        hideWarningOverlay();
    }
}

/**
 * Create and show the warning overlay
 */
function showWarningOverlay(mismatches = [], isUnauthorized = false) {
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

    overlayElement = document.createElement('div');
    overlayElement.id = 'pinchat-integrity-warning';

    // Apply styles directly to the overlay element
    overlayElement.style.cssText = `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        right: 0 !important;
        bottom: 0 !important;
        width: 100vw !important;
        height: 100vh !important;
        background: rgba(220, 38, 38, 0.98) !important;
        z-index: 2147483647 !important;
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        color: white !important;
        padding: 20px !important;
        box-sizing: border-box !important;
        margin: 0 !important;
    `;

    overlayElement.innerHTML = `
        <div style="font-size: 72px; margin-bottom: 20px;">⚠️</div>

        <h1 style="
            font-size: 48px;
            font-weight: bold;
            margin: 0 0 20px 0;
            text-align: center;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            color: white;
        ">${title}</h1>

        <p style="
            font-size: 24px;
            margin: 0 0 30px 0;
            text-align: center;
            max-width: 800px;
            line-height: 1.5;
            color: white;
        ">
            ${description}
            <br>
            <strong>Do not enter any sensitive information.</strong>
        </p>

        <div style="
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 10px;
            max-width: 600px;
            width: 100%;
            max-height: 200px;
            overflow-y: auto;
            margin-bottom: 30px;
        ">
            <h3 style="margin: 0 0 10px 0; font-size: 18px; color: white;">${listTitle}</h3>
            <ul style="margin: 0; padding-left: 20px; font-size: 14px; font-family: monospace; color: white;">
                ${mismatches.map(m => `<li>${m.path}: ${m.error}</li>`).join('')}
            </ul>
        </div>

        <div style="display: flex; gap: 20px;">
            <button id="pinchat-leave-btn" style="
                background: white;
                color: #dc2626;
                border: none;
                padding: 15px 40px;
                font-size: 18px;
                font-weight: bold;
                border-radius: 8px;
                cursor: pointer;
            ">Leave This Site</button>

            <button id="pinchat-dismiss-btn" style="
                background: transparent;
                color: white;
                border: 2px solid white;
                padding: 15px 40px;
                font-size: 18px;
                font-weight: bold;
                border-radius: 8px;
                cursor: pointer;
                opacity: 0.7;
            ">Dismiss (Unsafe)</button>
        </div>

        <p style="margin-top: 30px; font-size: 14px; opacity: 0.8; color: white;">
            This warning is shown by the PinChat Integrity Verifier extension.
        </p>
    `;

    // Append to body if available, otherwise to documentElement
    (document.body || document.documentElement).appendChild(overlayElement);

    document.getElementById('pinchat-leave-btn').addEventListener('click', () => {
        window.location.href = 'about:blank';
    });

    document.getElementById('pinchat-dismiss-btn').addEventListener('click', () => {
        if (confirm('WARNING: You are choosing to ignore a security warning. Continue at your own risk.')) {
            hideWarningOverlay();
        }
    });
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
    if (state.status === 'failed') {
        showWarningOverlay(state.mismatches);
    } else if (state.status === 'verified') {
        // Store manifest data for DOM verification
        if (state.manifest) {
            manifestData = state.manifest;
            // Re-run DOM check with manifest data
            performDOMSecurityCheck();
        }
    }
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'VERIFICATION_STATUS') {
        handleVerificationStatus(message.state);
    }
    if (message.type === 'MANIFEST_DATA') {
        manifestData = message.manifest;
        performDOMSecurityCheck();
    }
});

// Request current status and manifest when page loads
chrome.runtime.sendMessage({ type: 'GET_STATUS' }, (response) => {
    if (response) {
        if (response.manifest) {
            manifestData = response.manifest;
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
