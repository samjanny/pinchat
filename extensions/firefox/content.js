/**
 * PinChat Integrity Verifier - Firefox Content Script
 * Shows warning overlay if verification fails
 *
 * Security features:
 * - Verifies hashes of known files
 * - Detects unauthorized scripts/stylesheets not in whitelist
 * - Uses MutationObserver to detect dynamic injections
 */

let overlayElement = null;
let authorizedPaths = null;
let domObserver = null;
let unauthorizedResources = [];

// Whitelist of allowed resource paths (must match generate-hashes.js)
const ALLOWED_PATHS = [
    '/index.html',
    '/login.html',
    '/chat.html',
    '/css/style.css',
    '/js/alpine-csp.min.js',
    '/js/app.js',
    '/js/crypto.js',
    '/js/double-ratchet.js',
    '/js/ecdh.js',
    '/js/emoji.js',
    '/js/homepage.js',
    '/js/identity.js',
    '/js/nicknames.js',
    '/js/pow.js',
    '/js/websocket.js'
];

// Allowed inline script hashes (for legitimate inline scripts if any)
const ALLOWED_INLINE_HASHES = [];

/**
 * Extract pathname from a URL, handling both absolute and relative URLs
 */
function getPathFromUrl(url) {
    if (!url) return null;
    try {
        // Handle relative URLs
        if (url.startsWith('/')) {
            return url.split('?')[0].split('#')[0];
        }
        // Handle absolute URLs
        const parsed = new URL(url, window.location.origin);
        // Only check resources from the same origin
        if (parsed.origin === window.location.origin) {
            return parsed.pathname;
        }
        // External resources - return full URL for logging
        return url;
    } catch (e) {
        return url;
    }
}

/**
 * Check if a resource path is authorized
 */
function isAuthorizedPath(path) {
    if (!path) return true; // Inline resources handled separately

    // Check if it's an external resource (different origin)
    if (path.startsWith('http://') || path.startsWith('https://')) {
        // External resources are NOT authorized unless explicitly whitelisted
        // This prevents loading malicious scripts from other domains
        return false;
    }

    // Check against whitelist
    return ALLOWED_PATHS.includes(path);
}

/**
 * Scan the DOM for unauthorized scripts and stylesheets
 */
function scanDOMForUnauthorizedResources() {
    const unauthorized = [];

    // Check all script tags
    const scripts = document.querySelectorAll('script');
    scripts.forEach(script => {
        const src = script.getAttribute('src');
        if (src) {
            const path = getPathFromUrl(src);
            if (!isAuthorizedPath(path)) {
                unauthorized.push({
                    type: 'script',
                    path: path || src,
                    element: script.outerHTML.substring(0, 100)
                });
            }
        } else if (script.textContent && script.textContent.trim()) {
            // Inline script - check if it's allowed
            // For now, flag all inline scripts as they could be injected
            const content = script.textContent.trim();
            if (content.length > 0 && !script.type?.includes('application/json')) {
                // Skip JSON data scripts (like Alpine.js data)
                unauthorized.push({
                    type: 'inline-script',
                    path: '[inline]',
                    element: `<script>${content.substring(0, 50)}...</script>`
                });
            }
        }
    });

    // Check all stylesheet links
    const stylesheets = document.querySelectorAll('link[rel="stylesheet"]');
    stylesheets.forEach(link => {
        const href = link.getAttribute('href');
        if (href) {
            const path = getPathFromUrl(href);
            if (!isAuthorizedPath(path)) {
                unauthorized.push({
                    type: 'stylesheet',
                    path: path || href,
                    element: link.outerHTML.substring(0, 100)
                });
            }
        }
    });

    // Check for style tags with @import (could load external CSS)
    const styles = document.querySelectorAll('style');
    styles.forEach(style => {
        const content = style.textContent || '';
        const importMatches = content.match(/@import\s+(?:url\()?['"]?([^'")\s]+)/gi);
        if (importMatches) {
            importMatches.forEach(match => {
                unauthorized.push({
                    type: 'css-import',
                    path: match,
                    element: `<style>@import detected</style>`
                });
            });
        }
    });

    return unauthorized;
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

                // Check if the added node is a script or stylesheet
                if (node.tagName === 'SCRIPT') {
                    const src = node.getAttribute('src');
                    const path = src ? getPathFromUrl(src) : '[inline]';

                    if (src && !isAuthorizedPath(path)) {
                        unauthorizedResources.push({
                            type: 'script (dynamic)',
                            path: path,
                            error: 'Unauthorized script injected dynamically'
                        });
                        foundUnauthorized = true;
                    } else if (!src && node.textContent?.trim() && !node.type?.includes('application/json')) {
                        unauthorizedResources.push({
                            type: 'inline-script (dynamic)',
                            path: '[inline]',
                            error: 'Inline script injected dynamically'
                        });
                        foundUnauthorized = true;
                    }
                }

                if (node.tagName === 'LINK' && node.rel === 'stylesheet') {
                    const href = node.getAttribute('href');
                    const path = href ? getPathFromUrl(href) : null;

                    if (!isAuthorizedPath(path)) {
                        unauthorizedResources.push({
                            type: 'stylesheet (dynamic)',
                            path: path || href,
                            error: 'Unauthorized stylesheet injected dynamically'
                        });
                        foundUnauthorized = true;
                    }
                }

                // Also check children of added nodes
                if (node.querySelectorAll) {
                    const scripts = node.querySelectorAll('script');
                    const links = node.querySelectorAll('link[rel="stylesheet"]');

                    scripts.forEach(script => {
                        const src = script.getAttribute('src');
                        const path = src ? getPathFromUrl(src) : '[inline]';
                        if (src && !isAuthorizedPath(path)) {
                            unauthorizedResources.push({
                                type: 'script (dynamic)',
                                path: path,
                                error: 'Unauthorized script in injected HTML'
                            });
                            foundUnauthorized = true;
                        }
                    });

                    links.forEach(link => {
                        const href = link.getAttribute('href');
                        const path = href ? getPathFromUrl(href) : null;
                        if (!isAuthorizedPath(path)) {
                            unauthorizedResources.push({
                                type: 'stylesheet (dynamic)',
                                path: path || href,
                                error: 'Unauthorized stylesheet in injected HTML'
                            });
                            foundUnauthorized = true;
                        }
                    });
                }
            });
        });

        if (foundUnauthorized) {
            showUnauthorizedResourceWarning(unauthorizedResources);
        }
    });

    // Observe the entire document for added nodes
    domObserver.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
}

/**
 * Show warning for unauthorized resources
 */
function showUnauthorizedResourceWarning(resources) {
    const mismatches = resources.map(r => ({
        path: r.path,
        error: `Unauthorized ${r.type}: ${r.error || 'Not in whitelist'}`
    }));

    showWarningOverlay(mismatches, true);
}

/**
 * Perform initial DOM scan
 */
function performDOMSecurityCheck() {
    const unauthorized = scanDOMForUnauthorizedResources();

    if (unauthorized.length > 0) {
        console.warn('[PinChat Verify] Unauthorized resources detected:', unauthorized);
        unauthorizedResources = unauthorized.map(r => ({
            path: r.path,
            error: `Unauthorized ${r.type}`
        }));
        showUnauthorizedResourceWarning(unauthorizedResources);
    }
}

/**
 * Create and show the warning overlay
 * @param {Array} mismatches - List of mismatched/unauthorized resources
 * @param {boolean} isUnauthorized - True if warning is for unauthorized resources (not hash mismatch)
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
    overlayElement.innerHTML = `
        <div style="
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(220, 38, 38, 0.95);
            z-index: 2147483647;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: white;
            padding: 20px;
            box-sizing: border-box;
        ">
            <div style="
                font-size: 72px;
                margin-bottom: 20px;
            ">⚠️</div>

            <h1 style="
                font-size: 48px;
                font-weight: bold;
                margin: 0 0 20px 0;
                text-align: center;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            ">${title}</h1>

            <p style="
                font-size: 24px;
                margin: 0 0 30px 0;
                text-align: center;
                max-width: 800px;
                line-height: 1.5;
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
                <h3 style="margin: 0 0 10px 0; font-size: 18px;">${listTitle}</h3>
                <ul style="margin: 0; padding-left: 20px; font-size: 14px; font-family: monospace;">
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
                    transition: transform 0.2s;
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
                    transition: opacity 0.2s;
                ">Dismiss (Unsafe)</button>
            </div>

            <p style="
                margin-top: 30px;
                font-size: 14px;
                opacity: 0.8;
            ">
                This warning is shown by the PinChat Integrity Verifier extension.
            </p>
        </div>
    `;

    document.documentElement.appendChild(overlayElement);

    // Event listeners
    document.getElementById('pinchat-leave-btn').addEventListener('click', () => {
        window.location.href = 'about:blank';
    });

    document.getElementById('pinchat-dismiss-btn').addEventListener('click', () => {
        if (confirm('WARNING: You are choosing to ignore a security warning. ' +
                    'The server may be compromised. Continue at your own risk.')) {
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
 * Handle verification status updates
 */
function handleVerificationStatus(state) {
    if (state.status === 'failed') {
        showWarningOverlay(state.mismatches);
    } else if (state.status === 'verified') {
        hideWarningOverlay();
    }
}

// Listen for messages from background script
browser.runtime.onMessage.addListener((message, sender) => {
    if (message.type === 'VERIFICATION_STATUS') {
        handleVerificationStatus(message.state);
    }
});

// Request current status when page loads
browser.runtime.sendMessage({ type: 'GET_STATUS' }).then((response) => {
    if (response) {
        handleVerificationStatus(response);
    }
}).catch(() => {
    // Background script might not be ready yet
});

// Initialize DOM security monitoring
// Wait for DOM to be ready before scanning
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        performDOMSecurityCheck();
        setupDOMObserver();
    });
} else {
    // DOM is already ready
    performDOMSecurityCheck();
    setupDOMObserver();
}

// Also perform a delayed check to catch late-loaded resources
setTimeout(() => {
    performDOMSecurityCheck();
}, 2000);

console.log('[PinChat Verify] Content script loaded with DOM security monitoring');
