/**
 * Debug logging wrapper for PinChat
 *
 * Provides conditional logging that can be enabled/disabled at runtime.
 * In production, logs are suppressed by default for security.
 *
 * Usage:
 *   - Enable in browser console: window.PINCHAT_DEBUG = true
 *   - Logs are disabled by default in production
 *
 * Security:
 *   - Prevents leaking cryptographic state in production
 *   - Can be enabled for debugging without code changes
 */

(function() {
    'use strict';

    // Explicit opt-in only (prevents accidental enablement via URL substrings)
    const DEBUG_ENABLED = typeof window.PINCHAT_DEBUG !== 'undefined'
        ? !!window.PINCHAT_DEBUG
        : false;

    function isDebugEnabled() {
        return DEBUG_ENABLED;
    }

    // Debug log function - only logs if debug mode is enabled
    window.debugLog = function(...args) {
        if (isDebugEnabled()) {
            console.log(...args);
        }
    };

    // Debug warn function
    window.debugWarn = function(...args) {
        if (isDebugEnabled()) {
            console.warn(...args);
        }
    };

    // Debug error function (always logs - errors are important)
    window.debugError = function(...args) {
        console.error(...args);
    };

    // Debug info function
    window.debugInfo = function(...args) {
        if (isDebugEnabled()) {
            console.info(...args);
        }
    };

    // Debug group functions
    window.debugGroup = function(...args) {
        if (isDebugEnabled()) {
            console.group(...args);
        }
    };

    window.debugGroupEnd = function() {
        if (isDebugEnabled()) {
            console.groupEnd();
        }
    };

    // Log that debug module is loaded (only if debug enabled)
    if (isDebugEnabled()) {
        console.log('[DEBUG] PinChat debug mode ENABLED');
    }
})();
