/**
 * Login hash stash (C-03 mitigation).
 *
 * When an unauthenticated user clicks an invite link such as
 *
 *   https://pinchat.io/c/<uuid>#key=<base64url>
 *
 * the server-side `require_auth` middleware redirects them to
 *
 *   /login?redirect=/c/<uuid>
 *
 * Per RFC 7231 §7.1.2 most browsers preserve the original URL fragment
 * across 303 redirects when the Location header carries no fragment of
 * its own — which means the URL bar on /login (and later /static/login.html)
 * still shows `#key=<base64url>`. That is the E2E bootstrap secret and it
 * MUST NOT linger on a page that is not the chat itself: browser history,
 * accidental screen-shares, malicious extensions reading window.location.hash
 * on /login, etc.
 *
 * This script runs synchronously in <head>, before the login form is
 * rendered, and:
 *
 *   1. detects the bootstrap fragment `#key=...`,
 *   2. validates that we are en route to a /c/<uuid> chat page,
 *   3. moves the fragment into sessionStorage (tab-scoped, ephemeral) under
 *      a key matching what crypto.js extractKeyFromURL expects on the chat
 *      page,
 *   4. scrubs the fragment from the URL bar + history,
 *   5. installs a 5-minute safety-net cleanup of the stash key so an
 *      abandoned login doesn't leave the secret behind for the lifetime
 *      of the tab.
 *
 * After this runs, the URL bar shows /static/login.html?redirect=/c/<uuid>
 * with no fragment, and the bootstrap key survives the form-submit
 * round-trip via sessionStorage.
 */
(function () {
    'use strict';

    // Only act when we actually have a `#key=` fragment to handle. Avoids
    // running on /login GETs that are not part of an invite-link flow
    // (e.g. someone navigating manually).
    var hash = window.location.hash || '';
    if (!hash || hash.indexOf('#key=') !== 0) {
        return;
    }

    var params = new URLSearchParams(window.location.search);
    var redirect = params.get('redirect') || '';

    // Strict validation of the redirect target. We forward the fragment
    // only when the post-login destination is the chat-room page
    // /c/<base64url-safe identifier>. Anything else (open-redirect attempt,
    // arbitrary internal page, or no redirect at all) means we do not know
    // where the user should land, so we scrub the fragment but DO NOT
    // persist it — the user will be asked to re-open the invite link.
    var match = redirect.match(/^\/c\/([A-Za-z0-9\-_]+)$/);
    if (match) {
        // The crypto.js extractKeyFromURL helper looks up the stash by
        // `pinchat_hash:${window.location.pathname}`. The eventual chat
        // page is served at /static/chat.html (the /c/<uuid> route
        // server-side issues a 302 to that path with ?room=<uuid>), so
        // that is the path we key under.
        var stashKey = 'pinchat_hash:/static/chat.html';
        try {
            sessionStorage.setItem(stashKey, hash);
        } catch (_) {
            // sessionStorage full or disabled: nothing we can do; we still
            // scrub the URL because keeping the secret visible is worse
            // than losing the convenience of an automatic restore.
        }
        // Safety net: even if extractKeyFromURL consumes the stash on the
        // chat page, an abandoned login (user closes the tab on /login)
        // shouldn't leave the bootstrap secret in sessionStorage for the
        // lifetime of the tab. 5 minutes is comfortably longer than any
        // honest login round-trip.
        try {
            setTimeout(function () {
                try {
                    sessionStorage.removeItem(stashKey);
                } catch (_) {
                    /* ignore */
                }
            }, 5 * 60 * 1000);
        } catch (_) {
            /* setTimeout unavailable: nothing to do */
        }
    }

    // Always scrub the fragment from the URL bar, even when we couldn't
    // stash (no redirect, or storage full). Keeping the secret visible on
    // /login is the worse of the two failure modes.
    try {
        var clean = window.location.pathname + window.location.search;
        history.replaceState(null, '', clean);
    } catch (_) {
        /* replaceState unavailable: best-effort */
    }
})();
