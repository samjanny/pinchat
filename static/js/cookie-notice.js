/**
 * PinChat — Cookie notice (informational only).
 *
 * The site uses only strictly-necessary cookies (session, CSRF). Under
 * GDPR/ePrivacy these don't require consent, so this is a transparency
 * notice — not a consent banner. Dismissed state lives in localStorage,
 * never in a cookie, so dismissing it does not itself create tracking.
 *
 * Versioned key (`_v1`) so we can re-show the notice if the cookie set
 * meaningfully changes in a future release.
 */
(function () {
    'use strict';

    var KEY = 'pinchat_cookie_notice_v1';

    function init() {
        try {
            if (localStorage.getItem(KEY) === 'dismissed') return;
        } catch (_) {
            // localStorage unavailable (private mode + restrictions): just show
            // the notice every visit. Harmless.
        }

        var el = document.getElementById('cookie-notice');
        if (!el) return;
        el.classList.remove('hidden');

        var btn = el.querySelector('.cookie-notice-ok');
        if (!btn) return;
        btn.addEventListener('click', function () {
            try { localStorage.setItem(KEY, 'dismissed'); } catch (_) { /* ignore */ }
            el.classList.add('hidden');
        }, { once: true });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
