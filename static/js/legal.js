/**
 * Operator-data injector for the legal pages (terms, privacy).
 *
 * Security model:
 *   - This JS file, plus the HTML templates it operates on, are covered by
 *     the signed manifest and verified by the PinChat extension via SRI.
 *     Tampering with either is caught by the extension.
 *   - The operator-specific values (name, contact email, PEC, hosting, etc.)
 *     live in /static/operator.json, which is intentionally NOT in the signed
 *     manifest: it is deployment-specific data, different per operator.
 *   - All substitution is done with textContent / href, never innerHTML.
 *     Even if an attacker compromised the server and tampered with
 *     operator.json, they could only change displayed text — not inject
 *     script, HTML, or navigate to hostile origins. Mailto links are
 *     sanity-checked to be syntactically plausible email addresses before
 *     being assigned.
 *
 * Template conventions:
 *   <span data-legal="OPERATOR_NAME">fallback</span>
 *     → text replaced with operator.OPERATOR_NAME
 *   <a data-legal-mailto="OPERATOR_EMAIL_SUPPORT" href="#">...</a>
 *     → href replaced with "mailto:" + operator.OPERATOR_EMAIL_SUPPORT
 *   <p data-legal-optional="OPERATOR_FOO">...</p>
 *     → element is removed entirely when operator.OPERATOR_FOO is missing
 *       or an empty string, so the page does not render orphan paragraphs.
 *
 * If operator.json cannot be fetched or does not contain a requested key,
 * the template's fallback text (or the inert "#" href) remains, so the
 * page degrades safely instead of showing empty gaps.
 */
(function () {
    'use strict';

    function isSafeEmail(value) {
        return typeof value === 'string'
            && value.length <= 254
            && /^[^\s@<>"']+@[^\s@<>"']+\.[^\s@<>"']+$/.test(value);
    }

    function isSafeHttpsUrl(value) {
        if (typeof value !== 'string' || value.length > 2048) return false;
        try {
            var u = new URL(value);
            // Only https:// to avoid javascript:, data:, file:, http:, etc.
            return u.protocol === 'https:';
        } catch (e) {
            return false;
        }
    }

    function applyOperatorData(op) {
        if (!op || typeof op !== 'object') return;

        document.querySelectorAll('[data-legal-optional]').forEach(function (el) {
            var key = el.getAttribute('data-legal-optional');
            if (!key) return;
            var value = op[key];
            if (typeof value !== 'string' || value.length === 0) {
                el.parentNode && el.parentNode.removeChild(el);
            }
        });

        document.querySelectorAll('[data-legal]').forEach(function (el) {
            var key = el.getAttribute('data-legal');
            if (!key) return;
            var value = op[key];
            if (typeof value === 'string' && value.length > 0) {
                el.textContent = value;
            }
        });

        document.querySelectorAll('[data-legal-mailto]').forEach(function (el) {
            var key = el.getAttribute('data-legal-mailto');
            if (!key) return;
            var value = op[key];
            if (isSafeEmail(value)) {
                el.setAttribute('href', 'mailto:' + value);
            }
        });

        document.querySelectorAll('[data-legal-href]').forEach(function (el) {
            var key = el.getAttribute('data-legal-href');
            if (!key) return;
            var value = op[key];
            if (isSafeHttpsUrl(value)) {
                el.setAttribute('href', value);
            }
        });
    }

    function load() {
        fetch('/static/operator.json', { credentials: 'same-origin' })
            .then(function (res) {
                if (!res.ok) throw new Error('operator.json not available');
                return res.json();
            })
            .then(applyOperatorData)
            .catch(function () {
                // Silent: fallback text in the template stays.
            });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', load);
    } else {
        load();
    }
})();
