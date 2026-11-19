/**
 * PinChat Integrity Verifier - verdict logic.
 *
 * Pure functions, no browser API. The background script, the content script
 * and the popup all load this file, and tests/test-verifier-verdict.js runs
 * it under Node, so what a state means is defined in exactly one place.
 *
 * Two separate questions are answered here and must never be merged:
 *
 *   1. Integrity: what did the server deliver to this document, and how much
 *      of that was actually checked against the signed release?
 *   2. Environment: did anything else touch the page afterwards? Other
 *      extensions do, legitimately. The verifier cannot tell who added a
 *      node to the DOM, so such observations are listed, never judged, and
 *      never change the answer to the first question.
 */

(function (root, factory) {
    const api = factory();
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.PinChatVerdict = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, () => {
    'use strict';

    /**
     * Integrity states of one document.
     *
     * VERIFIED      The bytes of the navigation response were compared with
     *               the signed hash before the parser saw them, and the
     *               packaged policy is in force. Only reachable where the
     *               browser lets an extension hold a response body.
     * PARTIAL       The packaged policy is in force, so only signed scripts
     *               can run, but the document itself was not attested.
     * FAILED        A discrepancy with the signed release was established.
     * UNVERIFIABLE  The check could not be made. Absence of proof, not
     *               evidence of tampering.
     * CHECKING      Not decided yet. Never shown as a positive state.
     */
    const INTEGRITY = Object.freeze({
        VERIFIED: 'verified',
        PARTIAL: 'partial',
        FAILED: 'failed',
        UNVERIFIABLE: 'unverifiable',
        CHECKING: 'checking',
    });

    /**
     * Classes of findings.
     *
     * CONFIRMED    Established discrepancy between what the server delivered
     *              and the signed release. Leads to FAILED. Cannot be
     *              dismissed.
     * SUSPICIOUS   Something the policy blocked, or an oddity, that points at
     *              the page but cannot be pinned on the server. Shown as a
     *              notice; does not by itself change the integrity state.
     * LIMIT        The verifier could not do its job. Leads to UNVERIFIABLE.
     * ENVIRONMENT  A change to the page whose origin cannot be attested,
     *              typically another extension. Listed only.
     */
    const CLASS = Object.freeze({
        CONFIRMED: 'confirmed',
        SUSPICIOUS: 'suspicious',
        LIMIT: 'limit',
        ENVIRONMENT: 'environment',
    });

    /**
     * Every finding the extension can raise, with its class and the sentence
     * shown to the user. Keeping the catalogue here means a finding cannot be
     * raised with an ad hoc severity somewhere else.
     */
    const FINDINGS = Object.freeze({
        // ---- confirmed ----------------------------------------------------
        'document-hash-mismatch': [CLASS.CONFIRMED,
            'The page sent by the server is not the signed page.'],
        'file-hash-mismatch': [CLASS.CONFIRMED,
            'A file served by the site differs from the signed release.'],
        'unsigned-stylesheet': [CLASS.CONFIRMED,
            'A stylesheet from the site that is not part of the signed release was loaded.'],
        'policy-not-in-force': [CLASS.CONFIRMED,
            'The verifier\'s script policy is not in force on this page, so nothing limits what it runs.'],
        'service-worker-controlled': [CLASS.CONFIRMED,
            'This page was served by a service worker instead of the network. The site does not use one.'],
        'manifest-invalid': [CLASS.CONFIRMED,
            'The signed release manifest failed its signature or anti-rollback check.'],
        'redirect-off-site': [CLASS.CONFIRMED,
            'The server tried to redirect this link to another site. A link carries its key after the "#", '
            + 'and the redirect would have handed that key over. The navigation was stopped.'],
        // ---- suspicious ---------------------------------------------------
        'blocked-script': [CLASS.SUSPICIOUS,
            'The page contains a script that is not part of the signed release. It was not run.'],
        'page-policy-violation': [CLASS.SUSPICIOUS,
            'The page itself tried something the script policy forbids. It was blocked.'],
        'blocked-element': [CLASS.SUSPICIOUS,
            'The page contains an element that the policy does not allow. It was blocked.'],
        'service-worker-removed': [CLASS.SUSPICIOUS,
            'A service worker was registered for this site and has been removed. The site does not use one.'],
        'file-unreachable': [CLASS.SUSPICIOUS,
            'A file of the signed release could not be downloaded from the site.'],
        // ---- limits -------------------------------------------------------
        'manifest-unavailable': [CLASS.LIMIT,
            'The signed release manifest could not be obtained, so nothing could be compared.'],
        'document-not-attested': [CLASS.LIMIT,
            'This page was loaded without passing through the verifier. Reload it.'],
        'unlisted-document': [CLASS.LIMIT,
            'The server answered with a page that is not part of the signed release.'],
        'document-too-large': [CLASS.LIMIT,
            'The page was larger than any signed page and was not read.'],
        // ---- environment --------------------------------------------------
        'inline-script-element': [CLASS.ENVIRONMENT,
            'An inline script element was added to the page. The policy does not run inline scripts.'],
        'extension-resource': [CLASS.ENVIRONMENT,
            'A resource of another browser extension was added to the page.'],
        'inline-style-element': [CLASS.ENVIRONMENT,
            'An inline style element was added to the page.'],
        'extension-policy-violation': [CLASS.ENVIRONMENT,
            'Another extension tried something the script policy forbids. It was blocked.'],
        'unattributed-policy-violation': [CLASS.ENVIRONMENT,
            'Something the script policy forbids was attempted and blocked. Its origin is unknown.'],
    });

    function finding(code, detail) {
        const entry = FINDINGS[code];
        if (!entry) throw new Error(`unknown finding code: ${code}`);
        return { code, class: entry[0], message: entry[1], detail: detail ? String(detail).slice(0, 300) : '' };
    }

    /**
     * Maps the DOM inspection's issue types to finding codes.
     *
     * The inspection looks at elements, and an element says nothing about
     * who put it there. So the mapping is by consequence, not by blame:
     *
     * - Something the policy stops from running or loading cannot hurt and
     *   proves nothing about the server. Script elements land in SUSPICIOUS
     *   when they name a site or web URL, ENVIRONMENT when they are inline
     *   or come from an extension.
     * - A stylesheet from the site's own origin that is not in the signed
     *   release is different: the policy allows same-origin styles, so it
     *   was loaded, and the unsigned bytes came from the server whoever
     *   linked them. That is CONFIRMED.
     */
    const ISSUE_CODES = Object.freeze({
        'inline-script': 'inline-script-element',
        'extension-script': 'extension-resource',
        'extension-frame': 'extension-resource',
        'css-import': 'inline-style-element',
        'dangerous-script': 'blocked-script',
        'type-confusion-script': 'blocked-script',
        'unknown-script': 'blocked-script',
        'unauthorized-script': 'blocked-script',
        'external-script': 'blocked-script',
        'missing-sri': 'blocked-script',
        'sri-mismatch': 'blocked-script',
        'unknown-stylesheet': 'unsigned-stylesheet',
        'unauthorized-stylesheet': 'unsigned-stylesheet',
        'type-confusion-stylesheet': 'unsigned-stylesheet',
        'stylesheet-missing-sri': 'unsigned-stylesheet',
        'stylesheet-sri-mismatch': 'unsigned-stylesheet',
        'dangerous-stylesheet': 'blocked-element',
        'external-stylesheet': 'blocked-element',
        'external-iframe': 'blocked-element',
        'external-form': 'blocked-element',
        'base-invalid': 'blocked-element',
        'base-cross-origin': 'blocked-element',
        'base-unexpected': 'blocked-element',
        'hash-mismatch': 'file-hash-mismatch',
        'fetch-error': 'file-unreachable',
        'unknown-file': 'file-unreachable',
    });

    function findingForIssue(issue) {
        const code = ISSUE_CODES[issue.type];
        if (!code) return finding('blocked-element', `${issue.path}: ${issue.error}`);
        return finding(code, `${issue.path}: ${issue.error}`);
    }

    const EXTENSION_SCHEMES = ['chrome-extension:', 'moz-extension:', 'safari-web-extension:'];

    function isExtensionUrl(url) {
        return EXTENSION_SCHEMES.some((scheme) => String(url || '').startsWith(scheme));
    }

    /**
     * Classifies a securitypolicyviolation event.
     *
     * A violation proves that the policy is working and that the thing did
     * not run; it does not prove who tried. Chromium names the script that
     * made the attempt in `sourceFile`: the document's own URL when the
     * parser met an inline script in the HTML, an extension URL when an
     * extension's code did it. Firefox is less precise. Only an attempt
     * attributed to the document itself points at the page, and even that is
     * SUSPICIOUS, not CONFIRMED: another extension can write markup into the
     * document that the parser then trips over.
     */
    function findingForViolation(violation, documentUrl) {
        const source = String(violation.sourceFile || '');
        const what = `${violation.effectiveDirective || violation.violatedDirective || 'policy'}`
            + ` blocked ${violation.blockedURI || 'inline'}`;
        if (isExtensionUrl(source) || isExtensionUrl(violation.blockedURI)) {
            return finding('extension-policy-violation', what);
        }
        // Browsers report the source without the fragment, and Chromium
        // without the query string too. Compare scheme, host and path.
        const bare = (url) => String(url || '').split(/[?#]/)[0];
        if (source && bare(source) === bare(documentUrl)) {
            return finding('page-policy-violation', what);
        }
        return finding('unattributed-policy-violation', `${what}${source ? ` (from ${source.slice(0, 80)})` : ''}`);
    }

    /**
     * Decides the integrity state of one document.
     *
     * record:
     *   manifest        'valid' | 'invalid' | 'unavailable' | 'unknown'
     *   official        the document is on one of the official origins
     *   topLevel        the document is the top-level document of its tab
     *   checksDone      the content script finished its inspection
     *   policyInForce   the canary showed the packaged policy applies
     *   workerControlled  a service worker controls the document
     *   canAttest       this browser lets the extension hold response bodies
     *   attested        the response body of this very document was compared
     *                   with the signed hash before it was parsed
     *   findings        list of findings raised for the document
     */
    function decide(record) {
        const findings = Array.isArray(record.findings) ? record.findings : [];
        const has = (cls) => findings.some((entry) => entry.class === cls);
        const attention = has(CLASS.SUSPICIOUS);

        if (!record.official) {
            // Not a document this extension vouches for in any way.
            return { integrity: INTEGRITY.UNVERIFIABLE, attention };
        }
        if (record.manifest === 'invalid' || has(CLASS.CONFIRMED)
            || record.policyInForce === false || record.workerControlled === true) {
            return { integrity: INTEGRITY.FAILED, attention };
        }
        if (record.manifest === 'unavailable' || has(CLASS.LIMIT)) {
            return { integrity: INTEGRITY.UNVERIFIABLE, attention };
        }
        if (record.manifest !== 'valid' || !record.checksDone || record.policyInForce !== true) {
            return { integrity: INTEGRITY.CHECKING, attention };
        }
        if (record.canAttest) {
            // Where attestation is possible, its absence is not a lesser
            // positive state: the document simply was not checked.
            return record.attested === true && record.topLevel !== false
                ? { integrity: INTEGRITY.VERIFIED, attention }
                : { integrity: INTEGRITY.UNVERIFIABLE, attention };
        }
        return { integrity: INTEGRITY.PARTIAL, attention };
    }

    /** Badge shown on the toolbar button for a tab. Green only for VERIFIED. */
    function badge(integrity, attention) {
        switch (integrity) {
        case INTEGRITY.VERIFIED:
            return attention ? { text: '!', color: '#f59e0b' } : { text: 'OK', color: '#16a34a' };
        case INTEGRITY.PARTIAL:
            return attention ? { text: '!', color: '#f59e0b' } : { text: '~', color: '#2563eb' };
        case INTEGRITY.FAILED:
            return { text: '!', color: '#dc2626' };
        case INTEGRITY.UNVERIFIABLE:
            return { text: '?', color: '#f59e0b' };
        case INTEGRITY.CHECKING:
            return { text: '...', color: '#6b7280' };
        default:
            return { text: '', color: '#6b7280' };
        }
    }

    /** One-line headline for a state, as shown in the popup. */
    function headline(integrity) {
        switch (integrity) {
        case INTEGRITY.VERIFIED:
            return 'The page and the code received from the server match the signed release.';
        case INTEGRITY.PARTIAL:
            return 'Only signed code can run on this page. The page itself could not be attested in this browser.';
        case INTEGRITY.FAILED:
            return 'This page does not match the signed release.';
        case INTEGRITY.UNVERIFIABLE:
            return 'This page could not be verified.';
        case INTEGRITY.CHECKING:
            return 'Checking this page.';
        default:
            return 'No information about this page.';
        }
    }

    /**
     * Whether a redirect may be followed by a document navigation on the
     * site.
     *
     * An invite link carries its key in the URL fragment, and browsers carry
     * a fragment across HTTP redirects, to another origin too, unless the
     * Location header names a fragment of its own. A server that answers an
     * invite link with a redirect to an origin it controls therefore
     * receives the key in that origin's `location.hash`. So a navigation
     * may be redirected to the site and nowhere else.
     *
     * `location` is resolved against `fromUrl` exactly as a browser does,
     * which settles scheme-relative, backslash and other odd forms.
     *
     * The one exception is EXTERNAL_REDIRECT_TARGETS, and only for a
     * navigation whose address carries no fragment: with nothing after the
     * "#" there is nothing a redirect could hand over.
     */
    function isAllowedRedirect(fromUrl, location, officialOrigins, externalTargets = []) {
        let target;
        let from;
        try {
            target = new URL(location, fromUrl);
            from = new URL(fromUrl);
        } catch (_) {
            return false;
        }
        if (officialOrigins.includes(target.origin)) return true;
        if (from.hash !== '') return false;
        return externalTargets.some((pattern) => (pattern.endsWith('*')
            ? target.href.startsWith(pattern.slice(0, -1))
            : target.href === pattern));
    }

    /**
     * The places outside the site that the site itself sends a visitor to
     * with a redirect: the "Add to Chrome" and "Add to Firefox" buttons of
     * the home page go through /ext/chrome and /ext/firefox, which the
     * reverse proxy answers with a redirect to the release page today and
     * to the store listings once they exist.
     *
     * Each entry is either a complete address or a prefix ending in "*",
     * and every prefix ends after the "/" that closes the host name, so
     * none can be extended into another authority. The same strings are
     * packaged as header-value patterns in the Chromium ruleset (see
     * generate-csp-rules.js), where none of them contains a character that
     * is special in that syntax apart from the final "*".
     *
     * None of these is an origin the server operator controls, which is
     * what the redirect guard is about. A navigation that carries a
     * fragment is still never allowed to reach them.
     */
    const EXTERNAL_REDIRECT_TARGETS = Object.freeze([
        'https://github.com/samjanny/pinchat/releases/latest',
        'https://chromewebstore.google.com/detail/*',
        'https://addons.mozilla.org/*',
    ]);

    /** URL without its fragment: the identity of a document for bookkeeping. */
    function documentUrl(url) {
        return String(url || '').split('#')[0];
    }

    /** path -> sha256 hex for the HTML documents of a signed manifest. */
    function documentHashes(manifest) {
        const map = new Map();
        for (const entry of (manifest && manifest.files) || []) {
            if (typeof entry.path === 'string' && entry.path.startsWith('/static/')
                && entry.path.endsWith('.html') && /^[a-f0-9]{64}$/i.test(entry.hash || '')) {
                map.set(entry.path, entry.hash.toLowerCase());
            }
        }
        return map;
    }

    return {
        INTEGRITY,
        CLASS,
        FINDINGS,
        finding,
        findingForIssue,
        findingForViolation,
        isExtensionUrl,
        decide,
        badge,
        headline,
        isAllowedRedirect,
        EXTERNAL_REDIRECT_TARGETS,
        documentUrl,
        documentHashes,
    };
}));
