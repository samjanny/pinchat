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
        'page-refresh': [CLASS.SUSPICIOUS,
            'The page asked to load another address by itself. The page was stopped.'],
        // ---- limits -------------------------------------------------------
        'manifest-unavailable': [CLASS.LIMIT,
            'The signed release manifest could not be obtained, so nothing could be compared.'],
        'manifest-unusable': [CLASS.LIMIT,
            'The signed release manifest was obtained, but this version of the extension cannot use it, '
            + 'so nothing could be compared.'],
        'no-host-access': [CLASS.LIMIT,
            'The extension is not allowed to act on this site at all times, so its script policy and '
            + 'redirect guard may not apply. Allow it in the extension\'s site access settings.'],
        'shadow-root': [CLASS.LIMIT,
            'Part of the page was drawn in a shadow tree while the page was loading. It may have come from '
            + 'the server, and it could not be compared with the signed release.'],
        'document-not-attested': [CLASS.LIMIT,
            'This page was loaded without passing through the verifier. Reload it.'],
        'unlisted-document': [CLASS.LIMIT,
            'The server answered with a page that is not part of the signed release.'],
        'document-too-large': [CLASS.LIMIT,
            'The page was larger than any signed page and was not read.'],
        'error-response': [CLASS.LIMIT,
            'The server answered with an error instead of a page. What it sent is not shown.'],
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
        'shadow-root-added': [CLASS.ENVIRONMENT,
            'A shadow tree was attached to the page by a script, typically by another extension.'],
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
        'meta-refresh': 'page-refresh',
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
     * The inline handler of the content script's policy probe, and how to
     * tell the violation it causes from every other one.
     *
     * The handler begins with a marker drawn at random for each document,
     * and the packaged page policies carry 'report-sample', so a browser
     * that reports the probe's violation puts the first 40 characters of
     * the handler, marker included, in its `sample`. Nothing else belongs to
     * the probe alone: its element is not in the document, so the event is
     * aimed at the document, and blockedURI and lineNumber are those of any
     * inline handler. A violation that does not carry the marker is
     * therefore never taken for the probe's, whatever else it looks like: a
     * violation the page causes must not go unrecorded, and a rare one of the
     * probe's that is recorded only lists one change too many.
     */
    const PROBE_MARKER_LENGTH = 24;

    function probeHandler(marker) {
        return `/*${marker}*/this.setAttribute("data-ran", "1")`;
    }

    function isProbeViolation(violation, marker) {
        return typeof marker === 'string' && /^[0-9a-f]+$/.test(marker) && marker.length >= PROBE_MARKER_LENGTH
            && !!violation && violation.effectiveDirective === 'script-src-attr'
            && String(violation.sample || '').includes(marker);
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

    /**
     * Badge shown on the toolbar button for a tab. Green only for VERIFIED.
     * VERIFIED and PARTIAL are both a check mark and differ by color: green
     * when the page itself was compared with the signed release, yellow when
     * what could be checked passed and the page itself could not be checked
     * in this browser. The yellow badge has dark text, since white does not
     * read on yellow.
     */
    function badge(integrity, attention) {
        const WHITE = '#ffffff';
        switch (integrity) {
        case INTEGRITY.VERIFIED:
            return attention
                ? { text: '!', color: '#f59e0b', textColor: WHITE }
                : { text: '\u2713', color: '#16a34a', textColor: WHITE };
        case INTEGRITY.PARTIAL:
            return attention
                ? { text: '!', color: '#f59e0b', textColor: WHITE }
                : { text: '\u2713', color: '#facc15', textColor: '#111827' };
        case INTEGRITY.FAILED:
            return { text: '!', color: '#dc2626', textColor: WHITE };
        case INTEGRITY.UNVERIFIABLE:
            return { text: '?', color: '#f59e0b', textColor: WHITE };
        case INTEGRITY.CHECKING:
            return { text: '...', color: '#6b7280', textColor: WHITE };
        default:
            return { text: '', color: '#6b7280', textColor: WHITE };
        }
    }

    /**
     * What the popup says under the headline of a state, beyond the scope
     * line. Only PARTIAL has one: it is the best state this browser can reach,
     * and the user should know where a complete check is available.
     */
    function headlineNote(integrity) {
        if (integrity === INTEGRITY.PARTIAL) {
            return 'A complete check, which also compares the page itself with the signed release, '
                + 'is currently possible only in Firefox.';
        }
        return '';
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

    /**
     * The policy the packaged rules give a document address: the value set
     * by the highest-priority rule that sets Content-Security-Policy and
     * whose filter matches. declarativeNetRequest compares a regexFilter
     * without regard to case unless the rule says otherwise, and so does
     * this. null when no rule matches.
     */
    function packagedPolicy(rules, url) {
        let best = null;
        for (const rule of Array.isArray(rules) ? rules : []) {
            const action = rule && rule.action;
            if (!action || action.type !== 'modifyHeaders' || !rule.condition) continue;
            const header = (action.responseHeaders || []).find((entry) => entry && entry.operation === 'set'
                && String(entry.header).toLowerCase() === 'content-security-policy');
            if (!header) continue;
            let matches = false;
            try {
                matches = new RegExp(rule.condition.regexFilter, rule.condition.isUrlFilterCaseSensitive ? '' : 'i')
                    .test(String(url));
            } catch (_) {
                matches = false;
            }
            const priority = rule.priority || 1;
            if (matches && (!best || priority > best.priority)) best = { priority, value: String(header.value) };
        }
        return best ? best.value : null;
    }

    /**
     * The sources a policy allows scripts from: for script elements and for
     * inline handlers, each with the fallback to script-src and then to
     * default-src. Each is a sorted list of sources, or null when nothing
     * restricts it. Keywords are compared without regard to case, hashes
     * and nonces with it.
     */
    function scriptSources(policy) {
        const directives = new Map();
        for (const part of String(policy || '').split(';')) {
            const tokens = part.trim().split(/\s+/).filter(Boolean);
            if (tokens.length === 0) continue;
            const name = tokens[0].toLowerCase();
            if (directives.has(name)) continue; // the first occurrence is the one in force
            directives.set(name, tokens.slice(1).map((token) => {
                const value = /^'(sha256|sha384|sha512|nonce)-/i.exec(token);
                return value ? `'${value[1].toLowerCase()}${token.slice(value[0].length - 1)}` : token.toLowerCase();
            }).sort());
        }
        const effective = (name) => directives.get(name) || directives.get('script-src')
            || directives.get('default-src') || null;
        return { elements: effective('script-src-elem'), handlers: effective('script-src-attr') };
    }

    /**
     * Whether a policy the browser reports as enforced lets exactly the same
     * scripts run as the expected one.
     *
     * The probe in the content script only learns that an inline handler was
     * blocked, and a policy of the server's own, such as script-src 'self',
     * blocks one too while it runs any script of the origin. The policy the
     * browser names for that block tells the two apart. Only the directives
     * that decide which code runs are compared: that is what the probe tests
     * and what a positive state claims, and a browser may report the other
     * directives written differently.
     */
    function sameScriptPolicy(reported, expected) {
        const a = scriptSources(reported);
        const b = scriptSources(expected);
        const same = (x, y) => (x === null || y === null ? x === y : x.join(' ') === y.join(' '));
        return same(a.elements, b.elements) && same(a.handlers, b.handlers);
    }

    return {
        INTEGRITY,
        CLASS,
        FINDINGS,
        finding,
        findingForIssue,
        findingForViolation,
        PROBE_MARKER_LENGTH,
        probeHandler,
        isProbeViolation,
        isExtensionUrl,
        decide,
        badge,
        headline,
        headlineNote,
        isAllowedRedirect,
        EXTERNAL_REDIRECT_TARGETS,
        documentUrl,
        documentHashes,
        packagedPolicy,
        sameScriptPolicy,
    };
}));
