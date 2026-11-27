/**
 * PinChat Integrity Verifier - the preventive script policy of the site,
 * built from a signed manifest.
 *
 * The same code builds the rules packaged with the extension (rules.json,
 * written by generate-csp-rules.js when the manifest is signed) and the rules
 * the background script installs from the manifest it fetched and verified.
 * Only what the manifest signs varies: which scripts each page loads and
 * their hashes. Everything else about the policy is fixed here, in the
 * extension's own code, so a manifest can allow a page nothing but scripts
 * that the same manifest signs.
 *
 * Runs in the background script of both browsers and in Node.
 */
(function (root, factory) {
    const verdict = typeof module === 'object' && module.exports
        ? require('./verdict.js')
        : root.PinChatVerdict;
    const api = factory(verdict);
    if (typeof module === 'object' && module.exports) {
        module.exports = api;
    } else {
        root.PinChatRules = api;
    }
}(typeof globalThis !== 'undefined' ? globalThis : this, (V) => {
    'use strict';

    const { EXTERNAL_REDIRECT_TARGETS } = V;

    /**
     * Where each page may submit a form. Only the login page posts one to
     * the server. The forms of the chat and the home page are handled by the
     * application (@submit.prevent) and never submitted, and the legal pages
     * have none. Everywhere else a form, a served one included, whether in
     * the page or in a shadow tree, has nowhere to send what is typed into it.
     */
    const FORM_ACTIONS = {
        '/static/login.html': "'self'",
    };

    function cspBase(pagePath) {
        return [
            "default-src 'none'",
            "style-src 'self'",
            "img-src 'self' blob:",
            "font-src 'self'",
            "connect-src 'self' wss://pinchat.im wss://www.pinchat.im",
            "object-src 'none'",
            // The site uses no worker of any kind. Stated explicitly so that
            // it does not depend on worker-src falling back to script-src.
            "worker-src 'none'",
            "base-uri 'none'",
            `form-action ${FORM_ACTIONS[pagePath] || "'none'"}`,
            "frame-ancestors 'none'",
        ];
    }

    /**
     * Header changes applied to every document response on the site.
     *
     * Besides setting the policy, two response headers are removed because
     * they act on the document without being part of its body, so no check
     * of the HTML can see them: `Link: <...>; rel=stylesheet` attaches a
     * stylesheet (honoured by Firefox), and `Refresh` navigates away.
     */
    function documentHeaders(csp) {
        return [
            { header: 'content-security-policy', operation: 'set', value: csp },
            { header: 'link', operation: 'remove' },
            { header: 'refresh', operation: 'remove' },
        ];
    }

    /**
     * Location values a document response on the site may redirect to.
     *
     * An invite link carries its key in the URL fragment. Browsers carry the
     * fragment across an HTTP redirect, to another origin as well, unless the
     * Location header names a fragment of its own. A server that answers an
     * invite link with a redirect to an origin it controls therefore finds
     * the key in that origin's location.hash, without running any code on the
     * site. So a navigation whose address carries a fragment may be
     * redirected to the site and nowhere else (FRAGMENT_REGEX below), and one
     * without a fragment to the site or to one of EXTERNAL_REDIRECT_TARGETS,
     * the few places the site's own links lead to through a redirect.
     *
     * These are header-value patterns: "*" matches any run of characters, "?"
     * matches zero or one character, and a backslash makes the next character
     * literal. A literal question mark therefore has to be escaped: written
     * bare, "/?*" means "a slash, optionally one more character, then
     * anything", which is every value that starts with a slash. They are an
     * allowlist on purpose. "//host/..." and "/\\host/..." are
     * scheme-relative to a browser and start with a slash, so "any value that
     * begins with a slash" would let them through; each relative prefix the
     * site actually uses is listed instead, and none of them can be extended
     * into another authority.
     */
    const ALLOWED_REDIRECT_LOCATIONS = [
        'https://pinchat.im/*',
        'https://www.pinchat.im/*',
        '/',
        '/\\?*',
        '/static/*',
        '/c/*',
        '/login',
        '/login\\?*',
    ];

    // EXTERNAL_REDIRECT_TARGETS is written for both browsers: complete
    // addresses, or a prefix with one final "*". Anything else in an entry
    // would mean something different as a header-value pattern here than it
    // does to the check in verdict.js.
    for (const target of EXTERNAL_REDIRECT_TARGETS) {
        if (!/^https:\/\/[a-z0-9.-]+\/[A-Za-z0-9._~\/-]*\*?$/.test(target)) {
            throw new Error(`External redirect target cannot be used as a header-value pattern: ${target}`);
        }
    }

    const HEX_HASH = /^[a-f0-9]{64}$/i;

    function hexToSRI(hex) {
        if (!HEX_HASH.test(String(hex))) {
            throw new Error(`Invalid SHA-256 manifest hash: ${hex}`);
        }
        let binary = '';
        for (let i = 0; i < 64; i += 2) binary += String.fromCharCode(parseInt(hex.slice(i, i + 2), 16));
        return `sha256-${btoa(binary)}`;
    }

    /**
     * 'report-sample' allows no script. It makes a violation report carry the
     * first 40 characters of what was blocked, which is how the content script
     * tells the violation of its own policy probe, whose handler begins with a
     * marker of its own, from the page's (see isProbeViolation in verdict.js).
     * The catch-all rule keeps a bare 'none', which takes no other keyword.
     */
    function buildCsp(pagePath, scriptPaths, hashesByPath) {
        const hashSources = scriptPaths.map((scriptPath) => `'${hexToSRI(hashesByPath.get(scriptPath))}'`);
        return [`script-src 'report-sample' ${hashSources.join(' ')}`, ...cspBase(pagePath)].join('; ') + ';';
    }

    // Chrome matches a declarativeNetRequest regexFilter against the full
    // URL, fragment included, even though the fragment never reaches the
    // server. A tail that only allowed an optional query string therefore
    // missed `/static/index.html#features`, the page rule did not apply, and
    // the catch-all `script-src 'none'` rule blocked every script on the page.
    // The chat page never showed it because it always carries `?room=`. The
    // tail now accepts a query, a fragment, or both.
    const CATCH_ALL_REGEX = '^https://(www\\.)?pinchat\\.im\\.?(:[0-9]+)?/';

    // The same documents, when the address carries a fragment. The browser
    // matches a rule against the whole address, and the fragment an earlier
    // redirect carried over is part of it.
    const FRAGMENT_REGEX = `${CATCH_ALL_REGEX}[^#]*#`;

    function pageRegex(pagePath) {
        const escapedPath = pagePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        return `^https://(www\\.)?pinchat\\.im${escapedPath}(?:[?#].*)?$`;
    }

    // What a page and a script path may look like. A path that does not
    // match would be the manifest asking for something the site never
    // serves: another origin, a parent directory, a pattern character in the
    // rule's filter.
    const PAGE_PATH = /^\/static\/[A-Za-z0-9_-]+\.html$/;
    const SCRIPT_PATH = /^\/static\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9._-]+\.js$/;

    /**
     * The pages of a signed manifest and the scripts each one loads, in
     * document order, after checking that the manifest signs every one of
     * them. Throws on anything else: a page whose policy cannot be built
     * must not get a policy that allows less or more than it says.
     */
    function pageScriptLists(data) {
        if (!data || !Array.isArray(data.files)) {
            throw new Error('Manifest does not contain a files array');
        }
        if (!Array.isArray(data.pages) || data.pages.length === 0) {
            throw new Error('Manifest does not list the scripts of its pages');
        }
        const hashesByPath = new Map();
        for (const entry of data.files) {
            if (entry && typeof entry.path === 'string' && HEX_HASH.test(String(entry.hash))) {
                hashesByPath.set(entry.path, String(entry.hash).toLowerCase());
            }
        }
        const lists = new Map();
        for (const page of data.pages) {
            const pagePath = page && page.path;
            if (typeof pagePath !== 'string' || !PAGE_PATH.test(pagePath)) {
                throw new Error(`Manifest lists an unexpected page: ${pagePath}`);
            }
            if (lists.has(pagePath)) throw new Error(`Manifest lists ${pagePath} twice`);
            if (!hashesByPath.has(pagePath)) throw new Error(`Manifest does not sign the page ${pagePath}`);
            const scripts = page.scripts;
            if (!Array.isArray(scripts) || scripts.length === 0) {
                throw new Error(`Manifest lists no script for ${pagePath}`);
            }
            for (const scriptPath of scripts) {
                if (typeof scriptPath !== 'string' || !SCRIPT_PATH.test(scriptPath)) {
                    throw new Error(`${pagePath} loads an unexpected script path: ${scriptPath}`);
                }
                if (!hashesByPath.has(scriptPath)) {
                    throw new Error(`${pagePath} loads ${scriptPath}, which the manifest does not sign`);
                }
            }
            if (new Set(scripts).size !== scripts.length) {
                throw new Error(`Manifest lists a script of ${pagePath} twice`);
            }
            lists.set(pagePath, scripts.slice());
        }
        return { lists, hashesByPath };
    }

    /**
     * Build the ruleset for one browser. The policy rules are the same for
     * both. The redirect rules exist for Chromium only: they rely on matching
     * a response header, which Firefox's declarativeNetRequest does not
     * support. The Firefox build enforces the same rule in its background
     * script.
     */
    function buildRules(manifestDocument, browser = 'chrome') {
        const data = (manifestDocument && manifestDocument.data) || manifestDocument;
        const { lists, hashesByPath } = pageScriptLists(data);
        const rules = [
            {
                id: 1,
                priority: 1,
                action: {
                    type: 'modifyHeaders',
                    responseHeaders: documentHeaders(["script-src 'none'", ...cspBase(null)].join('; ') + ';'),
                },
                condition: {
                    // Every document on the site's host names, on any port
                    // and with or without the trailing root dot. The page
                    // rules below only match the default port, so anything
                    // else keeps this policy and can run no script at all.
                    // Anchoring this rule to the default port left
                    // https://pinchat.im:<port> without any packaged policy,
                    // while the content script and the badge still treated it
                    // as the site.
                    regexFilter: CATCH_ALL_REGEX,
                    resourceTypes: ['main_frame', 'sub_frame'],
                },
            },
        ];

        let id = 2;
        for (const [pagePath, scripts] of lists) {
            rules.push({
                id: id++,
                priority: 2,
                action: {
                    type: 'modifyHeaders',
                    responseHeaders: documentHeaders(buildCsp(pagePath, scripts, hashesByPath)),
                },
                condition: {
                    regexFilter: pageRegex(pagePath),
                    resourceTypes: ['main_frame', 'sub_frame'],
                },
            });
        }
        if (browser === 'chrome') {
            // Two rules, and a redirect has to pass both. The first holds for
            // every navigation and does not depend on the fragment at all;
            // the second takes the external targets away again from a
            // navigation that carries one.
            const redirectRule = (regexFilter, allowed) => ({
                id: id++,
                priority: 3,
                action: { type: 'block' },
                condition: {
                    regexFilter,
                    resourceTypes: ['main_frame', 'sub_frame'],
                    responseHeaders: [{
                        header: 'location',
                        excludedValues: allowed,
                    }],
                },
            });
            rules.push(redirectRule(CATCH_ALL_REGEX, [...ALLOWED_REDIRECT_LOCATIONS, ...EXTERNAL_REDIRECT_TARGETS]));
            rules.push(redirectRule(FRAGMENT_REGEX, ALLOWED_REDIRECT_LOCATIONS));
        }
        return rules;
    }

    return {
        FORM_ACTIONS,
        CATCH_ALL_REGEX,
        FRAGMENT_REGEX,
        ALLOWED_REDIRECT_LOCATIONS,
        pageRegex,
        pageScriptLists,
        buildRules,
    };
}));
