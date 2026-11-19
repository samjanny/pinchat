#!/usr/bin/env node

/**
 * Generate preventive, hash-only CSP rules for the browser extensions.
 *
 * The rules are derived from the release's signed manifest and packaged in
 * the extension. declarativeNetRequest applies them to response headers before
 * the page is parsed, so a compromised origin cannot execute a newly injected
 * same-origin script. The existing content script remains the detection and
 * warning layer for HTML/SRI tampering.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { EXTERNAL_REDIRECT_TARGETS } = require('./chrome/verdict.js');

// Pages that get a per-page, hash-pinned script-src. The script list for
// each one is READ FROM THE PAGE ITSELF rather than repeated here.
//
// It used to be a hand-maintained map, and it had silently drifted: chat.html
// loads theme.js, pow.js and nicknames.js, none of which were listed, so the
// generated policy pinned ten hashes for a page that loads thirteen scripts.
// Because script-src does not include 'self', the three unlisted files were
// blocked outright for anyone running the extension, and app.js calls
// generateNickname() from nicknames.js on every connection.
//
// Deriving the list makes that class of drift impossible: adding a <script>
// to a page automatically adds its hash to that page's policy on the next
// regeneration, and verify-sri.js fails the build if a page ever loads a
// script the rules do not cover.
const PAGES = [
    '/static/index.html',
    '/static/login.html',
    '/static/chat.html',
    '/static/terms.html',
    '/static/privacy.html',
];

const SCRIPT_SRC_RE = /<script\b[^>]*\ssrc="([^"]+)"/g;

/**
 * Collect, in document order, the same-origin scripts a page loads.
 * Absolute URLs are rejected rather than ignored: the CSP has no 'self' and
 * no third-party host, so a cross-origin script tag would be blocked at
 * runtime and silently breaking the page is worse than failing the build.
 */
function pageScripts(pagePath, hashesByPath) {
    const filePath = path.join(__dirname, '..', pagePath.replace(/^\//, ''));
    const html = fs.readFileSync(filePath, 'utf8');

    // Prove this is the signed page before trusting anything in it.
    //
    // Deriving the allowlist from a document is only safe while that document
    // is itself covered by the signed manifest: an unsigned edit that added a
    // <script> would otherwise widen the very policy meant to constrain it.
    // verify-sri.js checks every static file against the manifest too, but
    // relying on that would make this generator's safety depend on a separate
    // script having run first. Check it here so the property is local.
    const expected = hashesByPath.get(pagePath);
    if (!expected) {
        throw new Error(`Signed manifest is missing ${pagePath}`);
    }
    const actual = crypto.createHash('sha256')
        .update(Buffer.from(html.replace(/\r\n/g, '\n'), 'utf8'))
        .digest('hex');
    if (actual !== expected) {
        throw new Error(
            `${pagePath} does not match the signed manifest `
            + `(signed ${expected}, actual ${actual}); re-sign before regenerating rules`,
        );
    }
    const scripts = [];
    SCRIPT_SRC_RE.lastIndex = 0;
    let match;
    while ((match = SCRIPT_SRC_RE.exec(html)) !== null) {
        const src = match[1];
        if (/^[a-z]+:|^\/\//i.test(src)) {
            throw new Error(`${pagePath} loads an off-origin script: ${src}`);
        }
        if (!src.startsWith('/static/')) {
            throw new Error(`${pagePath} loads an unexpected script path: ${src}`);
        }
        if (!scripts.includes(src)) scripts.push(src);
    }
    if (scripts.length === 0) {
        throw new Error(`${pagePath} declares no scripts; refusing to emit an empty allowlist`);
    }
    return scripts;
}

const CSP_BASE = [
    "default-src 'none'",
    "style-src 'self'",
    "img-src 'self' blob:",
    "font-src 'self'",
    "connect-src 'self' wss://pinchat.io wss://www.pinchat.io",
    "object-src 'none'",
    // The site uses no worker of any kind. Stated explicitly so that it does
    // not depend on worker-src falling back to script-src.
    "worker-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
];

/**
 * Header changes applied to every document response on the site.
 *
 * Besides setting the policy, two response headers are removed because they
 * act on the document without being part of its body, so no check of the
 * HTML can see them: `Link: <...>; rel=stylesheet` attaches a stylesheet
 * (honoured by Firefox), and `Refresh` navigates away.
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
 * invite link with a redirect to an origin it controls therefore finds the
 * key in that origin's location.hash, without running any code on the site.
 * So a navigation whose address carries a fragment may be redirected to
 * the site and nowhere else (FRAGMENT_REGEX below), and one without a
 * fragment to the site or to one of EXTERNAL_REDIRECT_TARGETS, the few
 * places the site's own links lead to through a redirect.
 *
 * These are header-value patterns: "*" matches any run of characters, "?"
 * matches zero or one character, and a backslash makes the next character
 * literal. A literal question mark therefore has to be escaped: written
 * bare, "/?*" means "a slash, optionally one more character, then
 * anything", which is every value that starts with a slash. They
 * are an allowlist on purpose. "//host/..." and "/\\host/..." are
 * scheme-relative to a browser and start with a slash, so "any value that
 * begins with a slash" would let them through; each relative prefix the
 * site actually uses is listed instead, and none of them can be extended
 * into another authority.
 */
const ALLOWED_REDIRECT_LOCATIONS = [
    'https://pinchat.io/*',
    'https://www.pinchat.io/*',
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

function hexToSRI(hex) {
    if (!/^[a-f0-9]{64}$/i.test(hex)) {
        throw new Error(`Invalid SHA-256 manifest hash: ${hex}`);
    }
    return `sha256-${Buffer.from(hex, 'hex').toString('base64')}`;
}

function buildCsp(scriptPaths, hashesByPath) {
    const hashSources = scriptPaths.map((scriptPath) => {
        const hash = hashesByPath.get(scriptPath);
        if (!hash) throw new Error(`Signed manifest is missing ${scriptPath}`);
        return `'${hexToSRI(hash)}'`;
    });
    return [`script-src ${hashSources.join(' ')}`, ...CSP_BASE].join('; ') + ';';
}

// Chrome matches a declarativeNetRequest regexFilter against the full URL,
// fragment included, even though the fragment never reaches the server. A
// tail that only allowed an optional query string therefore missed
// `/static/index.html#features`, the page rule did not apply, and the
// catch-all `script-src 'none'` rule blocked every script on the page. The
// chat page never showed it because it always carries `?room=`. The tail
// now accepts a query, a fragment, or both.
const CATCH_ALL_REGEX = '^https://(www\\.)?pinchat\\.io\\.?(:[0-9]+)?/';

// The same documents, when the address carries a fragment. The browser
// matches a rule against the whole address, and the fragment an earlier
// redirect carried over is part of it.
const FRAGMENT_REGEX = `${CATCH_ALL_REGEX}[^#]*#`;

function pageRegex(pagePath) {
    const escapedPath = pagePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `^https://(www\\.)?pinchat\\.io${escapedPath}(?:[?#].*)?$`;
}

/**
 * Build the ruleset for one browser. The policy rules are the same for
 * both. The redirect rules exist for Chromium only: they rely on matching a
 * response header, which Firefox's declarativeNetRequest does not support.
 * The Firefox build enforces the same rule in its background script.
 */
function buildRules(manifestDocument, browser = 'chrome') {
    const data = manifestDocument.data || manifestDocument;
    if (!data || !Array.isArray(data.files)) {
        throw new Error('Manifest does not contain a files array');
    }

    const hashesByPath = new Map(data.files.map((entry) => [entry.path, entry.hash]));
    const rules = [
        {
            id: 1,
            priority: 1,
            action: {
                type: 'modifyHeaders',
                responseHeaders: documentHeaders(["script-src 'none'", ...CSP_BASE].join('; ') + ';')
            },
            condition: {
                // Every document on the site's host names, on any port and
                // with or without the trailing root dot. The page rules
                // below only match the default port, so anything else keeps
                // this policy and can run no script at all. Anchoring this
                // rule to the default port left https://pinchat.io:<port>
                // without any packaged policy, while the content script and
                // the badge still treated it as the site.
                regexFilter: CATCH_ALL_REGEX,
                resourceTypes: ['main_frame', 'sub_frame']
            }
        }
    ];

    let id = 2;
    for (const pagePath of PAGES) {
        const scripts = pageScripts(pagePath, hashesByPath);
        rules.push({
            id: id++,
            priority: 2,
            action: {
                type: 'modifyHeaders',
                responseHeaders: documentHeaders(buildCsp(scripts, hashesByPath))
            },
            condition: {
                regexFilter: pageRegex(pagePath),
                resourceTypes: ['main_frame', 'sub_frame']
            }
        });
    }
    if (browser === 'chrome') {
        // Two rules, and a redirect has to pass both. The first holds for
        // every navigation and does not depend on the fragment at all; the
        // second takes the external targets away again from a navigation
        // that carries one.
        const redirectRule = (regexFilter, allowed) => ({
            id: id++,
            priority: 3,
            action: { type: 'block' },
            condition: {
                regexFilter,
                resourceTypes: ['main_frame', 'sub_frame'],
                responseHeaders: [{
                    header: 'location',
                    excludedValues: allowed
                }]
            }
        });
        rules.push(redirectRule(CATCH_ALL_REGEX, [...ALLOWED_REDIRECT_LOCATIONS, ...EXTERNAL_REDIRECT_TARGETS]));
        rules.push(redirectRule(FRAGMENT_REGEX, ALLOWED_REDIRECT_LOCATIONS));
    }
    return rules;
}

function writeRulesFromManifest(manifestPath) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const written = {};
    for (const browser of ['chrome', 'firefox']) {
        written[browser] = buildRules(manifest, browser);
        const outputPath = path.join(__dirname, browser, 'rules.json');
        fs.writeFileSync(outputPath, JSON.stringify(written[browser], null, 2) + '\n');
        console.log(`Preventive CSP rules written: ${outputPath}`);
    }
    return written;
}

if (require.main === module) {
    const manifestPath = process.argv[2]
        ? path.resolve(process.argv[2])
        : path.join(__dirname, '..', 'hashes.json.signed');
    writeRulesFromManifest(manifestPath);
}

module.exports = {
    PAGES,
    CATCH_ALL_REGEX,
    FRAGMENT_REGEX,
    ALLOWED_REDIRECT_LOCATIONS,
    pageRegex,
    pageScripts,
    buildRules,
    writeRulesFromManifest,
};
