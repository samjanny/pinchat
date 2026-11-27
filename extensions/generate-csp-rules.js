#!/usr/bin/env node

/**
 * Generate preventive, hash-only CSP rules for the browser extensions.
 *
 * The rules are derived from the release's signed manifest. The manifest
 * signs, for every page, the scripts it loads (pageEntries below, read from
 * the page when the manifest is signed), and the extension builds the same
 * rules from the manifest it fetches and verifies, with the same code
 * (chrome/csp-rules.js). The copy packaged here as rules.json is what applies
 * before the extension has verified any manifest.
 *
 * declarativeNetRequest applies the rules to response headers before the
 * page is parsed, so a compromised origin cannot execute a newly injected
 * same-origin script. The content script remains the detection and warning
 * layer for HTML/SRI tampering.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const policy = require('./chrome/csp-rules.js');

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
// to a page automatically adds it to the signed list of that page on the
// next signature, and verify-sri.js fails the build if the signed list and
// the page ever disagree.
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
function pageScripts(pagePath, hashesByPath, html = null) {
    if (html === null) {
        html = fs.readFileSync(path.join(__dirname, '..', pagePath.replace(/^\//, '')), 'utf8');
    }

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

/**
 * The `pages` entry of a manifest being signed: every page with the scripts
 * it loads, read from the page. `htmlOf(pagePath)` may supply the markup
 * (the signer passes what it is about to write); by default it is read from
 * the repository.
 */
function pageEntries(files, htmlOf = () => null) {
    const hashesByPath = new Map(files.map((entry) => [entry.path, entry.hash]));
    return PAGES.map((pagePath) => ({
        path: pagePath,
        scripts: pageScripts(pagePath, hashesByPath, htmlOf(pagePath)),
    }));
}

function writeRulesFromManifest(manifestPath) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const written = {};
    for (const browser of ['chrome', 'firefox']) {
        written[browser] = policy.buildRules(manifest, browser);
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
    FORM_ACTIONS: policy.FORM_ACTIONS,
    CATCH_ALL_REGEX: policy.CATCH_ALL_REGEX,
    FRAGMENT_REGEX: policy.FRAGMENT_REGEX,
    ALLOWED_REDIRECT_LOCATIONS: policy.ALLOWED_REDIRECT_LOCATIONS,
    pageRegex: policy.pageRegex,
    pageScripts,
    pageEntries,
    buildRules: policy.buildRules,
    writeRulesFromManifest,
};
