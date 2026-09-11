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
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'"
];

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
function pageRegex(pagePath) {
    const escapedPath = pagePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `^https://(www\\.)?pinchat\\.io${escapedPath}(?:[?#].*)?$`;
}

function buildRules(manifestDocument) {
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
                responseHeaders: [{
                    header: 'content-security-policy',
                    operation: 'set',
                    value: ["script-src 'none'", ...CSP_BASE].join('; ') + ';'
                }]
            },
            condition: {
                regexFilter: '^https://(www\\.)?pinchat\\.io/',
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
                responseHeaders: [{
                    header: 'content-security-policy',
                    operation: 'set',
                    value: buildCsp(scripts, hashesByPath)
                }]
            },
            condition: {
                regexFilter: pageRegex(pagePath),
                resourceTypes: ['main_frame', 'sub_frame']
            }
        });
    }
    return rules;
}

function writeRulesFromManifest(manifestPath) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const rules = buildRules(manifest);
    const output = JSON.stringify(rules, null, 2) + '\n';
    for (const browser of ['chrome', 'firefox']) {
        const outputPath = path.join(__dirname, browser, 'rules.json');
        fs.writeFileSync(outputPath, output);
        console.log(`Preventive CSP rules written: ${outputPath}`);
    }
    return rules;
}

if (require.main === module) {
    const manifestPath = process.argv[2]
        ? path.resolve(process.argv[2])
        : path.join(__dirname, '..', 'hashes.json.signed');
    writeRulesFromManifest(manifestPath);
}

module.exports = { PAGES, pageScripts, buildRules, writeRulesFromManifest };
