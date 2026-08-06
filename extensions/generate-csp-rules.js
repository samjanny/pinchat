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

const fs = require('fs');
const path = require('path');

const PAGE_SCRIPTS = {
    '/static/index.html': [
        '/static/js/theme.js',
        '/static/js/pow.js',
        '/static/js/homepage.js',
        '/static/js/alpine-csp.min.js',
        '/static/js/cookie-notice.js'
    ],
    '/static/login.html': [
        '/static/js/login-stash.js',
        '/static/js/theme.js',
        '/static/js/login.js',
        '/static/js/cookie-notice.js'
    ],
    '/static/chat.html': [
        '/static/js/debug.js',
        '/static/js/crypto.js',
        '/static/js/identity.js',
        '/static/js/double-ratchet.js',
        '/static/js/ecdh.js',
        '/static/js/websocket.js',
        '/static/js/emoji.js',
        '/static/js/app.js',
        '/static/js/alpine-csp.min.js',
        '/static/js/cookie-notice.js'
    ],
    '/static/terms.html': [
        '/static/js/theme.js',
        '/static/js/legal.js',
        '/static/js/cookie-notice.js'
    ],
    '/static/privacy.html': [
        '/static/js/theme.js',
        '/static/js/legal.js',
        '/static/js/cookie-notice.js'
    ]
};

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

function pageRegex(pagePath) {
    const escapedPath = pagePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return `^https://(www\\.)?pinchat\\.io${escapedPath}(?:\\?.*)?$`;
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
    for (const [pagePath, scripts] of Object.entries(PAGE_SCRIPTS)) {
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

module.exports = { PAGE_SCRIPTS, buildRules, writeRulesFromManifest };
