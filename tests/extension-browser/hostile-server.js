#!/usr/bin/env node
/**
 * Hostile stand-in for the origin, for tests/extension-browser/run.sh.
 *
 * It serves the repository's static files unchanged, so every hash in the
 * signed manifest matches, with one exception: a *navigation* to chat.html
 * receives one extra element. Every other request for chat.html, which is
 * what the extension's own verification fetch looks like, receives the signed
 * bytes. This is the split serving a compromised server would use.
 *
 * The extra element is chosen with the `poc` query parameter:
 *   (none)      an image with an inline error handler
 *   rel-exact   <link rel="stylesheet"> to a stylesheet outside the manifest
 *   rel-multi   the same link with rel="stylesheet nofollow"
 *   rel-case    the same link with rel="StyleSheet"
 *
 * A request whose Host header names port 8446 gets the altered page on every
 * request, with no split serving. That is the control case: the extension's
 * fetch sees the alteration, so a warning must appear.
 *
 * Listens on 127.0.0.1 only. Usage: hostile-server.js <cert-dir> <log-file>
 */

const fs = require('fs');
const https = require('https');
const path = require('path');

const [certDir, logFile] = process.argv.slice(2);
const staticDir = path.join(__dirname, '..', '..', 'static');
const PORT = 8443;

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.woff2': 'font/woff2',
};

const HANDLER = '<img src="/static/missing.png" '
    + 'onerror="document.documentElement.setAttribute(\'data-attacker\',\'handler-ran\')">';

function injection(poc) {
    switch (poc) {
    case 'rel-exact': return '<link rel="stylesheet" href="/static/css/evil.css">';
    case 'rel-multi': return '<link rel="stylesheet nofollow" href="/static/css/evil.css">';
    case 'rel-case': return '<link rel="StyleSheet" href="/static/css/evil.css">';
    default: return HANDLER;
    }
}

https.createServer({
    key: fs.readFileSync(path.join(certDir, 'key.pem')),
    cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
}, (req, res) => {
    const url = new URL(req.url, 'https://placeholder');
    const host = req.headers.host || '';
    const navigation = req.headers['sec-fetch-mode'] === 'navigate';
    fs.appendFileSync(
        logFile,
        `${host} ${url.pathname} mode=${req.headers['sec-fetch-mode']} dest=${req.headers['sec-fetch-dest']}\n`,
    );

    if (url.pathname === '/static/css/evil.css') {
        res.writeHead(200, { 'content-type': 'text/css' });
        res.end('html { outline: 9px solid red; }');
        return;
    }
    if (!url.pathname.startsWith('/static/')) {
        res.writeHead(404);
        res.end();
        return;
    }
    const file = path.join(staticDir, path.normalize(url.pathname.slice('/static/'.length)));
    if (!file.startsWith(staticDir + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        res.writeHead(404);
        res.end();
        return;
    }

    let body = fs.readFileSync(file);
    const everyRequest = host.endsWith(':8446');
    if ((navigation || everyRequest) && url.pathname === '/static/chat.html') {
        const html = body.toString('utf8');
        body = Buffer.from(html.replace('</body>', `${injection(url.searchParams.get('poc'))}</body>`));
    }
    res.writeHead(200, {
        'content-type': TYPES[path.extname(file)] || 'application/octet-stream',
        'cache-control': 'no-store',
    });
    res.end(body);
}).listen(PORT, '127.0.0.1', () => console.log(`hostile origin listening on 127.0.0.1:${PORT}`));
