#!/usr/bin/env node
/**
 * Browser tests of the verifier extension against a hostile origin.
 *
 * Loads the extension into a real headless Chromium and a real headless
 * Firefox, points the site's host name at a local server that behaves like a
 * compromised origin (hostile-server.js), and records for every case what
 * the browser executed, what the extension intercepted, verified and
 * blocked, and what it told the user.
 *
 * Not part of CI. It needs Chromium or Google Chrome (CHROMIUM names the
 * binary; extensions are loaded through the DevTools protocol, since Chrome
 * ignores --load-extension), Firefox with geckodriver, openssl and Node 22 or
 * later. The extension fetches the signed manifest of its pinned
 * release from the project's release host, so a run needs network access and
 * the static/ files in the working tree must be the ones of that release.
 * Nothing is sent to the real site: its host name is remapped to 127.0.0.1
 * (Chromium) or tunnelled there by a proxy that refuses everything else
 * (Firefox). The same goes for the host of the release page, which the
 * site's extension links redirect to.
 *
 * A working tree whose static files differ from the pinned release cannot be
 * tested against that release's manifest. For that, sign the tree with a
 * throwaway key, build a copy of the extension that trusts it, and name the
 * manifest in VERIFIER_TEST_MANIFEST: the release host is then answered
 * locally with that file and never contacted.
 *
 *   openssl ecparam -name prime256v1 -genkey -noout -out test-key.pem
 *   node extensions/generate-hashes.js --private-key test-key.pem   (in a copy of the tree)
 *   replace PINCHAT_PUBLIC_KEY in the copy's extensions/<browser>/background.js
 *   VERIFIER_TEST_MANIFEST=<copy>/hashes.json.signed node <copy>/tests/extension-browser/run.js
 *
 * Usage:
 *   node tests/extension-browser/run.js [options] [case-id ...]
 *     --browser chromium|firefox   run one browser only (default: both)
 *     --extension-root DIR         directory holding chrome/ and firefox/
 *                                  (default: extensions)
 *     --observe                    print observations, check nothing
 *
 * Exit status is the number of failed expectations.
 */

'use strict';

const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { launchChromium } = require('./lib/chromium');
const { launchFirefox } = require('./lib/firefox');
const { startProxy } = require('./lib/proxy');

// Overridable so that two runs can share a machine.
const HTTPS_PORT = Number(process.env.VERIFIER_TEST_HTTPS_PORT || 8443);
const CONTROL_PORT = Number(process.env.VERIFIER_TEST_CONTROL_PORT || 8442);
// A manifest that replaces the one of the pinned release; see above.
const TEST_MANIFEST = process.env.VERIFIER_TEST_MANIFEST
    ? path.resolve(process.env.VERIFIER_TEST_MANIFEST) : null;
const SITE = 'https://pinchat.im';
const ROOM = '00000000-0000-4000-8000-000000000000';
// What an invite link carries after the "#". The value is a made-up key.
const SECRET = 'key=TESTSECRET0TESTSECRET0TESTSECRET0TESTSECRET0';
const CHAT = `${SITE}/static/chat.html?room=${ROOM}`;
const INVITE = `${SITE}/c/${ROOM}#${SECRET}`;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const argv = process.argv.slice(2);
const option = (name) => {
    const index = argv.indexOf(name);
    if (index === -1) return null;
    const [, value] = argv.splice(index, 2);
    return value;
};
const flag = (name) => {
    const index = argv.indexOf(name);
    if (index === -1) return false;
    argv.splice(index, 1);
    return true;
};
const onlyBrowser = option('--browser');
const extensionRoot = path.resolve(option('--extension-root') || path.join(__dirname, '..', '..', 'extensions'));
const observeOnly = flag('--observe');
const selected = argv;

/** Everything the tests read from a page, in one evaluation. */
const PROBE = `() => {
    const root = document.documentElement;
    const text = (id) => { const el = document.getElementById(id); return el ? el.textContent : null; };
    const overlay = document.getElementById('pinchat-integrity-warning-host');
    const style = root ? getComputedStyle(root) : null;
    return {
        url: location.href,
        fragment: location.hash,
        title: document.title,
        contentType: document.contentType,
        text: document.body ? document.body.textContent.trim().slice(0, 200) : '',
        appLoaded: document.title.includes('PinChat') && !!document.querySelector('.chat-container, .home-container'),
        attacker: root ? root.getAttribute('data-attacker') : null,
        marker: text('marker'),
        leak: text('leak'),
        swStatus: text('sw-status'),
        serverAdded: !!document.getElementById('server-added') || !!document.querySelector('form[action="/collect"]'),
        boundByServer: [
            ...Array.from(document.querySelectorAll('#server-added'), (el) => el.getAttribute('src')),
            document.body ? document.body.getAttribute('background') : null,
        ].filter(Boolean),
        overlay: overlay ? (overlay.getAttribute('data-kind') || 'present') : null,
        blockPage: text('verifier-block-reason'),
        evilCss: !!style && style.outlineStyle === 'solid' && style.outlineColor === 'rgb(255, 0, 0)',
        // A shadow root on the body: an open one is visible, a closed one
        // only through what its stylesheet does to its host.
        bodyShadowRoot: !!(document.body && document.body.shadowRoot),
        shadowCss: !!document.body && getComputedStyle(document.body).outlineColor === 'rgb(255, 0, 0)',
        pm: root ? {
            injected: root.getAttribute('data-pm-sim'),
            inline: root.getAttribute('data-pm-inline'),
            transient: root.getAttribute('data-pm-transient'),
            external: root.getAttribute('data-pm-external'),
        } : null,
    };
}`;

async function control(route) {
    const response = await fetch(`http://127.0.0.1:${CONTROL_PORT}${route}`);
    return response.headers.get('content-type') === 'application/json' ? response.json() : response.text();
}

async function withServer(work, body) {
    execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', path.join(work, 'key.pem'), '-out', path.join(work, 'cert.pem'),
        '-days', '1', '-subj', '/CN=pinchat.im',
        '-addext', 'subjectAltName=DNS:pinchat.im,DNS:www.pinchat.im,DNS:attacker.test,DNS:github.com,'
            + 'DNS:raw.githubusercontent.com',
    ], { stdio: 'ignore' });
    const server = spawn(process.execPath, [
        path.join(__dirname, 'hostile-server.js'), work, String(HTTPS_PORT), String(CONTROL_PORT),
        ...(TEST_MANIFEST ? [TEST_MANIFEST] : []),
    ], { stdio: 'ignore' });
    try {
        for (let i = 0; i < 50; i += 1) {
            try {
                await control('/reset');
                break;
            } catch (_) {
                await sleep(100);
            }
        }
        return await body();
    } finally {
        server.kill();
    }
}

/**
 * Per-browser context: launches browsers with a given set of extensions and
 * gives the cases a uniform way to drive them.
 */
function makeContext(browserName, work) {
    const open = [];
    let proxy = null;

    const verifierDir = path.join(extensionRoot, browserName === 'chromium' ? 'chrome' : 'firefox');

    async function launch({
        verifier = true, passwordManager = false, releaseHost = true, profileDir = null,
    } = {}) {
        if (TEST_MANIFEST) await control(`/manifest?serve=${releaseHost ? 1 : 0}`);
        const extensions = [];
        if (verifier) extensions.push(verifierDir);
        if (passwordManager) extensions.push(path.join(__dirname, 'pm-sim'));
        let browser;
        if (browserName === 'chromium') {
            const hosts = ['pinchat.im', 'www.pinchat.im', 'attacker.test', 'github.com'];
            // No release host: point it at the local server, which has no
            // manifest to offer.
            if (!releaseHost || TEST_MANIFEST) hosts.push('raw.githubusercontent.com');
            browser = await launchChromium({
                extensions, workDir: work, httpsPort: HTTPS_PORT, hosts, profileDir,
            });
        } else {
            proxy = await startProxy({
                localHosts: ['pinchat.im', 'www.pinchat.im', 'attacker.test', 'github.com',
                    ...(TEST_MANIFEST && releaseHost ? ['raw.githubusercontent.com'] : [])],
                localPort: HTTPS_PORT,
                passthroughHosts: releaseHost && !TEST_MANIFEST ? ['raw.githubusercontent.com'] : [],
            });
            browser = await launchFirefox({ extensions, proxyPort: proxy.port });
        }
        open.push(browser);
        // Give the extension time to fetch and validate its manifest.
        await sleep(verifier ? 4000 : 500);
        return browser;
    }

    /** The extension's own record for the tab showing `urlPrefix`, if it has one. */
    async function verifierState(browser, urlPrefix) {
        const page = browser.extensionUrl('popup.html?debug=states');
        if (!page) return null;
        const tab = await browser.newTab();
        try {
            await tab.goto(page, 300);
            let raw = null;
            for (let attempt = 0; attempt < 40 && !raw; attempt += 1) {
                raw = await tab.eval(`() => {
                    const el = document.getElementById('debug-states');
                    return el ? el.textContent : null;
                }`);
                if (!raw) await sleep(150);
            }
            if (process.env.VERIFIER_TEST_DEBUG) console.log(`    (extension states: ${String(raw).slice(0, 600)})`);
            if (!raw) return null;
            const states = JSON.parse(raw);
            return states.find((entry) => entry.url && entry.url.startsWith(urlPrefix)) || null;
        } catch (failure) {
            if (process.env.VERIFIER_TEST_DEBUG) console.log(`    (state read failed: ${failure.message})`);
            return null;
        } finally {
            await tab.close().catch(() => {});
        }
    }

    /**
     * Run `before` in a browser without the verifier, then bring the
     * verifier in while keeping everything the site stored in that profile.
     * Chromium takes extensions at startup only, so it is restarted on the
     * same profile; Firefox installs the add-on into the running session.
     */
    async function addVerifierAfter(before) {
        if (browserName === 'chromium') {
            const profileDir = fs.mkdtempSync(path.join(work, 'chromium-kept-'));
            const first = await launch({ verifier: false, profileDir });
            await before(first);
            await first.close();
            open.splice(open.indexOf(first), 1);
            return launch({ verifier: true, profileDir });
        }
        const browser = await launch({ verifier: false });
        await before(browser);
        await browser.install(verifierDir);
        await sleep(4000);
        return browser;
    }

    return {
        browserName,
        launch,
        addVerifierAfter,
        verifierState,
        async visit(browser, url, settleMs) {
            await control('/reset');
            const tab = await browser.newTab();
            const navigation = await tab.goto(url, settleMs);
            let page = null;
            try {
                page = await tab.eval(PROBE);
            } catch (failure) {
                page = { probeError: failure.message.slice(0, 120) };
            }
            const log = await control('/log');
            return { tab, navigation, page, log };
        },
        async closeAll() {
            while (open.length) await open.pop().close().catch(() => {});
            if (proxy) proxy.close();
        },
    };
}

/** Summarise a server log: what the attacker's origin learned, what was fetched. */
function digest(log) {
    const leak = log.find((entry) => entry.note.startsWith('leak '));
    return {
        attackerRequests: log.filter((entry) => entry.host.startsWith('attacker.test')).length,
        releasePageRequests: log.filter((entry) => entry.note === 'release page').length,
        leakedFragment: leak ? leak.note.slice(5) : null,
        verifierFetches: log.filter((entry) => entry.mode === 'cors' && entry.dest === 'empty'
            && !entry.host.startsWith('attacker.test') && entry.path.startsWith('/static/')).length,
        evilCssRequested: log.some((entry) => entry.path === '/static/css/evil.css'),
    };
}

const results = [];
let failures = 0;

function report(browserName, id, title, observed, expectations) {
    console.log(`\n[${browserName}] ${id} ${title}`);
    for (const [key, value] of Object.entries(observed)) {
        console.log(`    ${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
    }
    const outcome = { browser: browserName, id, title, observed, checks: [] };
    for (const [description, kind, passed] of observeOnly ? [] : expectations) {
        const label = passed ? 'ok' : (kind === 'limit' ? 'LIMIT' : 'FAILED');
        if (!passed && kind !== 'limit') failures += 1;
        console.log(`    ${label.padEnd(7)} ${description}`);
        outcome.checks.push({ description, kind, passed });
    }
    results.push(outcome);
}

const cases = require('./cases');

(async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'verifier-test-'));
    const browsers = onlyBrowser ? [onlyBrowser] : ['chromium', 'firefox'];
    try {
        await withServer(work, async () => {
            for (const browserName of browsers) {
                for (const testCase of cases) {
                    if (selected.length && !selected.includes(testCase.id)) continue;
                    const context = makeContext(browserName, work);
                    try {
                        await control('/mode?set=clean');
                        await control('/manifest?serve=1');
                        await testCase.run({
                            ...context,
                            control,
                            digest,
                            sleep,
                            urls: { SITE, ROOM, SECRET, CHAT, INVITE },
                            report: (observed, expectations = []) => report(
                                browserName, testCase.id, testCase.title, observed, expectations,
                            ),
                        });
                    } catch (failure) {
                        failures += 1;
                        console.log(`\n[${browserName}] ${testCase.id} ${testCase.title}\n    FAILED  case crashed: ${failure.stack}`);
                    } finally {
                        await context.closeAll();
                    }
                }
            }
        });
    } finally {
        fs.rmSync(work, { recursive: true, force: true });
    }
    const out = process.env.VERIFIER_TEST_RESULTS;
    if (out) fs.writeFileSync(out, JSON.stringify(results, null, 2));
    console.log(observeOnly
        ? '\nobservations only, nothing checked'
        : `\n${failures === 0 ? 'PASSED' : `FAILED: ${failures} expectation(s)`}`);
    process.exit(Math.min(failures, 100));
})();
