'use strict';

/**
 * Minimal Firefox driver over geckodriver's WebDriver HTTP interface.
 *
 * The browser is pointed at a restricting CONNECT proxy (lib/proxy.js) for
 * every HTTPS request, since Firefox cannot be told to resolve a host name
 * to another address. Extensions are installed as temporary add-ons.
 */

const { spawn } = require('child_process');
const net = require('net');
const path = require('path');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Fixed internal UUIDs, so moz-extension:// URLs are known in advance. */
const EXTENSION_UUIDS = {
    'pinchat-verifier@pinchat.io': '0a6c1b7e-5f0c-4c3a-9d55-70f1c0de0001',
};

function freePort() {
    return new Promise((resolve) => {
        const probe = net.createServer();
        probe.listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });
}

async function launchFirefox({ extensions, proxyPort, binary }) {
    const port = await freePort();
    // System access lets the driver load the extension's own pages in a tab,
    // which web content is not allowed to navigate to. The tests read the
    // extension's conclusions from there.
    const driver = spawn('geckodriver', [
        '--port', String(port), '--allow-system-access',
        '--binary', binary || process.env.FIREFOX || '/usr/bin/firefox-esr',
    ], { stdio: 'ignore', env: { ...process.env, MOZ_HEADLESS: '1' } });
    const base = `http://127.0.0.1:${port}`;

    const call = async (method, route, body) => {
        const response = await fetch(base + route, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: body ? JSON.stringify(body) : undefined,
        });
        const { value } = await response.json();
        if (value && value.error) {
            throw new Error(`${value.error}: ${(value.message || '').slice(0, 200)}`);
        }
        return value;
    };

    for (let i = 0; i < 50; i += 1) {
        try {
            if ((await call('GET', '/status')).ready) break;
        } catch (_) { /* not listening yet */ }
        await sleep(100);
    }

    const created = await call('POST', '/session', {
        capabilities: {
            alwaysMatch: {
                browserName: 'firefox',
                acceptInsecureCerts: true,
                'moz:firefoxOptions': {
                    args: ['-headless'],
                    prefs: {
                        'network.proxy.type': 1,
                        'network.proxy.ssl': '127.0.0.1',
                        'network.proxy.ssl_port': proxyPort,
                        'network.proxy.http': '127.0.0.1',
                        'network.proxy.http_port': proxyPort,
                        'network.proxy.no_proxies_on': '',
                        'network.proxy.allow_hijacking_localhost': true,
                        'extensions.webextensions.uuids': JSON.stringify(EXTENSION_UUIDS),
                        'xpinstall.signatures.required': false,
                        'browser.aboutConfig.showWarning': false,
                        'network.http.speculative-parallel-limit': 0,
                        'browser.cache.disk.enable': true,
                    },
                },
            },
        },
    });
    const session = `/session/${created.sessionId}`;
    const version = `Firefox/${created.capabilities.browserVersion}`;

    const install = async (dir) => {
        await call('POST', `${session}/moz/addon/install`, { path: path.resolve(dir), temporary: true });
        await sleep(1500);
    };
    for (const dir of extensions) await install(dir);

    let current = null;
    const focus = async (handle) => {
        if (current !== handle) {
            await call('POST', `${session}/window`, { handle });
            current = handle;
        }
    };

    async function newTab() {
        // "New window" is issued from the current window; if that one was
        // closed, pick any that is still open first.
        const handles = await call('GET', `${session}/window/handles`);
        if (!handles.includes(current)) await focus(handles[0]);
        const { handle } = await call('POST', `${session}/window/new`, { type: 'tab' });
        return {
            async goto(url, settleMs = 2500) {
                await focus(handle);
                let error = null;
                try {
                    if (url.startsWith('moz-extension://')) {
                        await call('POST', `${session}/moz/context`, { context: 'chrome' });
                        try {
                            await call('POST', `${session}/execute/sync`, {
                                script: 'gBrowser.selectedBrowser.fixupAndLoadURIString(arguments[0], '
                                    + '{ triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal() });',
                                args: [url],
                            });
                        } finally {
                            await call('POST', `${session}/moz/context`, { context: 'content' });
                        }
                    } else {
                        await call('POST', `${session}/url`, { url });
                    }
                } catch (failure) {
                    error = failure.message;
                }
                await sleep(settleMs);
                return { error };
            },
            async eval(source) {
                await focus(handle);
                return call('POST', `${session}/execute/sync`, {
                    script: `return (${source})();`,
                    args: [],
                });
            },
            async close() {
                await focus(handle);
                await call('DELETE', `${session}/window`);
                current = null;
            },
        };
    }

    return {
        name: 'firefox',
        version,
        extensionUrl: (file) => `moz-extension://${EXTENSION_UUIDS['pinchat-verifier@pinchat.io']}/${file}`,
        newTab,
        install,
        async close() {
            try { await call('DELETE', session); } catch (_) { /* already gone */ }
            driver.kill();
        },
    };
}

module.exports = { launchFirefox };
