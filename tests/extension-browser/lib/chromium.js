'use strict';

/**
 * Minimal Chromium driver over the DevTools protocol. No dependencies.
 *
 * The protocol runs over a pipe, and extensions are loaded with the
 * protocol's Extensions.loadUnpacked. Google Chrome ignores the
 * --load-extension switch since version 137; loadUnpacked works in Chrome
 * and Chromium alike, but only over a pipe and with
 * --enable-unsafe-extension-debugging.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function launchChromium({ extensions, workDir, httpsPort, hosts, binary, profileDir }) {
    // A caller that wants state to survive a restart passes its own profile.
    const profile = profileDir || fs.mkdtempSync(path.join(workDir, 'chromium-'));
    const map = hosts.map((host) => `MAP ${host} 127.0.0.1:${httpsPort}`).join(', ');
    const args = [
        '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        `--user-data-dir=${profile}`,
        '--remote-debugging-pipe', '--enable-unsafe-extension-debugging',
        `--host-resolver-rules=${map}`,
        '--ignore-certificate-errors',
        'about:blank',
    ];
    // The browser reads commands from descriptor 3 and writes to 4.
    const child = spawn(binary || process.env.CHROMIUM || 'chromium', args,
        { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
    const toBrowser = child.stdio[3];
    const fromBrowser = child.stdio[4];
    toBrowser.on('error', () => { /* the browser has gone away */ });

    let nextId = 1;
    const pending = new Map();
    let buffered = '';
    // Messages are JSON, each one terminated by a NUL byte.
    fromBrowser.on('data', (chunk) => {
        buffered += chunk.toString('utf8');
        for (let end = buffered.indexOf('\0'); end !== -1; end = buffered.indexOf('\0')) {
            const message = JSON.parse(buffered.slice(0, end));
            buffered = buffered.slice(end + 1);
            if (!message.id || !pending.has(message.id)) continue;
            const { resolve, reject } = pending.get(message.id);
            pending.delete(message.id);
            if (message.error) reject(new Error(message.error.message));
            else resolve(message.result);
        }
    });
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
        const id = nextId;
        nextId += 1;
        pending.set(id, { resolve, reject });
        toBrowser.write(`${JSON.stringify({ id, method, params, sessionId })}\0`);
    });

    const version = (await send('Browser.getVersion')).product;

    // The first extension is the one whose pages the caller asks for.
    let extensionBase = null;
    for (const directory of extensions) {
        const { id } = await send('Extensions.loadUnpacked', { path: path.resolve(directory) });
        if (!extensionBase) extensionBase = `chrome-extension://${id}/`;
    }

    async function newTab() {
        const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
        const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
        await send('Page.enable', {}, sessionId);
        await send('Runtime.enable', {}, sessionId);

        const evaluate = async (source) => {
            const result = await send('Runtime.evaluate', {
                expression: `(${source})()`,
                returnByValue: true,
                awaitPromise: true,
                allowUnsafeEvalBlockedByCSP: true,
            }, sessionId);
            if (result.exceptionDetails) {
                throw new Error(result.exceptionDetails.exception?.description || 'evaluation failed');
            }
            return result.result.value;
        };

        return {
            async goto(url, settleMs = 2500) {
                const result = await send('Page.navigate', { url }, sessionId);
                const deadline = Date.now() + 20000;
                while (Date.now() < deadline) {
                    try {
                        if (await evaluate('() => document.readyState') === 'complete') break;
                    } catch (_) { /* document is being replaced */ }
                    await sleep(100);
                }
                await sleep(settleMs);
                return { error: result.errorText || null };
            },
            eval: evaluate,
            // A DevTools protocol command for this tab, for what the
            // helpers above do not cover (a viewport size, a screenshot).
            send: (method, params = {}) => send(method, params, sessionId),
            close: () => send('Target.closeTarget', { targetId }),
        };
    }

    return {
        name: 'chromium',
        version,
        extensionUrl: (file) => (extensionBase ? extensionBase + file : null),
        newTab,
        async close() {
            try { await send('Browser.close'); } catch (_) { /* already gone */ }
            await new Promise((resolve) => {
                child.once('exit', resolve);
                setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 5000);
            });
        },
    };
}

module.exports = { launchChromium };
