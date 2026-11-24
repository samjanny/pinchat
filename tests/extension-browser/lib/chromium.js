'use strict';

/**
 * Minimal Chromium driver over the DevTools protocol. No dependencies: Node's
 * built-in WebSocket and fetch are enough for what the tests need.
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function launchChromium({ extensions, workDir, httpsPort, hosts, binary, profileDir }) {
    // A caller that wants state to survive a restart passes its own profile.
    const profile = profileDir || fs.mkdtempSync(path.join(workDir, 'chromium-'));
    fs.rmSync(path.join(profile, 'DevToolsActivePort'), { force: true });
    const map = hosts.map((host) => `MAP ${host} 127.0.0.1:${httpsPort}`).join(', ');
    const args = [
        '--headless=new', '--no-sandbox', '--disable-gpu', '--no-first-run',
        '--disable-background-networking', '--disable-component-update', '--disable-sync',
        `--user-data-dir=${profile}`,
        '--remote-debugging-port=0',
        `--host-resolver-rules=${map}`,
        '--ignore-certificate-errors',
        'about:blank',
    ];
    if (extensions.length) args.unshift(`--load-extension=${extensions.join(',')}`);
    const child = spawn(binary || process.env.CHROMIUM || 'chromium', args, { stdio: 'ignore' });

    const portFile = path.join(profile, 'DevToolsActivePort');
    for (let i = 0; i < 100 && !fs.existsSync(portFile); i += 1) await sleep(100);
    const [port, browserPath] = fs.readFileSync(portFile, 'utf8').trim().split('\n');

    const socket = new WebSocket(`ws://127.0.0.1:${port}${browserPath}`);
    await new Promise((resolve, reject) => {
        socket.addEventListener('open', resolve, { once: true });
        socket.addEventListener('error', reject, { once: true });
    });
    let nextId = 1;
    const pending = new Map();
    socket.addEventListener('message', (event) => {
        const message = JSON.parse(event.data);
        if (!message.id || !pending.has(message.id)) return;
        const { resolve, reject } = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) reject(new Error(message.error.message));
        else resolve(message.result);
    });
    const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
        const id = nextId;
        nextId += 1;
        pending.set(id, { resolve, reject });
        socket.send(JSON.stringify({ id, method, params, sessionId }));
    });

    const version = (await send('Browser.getVersion')).product;

    // The extension id is derived from its directory; read it off the
    // service worker target the browser starts for it.
    let extensionBase = null;
    if (extensions.length) {
        for (let i = 0; i < 50 && !extensionBase; i += 1) {
            const { targetInfos } = await send('Target.getTargets');
            const worker = targetInfos.find((target) => target.type === 'service_worker'
                && /^chrome-extension:\/\/[a-p]{32}\/background\.js$/.test(target.url));
            if (worker) extensionBase = worker.url.replace(/background\.js$/, '');
            else await sleep(200);
        }
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
