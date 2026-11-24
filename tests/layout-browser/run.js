#!/usr/bin/env node
/**
 * Do the pages fit a phone?
 *
 * Serves static/ from the working tree on localhost, opens every page in a
 * headless Chromium at phone widths, and measures what a person would
 * notice: content wider than the screen, a text field small enough to make
 * iOS zoom the page when it takes focus, a main control too small for a
 * finger, the composer of the chat page out of reach.
 *
 * No backend runs here. The chat page is measured as it renders on its own,
 * with its header, conversation area and composer in place; nothing in this
 * test sends a message.
 *
 * Not part of CI: it needs Chromium and Node 22 or later.
 *
 * Usage:
 *   node tests/layout-browser/run.js [width ...]     default: 320 360 414
 *     --shots DIR    also write a screenshot of every page and width to DIR
 *
 * Exit status is the number of failed expectations.
 */

'use strict';

const fs = require('fs');
const http = require('http');
const os = require('os');
const path = require('path');

const { launchChromium } = require('../extension-browser/lib/chromium');

const staticDir = path.join(__dirname, '..', '..', 'static');
const argv = process.argv.slice(2);
const shotsIndex = argv.indexOf('--shots');
const shotsDir = shotsIndex === -1 ? null : path.resolve(argv.splice(shotsIndex, 2)[1]);
const widths = argv.length ? argv.map(Number) : [320, 360, 414];
const HEIGHT = 740;
const PAGES = ['index', 'login', 'terms', 'privacy', 'chat'];

const TYPES = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
};

function serve() {
    const server = http.createServer((req, res) => {
        const url = new URL(req.url, 'http://localhost');
        const file = path.join(staticDir, path.normalize(url.pathname.replace(/^\/static\//, '')));
        if (!url.pathname.startsWith('/static/') || !file.startsWith(staticDir + path.sep)
            || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
            res.writeHead(404);
            res.end();
            return;
        }
        res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream' });
        res.end(fs.readFileSync(file));
    });
    return new Promise((resolve) => {
        server.listen(0, '127.0.0.1', () => resolve(server));
    });
}

/** Runs in the page. Returns what was measured, as plain data. */
const MEASURE = `() => {
    const viewport = window.innerWidth;
    const shown = (el) => {
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') return false;
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    };
    const label = (el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '')
        + (el.classList.length ? '.' + Array.from(el.classList).slice(0, 2).join('.') : '');
    // A row that scrolls sideways on purpose may hold more than fits.
    const insideScroller = (el) => {
        for (let node = el.parentElement; node && node !== document.body; node = node.parentElement) {
            const overflow = getComputedStyle(node).overflowX;
            if (overflow === 'auto' || overflow === 'scroll') return true;
        }
        return false;
    };
    const all = Array.from(document.querySelectorAll('body *')).filter(shown);
    const tooWide = all.filter((el) => {
        const rect = el.getBoundingClientRect();
        return (rect.right > viewport + 1 || rect.left < -1) && !insideScroller(el);
    }).map((el) => label(el) + ' ' + Math.round(el.getBoundingClientRect().left) + '..'
        + Math.round(el.getBoundingClientRect().right));
    const zooming = all
        .filter((el) => el.matches('input[type="text"], input[type="password"], input:not([type]), textarea'))
        .filter((el) => parseFloat(getComputedStyle(el).fontSize) < 16)
        .map((el) => label(el) + ' ' + getComputedStyle(el).fontSize);
    const smallControls = all
        .filter((el) => el.matches('button, input[type="submit"], .btn, .topbar-link'))
        .filter((el) => {
            const rect = el.getBoundingClientRect();
            return rect.height < 40 || rect.width < 40;
        })
        .map((el) => label(el) + ' ' + Math.round(el.getBoundingClientRect().width) + 'x'
            + Math.round(el.getBoundingClientRect().height));
    const send = document.querySelector('.input-area .btn-send, .message-form button[type="submit"]');
    const header = document.querySelector('.chat-header');
    const composer = document.querySelector('.input-area');
    const conversation = document.querySelector('.messages-container');
    return {
        viewport,
        pageWidth: document.documentElement.scrollWidth,
        tooWide: [...new Set(tooWide)].slice(0, 8),
        zooming: [...new Set(zooming)],
        smallControls: [...new Set(smallControls)].slice(0, 8),
        application: !!document.querySelector('.chat-container, .home-container, .login-container, .page-legal, main, .container'),
        sendButton: send && shown(send) ? Math.round(send.getBoundingClientRect().right) : null,
        headerHeight: header && shown(header) ? Math.round(header.getBoundingClientRect().height) : null,
        composerBottom: composer && shown(composer) ? Math.round(composer.getBoundingClientRect().bottom) : null,
        composerHeight: composer && shown(composer) ? Math.round(composer.getBoundingClientRect().height) : 0,
        noticeHeight: (() => {
            const notice = document.getElementById('cookie-notice');
            return notice && shown(notice) ? Math.round(notice.getBoundingClientRect().height) : 0;
        })(),
        noticeCovers: (() => {
            const notice = document.getElementById('cookie-notice');
            if (!notice || !shown(notice) || !composer) return false;
            const a = notice.getBoundingClientRect();
            const b = composer.getBoundingClientRect();
            return a.top < b.bottom && a.bottom > b.top;
        })(),
        conversationHeight: conversation && shown(conversation)
            ? Math.round(conversation.getBoundingClientRect().height) : null,
        viewportHeight: window.innerHeight,
    };
}`;

let failures = 0;
function check(description, passed, detail = '') {
    if (!passed) failures += 1;
    console.log(`    ${passed ? 'ok     ' : 'FAILED '} ${description}${!passed && detail ? `: ${detail}` : ''}`);
}

(async () => {
    const work = fs.mkdtempSync(path.join(os.tmpdir(), 'layout-test-'));
    const server = await serve();
    const origin = `http://localhost:${server.address().port}`;
    const browser = await launchChromium({ extensions: [], workDir: work, httpsPort: 1, hosts: [] });
    if (shotsDir) fs.mkdirSync(shotsDir, { recursive: true });
    try {
        for (const width of widths) {
            for (const page of PAGES) {
                const tab = await browser.newTab();
                await tab.send('Emulation.setDeviceMetricsOverride', {
                    width, height: HEIGHT, deviceScaleFactor: 1, mobile: true,
                });
                await tab.send('Emulation.setTouchEmulationEnabled', { enabled: true });
                const query = page === 'chat' ? '?room=00000000-0000-4000-8000-000000000000' : '';
                await tab.goto(`${origin}/static/${page}.html${query}`, 1500);
                const measured = await tab.eval(MEASURE);
                if (shotsDir) {
                    const { data } = await tab.send('Page.captureScreenshot', { format: 'png' });
                    fs.writeFileSync(path.join(shotsDir, `${page}-${width}.png`), Buffer.from(data, 'base64'));
                }
                await tab.close();

                console.log(`\n[${width}px] ${page}`);
                check('the page renders', measured.application && measured.viewport === width);
                check('nothing is wider than the screen',
                    measured.tooWide.length === 0 && measured.pageWidth <= width + 1,
                    measured.tooWide.join(' | ') || `page is ${measured.pageWidth}px wide`);
                check('no text field is small enough to make the browser zoom', measured.zooming.length === 0,
                    measured.zooming.join(' | '));
                check('buttons and navigation links are at least 40px in both directions',
                    measured.smallControls.length === 0, measured.smallControls.join(' | '));
                if (page === 'chat') {
                    check('the send button is on the screen',
                        measured.sendButton !== null && measured.sendButton <= width,
                        `right edge at ${measured.sendButton}`);
                    check('the cookie notice does not cover the composer', measured.noticeCovers === false);
                    check('the header leaves most of the height to the conversation',
                        measured.headerHeight !== null && measured.headerHeight <= measured.viewportHeight * 0.2,
                        `${measured.headerHeight}px of ${measured.viewportHeight}px`);
                    // Only the cookie notice, while it is there, is below it.
                    check('the composer sits at the bottom of the screen',
                        measured.composerBottom !== null
                        && measured.composerBottom <= measured.viewportHeight
                        && measured.viewportHeight - measured.composerBottom <= measured.noticeHeight + 24,
                        `bottom at ${measured.composerBottom} of ${measured.viewportHeight}`);
                    // What is always there: header, composer and, until it
                    // is dismissed, the cookie notice. Banners come and go
                    // and are not counted; without a backend this page is
                    // showing an error.
                    const fixed = measured.headerHeight + measured.composerHeight + measured.noticeHeight;
                    check('header, composer and notice together leave the conversation more than half the height',
                        measured.conversationHeight !== null && fixed <= measured.viewportHeight * 0.45,
                        `${fixed}px of ${measured.viewportHeight}px`);
                }
            }
        }
    } catch (failure) {
        failures += 1;
        console.log(`\nFAILED  the run crashed: ${failure.stack}`);
    } finally {
        await browser.close().catch(() => {});
        server.close();
        fs.rmSync(work, { recursive: true, force: true });
    }
    console.log(`\n${failures === 0 ? 'PASSED' : `FAILED: ${failures} expectation(s)`}`);
    process.exit(Math.min(failures, 100));
})();
