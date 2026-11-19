#!/usr/bin/env node

/**
 * Markup that arrives with a page must not be able to drive the client.
 *
 * The client-side engine reads directives from markup, and in Chromium the
 * page markup is the one part of the client a browser extension cannot
 * attest. These tests pin the three things that keep served markup inert:
 *
 * 1. The engine file is the vendored build plus the guard, and the guard
 *    gives the engine a directive prefix nobody outside it knows, starts it
 *    only after parsing, and removes what was not mounted.
 * 2. The two pages that run the engine carry no application markup at all.
 * 3. That markup lives in signed template scripts, in a form mount() can
 *    take and nothing else.
 *
 * The behaviour in a real browser, against a server that adds markup, is
 * covered by tests/extension-browser (case markup-directives).
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.join(__dirname, '..');
const read = (relative) => fs.readFileSync(path.join(root, relative));

// The vendored Alpine.js CSP build, 3.15.0, as shipped before the guard was
// appended. Upgrading the engine means replacing these bytes on purpose.
const UPSTREAM_BYTES = 60017;
const UPSTREAM_SHA256 = 'e7c863da5896692f5d478e10dae089e6164fed1c5c1b6a1f7cbbf7a9b093f055';

const ENGINE = 'static/js/alpine-csp.min.js';
const PAGES = { chat: 'static/chat.html', index: 'static/index.html' };

let passed = 0;
let failed = 0;
function test(name, body) {
    try {
        body();
        console.log(`PASSED: ${name}`);
        passed += 1;
    } catch (error) {
        console.log(`FAILED: ${name}\n    ${error.message}`);
        failed += 1;
    }
}

const engineBytes = read(ENGINE);
const guardSource = engineBytes.subarray(UPSTREAM_BYTES).toString('utf8');

// -----------------------------------------------------------------------------
// A document small enough to run the guard in, with nothing it does not use.
// -----------------------------------------------------------------------------

function fakeElement(tagName, attributes = {}, children = []) {
    const element = {
        nodeType: 1,
        tagName,
        attrs: new Map(Object.entries(attributes)),
        childNodes: children,
        parent: null,
        content: null,
        get attributes() {
            return [...this.attrs].map(([name, value]) => ({ name, value }));
        },
        get children() {
            return this.childNodes.filter((node) => node.nodeType === 1);
        },
        removeAttribute(name) { this.attrs.delete(name); },
        setAttribute(name, value) { this.attrs.set(name, value); },
        remove() {
            if (this.parent) this.parent.childNodes = this.parent.childNodes.filter((node) => node !== this);
        },
        append(fragment) {
            for (const node of fragment.childNodes) {
                node.parent = this;
                this.childNodes.push(node);
            }
            fragment.childNodes = [];
        },
        querySelectorAll() {
            const all = [];
            const walk = (node) => {
                for (const child of node.childNodes.filter((entry) => entry.nodeType === 1)) {
                    all.push(child);
                    walk(child);
                }
            };
            walk(this);
            return all;
        },
    };
    for (const child of children) child.parent = element;
    return element;
}

const textNode = () => ({ nodeType: 3, childNodes: [], remove() {
    if (this.parent) this.parent.childNodes = this.parent.childNodes.filter((node) => node !== this);
} });

/** Runs the guard against a fake engine and document. */
function runGuard({ readyState = 'loading', body, html, head, nextTemplateContent } = {}) {
    const calls = { prefix: [], start: 0 };
    const engine = {
        prefix(value) { calls.prefix.push(value); },
        start() { calls.start += 1; },
    };
    const listeners = {};
    const microtasks = [];
    const document = {
        readyState,
        body: body === undefined ? fakeElement('BODY', { class: 'chat-page' }) : body,
        documentElement: html || fakeElement('HTML', { lang: 'en' }),
        head: head || fakeElement('HEAD'),
        addEventListener(type, listener) { listeners[type] = listener; },
        createElement(tagName) {
            assert.strictEqual(tagName, 'template');
            const template = fakeElement('TEMPLATE');
            template.content = nextTemplateContent();
            Object.defineProperty(template, 'innerHTML', { set() {} });
            return template;
        },
    };
    const window = { Alpine: engine };
    const context = vm.createContext({
        window,
        document,
        crypto: crypto.webcrypto,
        Node: { ELEMENT_NODE: 1 },
        queueMicrotask: (task) => microtasks.push(task),
        Uint8Array,
        Array,
        Object,
        String,
        WeakSet,
        Error,
    });
    vm.runInContext(guardSource, context, { filename: 'guard' });
    return {
        engine, calls, document, window,
        parsed: () => listeners.DOMContentLoaded && listeners.DOMContentLoaded(),
        flush: () => { while (microtasks.length) microtasks.shift()(); },
    };
}

// -----------------------------------------------------------------------------
// The engine file
// -----------------------------------------------------------------------------

test('the engine file is the vendored build followed by the guard', () => {
    const upstream = engineBytes.subarray(0, UPSTREAM_BYTES);
    assert.strictEqual(crypto.createHash('sha256').update(upstream).digest('hex'), UPSTREAM_SHA256,
        'the first bytes are no longer the vendored build');
    assert(upstream.toString('utf8').endsWith('queueMicrotask(()=>{Yt.start()});})();\n'),
        'the vendored build still ends by queueing its own start');
    assert(guardSource.trimStart().startsWith('/*\n * PinChat markup guard.'), 'the guard follows it directly');
    assert(guardSource.trimEnd().endsWith('})();'), 'and nothing follows the guard');
    new vm.Script(engineBytes.toString('utf8'), { filename: ENGINE });
});

test('the directive prefix is random, set once, and cannot be changed', () => {
    const first = runGuard();
    const second = runGuard();
    assert.strictEqual(first.calls.prefix.length, 1);
    assert(/^p[0-9a-f]{24}-$/.test(first.calls.prefix[0]), first.calls.prefix[0]);
    assert.notStrictEqual(first.calls.prefix[0], second.calls.prefix[0], 'a new value on every load');
    assert.notStrictEqual(first.calls.prefix[0], 'x-');
    assert.throws(() => first.engine.prefix('x-'), /fixed for the life of the page/);
    assert.strictEqual(first.calls.prefix.length, 1, 'a later call does not reach the engine');
    assert.deepStrictEqual(Object.keys(first.window.PinChatUI), ['mount'], 'only mount is exposed');
    assert(Object.isFrozen(first.window.PinChatUI));
});

test('the engine starts once, after parsing, and not when the build asks', () => {
    const loading = runGuard({ readyState: 'loading' });
    // What the vendored build does right after the file has run.
    loading.engine.start();
    loading.flush();
    assert.strictEqual(loading.calls.start, 0, 'not while the document is still being parsed');
    loading.parsed();
    assert.strictEqual(loading.calls.start, 1);
    loading.parsed();
    loading.engine.start();
    assert.strictEqual(loading.calls.start, 1, 'never a second time');

    // Loaded late, for example deferred: parsing is already over.
    const late = runGuard({ readyState: 'interactive' });
    late.engine.start();
    assert.strictEqual(late.calls.start, 0);
    late.flush();
    assert.strictEqual(late.calls.start, 1);
});

test('mount rewrites directives to the prefix, in nested templates too', () => {
    const inner = fakeElement('SPAN', { 'x-text': 'msg.text', '@click.stop': '' });
    const loop = fakeElement('TEMPLATE', { 'x-for': 'msg in messages', ':key': 'msg.id' });
    loop.content = fakeElement('#fragment', {}, [inner]);
    const image = fakeElement('IMG', { ':src': 'msg.imageUrl', class: 'message-image', 'xlink:href': '#i' });
    const top = fakeElement('DIV', { 'x-data': '$store.chatRoom', '@keydown.escape.window': 'handleEscape()' },
        [loop, image]);
    const guard = runGuard({ nextTemplateContent: () => fakeElement('#fragment', {}, [top]) });
    const prefix = guard.calls.prefix[0];

    guard.window.PinChatUI.mount('<div>ignored by the fake document</div>');

    assert.deepStrictEqual([...top.attrs.keys()].sort(), [`${prefix}data`, `${prefix}on:keydown.escape.window`].sort());
    assert.strictEqual(top.attrs.get(`${prefix}data`), '$store.chatRoom', 'values are kept');
    assert.deepStrictEqual([...loop.attrs.keys()].sort(), [`${prefix}bind:key`, `${prefix}for`].sort());
    assert.deepStrictEqual([...inner.attrs.keys()].sort(), [`${prefix}on:click.stop`, `${prefix}text`].sort());
    assert.deepStrictEqual([...image.attrs.keys()].sort(), [`${prefix}bind:src`, 'class', 'xlink:href'].sort(),
        'ordinary attributes are left alone');
    assert.strictEqual(guard.document.body.childNodes[0], top, 'mounted directly under the body');
});

test('what was not mounted is removed before the engine starts', () => {
    const script = fakeElement('SCRIPT', { src: '/static/js/app.js' });
    const served = fakeElement('DIV', { 'x-data': '', id: 'server-added' });
    const wrapper = fakeElement('FORM', { action: '/collect', 'x-data': '$store.chatRoom' });
    const noscript = fakeElement('NOSCRIPT');
    const text = textNode();
    const body = fakeElement('BODY', { class: 'chat-page', 'x-data': '', ':background': '$store.chatRoom.sas', hidden: '' },
        [noscript, served, script, wrapper, text]);
    text.parent = body;
    const html = fakeElement('HTML', { lang: 'en', 'data-theme': 'dark', 'x-data': '', inert: '' });
    const head = fakeElement('HEAD', { 'x-data': '' });
    const mountedNode = fakeElement('DIV', { class: 'chat-container' });
    const guard = runGuard({ body, html, head, nextTemplateContent: () => fakeElement('#fragment', {}, [mountedNode]) });

    guard.window.PinChatUI.mount('markup');
    guard.parsed();

    assert.strictEqual(guard.calls.start, 1);
    assert.deepStrictEqual(body.childNodes, [script, mountedNode],
        'only scripts and mounted nodes are left in the body');
    assert.deepStrictEqual([...body.attrs.keys()], ['class']);
    assert.deepStrictEqual([...html.attrs.keys()].sort(), ['data-theme', 'lang']);
    assert.deepStrictEqual([...head.attrs.keys()], []);
});

test('mount refuses to run without a body', () => {
    const guard = runGuard({ body: null, nextTemplateContent: () => fakeElement('#fragment') });
    assert.throws(() => guard.window.PinChatUI.mount('markup'), /needs the document body/);
});

// -----------------------------------------------------------------------------
// The pages and their templates
// -----------------------------------------------------------------------------

for (const [name, file] of Object.entries(PAGES)) {
    const html = read(file).toString('utf8');

    test(`${file} carries no application markup`, () => {
        const body = /<body[^>]*>([\s\S]*)<\/body>/.exec(html)[1];
        const withoutAllowed = body
            .replace(/<script src="[^"]+" integrity="sha256-[A-Za-z0-9+/=]+" crossorigin="anonymous" ><\/script>/g, '')
            .replace(/<noscript><p>[^<]*<\/p><\/noscript>/, '');
        assert.strictEqual(withoutAllowed.trim(), '', `unexpected content in the body: ${withoutAllowed.trim().slice(0, 80)}`);
        // No directive anywhere in the file: nothing in it is addressed to
        // the engine, so nothing in it has to be trusted.
        const directive = /<[^>]*\s(?:x-[a-z]|[:@][a-z])[^>]*>/i.exec(html);
        assert.strictEqual(directive, null, directive ? `directive in ${directive[0].slice(0, 80)}` : '');
    });

    test(`${file} loads the engine first and not deferred, then its template`, () => {
        const scripts = [...html.matchAll(/<script src="([^"]+)"([^>]*)>/g)].map((match) => ({
            src: match[1], rest: match[2],
        }));
        assert.strictEqual(scripts[0].src, '/static/js/alpine-csp.min.js');
        assert(!/\b(defer|async)\b/.test(scripts[0].rest), 'the engine must run before the template is mounted');
        const head = html.slice(0, html.indexOf('</head>'));
        assert(head.includes('/static/js/alpine-csp.min.js'), 'the engine is in the head');
        const firstInBody = /<body[^>]*>[\s\S]*?<script src="([^"]+)"/.exec(html)[1];
        assert.strictEqual(firstInBody, `/static/js/templates/${name}.js`);
        assert(!scripts.some((entry) => /\b(defer|async)\b/.test(entry.rest)),
            'scripts run in document order, so the stores exist when the engine starts');
    });

    test(`the ${name} template is one mount() call on a raw string`, () => {
        const source = read(`static/js/templates/${name}.js`).toString('utf8');
        const call = /^\/\*\*[\s\S]*?\*\/\nwindow\.PinChatUI\.mount\(String\.raw`([\s\S]*)`\);\n$/.exec(source);
        assert(call, 'a comment, then window.PinChatUI.mount(String.raw`...`); and nothing else');
        const markup = call[1];
        assert(!markup.includes('`'), 'a backtick would end the string');
        assert(!markup.includes('${'), '"${" would be evaluated');
        assert(!/<script/i.test(markup), 'templates carry markup, not scripts');
        assert(/\sx-data[=\s>]/.test(markup), 'the template declares its own engine roots');
    });
}

test('no other signed script mounts markup or hands the engine markup from the document', () => {
    const scriptDir = path.join(root, 'static', 'js');
    const sources = [];
    const walk = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) walk(full);
            else if (entry.name.endsWith('.js')) sources.push(full);
        }
    };
    walk(scriptDir);
    for (const file of sources) {
        const relative = path.relative(root, file);
        const source = relative === ENGINE ? guardSource : fs.readFileSync(file, 'utf8');
        const mounts = (source.match(/PinChatUI\.mount\(/g) || []).length;
        const isTemplate = relative.startsWith(path.join('static', 'js', 'templates'));
        if (relative === ENGINE) {
            assert.strictEqual(mounts, 0, 'the guard defines mount and does not call it');
        } else {
            assert.strictEqual(mounts, isTemplate ? 1 : 0, `${relative} calls PinChatUI.mount ${mounts} time(s)`);
        }
        assert(!/Alpine\.prefix\(/.test(source) || relative === ENGINE, `${relative} touches the directive prefix`);
    }
});

console.log(`\n${passed} inert markup tests passed${failed ? `, ${failed} failed` : ''}`);
process.exit(failed === 0 ? 0 : 1);
