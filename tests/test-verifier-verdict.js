#!/usr/bin/env node
/**
 * Verdict logic of the browser extension (extensions/chrome/verdict.js).
 *
 * The extension shows a state per document. These tests pin down what each
 * state may be based on, so that a later change cannot quietly let an
 * unverified document be shown as verified, let one tab's result colour
 * another, or turn another extension's harmless additions into an alarm.
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const V = require('../extensions/chrome/verdict.js');
const { INTEGRITY, CLASS } = V;

let passed = 0;
function test(name, body) {
    body();
    passed += 1;
    console.log(`PASSED: ${name}`);
}

/** A document on the site whose checks completed with nothing to report. */
const base = (overrides = {}) => ({
    manifest: 'valid',
    official: true,
    topLevel: true,
    checksDone: true,
    policyInForce: true,
    workerControlled: false,
    canAttest: false,
    attested: false,
    findings: [],
    ...overrides,
});

test('both browser builds ship the same verdict logic', () => {
    for (const file of ['verdict.js', 'background.js', 'content.js', 'popup.js', 'popup.html',
        'warning.css', 'blocked.html', 'blocked.js', 'blocked.css']) {
        assert.strictEqual(
            fs.readFileSync(path.join(root, 'extensions/chrome', file), 'utf8'),
            fs.readFileSync(path.join(root, 'extensions/firefox', file), 'utf8'),
            `${file} differs between the Chrome and the Firefox build`,
        );
    }
});

test('verified needs an attested response body, and nothing less will do', () => {
    // Chromium: no way to hold a response body, so never more than partial.
    assert.strictEqual(V.decide(base()).integrity, INTEGRITY.PARTIAL);
    assert.strictEqual(V.decide(base({ attested: true })).integrity, INTEGRITY.PARTIAL,
        'an attestation claim is meaningless where the browser cannot attest');

    // Firefox: verified only with a receipt for this very document.
    assert.strictEqual(V.decide(base({ canAttest: true, attested: true })).integrity, INTEGRITY.VERIFIED);
    assert.strictEqual(V.decide(base({ canAttest: true, attested: false })).integrity, INTEGRITY.UNVERIFIABLE,
        'where attestation is possible its absence is not a lesser positive state');
    assert.strictEqual(
        V.decide(base({ canAttest: true, attested: true, topLevel: false })).integrity,
        INTEGRITY.UNVERIFIABLE,
    );
});

test('no positive state before the checks are in', () => {
    for (const record of [
        base({ checksDone: false }),
        base({ canAttest: true, attested: true, checksDone: false }),
        base({ manifest: 'unknown' }),
        base({ policyInForce: null }),
    ]) {
        assert.strictEqual(V.decide(record).integrity, INTEGRITY.CHECKING);
    }
});

test('a document outside the official origins is never vouched for', () => {
    const verdict = V.decide(base({ official: false, canAttest: true, attested: true }));
    assert.strictEqual(verdict.integrity, INTEGRITY.UNVERIFIABLE);
});

test('every confirmed finding fails the document, attested or not', () => {
    const confirmed = Object.entries(V.FINDINGS).filter(([, entry]) => entry[0] === CLASS.CONFIRMED);
    assert(confirmed.length >= 6);
    for (const [code] of confirmed) {
        for (const canAttest of [false, true]) {
            const verdict = V.decide(base({ canAttest, attested: true, findings: [V.finding(code)] }));
            assert.strictEqual(verdict.integrity, INTEGRITY.FAILED, code);
        }
    }
    assert.strictEqual(V.decide(base({ policyInForce: false })).integrity, INTEGRITY.FAILED);
    assert.strictEqual(V.decide(base({ workerControlled: true })).integrity, INTEGRITY.FAILED);
    assert.strictEqual(V.decide(base({ manifest: 'invalid', canAttest: true, attested: true })).integrity,
        INTEGRITY.FAILED, 'a rejected manifest is an attack signal, not a missing one');
});

test('a missing manifest is unverifiable, not failed and not verified', () => {
    assert.strictEqual(V.decide(base({ manifest: 'unavailable' })).integrity, INTEGRITY.UNVERIFIABLE);
    assert.strictEqual(
        V.decide(base({ manifest: 'unavailable', canAttest: true, attested: true })).integrity,
        INTEGRITY.UNVERIFIABLE,
    );
    for (const [code, entry] of Object.entries(V.FINDINGS)) {
        if (entry[0] !== CLASS.LIMIT) continue;
        assert.strictEqual(
            V.decide(base({ canAttest: true, attested: true, findings: [V.finding(code)] })).integrity,
            INTEGRITY.UNVERIFIABLE,
            code,
        );
    }
});

test('changes of unattested origin never change the integrity state', () => {
    const environment = Object.entries(V.FINDINGS)
        .filter(([, entry]) => entry[0] === CLASS.ENVIRONMENT)
        .map(([code]) => V.finding(code));
    assert(environment.length >= 4);
    for (const [record, expected] of [
        [base({ findings: environment }), INTEGRITY.PARTIAL],
        [base({ canAttest: true, attested: true, findings: environment }), INTEGRITY.VERIFIED],
    ]) {
        const verdict = V.decide(record);
        assert.strictEqual(verdict.integrity, expected);
        assert.strictEqual(verdict.attention, false, 'and they do not raise a notice either');
    }
});

test('suspicious findings raise a notice without claiming tampering', () => {
    const suspicious = Object.entries(V.FINDINGS).filter(([, entry]) => entry[0] === CLASS.SUSPICIOUS);
    for (const [code] of suspicious) {
        const verdict = V.decide(base({ findings: [V.finding(code)] }));
        assert.strictEqual(verdict.integrity, INTEGRITY.PARTIAL, code);
        assert.strictEqual(verdict.attention, true, code);
    }
});

test('an inline script element in the DOM is an observation, not a verdict', () => {
    // What a password manager leaves behind.
    const inline = V.findingForIssue({ type: 'inline-script', path: '[inline script]', error: 'inline script element' });
    assert.strictEqual(inline.class, CLASS.ENVIRONMENT);
    const fromExtension = V.findingForIssue({ type: 'extension-script', path: 'chrome-extension://abc', error: 'x' });
    assert.strictEqual(fromExtension.class, CLASS.ENVIRONMENT);

    // A site script the policy will not run points at the page, but proves
    // nothing about the server.
    assert.strictEqual(
        V.findingForIssue({ type: 'unknown-script', path: '/static/js/x.js', error: 'x' }).class,
        CLASS.SUSPICIOUS,
    );
    // An unsigned stylesheet from the site's own origin was loaded: the
    // policy allows same-origin styles, and the bytes came from the server.
    for (const type of ['unknown-stylesheet', 'unauthorized-stylesheet', 'stylesheet-missing-sri']) {
        assert.strictEqual(V.findingForIssue({ type, path: '/static/css/x.css', error: 'x' }).class, CLASS.CONFIRMED);
    }
    assert.strictEqual(
        V.findingForIssue({ type: 'hash-mismatch', path: '/static/js/app.js', error: 'x' }).class,
        CLASS.CONFIRMED,
    );
});

test('policy violations are attributed conservatively', () => {
    const page = 'https://pinchat.im/static/chat.html?room=1#key=secret';
    const byPage = V.findingForViolation({
        sourceFile: 'https://pinchat.im/static/chat.html?room=1', blockedURI: 'inline', effectiveDirective: 'script-src-elem',
    }, page);
    assert.strictEqual(byPage.class, CLASS.SUSPICIOUS, 'even a page-attributed violation is not proof against the server');
    assert(!byPage.detail.includes('secret'), 'the fragment never ends up in a finding');
    // Chromium names the document without its query string.
    assert.strictEqual(V.findingForViolation({
        sourceFile: 'https://pinchat.im/static/chat.html', blockedURI: 'inline', effectiveDirective: 'script-src-elem',
    }, page).class, CLASS.SUSPICIOUS);
    assert.strictEqual(V.findingForViolation({
        sourceFile: 'https://pinchat.im/static/js/app.js', blockedURI: 'inline', effectiveDirective: 'script-src-elem',
    }, page).class, CLASS.ENVIRONMENT, 'another file of the site is not the document');

    for (const sourceFile of ['chrome-extension://abcdefghijklmnop/content.js', 'moz-extension']) {
        const entry = V.findingForViolation({ sourceFile, blockedURI: 'inline', effectiveDirective: 'script-src-elem' }, page);
        assert.strictEqual(entry.class, CLASS.ENVIRONMENT, sourceFile);
    }
    const unknown = V.findingForViolation({ sourceFile: '', blockedURI: 'inline', effectiveDirective: 'script-src-elem' }, page);
    assert.strictEqual(unknown.class, CLASS.ENVIRONMENT, 'an unattributed violation is not pinned on the page');
});

test('only verified gets the green badge', () => {
    const green = V.badge(INTEGRITY.VERIFIED, false);
    for (const integrity of Object.values(INTEGRITY)) {
        for (const attention of [false, true]) {
            const badge = V.badge(integrity, attention);
            if (integrity === INTEGRITY.VERIFIED && !attention) continue;
            assert.notStrictEqual(badge.color, green.color, `${integrity}/${attention} must not look verified`);
            // The yellow check of PARTIAL is the one state that shares the
            // verified symbol; it is told apart by its color, checked above
            // and in the test below.
            if (integrity !== INTEGRITY.PARTIAL || attention) assert.notStrictEqual(badge.text, green.text);
        }
    }
    assert.strictEqual(V.badge('nonsense', false).text, '');
});

test('verified is a green check, the best state of Chromium a yellow one that says where a complete check is made', () => {
    const partial = V.badge(INTEGRITY.PARTIAL, false);
    assert.strictEqual(V.badge(INTEGRITY.VERIFIED, false).text, '✓');
    assert.strictEqual(V.badge(INTEGRITY.VERIFIED, false).color, '#16a34a');
    assert.strictEqual(partial.text, '✓');
    assert.strictEqual(partial.color, '#facc15');
    assert.strictEqual(partial.textColor, '#111827', 'white does not read on yellow');
    // Every badge names its text color: it is kept per tab, so a state that
    // left it out would inherit the dark text of an earlier yellow badge.
    for (const integrity of Object.values(INTEGRITY)) {
        for (const attention of [false, true]) {
            assert.match(V.badge(integrity, attention).textColor, /^#[0-9a-f]{6}$/, `${integrity}/${attention}`);
        }
    }
    assert.match(V.headlineNote(INTEGRITY.PARTIAL), /only in Firefox/);
    for (const integrity of Object.values(INTEGRITY)) {
        if (integrity !== INTEGRITY.PARTIAL) assert.strictEqual(V.headlineNote(integrity), '', integrity);
    }
    // The popup and the verdict logic are the same file in both browsers.
    for (const file of ['verdict.js', 'popup.js', 'popup.html']) {
        assert.strictEqual(fs.readFileSync(path.join(root, 'extensions/chrome', file), 'utf8'),
            fs.readFileSync(path.join(root, 'extensions/firefox', file), 'utf8'), file);
    }
});

test('redirects off the site are refused, whatever the spelling', () => {
    const origins = ['https://pinchat.im', 'https://www.pinchat.im'];
    const from = 'https://pinchat.im/c/00000000-0000-4000-8000-000000000000';
    for (const location of [
        '/static/chat.html?room=00000000-0000-4000-8000-000000000000',
        '/',
        '/login?redirect=%2Fc%2Fx',
        'static/index.html',
        'https://pinchat.im/static/index.html',
        'https://www.pinchat.im/',
        'https:static/index.html',
    ]) {
        assert.strictEqual(V.isAllowedRedirect(from, location, origins), true, location);
    }
    for (const location of [
        'https://attacker.test/collect',
        '//attacker.test/collect',
        '/\\attacker.test/collect',
        '\\\\attacker.test/collect',
        'https://pinchat.im:8444/collect',
        'http://pinchat.im/collect',
        'https://pinchat.im.attacker.test/',
        'https://pinchat.im@attacker.test/',
        'http:attacker.test',
        'javascript:alert(1)',
        'data:text/html,x',
        'https://',
    ]) {
        assert.strictEqual(V.isAllowedRedirect(from, location, origins), false, location);
    }
});

test('only a navigation without a fragment may leave for the release page or a store', () => {
    const origins = ['https://pinchat.im', 'https://www.pinchat.im'];
    const external = V.EXTERNAL_REDIRECT_TARGETS;
    const release = 'https://github.com/samjanny/pinchat/releases/latest';
    const plain = 'https://pinchat.im/ext/chrome';
    for (const location of [
        release,
        'https://chromewebstore.google.com/detail/pinchat-integrity-verifier/abcdefghijklmnopabcdefghijklmnop',
        'https://addons.mozilla.org/firefox/addon/pinchat-integrity-verifier/',
    ]) {
        assert.strictEqual(V.isAllowedRedirect(plain, location, origins, external), true, location);
        // The same target, when the address being left carries a key.
        for (const from of [
            'https://pinchat.im/ext/chrome#key=SECRET',
            'https://pinchat.im/c/00000000-0000-4000-8000-000000000000#key=SECRET',
            'https://pinchat.im/static/chat.html?room=1#k',
        ]) {
            assert.strictEqual(V.isAllowedRedirect(from, location, origins, external), false, `${from} -> ${location}`);
        }
        // And without the list, as before.
        assert.strictEqual(V.isAllowedRedirect(plain, location, origins), false, location);
    }
    for (const location of [
        'https://github.com/',
        'https://github.com/samjanny/pinchat/releases/latest/x',
        'https://github.com/samjanny/pinchat/releases/latest?x=1',
        'https://github.com/attacker/pinchat/releases/latest',
        'https://github.com.attacker.test/samjanny/pinchat/releases/latest',
        'https://github.com@attacker.test/samjanny/pinchat/releases/latest',
        'http://github.com/samjanny/pinchat/releases/latest',
        'https://chromewebstore.google.com/',
        'https://chromewebstore.google.com/detail/../../x',
        'https://chromewebstore.google.com.attacker.test/detail/x',
        'https://addons.mozilla.org.attacker.test/',
        'https://addons.mozilla.org@attacker.test/',
        'https://addons.mozilla.org:8443/',
        'https://attacker.test/collect',
        '//attacker.test/collect',
    ]) {
        assert.strictEqual(V.isAllowedRedirect(plain, location, origins, external), false, location);
    }
    // Redirects that stay on the site are not affected by the fragment.
    assert.strictEqual(V.isAllowedRedirect(
        'https://pinchat.im/c/x#key=SECRET', '/static/chat.html?room=x', origins, external,
    ), true);
    // Every entry is a complete address or a prefix that ends after the
    // slash closing the host name, so no prefix can grow into another host.
    for (const target of external) {
        assert(/^https:\/\/[a-z0-9.-]+\/[A-Za-z0-9._~\/-]*\*?$/.test(target), target);
    }
});

test('the Chromium redirect rules allow only what the same check allows', () => {
    const { ALLOWED_REDIRECT_LOCATIONS, CATCH_ALL_REGEX, FRAGMENT_REGEX, buildRules }
        = require('../extensions/generate-csp-rules');
    const origins = ['https://pinchat.im', 'https://www.pinchat.im'];
    const from = 'https://pinchat.im/c/00000000-0000-4000-8000-000000000000';
    // Header value patterns as the browser reads them: "*" matches any run
    // of characters, "?" zero or one character, and a backslash makes the
    // next character literal. A bare "?" in a pattern is therefore a
    // wildcard, which once turned "/?*" into "anything after a slash".
    const literal = (character) => character.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const toRegExp = (pattern) => {
        let out = '';
        for (let i = 0; i < pattern.length; i += 1) {
            const character = pattern[i];
            if (character === '\\' && i + 1 < pattern.length) {
                i += 1;
                out += literal(pattern[i]);
            } else if (character === '*') {
                out += '.*';
            } else if (character === '?') {
                out += '.?';
            } else {
                out += literal(character);
            }
        }
        return new RegExp(`^${out}$`);
    };
    const matchers = ALLOWED_REDIRECT_LOCATIONS.map(toRegExp);
    assert(toRegExp('/?*').test('//attacker.test/'), 'the emulation treats a bare ? as a wildcard');
    const allowedByRule = (location) => matchers.some((matcher) => matcher.test(location));

    // Everything the rule lets through must stay on the site.
    for (const location of [
        'https://pinchat.im/x', 'https://www.pinchat.im/x', '/', '/?a=1', '/static/chat.html?room=1',
        '/c/00000000-0000-4000-8000-000000000000?_=1', '/login', '/login?redirect=%2F',
        '/static//attacker.test/', '/c/../../x', '/static/\\attacker.test',
    ]) {
        assert(allowedByRule(location), `rule should allow ${location}`);
        assert(V.isAllowedRedirect(from, location, origins), `${location} leaves the site`);
    }
    // And the spellings that leave the site must not match any pattern.
    for (const location of [
        'https://attacker.test/collect', '//attacker.test/collect', '/\\attacker.test/collect',
        'https://pinchat.im:8444/collect', 'http://pinchat.im/', 'https://pinchat.im.attacker.test/',
        'https://pinchat.im@attacker.test/', '/loginx//attacker.test', '',
    ]) {
        assert(!allowedByRule(location), `rule must not allow ${JSON.stringify(location)}`);
    }

    const signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
    const chrome = buildRules(signed, 'chrome');
    const firefox = buildRules(signed, 'firefox');
    const redirectRules = chrome.filter((rule) => rule.action.type === 'block');
    assert.strictEqual(redirectRules.length, 2, 'the Chromium ruleset has two redirect rules');
    for (const rule of redirectRules) {
        assert.deepStrictEqual(rule.condition.resourceTypes, ['main_frame', 'sub_frame']);
        assert.strictEqual(rule.condition.responseHeaders.length, 1);
        assert.strictEqual(rule.condition.responseHeaders[0].header, 'location');
    }
    const allowedBy = (filter) => redirectRules
        .find((rule) => rule.condition.regexFilter === filter).condition.responseHeaders[0].excludedValues;
    // Every navigation: the site, plus the external targets.
    assert.deepStrictEqual(allowedBy(CATCH_ALL_REGEX),
        [...ALLOWED_REDIRECT_LOCATIONS, ...V.EXTERNAL_REDIRECT_TARGETS]);
    // A navigation whose address carries a fragment: the site only.
    assert.deepStrictEqual(allowedBy(FRAGMENT_REGEX), ALLOWED_REDIRECT_LOCATIONS);
    const withFragment = new RegExp(FRAGMENT_REGEX);
    for (const [address, carriesFragment] of [
        ['https://pinchat.im/c/00000000-0000-4000-8000-000000000000#key=SECRET', true],
        ['https://pinchat.im/ext/chrome#key=SECRET', true],
        ['https://www.pinchat.im/static/chat.html?room=1#k', true],
        ['https://pinchat.im:8444/x#k', true],
        ['https://pinchat.im/#', true],
        ['https://pinchat.im/ext/chrome', false],
        ['https://pinchat.im/static/chat.html?room=1', false],
    ]) {
        assert.strictEqual(withFragment.test(address), carriesFragment, address);
        // The pattern and the check in verdict.js agree on what a fragment is,
        // except for an empty one, which the pattern treats as present.
        if (address !== 'https://pinchat.im/#') {
            assert.strictEqual(new URL(address).hash !== '', carriesFragment, address);
        }
    }
    // The external targets as header-value patterns let through exactly
    // what the check lets through.
    const externalMatchers = V.EXTERNAL_REDIRECT_TARGETS.map(toRegExp);
    for (const location of [
        'https://github.com/samjanny/pinchat/releases/latest',
        'https://chromewebstore.google.com/detail/x/abcdefghijklmnopabcdefghijklmnop',
        'https://addons.mozilla.org/firefox/addon/x/',
        'https://github.com/samjanny/pinchat/releases/latest/x',
        'https://github.com/attacker/pinchat/releases/latest',
        'https://github.com.attacker.test/samjanny/pinchat/releases/latest',
        'https://addons.mozilla.org.attacker.test/',
        'https://addons.mozilla.org@attacker.test/',
        'https://chromewebstore.google.com/',
        '//attacker.test/collect',
    ]) {
        assert.strictEqual(
            externalMatchers.some((matcher) => matcher.test(location)),
            V.isAllowedRedirect('https://pinchat.im/ext/chrome', location, [], V.EXTERNAL_REDIRECT_TARGETS),
            location,
        );
    }
    assert(!firefox.some((rule) => rule.condition.responseHeaders),
        'Firefox does not support response header conditions; its build enforces the rule in the background script');
    for (const rule of [...chrome, ...firefox].filter((entry) => entry.action.type === 'modifyHeaders')) {
        const operations = rule.action.responseHeaders.map((header) => `${header.header}:${header.operation}`);
        assert.deepStrictEqual(operations,
            ['content-security-policy:set', 'link:remove', 'refresh:remove']);
        assert(rule.action.responseHeaders[0].value.includes("worker-src 'none'"));
    }
});

test('an error answer from the server is unverifiable, never a mismatch', () => {
    assert.strictEqual(V.FINDINGS['error-response'][0], V.CLASS.LIMIT);
    const record = {
        manifest: 'valid',
        official: true,
        topLevel: true,
        checksDone: true,
        policyInForce: true,
        workerControlled: false,
        canAttest: true,
        attested: false,
        findings: [V.finding('error-response', 'HTTP status 404')],
    };
    assert.strictEqual(V.decide(record).integrity, V.INTEGRITY.UNVERIFIABLE);
    // A confirmed finding next to it still fails the document.
    record.findings.push(V.finding('unsigned-stylesheet'));
    assert.strictEqual(V.decide(record).integrity, V.INTEGRITY.FAILED);
});

test('document hashes come from the signed manifest only', () => {
    const signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
    const documents = V.documentHashes(signed.data);
    assert.deepStrictEqual([...documents.keys()].sort(), [
        '/static/chat.html', '/static/index.html', '/static/login.html',
        '/static/privacy.html', '/static/terms.html',
    ]);
    // The bytes the server serves are the bytes that were signed.
    const crypto = require('crypto');
    for (const [documentPath, hash] of documents) {
        const served = fs.readFileSync(path.join(root, documentPath.slice(1)));
        assert.strictEqual(crypto.createHash('sha256').update(served).digest('hex'), hash,
            `${documentPath}: the file as served does not hash to the signed value`);
    }
    assert.strictEqual(V.documentHashes(null).size, 0);
    assert.strictEqual(V.documentHashes({ files: [{ path: '/static/x.html', hash: 'not-a-hash' }] }).size, 0);
});

test('the background script assigns states in one place and never ahead of the facts', () => {
    const source = fs.readFileSync(path.join(root, 'extensions/chrome/background.js'), 'utf8');
    const assignments = source.match(/record\.integrity\s*=/g) || [];
    assert.strictEqual(assignments.length, 1, 'a state is assigned in evaluate() and nowhere else');
    assert(!/integrity:\s*['"]verified['"]/.test(source), 'no literal verified state');
    assert(!/Dismiss \(Unsafe\)/.test(fs.readFileSync(path.join(root, 'extensions/chrome/content.js'), 'utf8')),
        'a confirmed failure cannot be dismissed');
    // The response filter must fail closed in each of its handlers.
    for (const handler of ['function onDocumentRequest', 'function onDocumentHeaders']) {
        const body = source.slice(source.indexOf(handler), source.indexOf('\n}\n', source.indexOf(handler)));
        assert(/catch \(error\) \{[\s\S]*return \{ cancel: true \};/.test(body), `${handler} does not cancel on error`);
    }
});

console.log(`\n${passed} verdict tests passed`);
