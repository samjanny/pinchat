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

test('only the page that submits a form to the server may do so', () => {
    const { buildRules, PAGES, pageRegex, CATCH_ALL_REGEX, FORM_ACTIONS } = require('../extensions/generate-csp-rules');
    const signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
    const formAction = (rule) => /(?:^|;\s*)form-action ([^;]+)/.exec(rule.action.responseHeaders[0].value)[1];
    for (const rules of [buildRules(signed, 'chrome'), buildRules(signed, 'firefox')]) {
        const catchAll = rules.find((rule) => rule.condition.regexFilter === CATCH_ALL_REGEX);
        assert.strictEqual(formAction(catchAll), "'none'", 'a document the release does not know submits nothing');
        for (const page of PAGES) {
            const html = fs.readFileSync(path.join(root, page.slice(1)), 'utf8');
            // A form that the browser submits: one with an action, in the
            // page itself. The application's own forms live in the templates
            // and are handled by script.
            const submits = /<form\b[^>]*\baction=/i.test(html);
            const rule = rules.find((candidate) => candidate.condition.regexFilter === pageRegex(page));
            assert.strictEqual(formAction(rule), submits ? "'self'" : "'none'", page);
        }
    }
    assert.deepStrictEqual(Object.keys(FORM_ACTIONS), ['/static/login.html']);
    for (const template of ['chat', 'index']) {
        const markup = fs.readFileSync(path.join(root, `static/js/templates/${template}.js`), 'utf8');
        const forms = markup.match(/<form\b[^>]*>/g) || [];
        assert(forms.length > 0, template);
        for (const form of forms) {
            assert(/@submit\.prevent=/.test(form) && !/\baction=/.test(form), `${template}: ${form} is submitted`);
        }
    }
});

test('the packaged policy of an address is the one the rules give it', () => {
    const rules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/rules.json'), 'utf8'));
    const { CATCH_ALL_REGEX, pageRegex } = require('../extensions/generate-csp-rules');
    const policyOf = (filter) => rules.find((rule) => rule.condition.regexFilter === filter)
        .action.responseHeaders[0].value;
    assert.strictEqual(V.packagedPolicy(rules, 'https://pinchat.im/static/chat.html?room=1'),
        policyOf(pageRegex('/static/chat.html')), 'a page rule wins over the catch-all');
    assert.strictEqual(V.packagedPolicy(rules, 'https://www.pinchat.im/static/login.html'),
        policyOf(pageRegex('/static/login.html')));
    for (const url of ['https://pinchat.im/c/1', 'https://pinchat.im:8444/static/chat.html', 'https://pinchat.im/static/x.html']) {
        assert.strictEqual(V.packagedPolicy(rules, url), policyOf(CATCH_ALL_REGEX), url);
    }
    assert.strictEqual(V.packagedPolicy(rules, 'https://attacker.test/static/chat.html'), null);
    assert.strictEqual(V.packagedPolicy(null, 'https://pinchat.im/'), null);
});

test('another policy that also blocks inline handlers is not taken for the packaged one', () => {
    const rules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/rules.json'), 'utf8'));
    const expected = V.packagedPolicy(rules, 'https://pinchat.im/static/chat.html?room=1');
    const directives = expected.split(';').map((part) => part.trim()).filter(Boolean);
    // The same policy as a browser may report it: other order, other
    // spacing, keywords in capitals, without the last semicolon.
    const reserialised = [...directives].reverse().join(' ;  ').replace("'none'", "'NONE'");
    assert(V.sameScriptPolicy(expected, expected));
    assert(V.sameScriptPolicy(reserialised, expected));
    for (const other of [
        "script-src 'self'; style-src 'self'; default-src 'self'",
        "default-src 'self'",
        directives.filter((part) => !part.startsWith('script-src')).join('; '),
        directives.map((part) => (part.startsWith('script-src') ? part.split(' ').slice(0, -1).join(' ') : part)).join('; '),
        `${expected} script-src-attr 'unsafe-inline';`,
        `${expected.replace('script-src', "script-src 'self'")}`,
        `${expected.replace(/'sha256-([A-Za-z])/, (_, c) => `'sha256-${c === c.toLowerCase() ? c.toUpperCase() : c.toLowerCase()}`)}`,
        '',
    ]) {
        assert(!V.sameScriptPolicy(other, expected), other.slice(0, 80));
    }
});

test('the probe\'s own violation is told from the page\'s by its marker, and by nothing else', () => {
    const marker = '0123456789abcdef01234567';
    assert.strictEqual(marker.length, V.PROBE_MARKER_LENGTH);
    const handler = V.probeHandler(marker);
    // A browser reports at most the first 40 characters of the handler.
    const sample = handler.slice(0, 40);
    assert(sample.includes(marker), 'the marker is within what a report carries');
    const probe = { effectiveDirective: 'script-src-attr', blockedURI: 'inline', sourceFile: '', sample };
    assert.strictEqual(V.isProbeViolation(probe, marker), true);

    const page = 'https://pinchat.im/static/chat.html?room=1';
    for (const [what, violation] of [
        ['a handler of the page, which looks like the probe in every other way',
            { effectiveDirective: 'script-src-attr', blockedURI: 'inline', sourceFile: '', sample: 'this.setAttribute("data-ran", "1")' }],
        ['a report without a sample', { effectiveDirective: 'script-src-attr', blockedURI: 'inline', sourceFile: '' }],
        ['another marker', { ...probe, sample: V.probeHandler('fedcba9876543210fedcba98').slice(0, 40) }],
        ['the marker in another kind of violation', { ...probe, effectiveDirective: 'script-src-elem' }],
    ]) {
        assert.strictEqual(V.isProbeViolation(violation, marker), false, what);
    }
    for (const weak of ['', '0123', 'not-hex-not-hex-not-hex-', null, undefined]) {
        assert.strictEqual(V.isProbeViolation(probe, weak), false, `marker ${weak}`);
    }
    // What is not the probe's is classified like any violation.
    assert.strictEqual(V.findingForViolation({
        effectiveDirective: 'script-src-attr', blockedURI: 'inline', sourceFile: 'https://pinchat.im/static/chat.html',
    }, page).code, 'page-policy-violation');
});

test('the page policies ask for the sample that carries the probe\'s marker', () => {
    const { CATCH_ALL_REGEX } = require('../extensions/generate-csp-rules');
    for (const browser of ['chrome', 'firefox']) {
        const rules = JSON.parse(fs.readFileSync(path.join(root, `extensions/${browser}/rules.json`), 'utf8'));
        for (const rule of rules.filter((entry) => entry.action.type === 'modifyHeaders')) {
            const scriptSrc = rule.action.responseHeaders[0].value.split(';')[0].trim().split(/\s+/);
            if (rule.condition.regexFilter === CATCH_ALL_REGEX) {
                assert.deepStrictEqual(scriptSrc, ['script-src', "'none'"], 'nothing runs where the release has no page');
            } else {
                assert(scriptSrc.includes("'report-sample'"), `${browser}: ${rule.condition.regexFilter}`);
                assert(scriptSrc.slice(1).every((token) => token === "'report-sample'" || token.startsWith("'sha256-")),
                    'report-sample allows nothing; the rest are hashes');
            }
        }
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

// -----------------------------------------------------------------------------
// The background script itself, with the browser replaced by stand-ins
// -----------------------------------------------------------------------------

const vm = require('vm');
const nodeCrypto = require('crypto');

/**
 * Runs extensions/chrome/background.js against stand-ins for the extension
 * APIs. `canAttest` gives it a response filter, as in Firefox. With
 * `manifestFiles`, the manifest it fetches is one signed here with a key of
 * the test's own instead of the release manifest.
 */
function loadBackground({ canAttest = false, hostAccess = true, manifestFiles = null } = {}) {
    let source = fs.readFileSync(path.join(root, 'extensions/chrome/background.js'), 'utf8');
    let signed = JSON.parse(fs.readFileSync(path.join(root, 'hashes.json.signed'), 'utf8'));
    if (manifestFiles) {
        const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const data = { ...signed.data, files: manifestFiles };
        signed = {
            data,
            signature: nodeCrypto.sign('sha256', Buffer.from(JSON.stringify(data)), privateKey).toString('base64'),
        };
        const pem = publicKey.export({ type: 'spki', format: 'pem' }).trim();
        source = source.replace(/const PINCHAT_PUBLIC_KEY = `[\s\S]*?`;/, `const PINCHAT_PUBLIC_KEY = \`${pem}\`;`);
    }
    const rules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/rules.json'), 'utf8'));
    const listeners = {};
    const event = (name) => ({
        addListener(fn, filter) { (listeners[name] = listeners[name] || []).push({ fn, filter }); },
    });
    const storage = () => {
        const data = {};
        return {
            async get(keys) {
                const wanted = keys === undefined ? Object.keys(data) : [].concat(keys);
                return Object.fromEntries(wanted.filter((key) => key in data).map((key) => [key, data[key]]));
            },
            async set(entries) { Object.assign(data, JSON.parse(JSON.stringify(entries))); },
            async remove(key) { delete data[key]; },
        };
    };
    const streams = [];
    const browser = {
        runtime: {
            id: 'test-extension',
            getURL: (file) => `moz-extension://test-extension/${file}`,
            onMessage: event('message'),
            onInstalled: event('installed'),
        },
        alarms: { create() {}, onAlarm: event('alarm') },
        tabs: {
            onRemoved: event('removed'),
            onUpdated: event('updated'),
            query: async () => [],
            sendMessage: async () => null,
            update: async () => ({}),
            get: async (id) => ({ id }),
        },
        storage: { local: storage(), session: storage() },
        action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setBadgeTextColor() {} },
        permissions: { contains: async () => hostAccess },
    };
    if (canAttest) {
        browser.webRequest = {
            filterResponseData() {
                const stream = { written: [], closed: false, status: 'transferringdata' };
                stream.write = (bytes) => { stream.written.push(Buffer.from(bytes)); };
                stream.close = () => { stream.closed = true; };
                streams.push(stream);
                return stream;
            },
            onBeforeRequest: event('beforeRequest'),
            onHeadersReceived: event('headersReceived'),
            onErrorOccurred: event('errorOccurred'),
        };
    }
    const fetchStandIn = async (url) => {
        if (url === browser.runtime.getURL('rules.json')) return { ok: true, json: async () => rules };
        if (String(url).endsWith('/hashes.json.signed')) return { ok: true, json: async () => signed };
        throw new Error('no network in this test');
    };
    const quiet = { log() {}, warn() {}, error() {} };
    const context = vm.createContext({
        browser, PinChatVerdict: V, fetch: fetchStandIn, crypto: nodeCrypto.webcrypto, console: quiet,
        atob, btoa, TextEncoder, TextDecoder, AbortController, URL, setTimeout, clearTimeout,
        setInterval, clearInterval,
    });
    vm.runInContext(source, context, { filename: 'background.js' });

    const send = (message, sender) => new Promise((resolve) => {
        const answered = listeners.message.some(({ fn }) => fn(message, sender, resolve) === true);
        if (!answered) resolve(undefined);
    });
    const contentSender = (url, tabId = 7) => ({ id: 'test-extension', url, frameId: 0, tab: { id: tabId, url } });
    const popupSender = { id: 'test-extension', url: browser.runtime.getURL('popup.html') };
    const listener = (name, types) => listeners[name]
        .find(({ filter }) => JSON.stringify(filter.types) === JSON.stringify(types)).fn;
    const settle = async (done) => {
        for (let i = 0; i < 500 && !done(); i += 1) await new Promise((resolve) => setImmediate(resolve));
    };
    // Results cross from the script's own realm: compared as data.
    const plain = (value) => JSON.parse(JSON.stringify(value));
    return { send, contentSender, popupSender, listener, streams, settle, plain, rules };
}

/**
 * Runs extensions/chrome/content.js at document_start of a chat page, against
 * a document and an extension API reduced to what it touches. Returns the
 * means to deliver policy violations to it and to read what it reports.
 */
function loadContent({ expectedPolicy }) {
    const url = 'https://pinchat.im/static/chat.html?room=1';
    const listeners = {};
    const element = (tagName) => {
        const attributes = new Map();
        return {
            tagName, nodeType: 1, id: '',
            setAttribute(name, value) { attributes.set(name, String(value)); },
            getAttribute(name) { return attributes.has(name) ? attributes.get(name) : null; },
            hasAttribute(name) { return attributes.has(name); },
            removeAttribute(name) { attributes.delete(name); },
            querySelectorAll() { return []; },
            // The packaged policy is in force: a handler never runs.
            click() {},
            // What the overlay needs.
            attachShadow() { return element('#shadow-root'); },
            appendChild(child) { return child; },
            addEventListener() {},
            remove() {},
        };
    };
    const created = [];
    const document = {
        readyState: 'loading',
        documentElement: element('HTML'),
        body: null,
        createElement(tagName) {
            const made = element(tagName.toUpperCase());
            created.push(made);
            return made;
        },
        addEventListener(type, listener) { (listeners[type] = listeners[type] || []).push(listener); },
        contains() { return false; },
    };
    const messages = [];
    const browser = {
        runtime: {
            id: 'test-extension',
            getURL: (file) => `chrome-extension://test-extension/${file}`,
            onMessage: { addListener() {} },
            sendMessage: async (message) => {
                messages.push(JSON.parse(JSON.stringify(message)));
                const verdict = { integrity: INTEGRITY.PARTIAL, attention: false, reasons: [], attested: false };
                if (message.type === 'DOCUMENT_OPENED') {
                    return { manifestStatus: 'valid', manifest: { files: [] }, canAttest: false, expectedPolicy, verdict };
                }
                return { verdict };
            },
        },
    };
    const context = vm.createContext({
        browser, PinChatVerdict: V, document, crypto: nodeCrypto.webcrypto, btoa, URL, console: { log() {}, warn() {}, error() {} },
        navigator: {}, Node: { ELEMENT_NODE: 1 }, MutationObserver: class { observe() {} },
        // The overlay's watchdog is not under test, and would keep the run alive.
        setTimeout, clearTimeout, setInterval: () => 0, clearInterval: () => {},
    });
    context.window = context;
    context.location = new URL(url);
    context.top = context;
    context.addEventListener = () => {};
    context.stop = () => {};
    vm.runInContext(fs.readFileSync(path.join(root, 'extensions/chrome/content.js'), 'utf8'), context,
        { filename: 'content.js' });
    const fire = (type, event = {}) => (listeners[type] || []).forEach((listener) => listener(event));
    return {
        url,
        // The handler the probe gave its element, as a browser would report it.
        probeSample: () => created.find((made) => made.getAttribute('onclick')).getAttribute('onclick').slice(0, 40),
        parsed: () => { document.readyState = 'interactive'; fire('DOMContentLoaded'); },
        violation: (event) => fire('securitypolicyviolation', event),
        lastReport: () => [...messages].reverse().find((message) => message.type === 'DOCUMENT_REPORT'),
        settle: () => new Promise((resolve) => setTimeout(resolve, 450)),
    };
}

const asyncTests = [];
const asyncTest = (name, body) => asyncTests.push([name, body]);

asyncTest('the page\'s first inline handler violation is counted, reported probe or not', async () => {
    const rules = JSON.parse(fs.readFileSync(path.join(root, 'extensions/chrome/rules.json'), 'utf8'));
    const expectedPolicy = V.packagedPolicy(rules, 'https://pinchat.im/static/chat.html?room=1');
    const pageHandler = (sourceFile) => ({
        effectiveDirective: 'script-src-attr', violatedDirective: 'script-src-attr', blockedURI: 'inline',
        sourceFile, sample: 'document.documentElement.setAttribute(', originalPolicy: expectedPolicy,
    });
    const codes = (report) => [...report.findings, ...report.environment].map((entry) => entry.code);

    // Chromium: the probe's violation is never reported. The page's first
    // one used to be taken for it and dropped. This is how Chromium reports
    // a handler of served markup that it blocks: with no source file.
    const chromium = loadContent({ expectedPolicy });
    await new Promise((resolve) => setImmediate(resolve));
    chromium.parsed();
    chromium.violation(pageHandler(''));
    await chromium.settle();
    assert.deepStrictEqual(codes(chromium.lastReport()), ['unattributed-policy-violation']);

    // A browser that reports the probe's violation: that one, and only that
    // one, is left out, whenever it arrives.
    const reporting = loadContent({ expectedPolicy });
    await new Promise((resolve) => setImmediate(resolve));
    reporting.parsed();
    reporting.violation(pageHandler('https://pinchat.im/static/chat.html'));
    reporting.violation({
        effectiveDirective: 'script-src-attr', violatedDirective: 'script-src-attr', blockedURI: 'inline',
        sourceFile: '', sample: reporting.probeSample(), originalPolicy: expectedPolicy,
    });
    await reporting.settle();
    assert.deepStrictEqual(codes(reporting.lastReport()), ['page-policy-violation']);

    // And when it names another policy than the packaged one, the page fails.
    const replaced = loadContent({ expectedPolicy });
    await new Promise((resolve) => setImmediate(resolve));
    replaced.parsed();
    replaced.violation({
        effectiveDirective: 'script-src-attr', violatedDirective: 'script-src-attr', blockedURI: 'inline',
        sourceFile: '', sample: replaced.probeSample(), originalPolicy: "script-src 'self'; default-src 'self'",
    });
    await replaced.settle();
    assert.deepStrictEqual(codes(replaced.lastReport()), ['policy-not-in-force']);
});

asyncTest('without standing access to the site no positive state is shown', async () => {
    const url = 'https://pinchat.im/static/chat.html?room=1';
    for (const [hostAccess, expected] of [[false, INTEGRITY.UNVERIFIABLE], [true, INTEGRITY.PARTIAL]]) {
        const bg = loadBackground({ hostAccess });
        const sender = bg.contentSender(url);
        const opened = bg.plain(await bg.send(
            { type: 'DOCUMENT_OPENED', token: 't1', policyInForce: true, workerControlled: false }, sender,
        ));
        assert.strictEqual(opened.verdict.reasons.some((entry) => entry.code === 'no-host-access'), !hostAccess);
        const reportedState = bg.plain(await bg.send(
            { type: 'DOCUMENT_REPORT', token: 't1', checksDone: true, findings: [], environment: [] }, sender,
        ));
        assert.strictEqual(reportedState.verdict.integrity, expected, `host access ${hostAccess}`);
    }
});

asyncTest('the content script is told which policy the packaged rules give its document', async () => {
    const bg = loadBackground();
    for (const url of ['https://pinchat.im/static/chat.html?room=1', 'https://pinchat.im/c/1']) {
        const opened = bg.plain(await bg.send(
            { type: 'DOCUMENT_OPENED', token: 't2', policyInForce: true, workerControlled: false }, bg.contentSender(url),
        ));
        assert.strictEqual(opened.expectedPolicy, V.packagedPolicy(bg.rules, url), url);
        assert(opened.expectedPolicy.startsWith('script-src '), url);
    }
});

asyncTest('a 3xx answer that the browser displays is checked like any other (Firefox)', async () => {
    const bg = loadBackground({ canAttest: true });
    const documentTypes = ['main_frame', 'sub_frame'];
    const beforeRequest = bg.listener('beforeRequest', documentTypes);
    const headersReceived = bg.listener('headersReceived', documentTypes);
    const answer = (requestId, statusCode, location) => bg.plain(headersReceived({
        requestId, url: 'https://pinchat.im/static/chat.html', tabId: 3, frameId: 0, statusCode,
        responseHeaders: [{ name: 'Location', value: location }, { name: 'Content-Type', value: 'text/plain' }],
    }));
    // No response filter on these requests: a body that is displayed would
    // reach the parser unchecked, so the answer is refused.
    for (const statusCode of [300, 304, 305, 306, 399]) {
        assert.deepStrictEqual(answer(`unfiltered-${statusCode}`, statusCode, '/static/index.html'), { cancel: true },
            `status ${statusCode}`);
    }
    assert.deepStrictEqual(answer('empty-location', 302, ' '), { cancel: true }, 'a redirect to nowhere is displayed');
    // A redirect the browser follows has no body to check.
    for (const statusCode of [301, 302, 303, 307, 308]) {
        assert.deepStrictEqual(answer(`followed-${statusCode}`, statusCode, '/static/index.html'), {}, `status ${statusCode}`);
    }
    assert.deepStrictEqual(answer('off-site', 302, 'https://attacker.test/'), { cancel: true });
    // With the filter attached, a displayed 300 is held and checked.
    beforeRequest({ requestId: 'filtered-300', url: 'https://pinchat.im/static/chat.html', tabId: 3, frameId: 0 });
    const held = answer('filtered-300', 300, '/static/index.html');
    assert(Array.isArray(held.responseHeaders), 'released only after the body check');
});

asyncTest('a data file reaches the page only as signed (Firefox)', async () => {
    const signedBytes = Buffer.from('{"OPERATOR_NAME":"Example Operator"}');
    const hash = nodeCrypto.createHash('sha256').update(signedBytes).digest('hex');
    const terms = 'https://pinchat.im/static/terms.html';
    const fetchOperator = async (bg, requestId, bytes, statusCode = 200) => {
        const types = ['xmlhttprequest'];
        const request = {
            requestId, url: 'https://pinchat.im/static/operator.json', tabId: 7, frameId: 0, documentUrl: terms,
        };
        assert.deepStrictEqual(bg.plain(bg.listener('beforeRequest', types)(request)), {});
        bg.listener('headersReceived', types)({ ...request, statusCode });
        const stream = bg.streams[bg.streams.length - 1];
        stream.ondata({ data: Uint8Array.from(bytes).buffer });
        stream.onstop();
        await bg.settle(() => stream.closed);
        assert(stream.closed, 'the response is released');
        return Buffer.concat(stream.written);
    };
    const stateOf = async (bg) => bg.plain(await bg.send({ type: 'GET_ALL_STATES' }, bg.popupSender))
        .find((entry) => entry.url === terms);

    const bg = loadBackground({ canAttest: true, manifestFiles: [{ path: '/static/operator.json', hash }] });
    await bg.send({ type: 'DOCUMENT_OPENED', token: 't3', policyInForce: true, workerControlled: false },
        bg.contentSender(terms));
    assert.strictEqual((await fetchOperator(bg, 'd1', signedBytes)).toString(), signedBytes.toString());
    assert(!(await stateOf(bg)).reasons.some((entry) => entry.code === 'file-hash-mismatch'));

    // An error answer is withheld, and is not a mismatch.
    assert.strictEqual((await fetchOperator(bg, 'd2', Buffer.from('not found'), 404)).length, 0);
    assert(!(await stateOf(bg)).reasons.some((entry) => entry.code === 'file-hash-mismatch'));

    const forged = Buffer.from('{"OPERATOR_EMAIL_SUPPORT":"phish@attacker.test"}');
    assert.strictEqual((await fetchOperator(bg, 'd3', forged)).length, 0, 'other bytes are withheld');
    await bg.settle(() => false);
    const state = await stateOf(bg);
    assert.strictEqual(state.integrity, INTEGRITY.FAILED);
    assert(state.reasons.some((entry) => entry.code === 'file-hash-mismatch' && entry.detail.includes('operator.json')));
});

asyncTest('the data files held are the ones the release signs as data', async () => {
    const generator = fs.readFileSync(path.join(root, 'extensions/generate-hashes.js'), 'utf8');
    const background = fs.readFileSync(path.join(root, 'extensions/chrome/background.js'), 'utf8');
    const list = (text) => JSON.parse(/const DATA_FILES = (\[[^\]]*\])/.exec(text)[1].replace(/'/g, '"'));
    assert.deepStrictEqual(list(background), list(generator));
});

(async () => {
    for (const [name, body] of asyncTests) {
        await body();
        passed += 1;
        console.log(`PASSED: ${name}`);
    }
    console.log(`\n${passed} verdict tests passed`);
})().catch((error) => {
    console.error(`FAILED: ${error.stack}`);
    process.exit(1);
});
