'use strict';

/**
 * Test cases for run.js. Every case reports what was observed and a list of
 * expectations: [description, 'must' | 'limit', passed]. A 'limit' documents
 * behaviour that is known not to be achievable and does not fail the run.
 */

const REDIRECT_CODES = [301, 302, 303, 307, 308];

function summary(visit, t, extra = {}) {
    const { page, navigation, log } = visit;
    const seen = t.digest(log);
    return {
        'navigation error': navigation.error ? navigation.error.slice(0, 90) : 'none',
        'final url': page.url || '(none)',
        'fragment in final document': page.fragment || '(empty)',
        'app loaded': page.appLoaded,
        'attacker code ran': page.attacker || 'no',
        'server-added markup in DOM': page.serverAdded,
        'unsigned stylesheet applied': page.evilCss,
        'attacker origin learned': seen.leakedFragment === null ? 'nothing' : (seen.leakedFragment || '(empty fragment)'),
        'requests to attacker origin': seen.attackerRequests,
        'second-fetch requests by verifier': seen.verifierFetches,
        'overlay': page.overlay || 'none',
        'block page': page.blockPage || 'none',
        ...extra,
    };
}

/**
 * Click at a point of the page, type there and press Enter, the way a user
 * writes a message. Chromium only: the Firefox driver has no input events.
 * `where` is evaluated in the page and returns { x, y }.
 */
async function typeInto(tab, where, text) {
    if (!tab.send) return false;
    const { x, y } = await tab.eval(where);
    for (const type of ['mousePressed', 'mouseReleased']) {
        await tab.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
    }
    await tab.send('Input.insertText', { text });
    await tab.send('Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r',
    });
    await tab.send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
    return true;
}

/** What a served form posted to the server, if anything. */
const collected = (log) => {
    const entry = log.find((item) => item.note.startsWith('collect '));
    return entry ? entry.note.slice('collect '.length) : null;
};

const positive = (state) => !!state && ['verified', 'partial'].includes(state.integrity);
const reported = (state, code) => !!state && (state.reasons || []).some((entry) => entry.code === code);

const stateLabel = (state) => {
    if (!state) return 'no record';
    const reasons = (state.reasons || []).map((entry) => entry.code);
    const environment = (state.environment || []).map((entry) => entry.code);
    return state.integrity
        + (state.attention ? ' +notice' : '')
        + (reasons.length ? `; findings: ${[...new Set(reasons)].join(', ')}` : '')
        + (environment.length ? `; unattested changes: ${[...new Set(environment)].join(', ')}` : '');
};

module.exports = [
    {
        id: 'clean',
        title: 'original site, invite link with a key in the fragment',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the application loads', 'must', visit.page.appLoaded === true],
                ['no warning is shown', 'must', !visit.page.overlay && !visit.page.blockPage],
                ['nothing reaches the attacker origin', 'must', t.digest(visit.log).attackerRequests === 0],
                ['no request to the server carries the fragment', 'must',
                    !visit.log.some((entry) => `${entry.path}${entry.query}`.includes('TESTSECRET'))],
                [firefox ? 'state is verified' : 'state is partial: verified is not reachable in Chromium',
                    'must', !!state && state.integrity === (firefox ? 'verified' : 'partial')],
            ]);
        },
    },
    {
        id: 'password-manager',
        title: 'original site with another extension adding script elements',
        async run(t) {
            const browser = await t.launch({ passwordManager: true });
            const visit = await t.visit(browser, t.urls.CHAT, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'other extension': JSON.stringify(visit.page.pm),
                'verifier state': stateLabel(state),
                'environment notes': JSON.stringify(state?.environment || []),
            }), [
                ['the other extension did add its elements', 'must', visit.page.pm?.injected === 'injected'],
                ['its inline scripts did not execute', 'must', !visit.page.pm?.inline && !visit.page.pm?.transient],
                ['no integrity warning is shown', 'must', !visit.page.overlay && !visit.page.blockPage],
                ['the integrity state is the same as without the other extension', 'must',
                    !!state && state.integrity === (firefox ? 'verified' : 'partial')],
                ['the additions are listed as unattested page modifications', 'must',
                    !!state && Array.isArray(state.environment) && state.environment.length > 0],
                ['its shadow root, attached after the page was parsed, is listed the same way', 'must',
                    !!state && (state.environment || []).some((entry) => entry.code === 'shadow-root-added')],
            ]);
        },
    },
    {
        id: 'server-inline-script',
        title: 'unauthorised inline script in the server HTML (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const url = `${t.urls.CHAT}&poc=inline-script`;
            const visit = await t.visit(browser, url, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'verifier state': stateLabel(state),
                'recorded as': JSON.stringify([...(state?.reasons || []), ...(state?.environment || [])]
                    .map((entry) => `${entry.code}: ${entry.detail}`)),
            }), [
                ['the inline script did not execute', 'must', !visit.page.attacker],
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the blocked attempt is attributed to the page and shown as a notice, not as proof', 'must',
                        !!state && state.attention === true && visit.page.overlay === 'notice'
                        && state.reasons.some((entry) => entry.code === 'page-policy-violation')],
            ]);
        },
    },
    {
        id: 'page-handler',
        title: 'an inline handler in the served HTML: the first violation the page itself causes (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=handler`, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            const handlerBlocked = (entries) => (entries || [])
                .filter((entry) => /violation$/.test(entry.code) && entry.detail.startsWith('script-src-attr'));
            t.report(summary(visit, t, {
                'verifier state': stateLabel(state),
                'recorded as': JSON.stringify(handlerBlocked([...(state?.reasons || []), ...(state?.environment || [])])
                    .map((entry) => `${entry.code}: ${entry.detail}`)),
            }), [
                ['the handler did not run', 'must', !visit.page.attacker],
                ...(firefox ? [
                    ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage],
                ] : [
                    // It used to be taken for the violation of the extension's
                    // own probe, which Chromium never reports, and dropped.
                    ['the blocked handler is recorded', 'must',
                        handlerBlocked([...(state?.reasons || []), ...(state?.environment || [])]).length > 0],
                    // Chromium names no source file for a handler it blocks
                    // outside any script, so the violation cannot be told from
                    // one caused by markup another extension wrote, and is
                    // listed as of unknown origin.
                    ['it is attributed to the page and shown as a notice', 'limit',
                        !!state && state.attention === true
                        && handlerBlocked(state.reasons).some((entry) => entry.code === 'page-policy-violation')],
                ]),
            ]);
        },
    },
    {
        id: 'split-markup',
        title: 'HTML differs between the navigation and any other request',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=markup`, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
                ['the altered markup did not reach the page', firefox ? 'must' : 'limit', !visit.page.serverAdded],
                ['the navigation itself was checked, not a second download', firefox ? 'must' : 'limit',
                    firefox ? !!visit.page.blockPage : false],
            ]);
        },
    },
    ...[
        ['markup-directives', 'directives',
            'markup with framework directives, and no script, added to the navigation only', true],
        ['markup-directives-first', 'directives-first',
            'the same directives placed before every script of the page', true],
        ['markup-directives-on-body', 'directives-on-body',
            'directives on the body element itself', true],
        ['markup-directives-around', 'directives-around',
            'a served element with directives wrapped around the whole page', true],
        ['markup-directives-engine-last', 'directives-engine-last',
            'directives in place, and the framework loaded last and deferred', false],
    ].map(([id, poc, title, applicationLoads]) => ({
        id,
        title,
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=${poc}`, 6000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            // A framework that read directives from the served markup would
            // evaluate the added binding, and the page would request an image
            // whose URL is a value from the application. The client gives
            // its framework a directive prefix that served markup cannot
            // name, so the binding stays an ordinary attribute.
            const carried = visit.log.filter((entry) => entry.dest === 'image'
                && /challenge|connect|comput/i.test(decodeURIComponent(entry.path + entry.query)));
            const bound = visit.page.boundByServer || [];
            t.report(summary(visit, t, {
                'application state sent in a request': carried.length
                    ? decodeURIComponent(carried[0].path) : 'no',
                'application state bound into served markup': bound.length ? JSON.stringify(bound) : 'no',
                'verifier state': stateLabel(state),
            }), [
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
                ['markup alone could not route application state into a request', 'must',
                    carried.length === 0 && bound.length === 0],
                ['the added markup is gone once the page has loaded', 'must', !visit.page.serverAdded],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    // A page that loads the framework after everything else
                    // gets no application: its template had nothing to
                    // mount it. That is the server's loss, not a leak.
                    : [applicationLoads ? 'the application still loads' : 'the application does not load at all',
                        'must', visit.page.appLoaded === applicationLoads],
            ]);
        },
    })),
    {
        id: 'shadow-root-closed',
        title: 'a closed declarative shadow root on the body, with an unsigned stylesheet and a form (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=shadow-closed`, 6000);
            // Somebody writes a message at the bottom of the chat, where the
            // message field is, and presses Enter.
            const typed = await typeInto(visit.tab, '() => ({ x: Math.round(innerWidth / 2), y: innerHeight - 30 })',
                'meet at 9, the code is 4471');
            await t.sleep(1500);
            const sent = collected(await t.control('/log'));
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'stylesheet of the shadow root applied after load': visit.page.shadowCss,
                'typed into the page': typed,
                'what the server received': sent === null ? 'nothing' : sent,
                'verifier state': stateLabel(state),
            }), [
                ['the shadow root and what it holds are gone once the page has loaded', 'must', !visit.page.shadowCss],
                ['what was typed did not reach the server', 'must', sent === null],
                ['the state is neither verified nor partial', 'must', !positive(state)],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the unsigned stylesheet inside the shadow root is reported', 'must',
                        reported(state, 'unsigned-stylesheet')],
                ...(firefox ? [] : [['the application still loads', 'must', visit.page.appLoaded === true]]),
            ]);
        },
    },
    {
        id: 'shadow-root-signed',
        title: 'a declarative shadow root on the body that loads signed styles only (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=shadow-signed`, 6000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'shadow root on the body after load': visit.page.bodyShadowRoot,
                'verifier state': stateLabel(state),
            }), [
                ['the shadow root is gone once the page has loaded', 'must', !visit.page.bodyShadowRoot],
                ['the state is neither verified nor partial', 'must', !positive(state)],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the shadow root is reported as a part of the page that could not be attested', 'must',
                        reported(state, 'shadow-root')],
                ...(firefox ? [] : [['the application still loads', 'must', visit.page.appLoaded === true]]),
            ]);
        },
    },
    {
        id: 'name-body',
        title: 'served markup with an element named "body", which stands in for document.body (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=name-body`, 6000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the served markup is gone once the page has loaded', 'must', !visit.page.serverAdded],
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the application still loads', 'must', visit.page.appLoaded === true],
            ]);
        },
    },
    {
        id: 'form-action',
        title: 'a page served without the framework, with a form that posts to the server (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=no-engine-form`, 5000);
            const typed = visit.page.serverAdded && await typeInto(visit.tab, `() => {
                const box = document.querySelector('#server-added input').getBoundingClientRect();
                return { x: Math.round(box.x + box.width / 2), y: Math.round(box.y + box.height / 2) };
            }`, 'the code is 4471');
            await t.sleep(1500);
            const sent = collected(await t.control('/log'));
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'typed into the served form': typed,
                'what the server received': sent === null ? 'nothing' : sent,
                'verifier state': stateLabel(state),
            }), [
                ['the form could not send anything to the server', 'must', sent === null],
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the served form was there to be used', 'must', typed === true],
            ]);
        },
    },
    {
        id: 'meta-refresh',
        title: 'a served <meta http-equiv="refresh"> to another origin (navigation only)',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=meta-refresh`, 4000);
            const seen = t.digest(visit.log);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the page did not leave the site', 'must', (visit.page.url || '').startsWith(t.urls.SITE)],
                ['the attacker origin received no request', 'must', seen.attackerRequests === 0],
                firefox
                    ? ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage]
                    : ['the attempt is reported', 'must', reported(state, 'page-refresh') && state.attention === true],
            ]);
        },
    },
    {
        id: 'policy-replaced',
        title: 'the packaged policy did not apply, and the server sent its own, which blocks inline handlers too',
        async run(t) {
            await t.control('/mode?set=own-csp');
            const browser = await t.launch();
            // What a browser does when the extension may not act on the
            // site: the packaged rules are not applied to its responses.
            const page = await browser.newTab();
            await page.goto(browser.extensionUrl('popup.html?debug=states'), 300);
            const disabled = await page.eval(`async () => {
                const ext = globalThis.browser || globalThis.chrome;
                await ext.declarativeNetRequest.updateEnabledRulesets({ disableRulesetIds: ['pinchat_preventive_csp'] });
                return (await ext.declarativeNetRequest.getEnabledRulesets()).length === 0;
            }`);
            await page.close().catch(() => {});
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=own-script`, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const ran = visit.log.some((entry) => entry.note === 'leak unsigned-script-ran');
            const firefox = t.browserName === 'firefox';
            // The content script compares the policy the browser names for
            // blocking its probe with the packaged one. Chromium reports no
            // violation that an extension's own code causes, so there the
            // two cannot be told apart while the extension has access to the
            // site. Without that access no positive state is shown at all
            // (unit-tested in tests/test-verifier-verdict.js), which is how
            // the packaged rules come not to apply in practice.
            t.report(summary(visit, t, {
                'packaged rules disabled': disabled,
                'unsigned script of the site ran': ran,
                'verifier state': stateLabel(state),
            }), [
                ['the packaged rules were disabled for the test', 'must', disabled === true],
                ...(firefox ? [
                    ['the state is neither verified nor partial', 'must', !positive(state)],
                    ['the altered document was replaced by the block page', 'must', !!visit.page.blockPage],
                ] : [
                    ['another policy in force is told from the packaged one', 'limit',
                        !!state && state.integrity === 'failed' && reported(state, 'policy-not-in-force')],
                ]),
            ]);
        },
    },
    ...REDIRECT_CODES.map((code) => ({
        id: `redirect-${code}`,
        title: `invite link answered with a ${code} to another origin`,
        async run(t) {
            await t.control(`/mode?set=redirect:${code}:cross`);
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t), [
                ['the attacker origin received no request', 'must', seen.attackerRequests === 0],
                ['no document outside the site saw the fragment', 'must',
                    seen.leakedFragment === null && !visit.page.leak],
            ]);
        },
    })),
    ...['scheme-relative', 'backslash', 'port', 'chain'].map((kind) => ({
        id: `redirect-${kind}`,
        title: `invite link redirected off the site (${kind})`,
        async run(t) {
            await t.control(`/mode?set=redirect:302:${kind}`);
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t), [
                ['no document outside the site saw the fragment', 'must',
                    seen.leakedFragment === null && !visit.page.leak],
                ['the attacker origin received no request', 'must', seen.attackerRequests === 0],
            ]);
        },
    })),
    {
        id: 'redirect-own-fragment',
        title: 'redirect to another origin whose Location carries its own fragment',
        async run(t) {
            await t.control('/mode?set=redirect:302:cross-fragment');
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t), [
                ['the invite fragment is not what the destination sees', 'must',
                    !(seen.leakedFragment || '').includes('TESTSECRET') && !(visit.page.leak || '').includes('TESTSECRET')],
                ['the attacker origin received no request', 'must', seen.attackerRequests === 0],
            ]);
        },
    },
    {
        id: 'redirect-without-verifier',
        title: 'the same cross-origin redirect in a browser without the extension',
        async run(t) {
            await t.control('/mode?set=redirect:302:cross');
            const browser = await t.launch({ verifier: false });
            const visit = await t.visit(browser, t.urls.INVITE, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t), [
                ['without the extension the fragment does reach the other origin', 'limit',
                    !(seen.leakedFragment || '').includes('TESTSECRET')],
            ]);
        },
    },
    {
        id: 'extension-link',
        title: 'the site\'s own extension link, redirected to the release page',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.SITE}/ext/chrome`, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t, { 'requests to the release page': seen.releasePageRequests }), [
                ['the redirect is followed', 'must',
                    seen.releasePageRequests === 1 && visit.page.marker === 'RELEASE-PAGE-STAND-IN'],
                ['no warning is shown', 'must', !visit.page.overlay && !visit.page.blockPage],
                ['nothing reaches the attacker origin', 'must', seen.attackerRequests === 0],
            ]);
        },
    },
    ...['release', 'via-ext-link'].map((kind) => ({
        id: `redirect-${kind}`,
        title: kind === 'release'
            ? 'invite link redirected to the release page, an allowed target for a link without a key'
            : 'invite link redirected to the site\'s extension link, which redirects off the site',
        async run(t) {
            await t.control(`/mode?set=redirect:302:${kind}`);
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 3000);
            const seen = t.digest(visit.log);
            t.report(summary(visit, t, { 'requests to the release page': seen.releasePageRequests }), [
                ['the release page received no request', 'must', seen.releasePageRequests === 0],
                ['no document outside the site saw the fragment', 'must',
                    !(visit.page.leak || '').includes('TESTSECRET')
                    && visit.page.marker !== 'RELEASE-PAGE-STAND-IN'],
            ]);
        },
    })),
    {
        id: 'address-rewrite',
        title: 'a page that rewrites its own address without loading another document',
        async run(t) {
            const browser = await t.launch();
            const page = `${t.urls.SITE}/static/login.html`;
            // The login page shows the error and then drops the parameter
            // from its address with history.replaceState.
            const visit = await t.visit(browser, `${page}?error=Invalid%20password`, 5000);
            const state = await t.verifierState(browser, page);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'verifier state': stateLabel(state),
                'address in the record': state ? state.url : '(none)',
            }), [
                ['the page did rewrite its address', 'must', visit.page.url === page],
                ['the document keeps its state', 'must',
                    !!state && state.integrity === (firefox ? 'verified' : 'partial')],
                ['the record follows the new address', 'must', !!state && state.url === page],
            ]);
        },
    },
    {
        id: 'room-not-found',
        title: 'a link to a room that no longer exists, answered with a plain-text 404',
        async run(t) {
            await t.control('/mode?set=room-gone');
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.INVITE, 4000);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'document type': visit.page.contentType,
                'text shown': visit.page.text,
            }), firefox ? [
                ['what the server sent is not shown', 'must', !/Room not found/.test(visit.page.text || '')],
                ['the replacement is rendered as a page, not as its source', 'must',
                    visit.page.contentType === 'text/html' && !!visit.page.blockPage
                    && !(visit.page.text || '').includes('<')],
                ['it says that the server answered with an error, and which', 'must',
                    /error/i.test(visit.page.blockPage || '') && /404/.test(visit.page.text || '')],
                ['it does not call the answer tampering', 'must',
                    !/does not match|tried to redirect/i.test(visit.page.text || '')
                    && visit.page.overlay !== 'failed'],
            ] : [
                ['the server answer is shown as it is', 'must', /Room not found/.test(visit.page.text || '')],
                ['no warning is shown', 'must', !visit.page.overlay && !visit.page.blockPage],
            ]);
        },
    },
    {
        id: 'gateway-error',
        title: 'the address of a signed page answered with a gateway error',
        async run(t) {
            await t.control('/mode?set=gateway-error');
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.CHAT, 4000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, {
                'text shown': visit.page.text,
                'verifier state': stateLabel(state),
            }), firefox ? [
                ['what the server sent is not shown', 'must', !/Bad Gateway/.test(visit.page.text || '')],
                ['it is reported as an error answer, with its status', 'must',
                    /error/i.test(visit.page.blockPage || '') && /502/.test(visit.page.text || '')],
                ['the state is unverifiable: an error answer is not a mismatch', 'must',
                    !!state && state.integrity === 'unverifiable'
                    && state.reasons.some((entry) => entry.code === 'error-response')],
            ] : [
                ['the state is not verified', 'must', !state || state.integrity !== 'verified'],
            ]);
        },
    },
    {
        id: 'service-worker',
        title: 'service worker registered before the extension answers the navigation',
        async run(t) {
            let installed = null;
            const browser = await t.addVerifierAfter(async (plain) => {
                const visit = await t.visit(plain, `${t.urls.SITE}/static/sw-install.html`, 4000);
                installed = visit.page.swStatus;
                await visit.tab.close().catch(() => {});
            });
            const first = await t.visit(browser, t.urls.CHAT, 5000);
            const firstState = await t.verifierState(browser, t.urls.CHAT);
            // The extension is expected to remove the worker; look again.
            const second = await t.visit(browser, t.urls.CHAT, 5000);
            const secondState = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            // The extension reloads the tab once it has removed the worker,
            // so the page read here may already be the reloaded one. Whether
            // the worker's own document ran its inline script is taken from
            // the request that script would have made.
            const workerScriptRan = first.log.some((entry) => entry.note === 'leak sw-inline-ran');
            t.report({
                'worker registered beforehand': installed,
                'worker-served document ran its inline script': workerScriptRan,
                'first load, served by': first.page.marker || 'network',
                'first load, attacker code ran': first.page.attacker || 'no',
                'first load, overlay': first.page.overlay || 'none',
                'first load, block page': first.page.blockPage || 'none',
                'first load, verifier state': stateLabel(firstState),
                'second load, served by': second.page.marker || 'network',
                'second load, app loaded': second.page.appLoaded,
                'second load, verifier state': stateLabel(secondState),
            }, [
                ['the worker was in place before the extension', 'must', installed === 'registered'],
                ['the worker-served document did not get to run its inline script', 'must', !workerScriptRan],
                ['a worker-served document is either gone or shown as failed, never as verified or partial', 'must',
                    first.page.marker !== 'SERVED-BY-SERVICE-WORKER'
                    || (first.page.overlay === 'failed'
                        && (!firstState || firstState.integrity === 'failed'))],
                ['the worker no longer answers the next load', 'must',
                    second.page.marker !== 'SERVED-BY-SERVICE-WORKER'],
                ['the next load reaches the usual state', 'must',
                    !!secondState && secondState.integrity === (firefox ? 'verified' : 'partial')],
            ]);
        },
    },
    {
        id: 'link-header',
        title: 'stylesheet attached through a Link response header',
        async run(t) {
            await t.control('/mode?set=link-header');
            const browser = await t.launch();
            const visit = await t.visit(browser, t.urls.CHAT, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the stylesheet named in the header is not applied', 'must', !visit.page.evilCss],
                ['the application loads', 'must', visit.page.appLoaded === true],
            ]);
        },
    },
    {
        id: 'cached-altered',
        title: 'altered HTML stored in the HTTP cache, then the server turns honest',
        async run(t) {
            await t.control('/mode?set=cacheable');
            const browser = await t.launch();
            const url = `${t.urls.CHAT}&poc=markup`;
            const first = await t.visit(browser, url, 5000);
            await first.tab.close().catch(() => {});
            await t.control('/mode?set=clean');
            const second = await t.visit(browser, url, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            const refetched = second.log.some((entry) => entry.mode === 'navigate');
            t.report({
                'second load came from': refetched ? 'network' : 'cache',
                'altered markup in DOM on second load': second.page.serverAdded,
                'block page': second.page.blockPage || 'none',
                'verifier state': stateLabel(state),
            }, [
                ['the cached document is not verified', 'must', !state || state.integrity !== 'verified'],
                ['the cached altered markup did not reach the page', firefox ? 'must' : 'limit', !second.page.serverAdded],
            ]);
        },
    },
    {
        id: 'two-tabs',
        title: 'two tabs at once, one clean and one altered',
        async run(t) {
            const browser = await t.launch();
            const bad = await t.visit(browser, `${t.urls.CHAT}&poc=rel-exact`, 5000);
            const good = await t.visit(browser, `${t.urls.SITE}/static/login.html`, 5000);
            const badState = await t.verifierState(browser, t.urls.CHAT);
            const goodState = await t.verifierState(browser, `${t.urls.SITE}/static/login.html`);
            const firefox = t.browserName === 'firefox';
            t.report({
                'altered tab, attacker code ran': bad.page.attacker || 'no',
                'altered tab, verifier state': stateLabel(badState),
                'clean tab, verifier state': stateLabel(goodState),
            }, [
                ['the clean tab reaches its usual state', 'must',
                    !!goodState && goodState.integrity === (firefox ? 'verified' : 'partial')],
                ['the altered tab keeps its own failed state', 'must', !!badState && badState.integrity === 'failed'],
            ]);
        },
    },
    {
        id: 'same-tab',
        title: 'altered document, then a clean one, in the same tab',
        async run(t) {
            const browser = await t.launch();
            const first = await t.visit(browser, `${t.urls.CHAT}&poc=rel-exact`, 5000);
            const before = await t.verifierState(browser, t.urls.CHAT);
            await first.tab.goto(t.urls.CHAT, 5000);
            const after = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report({
                'state on the altered document': stateLabel(before),
                'state after navigating to the clean document': stateLabel(after),
            }, [
                ['the altered document is failed', 'must', !!before && before.integrity === 'failed'],
                ['the new document gets a state of its own', 'must',
                    !!after && after.integrity === (firefox ? 'verified' : 'partial')],
            ]);
        },
    },
    {
        id: 'history-restore',
        title: 'going back to a page that the browser restores without fetching it again',
        async run(t) {
            const browser = await t.launch();
            const first = await t.visit(browser, `${t.urls.SITE}/static/terms.html`, 4000);
            const before = await t.verifierState(browser, `${t.urls.SITE}/static/terms.html`);
            await first.tab.goto(`${t.urls.SITE}/static/privacy.html`, 4000);
            await t.control('/reset');
            await first.tab.eval('() => { history.back(); return true; }').catch(() => {});
            await t.sleep(4000);
            const refetched = (await t.control('/log')).some((entry) => entry.mode === 'navigate');
            const after = await t.verifierState(browser, `${t.urls.SITE}/static/terms.html`);
            const firefox = t.browserName === 'firefox';
            t.report({
                'state on first load': stateLabel(before),
                'page fetched again on going back': refetched,
                'state after going back': stateLabel(after),
            }, [
                ['the first load reaches its usual state', 'must',
                    !!before && before.integrity === (firefox ? 'verified' : 'partial')],
                ['a restored page is verified only if it was fetched and checked again', 'must',
                    refetched || !after || after.integrity !== 'verified'],
            ]);
        },
    },
    {
        id: 'no-manifest',
        title: 'the signed manifest cannot be fetched and nothing is cached',
        async run(t) {
            const browser = await t.launch({ releaseHost: false });
            const visit = await t.visit(browser, t.urls.CHAT, 6000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the state is unverifiable, not verified and not failed', 'must',
                    !!state && state.integrity === 'unverifiable'],
            ]);
        },
    },
    {
        id: 'other-port',
        title: 'same host on another port, altered HTML',
        async run(t) {
            const browser = await t.launch();
            const url = `https://pinchat.im:8444/static/chat.html?room=${t.urls.ROOM}&poc=handler`;
            const visit = await t.visit(browser, url, 4000);
            const state = await t.verifierState(browser, 'https://pinchat.im:8444/');
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['attacker code did not run', 'must', !visit.page.attacker],
                ['a warning is shown', 'must', !!visit.page.overlay || !!visit.page.blockPage],
                ['the state is not verified or partial', 'must',
                    !state || !['verified', 'partial'].includes(state.integrity)],
                ['the extension made no verification fetches there', 'must', t.digest(visit.log).verifierFetches === 0],
            ]);
        },
    },
    {
        id: 'stylesheet-after-flood',
        title: 'an unsigned stylesheet after 250 blocked scripts that would crowd it out of the findings',
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=flood-style`, 6000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            t.report(summary(visit, t, { 'verifier state': stateLabel(state).slice(0, 200) }), [
                ['the state is failed', 'must', !!state && state.integrity === 'failed'],
                ...(t.browserName === 'firefox' ? [] : [['the unsigned stylesheet is among the findings', 'must',
                    reported(state, 'unsigned-stylesheet')]]),
            ]);
        },
    },
    ...['rel-exact', 'rel-multi', 'rel-case'].map((poc) => ({
        id: `stylesheet-${poc}`,
        title: `unsigned stylesheet linked from altered HTML (${poc})`,
        async run(t) {
            const browser = await t.launch();
            const visit = await t.visit(browser, `${t.urls.CHAT}&poc=${poc}`, 5000);
            const state = await t.verifierState(browser, t.urls.CHAT);
            const firefox = t.browserName === 'firefox';
            t.report(summary(visit, t, { 'verifier state': stateLabel(state) }), [
                ['the state is failed', 'must', !!state && state.integrity === 'failed'],
                ['the stylesheet was not applied', firefox ? 'must' : 'limit', !visit.page.evilCss],
            ]);
        },
    })),
];
