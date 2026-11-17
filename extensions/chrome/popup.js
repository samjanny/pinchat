/**
 * PinChat Integrity Verifier - popup
 *
 * Shows the state of the document in the active tab, and only of that
 * document. Every word of it comes from the record the background script
 * keeps for that tab; nothing is inferred here. Text is always written with
 * textContent.
 */

const ext = globalThis.browser || globalThis.chrome;
const V = globalThis.PinChatVerdict;

const ICONS = {
    [V.INTEGRITY.VERIFIED]: ['OK', 'status-verified'],
    [V.INTEGRITY.PARTIAL]: ['~', 'status-partial'],
    [V.INTEGRITY.FAILED]: ['!', 'status-failed'],
    [V.INTEGRITY.UNVERIFIABLE]: ['?', 'status-unverifiable'],
    [V.INTEGRITY.CHECKING]: ['...', 'status-checking'],
};

const byId = (id) => document.getElementById(id);
const show = (element, visible) => element.classList.toggle('is-hidden', !visible);

function renderList(container, entries, className) {
    container.textContent = '';
    for (const entry of entries) {
        const row = document.createElement('div');
        row.className = className;
        row.textContent = entry.detail ? `${entry.message} (${entry.detail})` : entry.message;
        container.appendChild(row);
    }
}

function manifestLine(manifest) {
    if (!manifest) return 'unknown';
    if (manifest.status === 'valid') {
        const origin = manifest.usingCached ? 'stored copy, release host unreachable' : 'from the release host';
        return `valid, sequence ${manifest.sequence} (${origin})`;
    }
    if (manifest.status === 'invalid') return 'REJECTED: bad signature or older than the last one seen';
    if (manifest.status === 'error') return 'not available';
    return 'not loaded yet';
}

function render(state) {
    const icon = byId('status-icon');
    const text = byId('status-text');
    const scope = byId('status-scope');

    show(byId('not-on-site-banner'), !state.onSite);
    byId('manifest-status').textContent = manifestLine(state.manifest);

    const verdict = state.verdict;
    if (!state.onSite) {
        icon.textContent = '-';
        icon.className = 'status-icon status-unknown';
        text.textContent = 'This tab is not showing pinchat.io. Nothing here is verified.';
        scope.textContent = '';
        show(byId('reasons'), false);
        show(byId('environment'), false);
        for (const id of ['policy-status', 'document-status', 'files-status']) byId(id).textContent = '-';
        return;
    }
    if (!verdict) {
        // On the site, but the document has not announced itself: it was
        // loaded before the extension started, or its check is not in yet.
        icon.textContent = '?';
        icon.className = 'status-icon status-unverifiable';
        text.textContent = 'No result for this page yet. If this does not change, reload the page.';
        scope.textContent = '';
        show(byId('reasons'), false);
        show(byId('environment'), false);
        for (const id of ['policy-status', 'document-status', 'files-status']) byId(id).textContent = '-';
        return;
    }

    const [symbol, className] = ICONS[verdict.integrity] || ['?', 'status-unknown'];
    icon.textContent = symbol;
    icon.className = `status-icon ${className}`;
    text.textContent = verdict.headline;
    scope.textContent = 'This describes what the server delivered. It says nothing about your browser, '
        + 'your device or other extensions.';

    const reasons = verdict.reasons || [];
    show(byId('reasons'), reasons.length > 0);
    byId('reasons-title').textContent = verdict.integrity === V.INTEGRITY.FAILED
        ? 'What does not match' : 'What was noticed';
    renderList(byId('reason-list'), reasons, 'mismatch-item');

    const environment = verdict.environment || [];
    show(byId('environment'), environment.length > 0);
    renderList(byId('environment-list'), environment, 'file-item');

    const has = (code) => reasons.some((entry) => entry.code === code);
    byId('policy-status').textContent = has('policy-not-in-force') || has('service-worker-controlled')
        ? 'NOT in force' : 'in force: only signed scripts can run';
    if (verdict.attested) {
        byId('document-status').textContent = 'compared with the signed page before it was shown';
    } else if (verdict.canAttest) {
        byId('document-status').textContent = 'not checked';
    } else {
        byId('document-status').textContent = 'cannot be checked in this browser';
    }
    byId('files-status').textContent = verdict.files
        ? `${verdict.files.checked - verdict.files.failed} of ${verdict.files.checked} match `
            + '(a second download, not proof of what the page loaded)'
        : 'not yet';
}

async function activeTab() {
    const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
    return tab || null;
}

async function refresh() {
    const tab = await activeTab();
    if (!tab) return;
    const state = await ext.runtime.sendMessage({ type: 'GET_TAB_STATE', tabId: tab.id }).catch(() => null);
    if (state) render(state);
}

byId('verify-btn').addEventListener('click', async () => {
    const button = byId('verify-btn');
    button.disabled = true;
    const tab = await activeTab();
    await ext.runtime.sendMessage({ type: 'VERIFY_NOW', tabId: tab ? tab.id : null }).catch(() => null);
    setTimeout(() => {
        button.disabled = false;
        refresh();
    }, 1500);
});

if (new URLSearchParams(window.location.search).get('debug') === 'states') {
    // Diagnostic view, opened as a page: the raw records of every tab. Used
    // by tests/extension-browser to read what the extension concluded.
    ext.runtime.sendMessage({ type: 'GET_ALL_STATES' }).then((states) => {
        const dump = byId('debug-states');
        dump.textContent = JSON.stringify(states || []);
        show(dump, true);
    }).catch(() => {});
} else {
    refresh();
    const poll = setInterval(refresh, 1000);
    window.addEventListener('unload', () => clearInterval(poll));
}
