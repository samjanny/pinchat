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
    [V.INTEGRITY.VERIFIED]: ['\u2713', 'status-verified'],
    [V.INTEGRITY.PARTIAL]: ['\u2713', 'status-partial'],
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

const CHECK_IDS = ['manifest-status', 'policy-status', 'document-status', 'files-status'];

/**
 * Write the outcome of one check: its text, and a color for how it went.
 * outcome is one of ok, limited (this browser cannot do more), missing (the
 * check could not be made), failed, pending.
 */
function setCheck(id, text, outcome) {
    const element = byId(id);
    element.textContent = text;
    element.className = `detail-value check-${outcome}`;
}

function manifestCheck(manifest) {
    if (!manifest) return ['unknown', 'pending'];
    if (manifest.status === 'valid') {
        return manifest.usingCached
            ? [`valid, sequence ${manifest.sequence} (stored copy, release host unreachable)`, 'limited']
            : [`valid, sequence ${manifest.sequence} (from the release host)`, 'ok'];
    }
    if (manifest.status === 'invalid') return ['REJECTED: bad signature or older than the last one seen', 'failed'];
    if (manifest.status === 'unusable') return ['signed, but this version of the extension cannot use it', 'missing'];
    if (manifest.status === 'error') return ['not available', 'missing'];
    return ['not loaded yet', 'pending'];
}

function render(state) {
    const icon = byId('status-icon');
    const text = byId('status-text');
    const scope = byId('status-scope');

    const note = byId('status-note');

    show(byId('not-on-site-banner'), !state.onSite);
    for (const id of CHECK_IDS) setCheck(id, '-', 'pending');
    show(note, false);

    const verdict = state.verdict;
    if (!state.onSite) {
        icon.textContent = '-';
        icon.className = 'status-icon status-unknown';
        text.textContent = 'This tab is not showing pinchat.im. Nothing here is verified.';
        scope.textContent = '';
        show(byId('reasons'), false);
        show(byId('environment'), false);
        return;
    }
    setCheck('manifest-status', ...manifestCheck(state.manifest));
    if (!verdict) {
        // On the site, but the document has not announced itself: it was
        // loaded before the extension started, or its check is not in yet.
        icon.textContent = '?';
        icon.className = 'status-icon status-unverifiable';
        text.textContent = 'No result for this page yet. If this does not change, reload the page.';
        scope.textContent = '';
        show(byId('reasons'), false);
        show(byId('environment'), false);
        return;
    }

    const [symbol, className] = ICONS[verdict.integrity] || ['?', 'status-unknown'];
    icon.textContent = symbol;
    icon.className = `status-icon ${className}`;
    text.textContent = verdict.headline;
    note.textContent = V.headlineNote(verdict.integrity);
    show(note, note.textContent !== '');
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
    if (has('policy-not-in-force') || has('service-worker-controlled')) {
        setCheck('policy-status', 'NOT in force', 'failed');
    } else if (has('no-host-access')) {
        setCheck('policy-status', 'may not apply: the extension has no standing access to this site', 'missing');
    } else {
        setCheck('policy-status', 'in force: only signed scripts can run', 'ok');
    }
    if (verdict.attested) {
        setCheck('document-status', 'compared with the signed page before it was shown', 'ok');
    } else if (verdict.canAttest) {
        setCheck('document-status', 'not checked', 'missing');
    } else {
        setCheck('document-status', 'cannot be checked in this browser', 'limited');
    }
    if (verdict.files) {
        const { checked, failed } = verdict.files;
        setCheck('files-status', `${checked - failed} of ${checked} match `
            + '(a second download, not proof of what the page loaded)',
        failed > 0 ? 'failed' : checked > 0 ? 'ok' : 'missing');
    } else {
        setCheck('files-status', 'not yet', 'pending');
    }
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
