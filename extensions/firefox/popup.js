/**
 * PinChat Integrity Verifier - Firefox Popup Script
 */

/**
 * Check if current tab is on pinchat.io and show/hide banner
 */
async function checkCurrentTab() {
    try {
        const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
        const banner = document.getElementById('not-on-site-banner');
        if (tab && tab.url) {
            const url = new URL(tab.url);
            const isPinChat = url.hostname === 'pinchat.io' || url.hostname === 'www.pinchat.io';
            banner.style.display = isPinChat ? 'none' : 'block';
        } else {
            banner.style.display = 'block';
        }
    } catch {
        document.getElementById('not-on-site-banner').style.display = 'block';
    }
}

const statusConfig = {
    verified: {
        icon: '✓',
        text: 'All Files Verified',
        class: 'status-verified'
    },
    failed: {
        icon: '✗',
        text: 'Verification Failed!',
        class: 'status-failed'
    },
    error: {
        icon: '⚠',
        text: 'Verification Error',
        class: 'status-error'
    },
    checking: {
        icon: 'spinner',
        text: 'Checking...',
        class: 'status-checking'
    },
    unknown: {
        icon: '?',
        text: 'Status Unknown',
        class: 'status-unknown'
    }
};

function updateUI(state) {
    const config = statusConfig[state.status] || statusConfig.unknown;

    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const lastCheck = document.getElementById('last-check');
    const details = document.getElementById('details');
    const mismatches = document.getElementById('mismatches');

    // Update status icon
    if (config.icon === 'spinner') {
        statusIcon.innerHTML = '<div class="spinner"></div>';
    } else {
        statusIcon.textContent = config.icon;
    }

    // Update status text
    statusText.textContent = config.text;
    statusText.className = `status-text ${config.class}`;

    // Update last check time
    if (state.lastCheck) {
        const date = new Date(state.lastCheck);
        lastCheck.textContent = `Last checked: ${date.toLocaleString()}`;
    } else {
        lastCheck.textContent = '';
    }

    // Update details if available
    if (state.details) {
        details.style.display = 'block';
        document.getElementById('files-checked').textContent = state.details.filesChecked;
        document.getElementById('files-matched').textContent = state.details.filesMatched;
        document.getElementById('files-failed').textContent = state.details.filesFailed;
    } else {
        details.style.display = 'none';
    }

    // Update mismatches if any
    if (state.mismatches && state.mismatches.length > 0) {
        mismatches.style.display = 'block';
        const mismatchList = document.getElementById('mismatch-list');
        mismatchList.innerHTML = state.mismatches.map(m =>
            `<div class="mismatch-item">${m.path}: ${m.error}</div>`
        ).join('');
    } else {
        mismatches.style.display = 'none';
    }

    // Update button state
    const verifyBtn = document.getElementById('verify-btn');
    verifyBtn.disabled = state.status === 'checking';
    verifyBtn.textContent = state.status === 'checking' ? 'Verifying...' : 'Verify Now';
}

// Check if we're on pinchat.io
checkCurrentTab();

// Get current status
browser.runtime.sendMessage({ type: 'GET_STATUS' }).then((response) => {
    if (response) {
        updateUI(response);
    }
}).catch(() => {
    updateUI({ status: 'unknown' });
});

// Handle verify button click
document.getElementById('verify-btn').addEventListener('click', () => {
    updateUI({ status: 'checking' });
    browser.runtime.sendMessage({ type: 'VERIFY_NOW' }).then((response) => {
        if (response) {
            updateUI(response);
        }
    }).catch((error) => {
        console.error('Verification error:', error);
        updateUI({ status: 'error', errors: [error.message] });
    });
});

// Listen for status updates
browser.runtime.onMessage.addListener((message, sender) => {
    if (message.type === 'VERIFICATION_STATUS') {
        updateUI(message.state);
    }
});
