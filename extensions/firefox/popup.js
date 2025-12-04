/**
 * PinChat Integrity Verifier - Firefox Popup Script
 */

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} - HTML-safe escaped text
 */
function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

let pollingInterval = null;
let lastStateJson = null;

/**
 * Start polling for status updates during verification
 */
function startPolling() {
    if (pollingInterval) return;
    pollingInterval = setInterval(() => {
        browser.runtime.sendMessage({ type: 'GET_STATUS' }).then((response) => {
            if (response) {
                // Only update UI if state actually changed to avoid animation flicker
                const stateJson = JSON.stringify({
                    status: response.status,
                    signatureStatus: response.signatureStatus,
                    fileStatus: response.fileStatus
                });
                if (stateJson !== lastStateJson) {
                    lastStateJson = stateJson;
                    updateUI(response);
                }
                if (response.status !== 'checking') {
                    stopPolling();
                    lastStateJson = null;
                }
            }
        }).catch(() => {
            // Extension context invalidated, stop polling
            stopPolling();
        });
    }, 1000);
}

/**
 * Stop polling for status updates
 */
function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

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
    signature_only: {
        icon: '✓',
        text: 'Signature Verified',
        class: 'status-verified'
    },
    partial: {
        icon: '◐',
        text: 'Partially Verified',
        class: 'status-partial'
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
    // Determine if we're on pinchat.io
    const onPinChat = state.debug?.onPinChat ?? false;

    // Use signature_only status when not on pinchat.io and signature is valid
    let effectiveStatus = state.status;
    if (!onPinChat && state.status === 'verified' && state.signatureStatus === 'valid') {
        effectiveStatus = 'signature_only';
    }

    const config = statusConfig[effectiveStatus] || statusConfig.unknown;

    const statusIcon = document.getElementById('status-icon');
    const statusText = document.getElementById('status-text');
    const lastCheck = document.getElementById('last-check');
    const verificationSteps = document.getElementById('verification-steps');
    const signatureStatus = document.getElementById('signature-status');
    const fileStatus = document.getElementById('file-status');
    const details = document.getElementById('details');
    const mismatches = document.getElementById('mismatches');
    const fileListSection = document.getElementById('file-list');
    const fileItems = document.getElementById('file-items');

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

    // Update verification steps (show if available)
    if (state.signatureStatus || state.fileStatus) {
        verificationSteps.style.display = 'block';

        // Update signature status
        const sigStatus = state.signatureStatus || 'unknown';
        switch(sigStatus) {
            case 'valid':
                signatureStatus.innerHTML = '<span style="color: #22c55e;">✓ Valid</span>';
                break;
            case 'invalid':
                signatureStatus.innerHTML = '<span style="color: #ef4444;">✗ Invalid</span>';
                break;
            case 'checking':
                signatureStatus.innerHTML = '<span style="color: #3b82f6;">⏳ Checking...</span>';
                break;
            case 'error':
                signatureStatus.innerHTML = '<span style="color: #f59e0b;">⚠ Error</span>';
                break;
            default:
                signatureStatus.innerHTML = '<span style="color: #6b7280;">⏳ Pending</span>';
        }

        // Get file hash row element
        const fileHashRow = document.getElementById('file-hash-row');

        if (onPinChat) {
            fileHashRow.style.display = 'flex';
            // Update file status
            const fStatus = state.fileStatus || 'pending';
            switch(fStatus) {
                case 'verified':
                    fileStatus.innerHTML = '<span style="color: #22c55e;">✓ Verified</span>';
                    break;
                case 'failed':
                    fileStatus.innerHTML = '<span style="color: #ef4444;">✗ Failed</span>';
                    break;
                case 'checking':
                    fileStatus.innerHTML = '<span style="color: #3b82f6;">⏳ Checking...</span>';
                    break;
                case 'pending':
                    fileStatus.innerHTML = '<span style="color: #6b7280;">⏳ Pending</span>';
                    break;
                case 'error':
                    fileStatus.innerHTML = '<span style="color: #f59e0b;">⚠ Error</span>';
                    break;
                default:
                    fileStatus.innerHTML = '<span style="color: #6b7280;">⏳ Pending</span>';
            }
        } else {
            // Not on pinchat.io - hide file hash row
            fileHashRow.style.display = 'none';
        }
    } else {
        verificationSteps.style.display = 'none';
    }

    // Update details from file verification if available (only on pinchat.io)
    if (onPinChat && state.fileVerification && state.fileVerification.summary) {
        details.style.display = 'block';
        const summary = state.fileVerification.summary;
        // Use 'checked' if available (new format), fallback to 'total' (legacy)
        document.getElementById('files-checked').textContent = summary.checked ?? summary.total;
        document.getElementById('files-matched').textContent = summary.passed;
        // 'failed' now includes all failures (hash + DOM issues)
        document.getElementById('files-failed').textContent = summary.failed;

        // Hide auth row since we don't track that anymore
        const authRow = document.getElementById('auth-row');
        authRow.style.display = 'none';
    } else if (onPinChat && state.details) {
        details.style.display = 'block';
        document.getElementById('files-checked').textContent = state.details.filesChecked;
        document.getElementById('files-matched').textContent = state.details.filesMatched;
        document.getElementById('files-failed').textContent = state.details.filesFailed;

        // Show auth required row if there are any
        const authRow = document.getElementById('auth-row');
        const filesAuth = document.getElementById('files-auth');
        if (state.details.filesAuthRequired > 0) {
            authRow.style.display = 'flex';
            filesAuth.textContent = state.details.filesAuthRequired;
        } else {
            authRow.style.display = 'none';
        }
    } else {
        details.style.display = 'none';
    }

    // Update file list if available (only on pinchat.io)
    if (onPinChat && state.fileVerification && state.fileVerification.files && state.fileVerification.files.length > 0) {
        fileListSection.style.display = 'block';
        const files = state.fileVerification.files;
        // Clear existing items and build with DOM methods to prevent XSS
        fileItems.innerHTML = '';
        files.forEach(f => {
            // Handle all status types: ok, failed, dom-issue
            let statusIcon, statusClass;
            if (f.status === 'ok') {
                statusIcon = '✓';
                statusClass = 'ok';
            } else if (f.status === 'failed') {
                statusIcon = '✗';
                statusClass = 'failed';
            } else if (f.status === 'dom-issue') {
                statusIcon = '⚠';
                statusClass = 'dom-issue';
            } else {
                statusIcon = '?';
                statusClass = 'unknown';
            }
            // Extract filename from path
            const filename = f.path ? f.path.split('/').pop() : '';
            // Build DOM elements safely
            const itemDiv = document.createElement('div');
            itemDiv.className = 'file-item';
            const statusSpan = document.createElement('span');
            statusSpan.className = `file-status ${statusClass}`;
            statusSpan.textContent = statusIcon;
            const pathSpan = document.createElement('span');
            pathSpan.className = 'file-path';
            pathSpan.textContent = filename;
            pathSpan.title = f.error ? `${f.path}: ${f.error}` : (f.path || '');
            itemDiv.appendChild(statusSpan);
            itemDiv.appendChild(pathSpan);
            fileItems.appendChild(itemDiv);
        });
    } else {
        fileListSection.style.display = 'none';
    }

    // Update mismatches if any (only show real failures, not auth-required or rate-limited)
    const realFailures = state.mismatches ?
        state.mismatches.filter(m => m.errorType !== 'auth' && m.errorType !== 'rate_limited') : [];

    if (realFailures.length > 0) {
        mismatches.style.display = 'block';
        const mismatchList = document.getElementById('mismatch-list');
        // Clear and build with DOM methods to prevent XSS
        mismatchList.innerHTML = '';
        realFailures.forEach(m => {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'mismatch-item';
            itemDiv.textContent = `${m.path || ''}: ${m.error || ''}`;
            mismatchList.appendChild(itemDiv);
        });
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
        // If already checking, start polling to get updates
        if (response.status === 'checking') {
            startPolling();
        }
    }
}).catch(() => {
    updateUI({ status: 'unknown' });
});

// Handle verify button click
document.getElementById('verify-btn').addEventListener('click', () => {
    updateUI({ status: 'checking' });
    startPolling();
    browser.runtime.sendMessage({ type: 'VERIFY_NOW' }).catch((error) => {
        console.error('Verification error:', error);
        stopPolling();
        updateUI({ status: 'error', errors: [error.message] });
    });
});

// Listen for status updates
browser.runtime.onMessage.addListener((message, sender) => {
    if (message.type === 'VERIFICATION_STATUS') {
        updateUI(message.state);
    }
});
