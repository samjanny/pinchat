/**
 * Login page initialization
 * Fetches CSRF token from API and sets up the form
 */
(function() {
    'use strict';

    const urlParams = new URLSearchParams(window.location.search);

    // Show error message if present in URL
    const errorMsg = urlParams.get('error');
    if (errorMsg) {
        renderError(errorMsg);
        // Clean URL (remove error param) without reloading
        const cleanUrl = window.location.pathname +
            (urlParams.get('redirect') ? '?redirect=' + encodeURIComponent(urlParams.get('redirect')) : '');
        window.history.replaceState({}, '', cleanUrl);
    }

    // Get redirect parameter from URL
    const redirectUrl = urlParams.get('redirect') || '';
    document.getElementById('redirect_url').value = redirectUrl;

    // Fetch CSRF token from API
    fetch('/api/csrf', { credentials: 'same-origin' })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to get security token');
            }
            return response.json();
        })
        .then(data => {
            // Validate CSRF token format: 32 hex chars + dot + 64 hex chars
            if (!/^[a-f0-9]{32}\.[a-f0-9]{64}$/.test(data.csrf_token)) {
                throw new Error('Invalid token format');
            }
            document.getElementById('csrf_token').value = data.csrf_token;
            document.getElementById('submit-btn').disabled = false;
            document.getElementById('submit-btn').textContent = 'Enter';
        })
        .catch(error => {
            renderError('Failed to initialize. Please refresh the page.');
            console.error('CSRF fetch error:', error);
        });

    // Render an error string into #error-container without ever using innerHTML.
    // Building the DOM via createElement + textContent removes the need for a
    // manual escape pass and prevents future regressions if the message source
    // changes.
    function renderError(text) {
        const div = document.createElement('div');
        div.className = 'login-error-message';
        div.textContent = text;
        const container = document.getElementById('error-container');
        container.replaceChildren(div);
    }
})();
