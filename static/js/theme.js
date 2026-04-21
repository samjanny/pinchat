/**
 * Theme controller: light/dark toggle with localStorage persistence.
 *
 * Applies the saved theme synchronously on load to prevent a flash of the
 * wrong theme. When no preference is stored, falls back to the OS setting
 * via the @media (prefers-color-scheme) rule in CSS.
 *
 * The toggle button is created in JS so every page gets it consistently
 * without each HTML file having to define the markup.
 */
(function () {
    'use strict';

    var STORAGE_KEY = 'pinchat-theme';

    function readStored() {
        try {
            return localStorage.getItem(STORAGE_KEY);
        } catch (e) {
            return null;
        }
    }

    function writeStored(value) {
        try {
            localStorage.setItem(STORAGE_KEY, value);
        } catch (e) {
            /* storage unavailable — fall through */
        }
    }

    function applyTheme(value) {
        var root = document.documentElement;
        if (value === 'light' || value === 'dark') {
            root.setAttribute('data-theme', value);
        } else {
            root.removeAttribute('data-theme');
        }
    }

    function effectiveTheme() {
        var stored = readStored();
        if (stored === 'light' || stored === 'dark') {
            return stored;
        }
        if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            return 'dark';
        }
        return 'light';
    }

    // Apply immediately, before the body paints, to avoid FOUC.
    applyTheme(readStored());

    function mountToggle() {
        if (document.getElementById('theme-toggle')) {
            return;
        }
        var btn = document.createElement('button');
        btn.id = 'theme-toggle';
        btn.className = 'theme-toggle';
        btn.type = 'button';
        btn.setAttribute('aria-label', 'Toggle light/dark theme');
        btn.setAttribute('title', 'Toggle light/dark theme');

        var sun = document.createElement('span');
        sun.className = 'theme-icon-sun';
        sun.setAttribute('aria-hidden', 'true');
        sun.textContent = '☀️';

        var moon = document.createElement('span');
        moon.className = 'theme-icon-moon';
        moon.setAttribute('aria-hidden', 'true');
        moon.textContent = '🌙';

        btn.appendChild(sun);
        btn.appendChild(moon);

        function refreshPressed() {
            btn.setAttribute('aria-pressed', effectiveTheme() === 'dark' ? 'true' : 'false');
        }
        refreshPressed();

        btn.addEventListener('click', function () {
            var next = effectiveTheme() === 'dark' ? 'light' : 'dark';
            writeStored(next);
            applyTheme(next);
            refreshPressed();
        });

        // React to OS-level changes while no explicit preference is stored.
        if (window.matchMedia) {
            var mql = window.matchMedia('(prefers-color-scheme: dark)');
            var onOsChange = function () {
                if (!readStored()) {
                    refreshPressed();
                }
            };
            if (mql.addEventListener) {
                mql.addEventListener('change', onOsChange);
            } else if (mql.addListener) {
                mql.addListener(onOsChange);
            }
        }

        document.body.appendChild(btn);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', mountToggle);
    } else {
        mountToggle();
    }
})();
