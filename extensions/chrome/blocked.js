/**
 * PinChat Integrity Verifier - page shown in place of a refused navigation.
 * The reason is a finding code; anything else in the query is ignored, and
 * the text comes from the catalogue in verdict.js.
 */

const code = new URLSearchParams(window.location.search).get('reason') || '';
const entry = globalThis.PinChatVerdict.FINDINGS[code];
if (entry) {
    document.getElementById('verifier-block-reason').textContent = entry[1];
}
