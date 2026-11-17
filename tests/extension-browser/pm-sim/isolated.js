// What an autofill extension typically does to reach the page's own
// JavaScript world: it adds script elements to the DOM. Three variants.

// 1. An inline script. Under the verifier's policy this does not execute.
const inline = document.createElement('script');
inline.textContent = 'document.documentElement.setAttribute("data-pm-inline", "ran");';
(document.head || document.documentElement).appendChild(inline);

// 2. An inline script that is removed again right away, as many do.
const transient = document.createElement('script');
transient.textContent = 'document.documentElement.setAttribute("data-pm-transient", "ran");';
(document.head || document.documentElement).appendChild(transient);
transient.remove();

// 3. A script loaded from the extension's own web-accessible resources.
const external = document.createElement('script');
external.src = (globalThis.browser || globalThis.chrome).runtime.getURL('page.js');
(document.head || document.documentElement).appendChild(external);

document.documentElement.setAttribute('data-pm-sim', 'injected');
