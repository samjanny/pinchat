# PinChat Integrity Verifier - Privacy Notice

This notice covers the browser extension only. The PinChat service has its
own Privacy Policy at https://pinchat.io/static/privacy.html.

## What the extension does

The extension runs only on pinchat.io. It applies a Content Security Policy
packaged inside the extension to pages of that site, downloads a signed
release manifest from GitHub, verifies its signature against a public key
compiled into the extension, and compares the scripts, stylesheets and pages
served by pinchat.io against the hashes in that manifest. If something does
not match, it shows a warning on the page and in the toolbar badge.

## Data the extension stores

Three values, in the browser's extension storage on your device:

- the highest manifest sequence number seen, so that an older but validly
  signed manifest cannot be replayed to the extension;
- the current verification result, so that the toolbar badge survives a
  restart of the extension's background process;
- the last manifest that passed verification, so that verification keeps
  working when the manifest host is unreachable.

Nothing else is stored. Uninstalling the extension removes these values.

## Network requests the extension makes

- One request to `https://raw.githubusercontent.com/samjanny/pinchat/<tag>/hashes.json.signed`
  to download the signed manifest. It is made when the extension is installed
  or updated, when you open pinchat.io, at most every five minutes while a
  pinchat.io tab is open, and when you press the re-check button in the
  popup. An idle extension makes no requests.
- Requests to pinchat.io for the files listed in the manifest, in order to
  compute their hashes. These go to the site you are already visiting.

Both requests carry the ordinary headers a browser sends. The extension adds
no identifiers, cookies or parameters of its own.

## Data the extension collects or transmits

None. The extension has no analytics, no accounts, no remote configuration
beyond the signed manifest, and no server of its own. Page content and
verification results never leave your browser.

## Source code

https://github.com/samjanny/pinchat/tree/main/extensions

The published packages are built from a tagged revision of that repository
with `extensions/package.sh` and can be reproduced byte for byte.

## Contact

Use the contact details in the PinChat Privacy Policy.
