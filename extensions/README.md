# PinChat Integrity Verifier Browser Extensions

Browser extensions that prevent unapproved scripts from executing on pinchat.im and verify served files using Subresource Integrity (SRI).

## How It Works

The extension uses a defense-in-depth approach combining a packaged CSP, SRI, and signed manifests:

1. **Preventive CSP**: A static Declarative Net Request rule replaces the response CSP before parsing. Each official page gets only its signed script hashes; unknown paths get `script-src 'none'`.
2. **Manifest Verification**: Extension fetches the signed hash list from GitHub.
3. **Signature Verification**: Verifies its ECDSA P-256 signature using the embedded public key.
4. **SRI DOM Verification**: Content script checks that all `<script>` and `<link>` tags in the actual page DOM have correct `integrity` attributes matching the signed manifest.
5. **Browser Enforcement**: CSP + SRI block injected or modified scripts before execution.
6. **Visual Feedback**: Green checkmark if verified, red warning overlay if issues are detected.

### Why SRI?

Previous approach (separate fetches) was vulnerable to bypass attacks: a compromised server could serve clean files to the extension while serving malicious code to the browser.

With the preventive CSP and SRI:
- The `integrity` attribute is hardcoded in HTML files
- The extension-packaged CSP does not trust `'self'` for scripts and permits only per-page signed hashes
- Browser refuses to execute injected scripts or JS that does not match the permitted hash
- Extension verifies the HTML contains correct integrity attributes
- Both the manifest AND integrity values are signed/verified

## Setup

### 1. Generate ECDSA Key Pair

```bash
# Generate private key
openssl ecparam -genkey -name prime256v1 -noout -out private.pem

# Extract public key
openssl ec -in private.pem -pubout -out public.pem

# View public key (copy this to the extensions)
cat public.pem
```

### 2. Update Extensions with Your Public Key

Edit the `PUBLIC_KEY` constant in both:
- `chrome/background.js`
- `firefox/background.js`

Replace the placeholder with your actual public key from `public.pem`.

### 3. Generate Signed Hash List with SRI Injection

```bash
node generate-hashes.js --private-key private.pem --output ../hashes.json.signed
```

This will:
1. Calculate SHA-256 hashes (SRI format) for all JS/CSS files
2. **Inject `integrity` attributes** into HTML files (`<script>` and `<link>` tags)
3. Calculate hashes of updated HTML files
4. Sign the complete manifest with your private key
5. Output `hashes.json.signed` to the repository root

**Important**: The script modifies HTML files in-place. Commit these changes along with the signed manifest.

Use `--dry-run` to preview changes without modifying files:
```bash
node generate-hashes.js --private-key private.pem --dry-run
```

### 4. Commit and Push Changes

```bash
# Add both HTML files (with SRI) and signed manifest
git add static/*.html hashes.json.signed extensions/chrome/rules.json extensions/firefox/rules.json
git commit -m "Update SRI attributes and signed hash list"
git push
```

The extensions fetch the manifest from the immutable release tag configured by
`GITHUB_TAG` in both background scripts. For the current security release this is:
`https://raw.githubusercontent.com/samjanny/pinchat/v0.9.2/hashes.json.signed`.

On every extension release, both background scripts move to the new tag,
`MIN_KNOWN_SEQUENCE` rises to the signed manifest sequence, both extension
manifest versions bump, and the release-pin test (`tests/test-security.js`,
Test 7) follows. `finish-release.sh` does all of that from the freshly signed
manifest and then runs every CI job, so the only manual step is the signature:

```bash
node extensions/generate-hashes.js --private-key private.pem --output hashes.json.signed
extensions/finish-release.sh v0.8.0 1.3.0   # <tag> <extension version>
```

The release tag must contain the exact signed manifest before the extensions
are published. addons.mozilla.org also refuses any upload whose Firefox
manifest lacks `browser_specific_settings.gecko.data_collection_permissions`
(mandatory for new submissions since November 2025); ours declares
`{"required": ["none"]}`, which is the truthful answer and must stay so. `generate-hashes.js` also regenerates `chrome/rules.json` and
`firefox/rules.json` from that exact signed manifest; commit those files with
the release.

### 5. Generate Icon PNGs

The extensions need PNG icons. If you have ImageMagick installed:

```bash
chmod +x generate-icons.sh
./generate-icons.sh
```

Or manually convert `chrome/icons/icon.svg` to PNG files:
- `icon-16.png` (16x16)
- `icon-32.png` (32x32)
- `icon-48.png` (48x48)
- `icon-128.png` (128x128)

## Installing Extensions

### Chrome

1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select the `chrome` directory

### Firefox

1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `firefox/manifest.json`

A temporary add-on is removed when Firefox restarts. A permanent install needs
a package signed by Mozilla; see Packaging below.

## Packaging

Store packages are built from a committed tree, never from the working
directory:

```bash
extensions/package.sh            # package HEAD
extensions/package.sh v0.7.2     # package a specific tag
```

The script writes `dist/pinchat-verifier-<browser>-<version>.zip` and prints a
SHA-256 for each, so a published package can be checked against a local
rebuild.

It uses `git archive`, which has three properties that matter here. The output
is reproducible from the repository by anyone. Only tracked files are included,
so Chromium's `_metadata/` directory (written whenever the folder is loaded
unpacked, and a reserved name in extensions) cannot leak into a release.
And `manifest.json` lands at the archive root, which is what both stores
require.

Before building, the script checks that both browsers agree on `GITHUB_TAG`,
`MIN_KNOWN_SEQUENCE` and the manifest version, that the pinned tag exists, and
that its signed manifest is at or above the floor. That last check matters:
store review takes days, and a build whose floor sits above the sequence at
its own tag rejects every manifest it can fetch.

### Release order

Cut and push the release tag first, then submit to the stores. The extension
fetches its manifest from the pinned tag, so a build that goes live before the
tag exists leaves every fresh install in an error state, with no cached
manifest to fall back on.

Auto-update on both stores is driven by one thing only: a higher `version` in
`manifest.json`. Bump it in both browsers, in the same commit.

## Extension Behavior

### One state per page

The extension keeps a state for the page shown in each tab, and only for that
page. A result obtained in one tab, or for an earlier page in the same tab,
is never shown for another. What each state may be based on is defined in one
file, `verdict.js`, and pinned by `tests/test-verifier-verdict.js`.

| Badge | State | Meaning |
|-------|-------|---------|
| `✓` (green) | Verified | The bytes of the page were compared with the signed hash before the browser parsed them, and the script policy is in force. Firefox only |
| `✓` (yellow) | Partially verified | The script policy is in force, so only signed scripts can run. The page itself could not be attested. This is the best state Chromium can reach; the popup adds that a complete check is currently possible only in Firefox |
| `!` (red) | Failed | A mismatch with the signed release was established |
| `?` (amber) | Unverifiable | The check could not be made: no manifest, or the page did not pass through the verifier |
| `!` (amber) | Notice | Something on the page was blocked, or looks wrong, without proof against the server |
| `...` (grey) | Checking | Not decided yet |

Green is shown for the first row only. "Verified" is a statement about what
the server delivered; it says nothing about the browser, the device, or other
extensions.

In the popup, each line under "What was checked" is colored by its own
outcome: green when the check passed, yellow when this browser cannot make
it (the page as received, in Chromium), amber when it could not be made,
red when it failed, grey while it is not known yet.

### What is shown on the page

- **Failed**: a full-page red overlay with the reason. It has no dismiss
  button. An established mismatch with the signed release is not something to
  click through.
- **Unverifiable, in Firefox**: a full-page amber overlay with a reload
  button. Nothing was found wrong, but the page was not checked.
- **Notice**: a bar at the top of the page that can be dismissed. Something
  was blocked, or could not be checked, while the script policy stayed in
  force.
- **Changes of unattested origin**: nothing on the page. They are listed in
  the popup.

The overlay uses a closed Shadow DOM with a stylesheet loaded from the
extension's `web_accessible_resources`, so it renders under the page's strict
CSP. Firefox MV3 exposes only `warning.css` and restricts it to
`https://pinchat.im/*` via `matches`.

### Server integrity and page changes are separate questions

Other extensions add elements to pages. A password manager typically adds
script elements, some of them inline. Nothing in the DOM says who added a
node, so the verifier does not try to decide whether an element is
"authorized":

- What may **run** is decided by the script policy, which the browser
  enforces: scripts whose hash is in the signed manifest, nothing inline.
- An inline script element, a resource of another extension, or a policy
  violation that cannot be attributed to the page is recorded as a **change
  of unattested origin**. It is listed in the popup, it is never called safe,
  and it never changes the integrity state.
- A policy violation that the browser attributes to the page itself raises a
  **notice**. It points at the page but proves nothing about the server:
  another extension can write markup into a document.
- **Failed** is reserved for what is established: the page bytes differ from
  the signed hash (Firefox), a file the site served to the extension differs
  from its signed hash, a stylesheet from the site that is not in the signed
  release was loaded, the script policy is not in force, a service worker
  answered the navigation, the manifest failed its signature or rollback
  check, or the server tried to redirect a link off the site.

There is no allowlist of other extensions and no exception for inline
scripts.

### What is checked, and how

1. **Script policy** (both browsers). `declarativeNetRequest` replaces the
   CSP of every document on the site, on any port, before parsing. Each known
   page permits only its signed script hashes; everything else permits no
   script. The same rules remove the `Link` and `Refresh` response headers,
   which act on a document without being part of its body.
2. **Policy probe** (both). At `document_start` the content script checks,
   synchronously, that inline handlers are in fact blocked and that no
   service worker controls the document. A document answered by a service
   worker never receives the extension's header rules. If either check
   fails, the document is stopped and marked failed. Service workers
   registered for the site are removed; the site uses none.
3. **Redirect guard** (both). An invite link carries its key after the `#`,
   and browsers carry that fragment across redirects, to another origin too.
   A document navigation on the site whose address carries a fragment may
   therefore only be redirected to the site itself. One without a fragment
   has nothing to hand over, and may also be redirected to the three places
   the site's own links lead to: the project's release page and the two
   extension stores (the "Add to Chrome" and "Add to Firefox" buttons go
   through `/ext/chrome` and `/ext/firefox`, which the reverse proxy
   redirects). The list is `EXTERNAL_REDIRECT_TARGETS` in `verdict.js`; none
   of the three is an origin the server operator controls. Every other
   redirect off the site is refused, fragment or not. Chromium enforces this
   with rules on the `Location` response header (which is why the minimum
   version is 128); Firefox enforces it in the background script.
4. **Page bytes** (Firefox). `webRequest.filterResponseData` holds the body
   of every document navigation on the site. It is hashed and compared with
   the signed hash for that address, and only then released to the parser,
   byte for byte. Anything else is replaced by a block page that contains
   nothing the server sent. If the filter cannot attach to a response, the
   response is cancelled. What is released is always delivered as HTML in
   UTF-8, whatever type, character encoding or disposition the server
   declared. An answer with an error status that is not a signed page (a
   room that no longer exists, a rate limit, a gateway error) is withheld
   in the same way but reported as an error answer and as "unverifiable",
   not as a mismatch.
5. **DOM inspection** (both). Script, stylesheet, base, frame and form
   elements are compared with the manifest, as described above.
6. **File re-download** (both). Every file of the manifest is downloaded
   again and hashed. A match is not counted towards any positive state,
   because a server can answer this request differently from the page's own;
   a mismatch is a failure.

### Anti-Downgrade Protection

The manifest includes an incrementing `sequence` number to prevent replay attacks:

1. Each new manifest has a higher sequence number than the previous
2. Extension stores the highest seen sequence in local storage
3. **Rejects** any manifest with sequence < stored sequence
4. Prevents attackers from replaying old (but validly signed) manifests

| Scenario | Result |
|----------|--------|
| First install | Accept any sequence, store it |
| New manifest (sequence >= stored) | Accept, update stored |
| Old manifest (sequence < stored) | **REJECT - Downgrade attack** |
| Storage cleared | Like first install (acceptable risk) |
| Manifest host unreachable | Fall back to the cached copy, re-validated |
| Cached copy fails re-validation | Drop it and report an error |

### Verification Interval

The extension verifies integrity:
- On extension install/update
- On every navigation to pinchat.im
- On the `CONFIG.CHECK_INTERVAL_MINUTES` alarm (default 5 minutes), but only
  while a pinchat.im tab is open, or while no usable manifest is cached yet
- When manually triggered via the popup, which always re-fetches

The alarm is gated on purpose. An unconditional timer means every install
contacts the manifest host every few minutes for the life of the profile,
which tells that host and every network observer in between that this
browser runs the extension and roughly when. An idle extension has nothing
to verify, so it stays silent. Two consecutive live fetches are also kept at
least 60 seconds apart (`MIN_LIVE_FETCH_INTERVAL_MS`).

### Offline and Blocked-Network Behaviour

The last manifest that passed both the signature and the sequence gate is
kept in extension storage and re-validated on every read. When the manifest
host cannot be reached, that copy is used and the popup shows
**Valid (cached)** with the date it was stored.

This is a security control, not a convenience. Without it, anyone able to
drop the connection to the manifest host - a hostile network, a filtering
proxy, a state-level block, or a plain GitHub outage - switches the whole
detection layer off simply by making a request fail, and leaves no trace on
the page. Storage tampering buys nothing: a stored manifest still has to
clear the same two gates as a freshly fetched one.

A bad signature or a sequence downgrade is never rescued by the cache. Those
are attack signals rather than transport problems, and they fail closed.

## Updating Hashes

After deploying changes to pinchat.im:

1. Run the hash generator with your private key
2. Commit and push the new `hashes.json.signed`
3. Extensions pick up the change on the next navigation to pinchat.im, or
   within `CHECK_INTERVAL_MINUTES` if a tab is already open

## Security Considerations

### Why the Public Key is Hardcoded

The public key (`PINCHAT_PUBLIC_KEY`) and domain (`OFFICIAL_DOMAIN`) are **intentionally hardcoded** in the extension source code. This is a critical security feature, not a limitation.

**Security benefits of hardcoding:**

1. **Server compromise protection**: If an attacker gains access to the pinchat.im server, they CANNOT change the public key used to verify file signatures. The key is baked into the extension code that users have already installed.

2. **Independent trust anchor**: The extension creates a verification path that is completely independent of the server:
   - Signed manifests are hosted on GitHub (separate from the main server)
   - The public key is embedded in extension code (distributed via browser stores)
   - An attacker would need to compromise BOTH GitHub AND the browser extension stores

3. **Verifiable by users**: Anyone can inspect the extension source code to verify:
   - Which public key is being used
   - That it matches the official PinChat repository
   - That the verification logic hasn't been tampered with

4. **Update protection**: The only way to change the public key is to release a new extension version, which requires:
   - Pushing to the official repository
   - Publishing through Chrome/Firefox extension stores
   - Users actively updating the extension

**Attack scenarios prevented:**

| Attack | Why it fails |
|--------|--------------|
| Attacker compromises server, serves malicious JS | Browser blocks (SRI mismatch) |
| Attacker signs malicious manifest with fake key | Extension rejects (wrong public key) |
| Attacker modifies extension on server | N/A - extension is from browser store, not server |

### Private Key Security

- **Keep your private key secure!** Never commit it to the repository
- The public key is embedded in the extension, so users trust files signed by you
- If your private key is compromised, attackers could sign malicious hash lists
- Consider using a hardware security module (HSM) for production

### Defense in Depth

The integrity approach provides multiple layers of protection:

1. **Extension-packaged preventive CSP**: Before HTML parsing, permits only the signed script hashes assigned to that page and blocks scripts on unknown paths.
2. **Browser SRI enforcement**: For scripts carrying `integrity`, blocks bytes that do not match the declared hash.
3. **Extension verification**: In Firefox, compares the bytes of every page with the signed hash before the browser parses them. In both browsers, inspects the DOM and re-downloads every file of the manifest; a mismatch there is a failure, a match is not counted as proof (see "What is checked, and how").
4. **Signed manifest**: Hash list is signed, so attackers cannot forge a valid allowlist with server access alone.

### Attack Prevention

| Attack | Chromium | Firefox |
|--------|----------|---------|
| Server serves malicious JS | Blocked before execution by the hash-only policy | Same |
| Server adds an inline script or handler to the HTML | Not run. Shown as a notice | Page replaced by the block page |
| Server serves different HTML to the navigation than to any other request | **Not detected.** State stays "partially verified" | Page replaced by the block page |
| Server adds markup with framework directives and no script | Not evaluated: the client's framework does not read directives from served markup (see below). The markup is removed once the page has loaded | Page replaced by the block page |
| Server links an unsigned same-origin stylesheet | Loaded; state "failed" | Page replaced by the block page |
| Server sends `Link: rel=stylesheet` | Header removed | Header removed |
| Server redirects an invite link to another origin | Navigation blocked | Navigation blocked |
| Server redirects an invite link to the release page or a store, directly or through `/ext/chrome` | Navigation blocked: the address carries a fragment | Same |
| Server redirects to another port or scheme of the host | Blocked, as above | Blocked, as above |
| Service worker registered before the extension answers the navigation | Document stopped, worker removed, page reloaded | Same |
| Manifest host unreachable, nothing stored | "Unverifiable"; script policy still in force | Navigation replaced by the block page |

The extension substantially narrows, but does not eliminate, the web-delivery
trust problem. It does not prevent abuse of a bug in already trusted client
code, protect a compromised signing key or browser store, or defend against a
malicious higher-privilege browser extension.

#### What Chromium cannot do

Manifest V3 in Chromium gives an extension no way to read or hold the body of
a navigation response. The page HTML therefore cannot be compared with the
signed hash before it is parsed, and a second download proves nothing, since
the server can answer it differently. In Chromium the script policy is the
only thing that binds what the page does to the signed release, and it binds
scripts, not markup.

That gap was not theoretical. The client uses a framework that reads
directives from markup. Up to and including v0.8.6, one element with a
binding attribute and no script, added to the navigation response only, made
the signed framework put a value from the application into the URL of an
image, which the page then requested from the server. The same mechanism
reached anything the application holds, decrypted messages included.

The client closes that path itself, since no extension can in Chromium:

- The two pages that run the application carry no application markup. It
  lives in signed scripts under `static/js/templates/`, so it is covered by
  the script policy like the rest of the client.
- The framework file carries a guard after the vendored build, in the same
  file, so that the framework cannot be loaded without it. The guard gives
  the framework a directive prefix drawn at random on every page load and
  known only inside that script. Markup that arrives with the page cannot
  name it, and its `x-`, `:` and `@` attributes are ordinary attributes
  that nothing evaluates. The signed templates are rewritten to the prefix
  when they are mounted.
- The framework starts once the document has been parsed. Before that,
  everything in the body that was not mounted and is not a script is
  removed.

This holds in whatever order, and with whatever attributes, a server arranges
the script elements of the page: it can leave the application out, it cannot
address the application's state.

What is left in Chromium is what markup can do without the framework. It is
shown until the document has been parsed. A page served without the
framework file runs no application but can show anything, a form that asks
for something included, under the site's address and a "partially verified"
state. An unsigned stylesheet from the site is detected and reported, not
blocked. Use Firefox when the server must not be trusted with the page.

#### Without the extension

None of the above applies. In particular a server can redirect an invite link
to an origin of its choice and read the key from the fragment there. No
change to the site can prevent that, because the first response to an invite
link is always the server's.

## Self-Hosted Instances

If you are running your own PinChat instance (not using the official pinchat.im), you **MUST** create your own extension with your own keys. Using the official extension with a self-hosted instance will not work because:

1. The hardcoded public key won't match your private key
2. The hardcoded domain won't match your server
3. Signature verification will always fail

### Steps for Self-Hosting

1. **Generate your own ECDSA P-256 key pair:**
   ```bash
   openssl ecparam -genkey -name prime256v1 -noout -out private.pem
   openssl ec -in private.pem -pubout -out public.pem
   ```

2. **Fork or copy the extension code**

3. **Update the hardcoded values in these files:**

   - `chrome/background.js`
   - `firefox/background.js`

   Replace:
   ```javascript
   // Change this to YOUR public key
   const PINCHAT_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
   YOUR_PUBLIC_KEY_HERE
   -----END PUBLIC KEY-----`;

   // Change this to YOUR domain
   const OFFICIAL_DOMAIN = 'your-domain.com';
   ```

4. **Update the manifest URL** in `CONFIG.HASH_LIST_URL` to point to your repository

5. **Generate signed hashes** for your static files:
   ```bash
   node generate-hashes.js --private-key private.pem --output hashes.json.signed
   ```

6. **Distribute your custom extension** to your users:
   - For internal use: Load unpacked in developer mode
   - For public distribution: Publish to Chrome/Firefox stores under your own account

### Important Notes for Self-Hosting

- Your users must install YOUR extension, not the official one
- Keep your private key secure and separate from your server
- Consider hosting your signed manifest on a separate service (e.g., GitHub) for additional security
- Document your public key so users can verify the extension they install

## File Structure

```
extensions/
├── README.md              # This file
├── generate-hashes.js     # Hash generation and signing script
├── generate-csp-rules.js  # Per-page preventive CSP generator
├── generate-icons.sh      # Icon generation script
├── hashes.json.example    # Example hash file format
├── chrome/                # Chromium build
│   ├── manifest.json      # Extension manifest (MV3)
│   ├── rules.json         # Script policy, header removals, redirect rules
│   ├── verdict.js         # What each state means (pure logic, unit tested)
│   ├── background.js      # Manifest validation, per-tab state, response check
│   ├── content.js         # Probes, DOM inspection, overlay
│   ├── popup.html         # Extension popup UI
│   ├── popup.js           # Popup logic
│   ├── blocked.html       # Shown in place of a refused navigation
│   ├── blocked.js
│   ├── blocked.css
│   ├── warning.css        # Overlay styles (web_accessible_resource limited to pinchat.im)
│   └── icons/             # Extension icons
└── firefox/               # Firefox build: same sources, own manifest and rules
    ├── manifest.json      # Adds the webRequest permissions for the response check
    ├── rules.json         # No redirect rules: enforced in background.js instead
    └── ...                # verdict.js, background.js, content.js, popup.*,
                           # blocked.* and warning.css are identical to chrome/
```

## Troubleshooting

### Extension shows "?" yellow badge
- Check browser console for errors
- Verify GitHub URL is accessible
- Check CORS headers on GitHub raw content

### Verification always fails
- Ensure public key matches private key used for signing
- Verify file paths in hashes.json match actual server paths
- Check that files haven't been modified after signing

### Signature verification fails
- Confirm the private key is ECDSA P-256 (prime256v1)
- Verify the public key in extensions matches the private key
- Re-generate keys if necessary

### Files not found (HTTP 404)
- Check file paths start with `/` (e.g., `/index.html`)
- Verify files exist at the expected URLs on pinchat.im
- Update `FILES_TO_HASH` in generate-hashes.js if paths changed

## Signing Stays Offline

Do not automate signing in CI. A workflow that holds the private key as a
repository secret and re-signs on every push to `static/` turns "can push to
the repository" into "can produce a manifest every installed extension
accepts", which is exactly the capability the signature exists to withhold
from the server and from the repository. Sign on a machine you control, as in
"Generate Signed Hash List" above, and commit the result.

Keep the key file out of the working tree. `*.pem` is ignored by git as a
safety net, not as a place to store it: `git add -f`, a different extension
or an editor backup would still pick it up.

## License

Copyright 2025 Raffaele Mangiacasale <support@pinchat.im>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

See the [LICENSE](LICENSE) file for details.
