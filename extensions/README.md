# PinChat Integrity Verifier Browser Extensions

Browser extensions that verify the integrity of files served by pinchat.io using Subresource Integrity (SRI) verification.

## How It Works

The extension uses a defense-in-depth approach combining SRI with signed manifests:

1. **Manifest Verification**: Extension fetches signed hash list from GitHub
2. **Signature Verification**: Verifies ECDSA P-256 signature using embedded public key
3. **SRI DOM Verification**: Content script checks that all `<script>` and `<link>` tags in the actual page DOM have correct `integrity` attributes matching the signed manifest
4. **Browser Enforcement**: Browser natively enforces SRI - blocks any file that doesn't match its integrity hash
5. **Visual Feedback**: Green checkmark if verified, red warning overlay if issues detected

### Why SRI?

Previous approach (separate fetches) was vulnerable to bypass attacks: a compromised server could serve clean files to the extension while serving malicious code to the browser.

With SRI:
- The `integrity` attribute is hardcoded in HTML files
- Browser refuses to execute any JS/CSS that doesn't match the hash
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
git add static/*.html hashes.json.signed
git commit -m "Update SRI attributes and signed hash list"
git push
```

The extensions will fetch the manifest from:
`https://raw.githubusercontent.com/samjanny/pinchat/main/hashes.json.signed`

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

For permanent Firefox installation, the extension needs to be signed by Mozilla.

## Extension Behavior

### Status Badge

| Badge | Meaning |
|-------|---------|
| ✓ (green) | Manifest signature verified, SRI attributes checked |
| ! (red) | Verification failed - possible compromise |
| ? (yellow) | Error fetching/verifying manifest |
| ... (blue) | Verification in progress |

### Warning Overlay

If verification fails, a full-screen red overlay appears with:
- **UNAUTHORIZED RESOURCES DETECTED!** warning
- List of issues (missing SRI, SRI mismatch, unauthorized scripts, etc.)
- "Leave This Site" button
- "Dismiss (Unsafe)" button with confirmation

**CSP Compatibility**: The warning overlay uses Shadow DOM with external CSS loaded from the extension's `web_accessible_resources`. This ensures the overlay displays correctly even on pages with strict Content Security Policy (CSP) that blocks inline styles. Firefox MV3 exposes only `warning.css` and restricts it to `https://pinchat.io/*` via `matches`.

### What the Extension Detects

- Missing `integrity` attribute on scripts/stylesheets
- SRI hash mismatch with signed manifest
- **File hash mismatch** (fetches ALL manifest files and verifies hashes)
- Inline scripts (not allowed)
- External scripts/stylesheets (not allowed)
- **Unauthorized same-origin scripts/stylesheets** (outside `/static/` path)
- External iframes
- Forms submitting to external URLs
- CSS `@import` directives

### Verification Approach

The extension uses a **dual verification** approach:

1. **DOM SRI Check**: Verifies that all `<script>` and `<link>` tags have correct `integrity` attributes matching the signed manifest
2. **File Hash Verification**: Fetches ALL files listed in the manifest (not just those in DOM) and computes their SHA-256 hashes to detect tampering

This catches:
- Lazy-loaded or deferred scripts not yet in DOM
- Server serving modified files (even with correct SRI in HTML)
- Files blocked by browser SRI (hash mismatch detected independently)

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

### Verification Interval

The extension verifies integrity:
- On extension install/update
- Every 5 minutes (configurable in `CONFIG.CHECK_INTERVAL_MINUTES`)
- When manually triggered via popup

## Updating Hashes

After deploying changes to pinchat.io:

1. Run the hash generator with your private key
2. Commit and push the new `hashes.json.signed`
3. Extensions will automatically pick up changes within 5 minutes

## Security Considerations

### Why the Public Key is Hardcoded

The public key (`PINCHAT_PUBLIC_KEY`) and domain (`OFFICIAL_DOMAIN`) are **intentionally hardcoded** in the extension source code. This is a critical security feature, not a limitation.

**Security benefits of hardcoding:**

1. **Server compromise protection**: If an attacker gains access to the pinchat.io server, they CANNOT change the public key used to verify file signatures. The key is baked into the extension code that users have already installed.

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

The SRI approach provides multiple layers of protection:

1. **Browser-level enforcement**: Even without the extension, browsers block any script/stylesheet that doesn't match its `integrity` hash
2. **Extension verification**: Verifies that the HTML contains the correct integrity values (matching signed manifest from GitHub)
3. **Signed manifest**: Hash list is signed, so attackers can't forge a valid manifest even with server access

### Attack Prevention

| Attack | Protection |
|--------|------------|
| Server serves malicious JS | Browser blocks (SRI mismatch) |
| Server removes SRI from HTML | Extension detects missing integrity |
| Server changes SRI in HTML | Extension detects SRI doesn't match manifest |
| Server serves different content to extension vs browser | N/A - Extension checks actual DOM, not separate fetch |

## Self-Hosted Instances

If you are running your own PinChat instance (not using the official pinchat.io), you **MUST** create your own extension with your own keys. Using the official extension with a self-hosted instance will not work because:

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
   - `shared/verify.js`

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
├── generate-icons.sh      # Icon generation script
├── hashes.json.example    # Example hash file format
├── shared/
│   └── verify.js          # Shared verification logic (reference)
├── chrome/
│   ├── manifest.json      # Chrome extension manifest (MV3)
│   ├── background.js      # Service worker
│   ├── content.js         # Content script for overlay
│   ├── popup.html         # Extension popup UI
│   ├── popup.js           # Popup logic
│   ├── warning.html       # Warning overlay page (web_accessible_resource)
│   ├── warning.css        # Warning overlay styles (CSP-compliant)
│   └── icons/             # Extension icons
└── firefox/
    ├── manifest.json      # Firefox extension manifest (MV3)
    ├── background.js      # Background script
    ├── content.js         # Content script for overlay
    ├── popup.html         # Extension popup UI
    ├── popup.js           # Popup logic
    ├── warning.html       # Warning overlay page
    ├── warning.css        # Warning overlay styles (web_accessible_resource limited to pinchat.io)
    └── icons/             # Extension icons
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
- Verify files exist at the expected URLs on pinchat.io
- Update `FILES_TO_HASH` in generate-hashes.js if paths changed

## Automated Hash Updates (GitHub Actions)

Automatically update the signed hash list when static files change:

```yaml
# .github/workflows/update-hashes.yml
name: Update Hash List

on:
  push:
    branches: [main]
    paths:
      - 'static/**'

jobs:
  update-hashes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Write private key
        run: echo "${{ secrets.HASH_SIGNING_KEY }}" > private.pem

      - name: Generate signed hashes
        run: node extensions/generate-hashes.js -k private.pem -o hashes.json.signed

      - name: Clean up private key
        run: rm -f private.pem

      - name: Commit and push
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add hashes.json.signed
          git diff --staged --quiet || git commit -m "Update signed hash list [skip ci]"
          git push
```

### Setting up the GitHub Action

1. Go to repository **Settings > Secrets and variables > Actions**
2. Create a new secret named `HASH_SIGNING_KEY`
3. Paste your private key content (from `private.pem`)

Now every push to `static/` will automatically update the signed hash list.

## License

Copyright 2025 Raffaele Mangiacasale <support@pinchat.io>

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
