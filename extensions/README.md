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

### What the Extension Detects

- Missing `integrity` attribute on scripts/stylesheets
- SRI hash mismatch with signed manifest
- Inline scripts (not allowed)
- External scripts/stylesheets (not allowed)
- External iframes
- Forms submitting to external URLs
- CSS `@import` directives

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
│   └── icons/             # Extension icons
└── firefox/
    ├── manifest.json      # Firefox extension manifest (MV2)
    ├── background.js      # Background script
    ├── content.js         # Content script for overlay
    ├── popup.html         # Extension popup UI
    ├── popup.js           # Popup logic
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