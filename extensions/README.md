# PinChat Integrity Verifier Browser Extensions

Browser extensions that verify the integrity of files served by pinchat.io against cryptographically signed hashes.

## How It Works

1. The extension fetches a signed hash list from GitHub
2. Verifies the ECDSA P-256 signature using the embedded public key
3. Fetches each file from pinchat.io and calculates its SHA-256 hash
4. Compares the calculated hashes with the signed list
5. Shows a green checkmark badge if all files match
6. Shows a **red warning overlay** if any file doesn't match

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

### 3. Generate Signed Hash List

```bash
node generate-hashes.js --private-key private.pem --output ../hashes.json.signed
```

This will:
- Calculate SHA-256 hashes for all static files
- Sign the hash list with your private key
- Output `hashes.json.signed` to the repository root

### 4. Commit and Push Hash File

```bash
git add ../hashes.json.signed
git commit -m "Update signed hash list"
git push
```

The extensions will fetch from:
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
| ✓ (green) | All files verified |
| ! (red) | Verification failed - possible compromise |
| ? (yellow) | Error during verification |
| ... (blue) | Verification in progress |

### Warning Overlay

If verification fails, a full-screen red overlay appears with:
- **POSSIBLE SERVER COMPROMISE!** warning
- List of files that failed verification
- "Leave This Site" button
- "Dismiss (Unsafe)" button with confirmation

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