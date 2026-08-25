#!/usr/bin/env node
/**
 * SRI consistency gate.
 *
 * For every <script src=... integrity=...> and <link href=... integrity=...>
 * in static/*.html, recompute the sha256 of the referenced asset (with the
 * same CRLF -> LF normalization used by extensions/generate-hashes.js) and
 * compare against the inline integrity attribute. It also verifies the
 * signature on hashes.json.signed with the extension trust anchor and checks
 * every repository-owned signed file hash against the working tree. The
 * deployment-specific operator.json is verified when present but may be
 * absent from a clean checkout. Exits non-zero on any other mismatch, bad
 * signature, or missing file.
 *
 * Run: node .github/scripts/verify-sri.js
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HTML_FILES = [
  'static/index.html',
  'static/login.html',
  'static/privacy.html',
  'static/terms.html',
  'static/chat.html',
];

const SRI_RE = /(?:src|href)="(\/static\/[^"]+)"\s+integrity="sha256-([^"]+)"/g;

const DEPLOYMENT_SPECIFIC_FILES = new Set(['/static/operator.json']);

function sha256Normalized(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('base64');
}

function sha256NormalizedHex(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

let totalChecked = 0;
let totalBad = 0;

for (const htmlFile of HTML_FILES) {
  if (!fs.existsSync(htmlFile)) {
    console.error(`MISSING: ${htmlFile}`);
    totalBad++;
    continue;
  }
  const html = fs.readFileSync(htmlFile, 'utf8');
  let fileChecked = 0;
  let fileBad = 0;
  let m;
  SRI_RE.lastIndex = 0;
  while ((m = SRI_RE.exec(html)) !== null) {
    const assetUrl = m[1];
    const expected = m[2];
    const assetPath = '.' + assetUrl;
    if (!fs.existsSync(assetPath)) {
      console.error(`  MISSING ASSET: ${assetUrl} (referenced in ${htmlFile})`);
      fileBad++;
      totalBad++;
      continue;
    }
    const actual = sha256Normalized(assetPath);
    fileChecked++;
    totalChecked++;
    if (actual !== expected) {
      console.error(`  MISMATCH ${assetUrl}`);
      console.error(`    in ${htmlFile}: ${expected}`);
      console.error(`    actual:        ${actual}`);
      fileBad++;
      totalBad++;
    }
  }
  const status = fileBad === 0 ? 'OK' : 'FAIL';
  console.log(`${htmlFile}: ${fileChecked} tags, ${fileBad} bad — ${status}`);
}

console.log(`\nTotal: ${totalChecked} SRI tags checked, ${totalBad} mismatches`);

// Signed-manifest gate. Inline SRI can be internally consistent while the
// release manifest still points at the previous assets; verify both layers.
try {
  const signed = JSON.parse(fs.readFileSync('hashes.json.signed', 'utf8'));
  const background = fs.readFileSync('extensions/chrome/background.js', 'utf8');
  const pemMatch = background.match(/const PINCHAT_PUBLIC_KEY = `([\s\S]*?)`;/);
  if (!pemMatch) throw new Error('extension public key not found');
  const signatureOk = crypto.verify(
    'sha256',
    Buffer.from(JSON.stringify(signed.data)),
    pemMatch[1],
    Buffer.from(signed.signature, 'base64'),
  );
  if (!signatureOk) {
    console.error('SIGNED MANIFEST: invalid ECDSA signature');
    totalBad++;
  }

  let manifestChecked = 0;
  let manifestSkipped = 0;
  let manifestBad = 0;
  for (const entry of signed.data.files) {
    const filePath = '.' + entry.path;
    if (!fs.existsSync(filePath)) {
      if (DEPLOYMENT_SPECIFIC_FILES.has(entry.path)) {
        console.log(`SIGNED MANIFEST: skipped deployment-specific ${entry.path}`);
        manifestSkipped++;
        continue;
      }
      console.error(`SIGNED MANIFEST: missing ${entry.path}`);
      manifestBad++;
      totalBad++;
      continue;
    }
    const actual = sha256NormalizedHex(filePath);
    manifestChecked++;
    if (actual !== entry.hash) {
      console.error(`SIGNED MANIFEST: hash mismatch ${entry.path}`);
      console.error(`  signed: ${entry.hash}`);
      console.error(`  actual: ${actual}`);
      manifestBad++;
      totalBad++;
    }
  }
  const signatureStatus = signatureOk ? 'valid' : 'INVALID';
  console.log(
    `Signed manifest: signature ${signatureStatus}, sequence ${signed.data.sequence}, `
    + `${manifestChecked} files checked, ${manifestSkipped} deployment-specific skipped, `
    + `${manifestBad} bad`,
  );
} catch (error) {
  console.error(`SIGNED MANIFEST: ${error.message}`);
  totalBad++;
}

process.exit(totalBad === 0 ? 0 : 1);
