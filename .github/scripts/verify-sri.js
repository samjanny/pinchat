#!/usr/bin/env node
/**
 * SRI consistency gate.
 *
 * For every <script src=... integrity=...> and <link href=... integrity=...>
 * in static/*.html, recompute the sha256 of the referenced asset (with the
 * same CRLF -> LF normalization used by extensions/generate-hashes.js) and
 * compare against the inline integrity attribute. Exits non-zero on any
 * mismatch or missing file.
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

function sha256Normalized(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('base64');
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
process.exit(totalBad === 0 ? 0 : 1);
