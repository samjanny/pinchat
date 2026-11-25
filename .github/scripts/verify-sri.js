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

const DEPLOYMENT_SPECIFIC_FILES = new Set(['/static/operator.json']);

/**
 * Every resource a page loads that SRI covers: each <script src> and each
 * <link rel="stylesheet" href>, with its integrity attribute, or null when
 * it has none. Attributes are read by name, in whatever order and with
 * whatever else between them. A pattern that expected the integrity
 * attribute right after src or href skipped a tag written another way, and
 * a tag without one, without saying so.
 */
function sriReferences(html) {
  const references = [];
  const tags = /<(script|link)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/gi;
  const attributeRe = /([^\s=/"'>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  for (const [, tagName, rest] of html.matchAll(tags)) {
    const attributes = new Map();
    for (const [, name, double, single, bare] of rest.matchAll(attributeRe)) {
      const key = name.toLowerCase();
      // The first occurrence of an attribute is the one a browser keeps.
      if (!attributes.has(key)) attributes.set(key, double ?? single ?? bare ?? '');
    }
    const kind = tagName.toLowerCase();
    const isStylesheet = kind === 'link'
      && (attributes.get('rel') || '').toLowerCase().split(/\s+/).includes('stylesheet');
    const url = kind === 'script' ? attributes.get('src') : isStylesheet ? attributes.get('href') : undefined;
    if (url === undefined) continue;
    references.push({ kind, url, integrity: attributes.has('integrity') ? attributes.get('integrity') : null });
  }
  return references;
}

/** What is wrong with one reference, or null. */
function checkReference(reference) {
  if (!reference.url.startsWith('/static/')) return `${reference.url}: not a file of the site under /static/`;
  if (reference.integrity === null) return `${reference.url}: no integrity attribute`;
  const match = /^sha256-([A-Za-z0-9+/]+={0,2})$/.exec(reference.integrity.trim());
  if (!match) return `${reference.url}: integrity is not a single sha256 value (${reference.integrity})`;
  const assetPath = '.' + reference.url;
  if (!fs.existsSync(assetPath)) return `${reference.url}: MISSING ASSET`;
  const actual = sha256Normalized(assetPath);
  return actual === match[1] ? null : `${reference.url}: MISMATCH, integrity ${match[1]}, actual ${actual}`;
}

function sha256Normalized(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('base64');
}

function sha256NormalizedHex(filePath) {
  const text = fs.readFileSync(filePath, 'utf8').replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
}

function verifyExtensionPackage(browser) {
  const baseDir = path.join('extensions', browser);
  const manifest = JSON.parse(fs.readFileSync(path.join(baseDir, 'manifest.json'), 'utf8'));
  const resources = new Set();
  const add = (value) => {
    if (typeof value === 'string' && value.length > 0) resources.add(value);
  };

  add(manifest.background?.service_worker);
  for (const script of manifest.background?.scripts || []) add(script);
  for (const contentScript of manifest.content_scripts || []) {
    for (const script of contentScript.js || []) add(script);
    for (const stylesheet of contentScript.css || []) add(stylesheet);
  }
  add(manifest.action?.default_popup);
  for (const icon of Object.values(manifest.action?.default_icon || {})) add(icon);
  for (const icon of Object.values(manifest.icons || {})) add(icon);
  for (const ruleSet of manifest.declarative_net_request?.rule_resources || []) add(ruleSet.path);
  for (const group of manifest.web_accessible_resources || []) {
    for (const resource of group.resources || []) add(resource);
  }

  let bad = 0;
  for (const resource of resources) {
    const segments = resource.split(/[\\/]/);
    if (path.isAbsolute(resource) || segments.includes('..')) {
      console.error(`EXTENSION PACKAGE: unsafe ${browser} resource path ${resource}`);
      bad++;
      continue;
    }
    if (!fs.existsSync(path.join(baseDir, resource))) {
      console.error(`EXTENSION PACKAGE: missing ${browser}/${resource}`);
      bad++;
    }
  }

  console.log(`Extension package: ${browser} ${resources.size} declared resources, ${bad} bad`);
  return bad;
}

function main() {
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
    for (const reference of sriReferences(html)) {
      fileChecked++;
      totalChecked++;
      const problem = checkReference(reference);
      if (problem) {
        console.error(`  ${htmlFile}: ${problem}`);
        fileBad++;
        totalBad++;
      }
    }
    const status = fileBad === 0 ? 'OK' : 'FAIL';
    console.log(`${htmlFile}: ${fileChecked} tags, ${fileBad} bad - ${status}`);
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
    let manifestBad = 0;
    let manifestSkipped = 0;
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

    // The preventive CSP is another release artifact derived from the same
    // signed hashes. Reject stale or hand-edited browser rulesets.
    const {
      buildRules, PAGES, CATCH_ALL_REGEX, pageRegex,
    } = require('../../extensions/generate-csp-rules');

    // Coverage gate. Comparing a ruleset against buildRules() only proves it is
    // not stale; it says nothing about whether the policy covers the page. It
    // did not, for a long time: chat.html loads theme.js, pow.js and
    // nicknames.js, the hand-maintained list omitted all three, and because
    // script-src carries no 'self' they were blocked outright for every
    // extension user while this gate stayed green.
    //
    // This must read the ruleset that actually ships, not the one buildRules()
    // just derived: the derived one is correct by construction and would make
    // the check vacuous.
    const sriFromHex = (hex) => `sha256-${Buffer.from(hex, 'hex').toString('base64')}`;
    const signedByPath = new Map(signed.data.files.map((f) => [f.path, f.hash]));

    // Rules are looked up by the exact filter the generator emits for each
    // page. An earlier version recovered the page path from the filter by
    // deleting a fixed prefix and suffix; when the suffix changed, no path
    // ended in ".html" any more, every rule was skipped as "the catch-all", and
    // the gate printed success without having compared a single hash. Pages
    // checked are therefore counted, and a rule this script cannot attribute is
    // an error instead of being skipped.
    function checkRuleCoverage(browser, rules) {
      let bad = 0;
      let pagesChecked = 0;
      const pageByFilter = new Map(PAGES.map((pagePath) => [pageRegex(pagePath), pagePath]));
      const filters = rules.map((rule) => rule.condition.regexFilter);

      const policyRules = rules.filter((rule) => rule.action.type === 'modifyHeaders');
      const catchAll = policyRules.filter((rule) => rule.condition.regexFilter === CATCH_ALL_REGEX);
      if (catchAll.length !== 1) {
        console.error(`CSP COVERAGE: ${browser} must have exactly one catch-all rule, found ${catchAll.length}`);
        bad++;
      } else if (!catchAll[0].action.responseHeaders[0].value.startsWith("script-src 'none';")) {
        console.error(`CSP COVERAGE: ${browser}: the catch-all rule must deny every script`);
        bad++;
      }

      // The redirect guard. Chromium enforces it with a rule that matches the
      // Location response header; Firefox has no such condition and enforces
      // the same rule in its background script, so its ruleset must not carry
      // a rule it would reject.
      const redirectRules = rules.filter((rule) => rule.action.type === 'block');
      // Two in Chromium: one for every navigation, one that is stricter for a
      // navigation whose address carries a fragment.
      const expectedRedirectRules = browser === 'chrome' ? 2 : 0;
      if (redirectRules.length !== expectedRedirectRules
        || redirectRules.some((rule) => !rule.condition.responseHeaders
          || rule.condition.responseHeaders[0].header !== 'location')) {
        console.error(`CSP COVERAGE: ${browser} must have ${expectedRedirectRules} redirect rule(s) on the Location header`);
        bad++;
      }
      for (const rule of policyRules) {
        const operations = rule.action.responseHeaders.map((header) => `${header.header}:${header.operation}`).join(',');
        if (operations !== 'content-security-policy:set,link:remove,refresh:remove') {
          console.error(`CSP COVERAGE: ${browser}: a policy rule does not remove Link and Refresh (${operations})`);
          bad++;
        }
      }

      for (const filter of policyRules.map((rule) => rule.condition.regexFilter)) {
        if (filter !== CATCH_ALL_REGEX && !pageByFilter.has(filter)) {
          console.error(`CSP COVERAGE: ${browser} has a rule this check cannot attribute to a page: ${filter}`);
          bad++;
        }
      }

      for (const [filter, pagePath] of pageByFilter) {
        const rule = policyRules.find((candidate) => candidate.condition.regexFilter === filter);
        if (!rule) {
          console.error(`CSP COVERAGE: ${browser} has no rule for ${pagePath}`);
          bad++;
          continue;
        }
        const pageFile = '.' + pagePath;
        if (!fs.existsSync(pageFile)) {
          console.error(`CSP COVERAGE: ${browser} has a rule for ${pagePath}, which does not exist`);
          bad++;
          continue;
        }
        const policy = rule.action.responseHeaders[0].value.split(';')[0];
        const html = fs.readFileSync(pageFile, 'utf8');
        const loaded = [...html.matchAll(/<script\b[^>]*\ssrc="([^"]+)"/g)].map((m) => m[1]);
        if (loaded.length === 0) {
          console.error(`CSP COVERAGE: ${browser}: found no script tag in ${pagePath}`);
          bad++;
          continue;
        }
        for (const src of loaded) {
          const hex = signedByPath.get(src);
          if (!hex) {
            console.error(`CSP COVERAGE: ${browser}: ${pagePath} loads ${src}, absent from the signed manifest`);
            bad++;
            continue;
          }
          if (!policy.includes(`'${sriFromHex(hex)}'`)) {
            console.error(`CSP COVERAGE: ${browser}: ${pagePath} loads ${src}, whose hash is not in its script-src`);
            bad++;
          }
        }
        pagesChecked++;
      }
      if (pagesChecked !== PAGES.length && bad === 0) {
        console.error(`CSP COVERAGE: ${browser}: checked ${pagesChecked} of ${PAGES.length} pages`);
        bad++;
      }
      return { bad, pagesChecked };
    }

    for (const browser of ['chrome', 'firefox']) {
      const rulesPath = `extensions/${browser}/rules.json`;
      const actualRules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      const expectedRules = buildRules(signed, browser);
      if (JSON.stringify(actualRules) !== JSON.stringify(expectedRules)) {
        console.error(`PREVENTIVE CSP: ${rulesPath} does not match signed manifest`);
        totalBad++;
      } else {
        console.log(`Preventive CSP: ${browser} rules match signed manifest`);
      }
      const coverage = checkRuleCoverage(browser, actualRules);
      if (coverage.bad === 0) {
        console.log(
          `Preventive CSP: ${browser} rules cover every script tag on all ${coverage.pagesChecked} pages`,
        );
      } else {
        totalBad += coverage.bad;
      }
    }
  } catch (error) {
    console.error(`SIGNED MANIFEST: ${error.message}`);
    totalBad++;
  }

  for (const browser of ['chrome', 'firefox']) {
    try {
      totalBad += verifyExtensionPackage(browser);
    } catch (error) {
      console.error(`EXTENSION PACKAGE: ${browser}: ${error.message}`);
      totalBad++;
    }
  }

  return totalBad;
}

if (require.main === module) {
  process.exit(main() === 0 ? 0 : 1);
}

module.exports = { sriReferences, checkReference };
