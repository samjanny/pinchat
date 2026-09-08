#!/usr/bin/env bash
#
# Finish a release after the offline re-sign.
#
# The one step that cannot be automated is signing hashes.json.signed with the
# offline private key. Everything that has to follow it, in lockstep, can be:
#
#   1. GITHUB_TAG and MIN_KNOWN_SEQUENCE in both extension background scripts
#   2. the extension manifest version (what drives store auto-update)
#   3. the release-pin expectations in tests/test-security.js (Test 7)
#   4. every CI job, so the commit that carries the manifest is green
#
# A pin left behind here ships an extension that rejects every manifest it can
# fetch, and a manifest that does not match the tree fails verify-sri in CI.
# Doing all of it from one script, after the signature, removes that class of
# mistake from the release.
#
# Usage:
#   node extensions/generate-hashes.js --private-key <key> --output hashes.json.signed
#   extensions/finish-release.sh <tag> <extension-version>
#
#   e.g. extensions/finish-release.sh v0.8.0 1.3.0
#
# The script does not commit, merge or tag. It stages nothing and prints the
# exact commands for those steps at the end.
#
set -euo pipefail

TAG="${1:-}"
EXT_VERSION="${2:-}"
ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

fail() { echo "ERROR: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

[ -n "$TAG" ] && [ -n "$EXT_VERSION" ] \
    || fail "usage: extensions/finish-release.sh <tag> <extension-version>"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must look like v1.2.3, got $TAG"
[[ "$EXT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "extension version must look like 1.2.3, got $EXT_VERSION"
command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v node >/dev/null 2>&1 || fail "node is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1 \
    && fail "tag $TAG already exists; pick the next version"

# ---------------------------------------------------------------------------
# The signature must be new. Compare the working-tree manifest with HEAD's.
# ---------------------------------------------------------------------------
step "Checking that hashes.json.signed was re-signed"
[ -f hashes.json.signed ] || fail "hashes.json.signed is missing"
NEW_SEQ="$(jq -r '.data.sequence' hashes.json.signed)"
[[ "$NEW_SEQ" =~ ^[0-9]+$ ]] || fail "hashes.json.signed has no numeric sequence"
HEAD_SEQ="$(git show HEAD:hashes.json.signed 2>/dev/null | jq -r '.data.sequence' 2>/dev/null || echo 0)"
[[ "$HEAD_SEQ" =~ ^[0-9]+$ ]] || HEAD_SEQ=0
[ "$NEW_SEQ" -gt "$HEAD_SEQ" ] \
    || fail "sequence $NEW_SEQ is not above HEAD's $HEAD_SEQ: run generate-hashes.js with the private key first"
echo "  sequence $HEAD_SEQ -> $NEW_SEQ"

read_pin() { # <browser> <const-name>
    sed -n "s/^const $2 = '\{0,1\}\([^';]*\)'\{0,1\};/\1/p" "extensions/$1/background.js" | head -1
}
OLD_TAG="$(read_pin chrome GITHUB_TAG)"
OLD_FLOOR="$(read_pin chrome MIN_KNOWN_SEQUENCE)"
OLD_VERSION="$(jq -r .version extensions/chrome/manifest.json)"
[ -n "$OLD_TAG" ] && [ -n "$OLD_FLOOR" ] || fail "could not read the current pins from extensions/chrome/background.js"

# Store auto-update keys off the manifest version alone, so it has to move.
if [ "$OLD_VERSION" = "$EXT_VERSION" ]; then
    fail "extension version $EXT_VERSION is already the current one; stores only update on a higher version"
fi

# ---------------------------------------------------------------------------
# Pins. Same values in both browsers, in the same commit as the manifest.
# ---------------------------------------------------------------------------
step "Setting release pins: tag $OLD_TAG -> $TAG, floor $OLD_FLOOR -> $NEW_SEQ, extension $OLD_VERSION -> $EXT_VERSION"
for browser in chrome firefox; do
    bg="extensions/$browser/background.js"
    sed -i "s/^const GITHUB_TAG = '[^']*';/const GITHUB_TAG = '$TAG';/" "$bg"
    sed -i "s/^const MIN_KNOWN_SEQUENCE = [0-9]*;/const MIN_KNOWN_SEQUENCE = $NEW_SEQ;/" "$bg"
    [ "$(read_pin "$browser" GITHUB_TAG)" = "$TAG" ] || fail "failed to set GITHUB_TAG in $bg"
    [ "$(read_pin "$browser" MIN_KNOWN_SEQUENCE)" = "$NEW_SEQ" ] || fail "failed to set MIN_KNOWN_SEQUENCE in $bg"

    manifest="extensions/$browser/manifest.json"
    # sed rather than jq so key order, indentation and the trailing newline
    # stay byte-identical apart from the version line.
    sed -i "s/^\(    \"version\": \"\)[^\"]*\(\",\)$/\1$EXT_VERSION\2/" "$manifest"
    [ "$(jq -r .version "$manifest")" = "$EXT_VERSION" ] || fail "failed to set version in $manifest"
done

# Test 7 in tests/test-security.js pins the same values so CI catches drift.
sed -i "s/const pinsOk = chromeTag === '[^']*'/const pinsOk = chromeTag === '$TAG'/" tests/test-security.js
sed -i "s/&& chromeManifest.version === '[^']*'/\&\& chromeManifest.version === '$EXT_VERSION'/" tests/test-security.js
grep -q "chromeTag === '$TAG'" tests/test-security.js || fail "failed to update the tag pin in tests/test-security.js"
grep -q "chromeManifest.version === '$EXT_VERSION'" tests/test-security.js || fail "failed to update the version pin in tests/test-security.js"

# The extension README quotes the current release tag.
sed -i "s#raw.githubusercontent.com/samjanny/pinchat/v[0-9.]*/hashes.json.signed#raw.githubusercontent.com/samjanny/pinchat/$TAG/hashes.json.signed#" extensions/README.md

# ---------------------------------------------------------------------------
# Every CI job. Order: cheapest and most likely to fail first.
# ---------------------------------------------------------------------------
step "verify-sri (signature, SRI, manifest coverage, CSP rule coverage)"
node .github/scripts/verify-sri.js

step "Node test suite"
node tests/run-all-tests.js

step "Typographic scan (no em/en dashes, ellipsis, arrows, curly quotes, nbsp in tracked files)"
if git ls-files -z | grep -zv 'alpine-csp.min.js' \
    | xargs -0 grep -nP '[\x{2013}\x{2014}\x{2026}\x{2190}\x{2192}\x{2018}\x{2019}\x{201C}\x{201D}\x{00A0}]' 2>/dev/null; then
    fail "tracked files contain characters the repository does not use"
fi
echo "  clean"

step "cargo fmt --check"
cargo fmt --all -- --check

step "cargo clippy (advisory, as in CI)"
cargo clippy --all-targets --locked || true

step "cargo test --locked"
cargo test --locked

if command -v cargo-audit >/dev/null 2>&1; then
    step "cargo audit"
    cargo audit
else
    echo; echo "NOTE: cargo-audit is not installed; CI will run it. Install with: cargo install cargo-audit --locked"
fi

# ---------------------------------------------------------------------------
# What is left is a matter of intent, not mechanics: commit, merge, tag.
# ---------------------------------------------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
cat <<MSG

All checks passed. Changed files:
MSG
git status --short
cat <<MSG

Next, in this order:

  git add -A
  git commit -m "chore(release): re-sign at sequence $NEW_SEQ, pin extension $EXT_VERSION at $TAG"
MSG
if [ "$BRANCH" != "main" ]; then
    cat <<MSG
  git checkout main
  git merge --no-ff $BRANCH -m "Merge $BRANCH: $TAG"
MSG
fi
cat <<MSG
  git tag -a $TAG -m "$TAG"
  git push origin main $TAG

Then deploy the tag (ops/store-release-runbook.md, per-release procedure) and
only after the tag is live build the store packages:

  extensions/package.sh $TAG
MSG
