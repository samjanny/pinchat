#!/usr/bin/env bash
#
# Finish a release after the offline re-sign.
#
# The one step that cannot be automated is signing hashes.json.signed with the
# offline private key. Everything that has to follow it, in lockstep, can be:
#
#   1. for a release of the extension too: MIN_KNOWN_SEQUENCE in both
#      background scripts, the extension manifest version (what drives store
#      auto-update) and the version pin in tests/test-security.js (Test 7)
#   2. every CI job, so the commit that carries the manifest is green
#
# The extensions read the manifest from the main branch, so a release of the
# site alone needs a signature and nothing in the extensions. A release that
# changes the extensions names their new version as the second argument: the
# packaged rules.json, written by the signer, then comes from this manifest,
# and the floor of the build moves to its sequence.
#
# Usage:
#   node extensions/generate-hashes.js --private-key <key> --output hashes.json.signed
#   extensions/finish-release.sh <tag> [<extension-version>]
#
#   e.g. extensions/finish-release.sh v0.9.4          # the site only
#        extensions/finish-release.sh v0.9.4 1.8.0    # the site and the extensions
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

[ -n "$TAG" ] || fail "usage: extensions/finish-release.sh <tag> [<extension-version>]"
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "tag must look like v1.2.3, got $TAG"
if [ -n "$EXT_VERSION" ]; then
    [[ "$EXT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "extension version must look like 1.2.3, got $EXT_VERSION"
fi
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
[ "$(jq -r '.data.pages | type' hashes.json.signed)" = "array" ] \
    || fail "hashes.json.signed lists no page scripts: sign it with the current generate-hashes.js"

read_pin() { # <browser> <const-name>
    sed -n "s/^const $2 = '\{0,1\}\([^';]*\)'\{0,1\};/\1/p" "extensions/$1/background.js" | head -1
}
OLD_FLOOR="$(read_pin chrome MIN_KNOWN_SEQUENCE)"
OLD_VERSION="$(jq -r .version extensions/chrome/manifest.json)"
[ -n "$OLD_FLOOR" ] || fail "could not read MIN_KNOWN_SEQUENCE from extensions/chrome/background.js"

# ---------------------------------------------------------------------------
# A release of the extensions: same values in both browsers, in the same
# commit as the manifest their packaged rules come from.
# ---------------------------------------------------------------------------
if [ -n "$EXT_VERSION" ]; then
    # Store auto-update keys off the manifest version alone, so it has to move.
    if [ "$OLD_VERSION" = "$EXT_VERSION" ]; then
        fail "extension version $EXT_VERSION is already the current one; stores only update on a higher version"
    fi
    step "Extension release: floor $OLD_FLOOR -> $NEW_SEQ, extension $OLD_VERSION -> $EXT_VERSION"
    for browser in chrome firefox; do
        bg="extensions/$browser/background.js"
        sed -i "s/^const MIN_KNOWN_SEQUENCE = [0-9]*;/const MIN_KNOWN_SEQUENCE = $NEW_SEQ;/" "$bg"
        [ "$(read_pin "$browser" MIN_KNOWN_SEQUENCE)" = "$NEW_SEQ" ] || fail "failed to set MIN_KNOWN_SEQUENCE in $bg"

        manifest="extensions/$browser/manifest.json"
        # sed rather than jq so key order, indentation and the trailing newline
        # stay byte-identical apart from the version line.
        sed -i "s/^\(    \"version\": \"\)[^\"]*\(\",\)$/\1$EXT_VERSION\2/" "$manifest"
        [ "$(jq -r .version "$manifest")" = "$EXT_VERSION" ] || fail "failed to set version in $manifest"
    done

    # Test 7 in tests/test-security.js pins the version so CI catches drift.
    sed -i "s/&& chromeManifest.version === '[^']*'/\&\& chromeManifest.version === '$EXT_VERSION'/" tests/test-security.js
    grep -q "chromeManifest.version === '$EXT_VERSION'" tests/test-security.js \
        || fail "failed to update the version pin in tests/test-security.js"
else
    step "Release of the site only: the extensions stay at $OLD_VERSION, floor $OLD_FLOOR"
fi

# ---------------------------------------------------------------------------
# Every CI job. Order: cheapest and most likely to fail first.
# ---------------------------------------------------------------------------
step "verify-sri (signature, SRI, manifest coverage, page lists, CSP rule coverage)"
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
# What is left is a matter of intent, not mechanics: commit, merge, tag, and
# the order in which the site and main change.
# ---------------------------------------------------------------------------
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [ -n "$EXT_VERSION" ]; then
    SUBJECT="chore(release): re-sign at sequence $NEW_SEQ, extension $EXT_VERSION, $TAG"
else
    SUBJECT="chore(release): re-sign at sequence $NEW_SEQ, $TAG"
fi
cat <<MSG

All checks passed. Changed files:
MSG
git status --short
cat <<MSG

Next, in this order:

  git add -u    # tracked files only; add any new file by name after reviewing the list above
  git commit -m "$SUBJECT"
MSG
if [ "$BRANCH" != "main" ]; then
    cat <<MSG
  git checkout main
  git merge --no-ff $BRANCH -m "Merge $BRANCH: $TAG"
MSG
fi
cat <<MSG
  git tag -a $TAG -m "$TAG"
  git push origin $TAG          # the tag only: main does not move yet

The extensions take the manifest from main. Pushed before the site serves
this release, it would make the pages still served look like a release
nobody signed. So build the tag on the server and dry-run it first
(README, "Docker"), then push main and switch the site right after:

  git push origin main          # then, on the server: docker compose up -d

A page loaded in between asks the release host again when it does not match,
and is loaded again under the new release once main has it.
MSG
if [ -n "$EXT_VERSION" ]; then
    cat <<MSG

Then build the store packages of $EXT_VERSION from the tag:

  extensions/package.sh $TAG
MSG
fi
